"""Offline-only owner-signed approval and single-host atomic claim.

NEVER obtains credentials, calls providers, or executes a command. A trusted
runner must independently enroll/pin the owner's signing key and verify the
protected-main checkout. SQLite claims are atomic only for contenders sharing
the same durable local file, NOT distributed/ephemeral CI runners. No claim
receipt grants live-execution authority. After a claim, never retry blindly.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from avuhz_engineering.development_handoff_approval_gate import (
    EXPECTED_OWNER, EXPECTED_STAGES, GatePreflightResult,
    HandoffApprovalGateStop, StageAuthorizationDocuments,
    prepare_handoff_stage_approval_state,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    DevelopmentHandoffSource,
)

_PURPOSE = "AVUHZ_DEVELOPMENT_HANDOFF_STAGE_OWNER_APPROVAL_V1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_CLAIM_FIELDS = frozenset({
    "purpose", "owner_identity", "repository", "source_sha", "command_digest",
    "authorization_set_digest", "stage", "plan_digest", "approval_digest",
    "tenant_id", "project_reference", "not_before", "expires_at", "nonce",
})


class SingleUseClaimStop(ValueError):
    """Fixed safe rejection; untrusted input and provider data never echoed."""


@dataclass(frozen=True)
class SingleUseClaimReceipt:
    stage: str
    plan_digest: str
    command_digest: str
    source_sha: str
    classification: str = "OFFLINE_ATOMIC_STAGE_CLAIM_RECORDED_NO_LIVE_AUTHORITY"
    durable_local_claim_recorded: bool = True
    owner_signing_key_binding_verified_externally: bool = False
    distributed_consumption_verified: bool = False
    remote_execution_authorized: bool = False
    retry_authorized: bool = False


def _reject(code: str) -> None:
    raise SingleUseClaimStop(code)


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject("HANDOFF_OWNER_PROOF_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (ValueError, TypeError, OverflowError):
        _reject("HANDOFF_OWNER_PROOF_TIME_INVALID")
    if parsed.tzinfo != timezone.utc:
        _reject("HANDOFF_OWNER_PROOF_TIME_INVALID")
    return parsed


def _canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _verify_owner_signature(
    claims: Mapping[str, object], signature: bytes, owner_public_key: bytes,
    expected_trust_anchor_digest: str,
) -> None:
    """Anchor digest MUST originate from independent, trusted owner enrollment."""
    if (
        type(owner_public_key) is not bytes or len(owner_public_key) != 32
        or type(signature) is not bytes or len(signature) != 64
        or type(expected_trust_anchor_digest) is not str
        or not _SHA256.fullmatch(expected_trust_anchor_digest)
        or "sha256:" + hashlib.sha256(owner_public_key).hexdigest()
        != expected_trust_anchor_digest
    ):
        _reject("HANDOFF_OWNER_TRUST_ANCHOR_UNVERIFIED")
    try:
        Ed25519PublicKey.from_public_bytes(owner_public_key).verify(
            signature, _canonical_bytes(dict(claims))
        )
    except (InvalidSignature, TypeError, ValueError):
        _reject("HANDOFF_OWNER_SIGNATURE_INVALID")


def _checked_ledger(path: Path) -> str:
    """Require an already-provisioned, owner-private local SQLite file."""
    if not isinstance(path, Path) or not path.is_absolute() or path.suffix != ".sqlite3":
        _reject("HANDOFF_CLAIM_LEDGER_UNTRUSTED")
    try:
        file_info = path.lstat()
        parent_info = path.parent.lstat()
    except OSError:
        _reject("HANDOFF_CLAIM_LEDGER_UNAVAILABLE")
    if (
        not stat.S_ISREG(file_info.st_mode)
        or stat.S_ISLNK(file_info.st_mode)
        or file_info.st_uid != os.getuid()
        or file_info.st_mode & 0o077
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or parent_info.st_mode & 0o077
    ):
        _reject("HANDOFF_CLAIM_LEDGER_UNTRUSTED")
    return "file:" + quote(str(path), safe="/") + "?mode=rw"


def _claim_once(
    ledger_path: Path, *, plan_id: str, step_id: str, stage: str,
    plan_digest: str, approval_digest: str, command_digest: str,
    source_sha: str, now: str,
) -> None:
    uri = _checked_ledger(ledger_path)
    connection = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=3, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS avuhz_offline_handoff_stage_claim ("
            "plan_id TEXT NOT NULL, step_id TEXT NOT NULL, stage TEXT NOT NULL, "
            "plan_digest TEXT NOT NULL, approval_digest TEXT NOT NULL UNIQUE, "
            "command_digest TEXT NOT NULL, source_sha TEXT NOT NULL, "
            "claimed_at TEXT NOT NULL, PRIMARY KEY (plan_id, step_id))"
        )
        connection.execute(
            "INSERT INTO avuhz_offline_handoff_stage_claim "
            "(plan_id, step_id, stage, plan_digest, approval_digest, command_digest, "
            "source_sha, claimed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plan_id, step_id, stage, plan_digest, approval_digest,
             command_digest, source_sha, now),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError:
        if connection is not None:
            connection.rollback()
        _reject("HANDOFF_STAGE_ALREADY_CLAIMED")
    except sqlite3.Error:
        if connection is not None:
            connection.rollback()
        _reject("HANDOFF_CLAIM_STORAGE_UNVERIFIED")
    finally:
        if connection is not None:
            connection.close()


def verify_and_claim_single_stage_offline(
    request: dict, *, source: DevelopmentHandoffSource,
    observed_main_sha: str, at_utc: datetime, stage: str,
    stages: Mapping[str, StageAuthorizationDocuments],
    owner_claims: Mapping[str, object], owner_signature: bytes,
    pinned_owner_public_key: bytes, pinned_owner_key_digest: str,
    ledger_path: Path,
) -> SingleUseClaimReceipt:
    """Verify an owner-signed exact stage, then claim it atomically, locally.

    The public key and its fingerprint must be independently owner-verified.
    The checkout SHA must be obtained from trusted source validation. The
    SQLite file must be common durable state across contenders (no guarantee
    of this across GitHub Actions runners). No provider interaction.
    """
    if (
        type(owner_claims) is not dict or set(owner_claims) != _CLAIM_FIELDS
        or type(stage) is not str or stage not in EXPECTED_STAGES
        or type(stages) is not dict or stage not in stages
        or type(stages[stage]) is not StageAuthorizationDocuments
        or not isinstance(at_utc, datetime) or at_utc.tzinfo is None
    ):
        _reject("HANDOFF_OWNER_PROOF_SHAPE_INVALID")
    documents = stages[stage]
    try:
        plan = documents.plan
        approval = documents.approval
        project = plan["target"]["project_reference"]
        expected = {
            "purpose": _PURPOSE,
            "owner_identity": EXPECTED_OWNER,
            "repository": source.repository,
            "source_sha": observed_main_sha,
            "command_digest": source.command_digest,
            "authorization_set_digest": source.authorization_plan_digest,
            "stage": stage,
            "plan_digest": plan["plan_digest"],
            "approval_digest": approval["approval_digest"],
            "tenant_id": source.tenant_id,
            "project_reference": project,
            "not_before": approval["effective_at"],
            "expires_at": approval["expires_at"],
        }
    except (AttributeError, KeyError, TypeError):
        _reject("HANDOFF_OWNER_PROOF_SHAPE_INVALID")
    if (
        any(owner_claims.get(k) != value for k, value in expected.items())
        or type(owner_claims.get("nonce")) is not str
        or not _NONCE.fullmatch(owner_claims["nonce"])
    ):
        _reject("HANDOFF_OWNER_PROOF_BINDING_MISMATCH")
    now = at_utc.astimezone(timezone.utc)
    if not _utc(owner_claims["not_before"]) <= now < _utc(owner_claims["expires_at"]):
        _reject("HANDOFF_OWNER_PROOF_EXPIRED")
    _verify_owner_signature(
        owner_claims, owner_signature, pinned_owner_public_key,
        pinned_owner_key_digest,
    )
    try:
        proposal: GatePreflightResult = prepare_handoff_stage_approval_state(
            request, source=source, observed_main_sha=observed_main_sha,
            at_utc=at_utc, stage=stage, stages=stages,
            owner_source_verified=True, observed_owner_identity=EXPECTED_OWNER,
            authorization_set_attested_digest=source.authorization_plan_digest,
        )
    except HandoffApprovalGateStop:
        _reject("HANDOFF_STAGE_AUTHORIZATION_DENIED")
    if (
        proposal.remote_execution_authorized is not False
        or proposal.stage.stage != stage
        or proposal.stage.approval_digest != approval["approval_digest"]
        or proposal.stage.authorized_progress["step_states"][0]["authorization_consumed"] is not False
    ):
        _reject("HANDOFF_STAGE_AUTHORIZATION_UNVERIFIED")
    _claim_once(
        ledger_path,
        plan_id=plan["plan_id"], step_id=plan["steps"][0]["step_id"],
        stage=stage, plan_digest=plan["plan_digest"],
        approval_digest=approval["approval_digest"],
        command_digest=proposal.command_digest, source_sha=observed_main_sha,
        now=now.isoformat().replace("+00:00", "Z"),
    )
    return SingleUseClaimReceipt(
        stage=stage, plan_digest=plan["plan_digest"],
        command_digest=proposal.command_digest, source_sha=observed_main_sha,
    )
