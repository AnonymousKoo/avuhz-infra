"""Offline Ed25519 owner-key enrollment *candidate* verification.

This proves possession of a candidate private key, NOT that the owner
controls that key. Independent human owner attribution, immutable public-key
pinning in a trusted runtime, approved plans, and authorization consumption
are separate. Never use this result as an execution permit.

There is no key generator, key storage, signature issuer, CLI, credential
lookup, network call, GitHub mutation, or Supabase contact in this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from avuhz_engineering.development_handoff_approval_gate import EXPECTED_OWNER
from avuhz_engineering.development_source_bound_handoff_lifecycle import REPOSITORY
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

PURPOSE = "AVUHZ_DEVELOPMENT_HANDOFF_OWNER_KEY_ENROLLMENT_CANDIDATE_V1"
_FIELDS = frozenset({
    "purpose", "owner_identity", "repository", "environment", "tenant_id",
    "auth_project_ref", "data_project_ref", "public_key_sha256",
    "issued_at", "expires_at", "nonce",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_WINDOW = timedelta(minutes=15)


class OwnerKeyEnrollmentStop(ValueError):
    """Only fixed, safe failure codes; never expose raw source or secrets."""


@dataclass(frozen=True)
class OwnerKeyEnrollmentCandidateResult:
    public_key_sha256: str
    classification: str = "OFFLINE_OWNER_KEY_PROOF_OF_POSSESSION_ONLY"
    candidate_signature_verified: bool = True
    candidate_scope_verified: bool = True
    human_owner_binding_verified: bool = False
    owner_fingerprint_independently_pinned: bool = False
    signed_stage_approvals_verified: bool = False
    provider_or_credential_authority: bool = False
    live_execution_authorized: bool = False


def _deny(reason: str) -> None:
    raise OwnerKeyEnrollmentStop(reason)


def _utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        _deny("HANDOFF_ENROLLMENT_TIME_INVALID")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError, OverflowError):
        _deny("HANDOFF_ENROLLMENT_TIME_INVALID")
    if instant.tzinfo != timezone.utc:
        _deny("HANDOFF_ENROLLMENT_TIME_INVALID")
    return instant


def verify_owner_key_enrollment_candidate(
    statement: Mapping[str, Any],
    signature: bytes,
    candidate_public_key: bytes,
    *,
    at_utc: datetime,
) -> OwnerKeyEnrollmentCandidateResult:
    """Verify one domain-separated candidate, never the owner's identity.

    The candidate statement and signature may be untrusted. Independent owner
    confirmation of the resulting digest must take place *outside* this API
    and must not be replaced by caller-provided Boolean or GitHub PR review.
    """
    if (
        type(statement) is not dict
        or set(statement) != _FIELDS
        or type(signature) is not bytes or len(signature) != 64
        or type(candidate_public_key) is not bytes or len(candidate_public_key) != 32
        or not isinstance(at_utc, datetime) or at_utc.tzinfo is None
    ):
        _deny("HANDOFF_ENROLLMENT_SHAPE_INVALID")

    fingerprint = "sha256:" + hashlib.sha256(candidate_public_key).hexdigest()
    expected = {
        "purpose": PURPOSE,
        "owner_identity": EXPECTED_OWNER,
        "repository": REPOSITORY,
        "environment": "DEVELOPMENT",
        "tenant_id": DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.tenant_id,
        "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
        "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
    }
    if (
        any(statement.get(k) != v for k, v in expected.items())
        or type(statement.get("public_key_sha256")) is not str
        or _DIGEST.fullmatch(statement["public_key_sha256"]) is None
        or not hmac.compare_digest(statement["public_key_sha256"], fingerprint)
        or type(statement.get("nonce")) is not str
        or _NONCE.fullmatch(statement["nonce"]) is None
    ):
        _deny("HANDOFF_ENROLLMENT_BINDING_INVALID")

    issued, expires = _utc(statement["issued_at"]), _utc(statement["expires_at"])
    now = at_utc.astimezone(timezone.utc)
    if (
        not issued <= now < expires
        or expires <= issued
        or expires - issued > _WINDOW
    ):
        _deny("HANDOFF_ENROLLMENT_WINDOW_INVALID")

    encoded = json.dumps(
        statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(candidate_public_key).verify(
            signature, encoded
        )
    except (InvalidSignature, ValueError, TypeError):
        _deny("HANDOFF_ENROLLMENT_SIGNATURE_INVALID")

    return OwnerKeyEnrollmentCandidateResult(public_key_sha256=fingerprint)
