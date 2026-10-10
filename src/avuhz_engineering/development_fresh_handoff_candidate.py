"""Fresh, fictional, in-memory DEVELOPMENT ImplementationHandoff candidate.

No CLI, credential, HTTP, Supabase, GitHub dispatch, signature, persistence,
workflow activation or owner approval. The frozen local schema fixture only
supplies bounded fictional domain content; its stale dates and fixed IDs are
NEVER reused. This factory produces a new envelope and a safe digest receipt.

This is NOT execution authority. A trusted runner must separately attest the
actual protected-main SHA, human owner, signed approval set, stage consumption,
short-lived AUTH session, and independent DATA readback before any live send.
Do not serialize/commit/log the command or hand it to the HTTP sender directly.
"""
from __future__ import annotations

import copy
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from avuhz_engineering.development_synthetic_handoff_preflight import (
    certify_synthetic_command,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    COMMAND_URL,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

_SHA = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "contracts/fixtures/v1/phase5d-implementation-package.cases.json"
)
_STOP = "HANDOFF_FRESH_CANDIDATE_INVALID"


class FreshHandoffCandidateStop(ValueError):
    """Safe fixed failure category, with no command/credential in the error."""


@dataclass(frozen=True, slots=True)
class FreshHandoffReceipt:
    repository: str
    environment: str
    canonical_main_sha_claimed: str
    tenant_id: str
    command_type: str
    command_digest: str
    handoff_id: str
    handoff_digest: str
    command_id: str
    authorized_http_target: str
    auth_project: str
    data_project: str
    request_expires_at: str
    authorization_verified: bool = False
    live_handoff_authorized: bool = False
    provider_contact_attempted: bool = False
    data_readback_verified: bool = False
    retry_authorized: bool = False


@dataclass(frozen=True, slots=True)
class FreshHandoffCandidate:
    """Ephemeral envelope: intentionally excluded from repr and receipt."""

    receipt: FreshHandoffReceipt
    _command: dict = field(repr=False)

    def command_copy(self) -> dict:
        """Return a deep copy only to a separately authorized executor."""
        return copy.deepcopy(self._command)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _uuid() -> str:
    return str(uuid.uuid4())


def prepare_fictional_development_handoff(
    *, at_utc: datetime, claimed_main_sha: str,
) -> FreshHandoffCandidate:
    """Prepare one fresh synthetically approved TEST envelope, never a send.

    claimed_main_sha is INPUT, not GitHub provenance: a later trusted runner
    must match it independently to protected main before any approval/claim.
    """
    if (
        type(claimed_main_sha) is not str
        or _SHA.fullmatch(claimed_main_sha) is None
        or type(at_utc) is not datetime
        or at_utc.tzinfo is None
        or at_utc.utcoffset() != timedelta(0)
        or at_utc.microsecond != 0
    ):
        raise FreshHandoffCandidateStop(_STOP)
    entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
    if (
        entry.caller_type != "PROVIDER_ADAPTER"
        or entry.capabilities != frozenset({"implementation_handoff:accept"})
        or DEVELOPMENT_AUTH_PROJECT_REF == DEVELOPMENT_DATA_PROJECT_REF
    ):
        raise FreshHandoffCandidateStop(_STOP)

    try:
        payload = copy.deepcopy(json.loads(_TEMPLATE.read_text())["positive"][
            "implementation_handoff"
        ])
        handoff_id, command_id, correlation_id, engagement_id = (
            _uuid(), _uuid(), _uuid(), _uuid()
        )
        approver_client, approver_provider = _uuid(), _uuid()
        created, client_approved, approved = (
            at_utc - timedelta(minutes=2),
            at_utc - timedelta(seconds=90),
            at_utc - timedelta(minutes=1),
        )
        payload.update(
            implementation_handoff_id=handoff_id,
            tenant_id=entry.tenant_id,
            client_reference="client.fictional.single-dev-proof",
            source_provider_reference="provider.fictional.sekinfra",
            source_engagement_reference=engagement_id,
            handoff_version=1,
            state="APPROVED",
            allowed_access_level="SANDBOX_ONLY",
            approved_at=_iso(approved),
            created_at=_iso(created),
        )
        payload.pop("supersedes_handoff_reference", None)
        payload.pop("revoked_at", None)
        payload.pop("revocation_reason", None)
        payload["upstream_approval_references"] = [
            {
                "approval_role": "CLIENT_APPROVER",
                "approval_reference": "approval.synthetic.client." + approver_client,
                "approved_by": "human.synthetic.client-only",
                "approved_at": _iso(client_approved),
            },
            {
                "approval_role": "PROVIDER_APPROVER",
                "approval_reference": "approval.synthetic.provider." + approver_provider,
                "approved_by": "human.synthetic.provider-only",
                "approved_at": _iso(approved),
            },
        ]
        # The fixture uses a fixed fictional artifact. Make even its source
        # reference unique to avoid accidentally replaying TEST fixture truth.
        payload["source_artifact_references"][0]["reference_id"] = (
            "provider.artifact.synthetic." + _uuid()
        )
        payload.pop("handoff_digest", None)
        payload["handoff_digest"] = canonical_digest(payload)

        authenticated = at_utc - timedelta(minutes=3)
        expiry = at_utc + timedelta(minutes=10)
        command = {
            "command_id": command_id,
            "command_type": "AcceptImplementationHandoff",
            "command_schema_version": 1,
            "tenant_id": entry.tenant_id,
            "subject_type": "IMPLEMENTATION_HANDOFF",
            "subject_id": handoff_id,
            "requested_by": entry.principal_reference,
            "caller_type": entry.caller_type,
            "caller_identity": {
                "subject": entry.principal_reference,
                "audience": "avuhz-command-api",
                "caller_type": entry.caller_type,
                "tenant_ids": [entry.tenant_id],
                "capabilities": ["implementation_handoff:accept"],
                "environment": "DEVELOPMENT",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": _iso(authenticated),
                "expires_at": _iso(expiry),
            },
            "correlation_id": correlation_id,
            "idempotency_key": "synthetic.handoff.once." + _uuid(),
            "requested_at": _iso(at_utc),
            "environment": "DEVELOPMENT",
            "payload_schema": (
                "urn:avuhz:schema:contracts:commands:"
                "accept-implementation-handoff-payload:v1"
            ),
            "payload_version": 1,
            "payload": payload,
        }
        certificate = certify_synthetic_command(command, at_utc=at_utc)
    except Exception:
        # Never return source-payload or schema-validation diagnostics.
        raise FreshHandoffCandidateStop(_STOP) from None

    receipt = FreshHandoffReceipt(
        repository="AnonymousKoo/avuhz-infra",
        environment="DEVELOPMENT",
        canonical_main_sha_claimed=claimed_main_sha,
        tenant_id=certificate.tenant_id,
        command_type="AcceptImplementationHandoff",
        command_digest=certificate.command_digest,
        handoff_id=certificate.handoff_id,
        handoff_digest=certificate.handoff_digest,
        command_id=certificate.command_id,
        authorized_http_target=COMMAND_URL,
        auth_project=DEVELOPMENT_AUTH_PROJECT_REF,
        data_project=DEVELOPMENT_DATA_PROJECT_REF,
        request_expires_at=_iso(expiry),
    )
    return FreshHandoffCandidate(receipt=receipt, _command=command)
