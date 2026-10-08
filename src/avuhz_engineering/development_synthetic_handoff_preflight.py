"""Offline, fail-closed preflight for one fictional DEVELOPMENT ImplementationHandoff.

Pure validation only. This module has no provider, network, token, secret-manager,
database, or workflow access. It grants no authority to send a live command.
A future one-shot executor must separately verify exact owner approval, retrieve
short-lived credentials through an approved boundary, and retire them.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from avuhz_runtime.implementation_handoff import (
    _validate_contract_boundary,
    canonical_digest,
)
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"
EXPECTED_COMMAND = "AcceptImplementationHandoff"
EXPECTED_SUBJECT = "IMPLEMENTATION_HANDOFF"
EXPECTED_PAYLOAD_SCHEMA = (
    "urn:avuhz:schema:contracts:commands:accept-implementation-handoff-payload:v1"
)
MAX_COMMAND_RESPONSE_BYTES = 1024
REQUIRED_EXCLUSIONS = frozenset({
    "OUT_OF_SCOPE_SYSTEM_CHANGE",
    "PERMISSION_WIDENING",
    "DATA_DELETION",
    "CREDENTIAL_ROTATION",
    "PRODUCTION_DEPLOYMENT",
    "PRODUCTION_CHANGE",
    "BILLING_CHANGE",
    "OUT_OF_SCOPE_NETWORK_CHANGE",
    "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
})


class SyntheticCommandPreflightStop(ValueError):
    """Static, non-sensitive failure category; never return rejected input."""


@dataclass(frozen=True)
class CertifiedSyntheticCommand:
    tenant_id: str
    command_id: str
    handoff_id: str
    handoff_digest: str
    command_digest: str


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise SyntheticCommandPreflightStop(code)


def _utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise SyntheticCommandPreflightStop("SYNTHETIC_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (ValueError, OverflowError):
        raise SyntheticCommandPreflightStop("SYNTHETIC_TIME_INVALID") from None
    _require(parsed.tzinfo == timezone.utc, "SYNTHETIC_TIME_INVALID")
    return parsed


def certify_synthetic_command(
    request: Mapping[str, object], *, at_utc: datetime
) -> CertifiedSyntheticCommand:
    """Validate exact synthetic identity envelope and approved fictional handoff.

    This only certifies the *shape* of caller_identity claims. It never resolves
    an actual provider identity, verifies a JWT, authorizes HTTP, or contacts DATA.
    """
    _require(type(request) is dict, "SYNTHETIC_ENVELOPE_INVALID")
    _require(
        isinstance(at_utc, datetime) and at_utc.tzinfo is not None,
        "SYNTHETIC_TIME_INVALID",
    )
    now = at_utc.astimezone(timezone.utc)
    validator = CommandValidator(SCHEMA_ROOT)
    prepared = validator.prepare(request)
    _require(isinstance(prepared, ValidationSuccess), "SYNTHETIC_ENVELOPE_INVALID")

    entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
    identity = request.get("caller_identity")
    payload = request.get("payload")
    _require(type(identity) is dict and type(payload) is dict, "SYNTHETIC_ENVELOPE_INVALID")
    _require(
        request.get("command_type") == EXPECTED_COMMAND
        and request.get("subject_type") == EXPECTED_SUBJECT
        and request.get("payload_schema") == EXPECTED_PAYLOAD_SCHEMA
        and request.get("environment") == "DEVELOPMENT"
        and request.get("tenant_id") == entry.tenant_id
        and request.get("caller_type") == entry.caller_type
        and request.get("requested_by") == entry.principal_reference
        and request.get("subject_id") == payload.get("implementation_handoff_id")
        and payload.get("tenant_id") == entry.tenant_id,
        "SYNTHETIC_BOUNDARY_MISMATCH",
    )
    _require(
        identity.get("subject") == entry.principal_reference
        and identity.get("audience") == "avuhz-command-api"
        and identity.get("caller_type") == entry.caller_type
        and identity.get("tenant_ids") == [entry.tenant_id]
        and identity.get("capabilities") == ["implementation_handoff:accept"]
        and identity.get("environment") == "DEVELOPMENT"
        and identity.get("authentication_strength") == "STRONG"
        and identity.get("step_up_performed") is False,
        "SYNTHETIC_CLAIMS_MISMATCH",
    )
    _require(
        payload.get("state") == "APPROVED"
        and payload.get("handoff_version") == 1
        and payload.get("allowed_access_level") == "SANDBOX_ONLY"
        and "supersedes_handoff_reference" not in payload
        and set(payload.get("prohibited_changes", [])) == REQUIRED_EXCLUSIONS,
        "SYNTHETIC_SCOPE_INVALID",
    )
    _require(
        type(payload.get("client_reference")) is str
        and payload["client_reference"].startswith("client.fictional.")
        and type(payload.get("source_provider_reference")) is str
        and payload["source_provider_reference"].startswith("provider.fictional."),
        "SYNTHETIC_SOURCE_NOT_FICTIONAL",
    )
    approvals = payload.get("upstream_approval_references")
    _require(type(approvals) is list and len(approvals) == 2, "SYNTHETIC_APPROVAL_SHAPE_INVALID")
    _require(
        all(
            type(approval) is dict
            and type(approval.get("approved_by")) is str
            and approval["approved_by"].startswith("human.synthetic.")
            and type(approval.get("approval_reference")) is str
            and approval["approval_reference"].startswith("approval.synthetic.")
            for approval in approvals
        ),
        "SYNTHETIC_APPROVAL_NOT_FICTIONAL",
    )
    try:
        _validate_contract_boundary(payload)
    except (ValueError, TypeError):
        raise SyntheticCommandPreflightStop("SYNTHETIC_HANDOFF_CONTRACT_INVALID") from None
    handoff_digest = payload.get("handoff_digest")
    _require(
        type(handoff_digest) is str
        and handoff_digest == canonical_digest({
            key: value for key, value in payload.items() if key != "handoff_digest"
        }),
        "SYNTHETIC_HANDOFF_DIGEST_MISMATCH",
    )
    requested = _utc(request["requested_at"])
    authenticated = _utc(identity["authenticated_at"])
    expires = _utc(identity["expires_at"])
    approved = _utc(payload["approved_at"])
    created = _utc(payload["created_at"])
    _require(
        created <= approved <= requested <= now
        and now - requested <= timedelta(minutes=15)
        and authenticated <= requested
        and now < expires,
        "SYNTHETIC_TIME_INVALID",
    )
    _require(
        all(_utc(approval["approved_at"]) <= approved for approval in approvals),
        "SYNTHETIC_TIME_INVALID",
    )
    encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return CertifiedSyntheticCommand(
        tenant_id=entry.tenant_id,
        command_id=prepared.prepared.command_id,
        handoff_id=prepared.prepared.subject_id,
        handoff_digest=handoff_digest,
        command_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )


def certify_accepted_response(
    *, http_status: object, response_bytes: object, candidate: CertifiedSyntheticCommand
) -> str:
    """Parse a single *supplied* response; never sends a command or logs a body."""
    _require(
        type(candidate) is CertifiedSyntheticCommand,
        "SYNTHETIC_CANDIDATE_INVALID",
    )
    _require(type(http_status) is int, "SYNTHETIC_HTTP_STATUS_INVALID")
    if http_status != 202:
        if http_status in {401, 403}:
            raise SyntheticCommandPreflightStop("SYNTHETIC_AUTHORIZATION_DENIED")
        if http_status in {409, 422}:
            raise SyntheticCommandPreflightStop("SYNTHETIC_COMMAND_NOT_ACCEPTED")
        raise SyntheticCommandPreflightStop("SYNTHETIC_HTTP_UNEXPECTED")
    _require(
        type(response_bytes) is bytes
        and 0 < len(response_bytes) <= MAX_COMMAND_RESPONSE_BYTES,
        "SYNTHETIC_RESPONSE_INVALID",
    )
    try:
        value = json.loads(response_bytes)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise SyntheticCommandPreflightStop("SYNTHETIC_RESPONSE_INVALID") from None
    _require(
        type(value) is dict
        and set(value) == {"result", "reason_code", "authoritative_record_reference"}
        and value.get("result") == "ACCEPTED"
        and value.get("reason_code") == "COMMAND_ACCEPTED"
        and value.get("authoritative_record_reference") == candidate.handoff_id,
        "SYNTHETIC_RESPONSE_INVALID",
    )
    return "SYNTHETIC_COMMAND_ACCEPTED_PENDING_DATA_VERIFICATION"
