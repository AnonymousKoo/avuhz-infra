"""Provider-neutral authoritative ImplementationHandoff acceptance."""
from __future__ import annotations

import copy
import hashlib
import json
import re


REQUIRED_FIELDS = frozenset({
    "implementation_handoff_id", "tenant_id", "client_reference",
    "source_provider_reference", "source_engagement_reference", "handoff_version",
    "state", "problem_statement", "desired_outcome", "approved_scope",
    "excluded_scope", "constraints", "context_references", "integrations",
    "allowed_access_level", "risks", "implementation_requirements",
    "acceptance_criteria", "prohibited_changes", "dependencies",
    "assumptions_limitations", "upstream_approval_references",
    "source_artifact_references", "approved_at", "created_at", "handoff_digest",
})
OPTIONAL_FIELDS = frozenset({
    "supersedes_handoff_reference", "revoked_at", "revocation_reason",
})
SECRET_FIELD_PARTS = frozenset({
    "credential", "password", "private_key", "secret", "token", "authenticated_url",
})
SECRET_VALUE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization)\s*[:=]\s*\S+|"
    r"bearer\s+[a-z0-9._~+/=-]{8,}|"
    r"\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@"
)


def canonical_digest(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def handoff_reference(record: dict) -> dict:
    return {
        "reference_type": "IMPLEMENTATION_HANDOFF",
        "reference_id": record["implementation_handoff_id"],
        "reference_version": record["handoff_version"],
        "reference_digest": record["handoff_digest"],
    }


def _reject_secret_material(value, path="handoff"):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if any(part in normalized for part in SECRET_FIELD_PARTS):
                raise ValueError(f"secret-bearing field is prohibited at {path}.{key}")
            _reject_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_VALUE.search(value):
        raise ValueError(f"secret-bearing value is prohibited at {path}")


def _validate_contract_boundary(value: dict) -> None:
    if not isinstance(value, dict) or not REQUIRED_FIELDS <= set(value):
        raise ValueError("complete ImplementationHandoff contract is required")
    if set(value) - REQUIRED_FIELDS - OPTIONAL_FIELDS:
        raise ValueError("non-contract ImplementationHandoff fields are prohibited")
    if value.get("state") not in {"APPROVED", "REVOKED"}:
        raise ValueError("only approved or revoked handoff truth may be accepted")
    version = value.get("handoff_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("handoff version must be a positive integer")
    supersedes = value.get("supersedes_handoff_reference")
    if version == 1 and supersedes is not None:
        raise ValueError("initial handoff cannot supersede history")
    if version > 1 and supersedes is None:
        raise ValueError("revised handoff must bind exact prior history")
    revoked = value["state"] == "REVOKED"
    if revoked != ("revoked_at" in value and "revocation_reason" in value):
        raise ValueError("revocation state and evidence must be exact")
    approvals = value.get("upstream_approval_references")
    if not isinstance(approvals, list) or len(approvals) != 2:
        raise ValueError("exact client and provider upstream approvals are required")
    roles = {item.get("approval_role") for item in approvals if isinstance(item, dict)}
    if roles != {"CLIENT_APPROVER", "PROVIDER_APPROVER"}:
        raise ValueError("exact client and provider upstream approvals are required")
    approval_ids = [item.get("approval_reference") for item in approvals]
    if len(set(approval_ids)) != 2:
        raise ValueError("upstream approvals must be separately attributable")
    artifacts = value.get("source_artifact_references")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("bounded source artifact references are required")
    artifact_keys = [
        (item.get("reference_type"), item.get("reference_id"),
         item.get("reference_version"), item.get("reference_digest"))
        for item in artifacts if isinstance(item, dict)
    ]
    if len(artifact_keys) != len(artifacts) or len(set(artifact_keys)) != len(artifact_keys):
        raise ValueError("source artifact references must be unique and bounded")
    _reject_secret_material(value)


class ImplementationHandoffAcceptanceService:
    """Accept externally approved truth without learning provider methodology."""

    def __init__(self, uow):
        self.uow = uow

    def accept(self, record: dict, trusted_context):
        value = copy.deepcopy(record)
        _validate_contract_boundary(value)
        if trusted_context.tenant_id != value.get("tenant_id"):
            raise ValueError("trusted tenant must match the handoff tenant")
        if trusted_context.caller_type not in {"INTERNAL_SERVICE", "PROVIDER_ADAPTER"}:
            raise ValueError("trusted service or provider adapter is required")
        if "implementation_handoff:accept" not in trusted_context.capabilities:
            raise ValueError("handoff acceptance capability is required")
        digest = value.pop("handoff_digest")
        if digest != canonical_digest(value):
            raise ValueError("handoff digest does not match the immutable body")
        value["handoff_digest"] = digest
        current = self.uow.implementation_handoffs.get_current(
            value["tenant_id"], value["implementation_handoff_id"]
        )
        if current is None:
            if value["handoff_version"] != 1 or value["state"] != "APPROVED":
                raise ValueError("initial handoff must be approved version one")
        else:
            if current.get("state") == "REVOKED":
                raise ValueError("revoked handoff history is terminal")
            expected = handoff_reference(current)
            if (value["handoff_version"] != current["handoff_version"] + 1
                    or value.get("supersedes_handoff_reference") != expected):
                raise ValueError("handoff revision must bind the exact current version and digest")
        return self.uow.implementation_handoffs.create(value)
