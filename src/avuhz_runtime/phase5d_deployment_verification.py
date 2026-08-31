"""Phase 5D-D5b immutable target-state verification truth; no deployment authority."""
from __future__ import annotations

import copy
import re

from .implementation_handoff import canonical_digest
from .phase5d_brief import reference
from .phase5d_deployment_execution import TERMINAL_STATUSES, _target_key


DEPLOYMENT_VERIFICATION_COMMANDS = ("RecordDeploymentVerification",)
DEPLOYMENT_VERIFICATION_CAPABILITIES = {
    "RecordDeploymentVerification": "deployment_verification:record",
}
DEPLOYMENT_VERIFICATION_EVENTS = {
    "RecordDeploymentVerification": "deployment_verification.recorded",
}
DEPLOYMENT_VERIFICATION_CALLERS = {
    "RecordDeploymentVerification": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
}

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_INVENTED_TRUTH = re.compile(
    r"(?i)\b(?:deployment\s+(?:successful|succeeded|verified)|verification\s+(?:passed|successful)|"
    r"production\s+(?:change\s+)?verified|rollback\s+verified)\b"
)


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_strings(child)


def _safe_payload(payload):
    for value in _walk_strings(payload):
        if _SECRET.search(value) or _AUTHENTICATED_URL.search(value):
            raise ValueError("credential or secret-bearing verification material is prohibited")
        if _INVENTED_TRUTH.search(value):
            raise ValueError("caller-supplied deployment or verification success claim is prohibited")


def derive_verification_status(target_verifications):
    results = {item["result"] for item in target_verifications}
    if results == {"MATCHED"}:
        return "VERIFIED"
    if "MISMATCHED" in results:
        return "FAILED"
    if results == {"BLOCKED"}:
        return "BLOCKED"
    return "PARTIAL"


def deployment_verification_digest(record):
    fields = (
        "deployment_verification_id", "verification_attempt", "tenant_id", "engagement_id",
        "deployment_execution_reference", "deployment_execution_digest", "execution_status",
        "authority_binding", "target_verifications", "overall_status", "rollback_required",
        "supersedes_deployment_verification_reference", "attribution", "recorded_at",
    )
    return canonical_digest({field: copy.deepcopy(record.get(field)) for field in fields if field in record})


def _exact_execution(uow, tenant_id, engagement_id, payload):
    execution_ref = payload["deployment_execution_reference"]
    execution = uow.deployment_executions.get(tenant_id, execution_ref["reference_id"])
    if (
        not execution
        or execution.get("engagement_id") != engagement_id
        or execution.get("status") not in TERMINAL_STATUSES - {"BLOCKED"}
        or execution_ref != reference(
            "DEPLOYMENT_EXECUTION", execution["deployment_execution_id"], execution["record_version"]
        )
        or execution.get("execution_digest") != payload["deployment_execution_digest"]
        or execution.get("authority_binding") != payload["authority_binding"]
    ):
        raise ValueError("exact terminal DeploymentExecution version, digest, and authority binding are required")
    authority_ref = execution["authority_binding"]["deployment_authorization_reference"]
    authority = uow.deployment_authorizations.get_version(
        tenant_id, authority_ref["reference_id"], authority_ref["reference_version"]
    )
    if (
        not authority
        or authority.get("engagement_id") != engagement_id
        or authority.get("deployment_authority_digest")
        != execution["authority_binding"]["deployment_authority_digest"]
    ):
        raise ValueError("exact historical DeploymentAuthorization binding is required")
    return execution


class DeploymentVerificationHandler:
    def __init__(self, uow):
        self.uow = uow

    def execute(self, command_type, prepared, context, now, command_id):
        if context.caller_type not in DEPLOYMENT_VERIFICATION_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for deployment verification")
        _safe_payload(prepared.payload)
        return self.RecordDeploymentVerification(prepared, context, now, command_id)

    def RecordDeploymentVerification(self, prepared, context, now, command_id):
        payload = prepared.payload
        if self.uow.deployment_verifications.get(prepared.tenant_id, prepared.subject_id):
            raise ValueError("DeploymentVerification identity already exists")
        execution = _exact_execution(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload
        )
        supersedes = payload.get("supersedes_deployment_verification_reference")
        if payload["verification_attempt"] == 1:
            if supersedes is not None:
                raise ValueError("initial verification cannot supersede history")
        else:
            previous = self.uow.deployment_verifications.get(
                prepared.tenant_id, supersedes["reference_id"] if supersedes else ""
            )
            if (
                not previous or previous["deployment_verification_id"] == prepared.subject_id
                or previous["record_version"] != supersedes["reference_version"]
                or previous["verification_attempt"] + 1 != payload["verification_attempt"]
                or previous["engagement_id"] != prepared.engagement_id
                or previous["deployment_execution_reference"] != payload["deployment_execution_reference"]
                or previous["deployment_execution_digest"] != payload["deployment_execution_digest"]
                or previous["authority_binding"] != payload["authority_binding"]
            ):
                raise ValueError("exact immutable predecessor verification is required")
        expected_targets = {_target_key(item) for item in execution["authority_binding"]["target_resources"]}
        actual_targets = [_target_key(item["target_resource"]) for item in payload["target_verifications"]]
        if len(actual_targets) != len(set(actual_targets)) or set(actual_targets) != expected_targets:
            raise ValueError("every exact authorized target must have one verification")
        authorized_digest = execution["authority_binding"]["artifact_reference"]["artifact_digest"]
        principal = context.human_principal_reference or context.principal_id
        for verification in payload["target_verifications"]:
            if verification["expected_artifact_digest"] != authorized_digest:
                raise ValueError("verification expected digest must match the exact authorized artifact")
            observed = verification.get("observed_artifact_digest")
            if verification["result"] == "MATCHED" and observed != authorized_digest:
                raise ValueError("MATCHED requires the exact observed authorized artifact")
            if verification["result"] == "MISMATCHED" and observed == authorized_digest:
                raise ValueError("MISMATCHED requires a distinct observed artifact")
            if verification["verified_at"] > now:
                raise ValueError("future verification evidence is prohibited")
            for evidence in verification["evidence_references"]:
                if evidence["provenance_reference"] != principal:
                    raise ValueError("evidence provenance must match the trusted verifier")
        overall_status = derive_verification_status(payload["target_verifications"])
        record = {
            "deployment_verification_id": prepared.subject_id,
            "verification_attempt": payload["verification_attempt"],
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "deployment_execution_reference": copy.deepcopy(payload["deployment_execution_reference"]),
            "deployment_execution_digest": payload["deployment_execution_digest"],
            "execution_status": execution["status"],
            "authority_binding": copy.deepcopy(payload["authority_binding"]),
            "target_verifications": copy.deepcopy(payload["target_verifications"]),
            "overall_status": overall_status,
            "rollback_required": overall_status != "VERIFIED",
            "attribution": {
                "principal_reference": principal,
                "caller_type": context.caller_type,
                "recorded_by": context.principal_id,
            },
            "recorded_at": now,
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if supersedes:
            record["supersedes_deployment_verification_reference"] = copy.deepcopy(supersedes)
        record["verification_digest"] = deployment_verification_digest(record)
        return self.uow.deployment_verifications.create(record)


class DeploymentVerificationReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, verification_id, generated_at):
        record = self.uow.deployment_verifications.get(tenant_id, verification_id)
        if not record:
            return None
        verified = record["overall_status"] == "VERIFIED"
        return {
            "deployment_verification_reference": reference(
                "DEPLOYMENT_VERIFICATION", verification_id, record["record_version"]
            ),
            "deployment_execution_reference": copy.deepcopy(record["deployment_execution_reference"]),
            "deployment_authorization_reference": copy.deepcopy(
                record["authority_binding"]["deployment_authorization_reference"]
            ),
            "overall_status": record["overall_status"],
            "target_state_matches_authority": verified,
            "deployment_verified": verified,
            "rollback_required": not verified,
            "tenant_id": tenant_id,
            "engagement_id": record["engagement_id"],
            "generated_at": generated_at,
        }
