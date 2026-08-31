"""Phase 5D-D5a immutable deployment-attempt truth; never verification truth."""
from __future__ import annotations

import copy
import re

from .implementation_handoff import canonical_digest
from .phase5d_brief import reference
from .phase5d_deployment_authorization import DeploymentAuthorizationReadService


DEPLOYMENT_EXECUTION_COMMANDS = ("StartDeploymentExecution", "CompleteDeploymentExecution")
DEPLOYMENT_EXECUTION_CAPABILITIES = {
    "StartDeploymentExecution": "deployment_execution:start",
    "CompleteDeploymentExecution": "deployment_execution:complete",
}
DEPLOYMENT_EXECUTION_EVENTS = {
    "StartDeploymentExecution": "deployment_execution.started",
    "CompleteDeploymentExecution": "deployment_execution.completed",
}
DEPLOYMENT_EXECUTION_CALLERS = {
    "StartDeploymentExecution": frozenset({"HUMAN", "INTERNAL_SERVICE"}),
    "CompleteDeploymentExecution": frozenset({"INTERNAL_SERVICE"}),
}
TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED", "PARTIAL", "BLOCKED"})

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_INVENTED_TRUTH = re.compile(
    r"(?i)\b(?:deployment\s+(?:verified|successful|succeeded)|verification\s+(?:passed|successful)|"
    r"production\s+(?:change\s+)?completed|rollback\s+verified)\b"
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
            raise ValueError("credential or secret-bearing deployment material is prohibited")
        if _INVENTED_TRUTH.search(value):
            raise ValueError("caller-supplied deployment success or verification truth is prohibited")


def _target_key(value):
    return value["target_reference_id"], value["target_class"]


def _expected_binding(authority):
    return {
        "deployment_authorization_reference": reference(
            "DEPLOYMENT_AUTHORIZATION",
            authority["deployment_authorization_id"],
            authority["authorization_version"],
        ),
        "deployment_authority_digest": authority["deployment_authority_digest"],
        "implementation_authorization_reference": copy.deepcopy(authority["implementation_authorization_reference"]),
        "implementation_authority_digest": authority["implementation_authority_digest"],
        "codex_build_package_reference": copy.deepcopy(authority["codex_build_package_reference"]),
        "package_digest": authority["package_digest"],
        "build_execution_reference": copy.deepcopy(authority["build_execution_reference"]),
        "build_execution_digest": authority["build_execution_digest"],
        "qa_result_reference": copy.deepcopy(authority["qa_result_reference"]),
        "qa_result_digest": authority["qa_result_digest"],
        "client_acceptance_reference": copy.deepcopy(authority["client_acceptance_reference"]),
        "client_acceptance_digest": authority["client_acceptance_digest"],
        "artifact_reference": copy.deepcopy(authority["artifact_reference"]),
        "target_environment": authority["target_environment"],
        "target_resources": copy.deepcopy(authority["target_resources"]),
    }


def _exact_authority(uow, tenant_id, engagement_id, binding, action, now):
    authority_ref = binding["deployment_authorization_reference"]
    authority = uow.deployment_authorizations.get_version(
        tenant_id, authority_ref["reference_id"], authority_ref["reference_version"]
    )
    if (
        not authority
        or authority.get("engagement_id") != engagement_id
        or authority.get("state") != "ACTIVE"
        or binding != _expected_binding(authority)
        or action not in authority.get("permitted_deployment_actions", ())
        or action in authority.get("prohibited_deployment_actions", ())
    ):
        raise ValueError("exact active bounded DeploymentAuthorization is required")
    status = DeploymentAuthorizationReadService(uow).status(
        tenant_id, authority["deployment_authorization_id"], authority["authorization_version"], now
    )
    if not status or not status["deployment_authorized"] or not status["production_target_exact"]:
        raise ValueError("DeploymentAuthorization is not currently valid for the exact target")
    return authority


def _terminal_truth(target_outcomes):
    outcomes = {item["outcome"] for item in target_outcomes}
    if outcomes <= {"APPLIED", "UNCHANGED"}:
        return "SUCCEEDED", "PENDING_VERIFICATION"
    if "APPLIED" in outcomes and outcomes & {"FAILED", "BLOCKED"}:
        return "PARTIAL", "REQUIRED"
    if "FAILED" in outcomes:
        return "FAILED", "NOT_REQUIRED"
    return "BLOCKED", "NOT_REQUIRED"


def deployment_execution_digest(record):
    fields = (
        "deployment_execution_id", "execution_attempt", "tenant_id", "engagement_id",
        "authority_binding", "execution_action", "execution_fingerprint",
        "supersedes_deployment_execution_reference", "rollback_of_deployment_execution_reference",
        "attribution", "status", "target_outcomes", "completion_summary", "failure_summary",
        "blocker_summary", "rollback_disposition", "started_at", "completed_at",
    )
    return canonical_digest({field: copy.deepcopy(record.get(field)) for field in fields if field in record})


class DeploymentExecutionHandler:
    def __init__(self, uow):
        self.uow = uow

    def execute(self, command_type, prepared, context, now, command_id):
        if context.caller_type not in DEPLOYMENT_EXECUTION_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for deployment execution")
        _safe_payload(prepared.payload)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def StartDeploymentExecution(self, prepared, context, now, command_id):
        payload = prepared.payload
        binding = payload["authority_binding"]
        authority = _exact_authority(
            self.uow, prepared.tenant_id, prepared.engagement_id,
            binding, payload["execution_action"], now,
        )
        if self.uow.deployment_executions.get(prepared.tenant_id, prepared.subject_id):
            raise ValueError("DeploymentExecution identity already exists")
        supersedes = payload.get("supersedes_deployment_execution_reference")
        if payload["execution_attempt"] == 1:
            if supersedes is not None:
                raise ValueError("initial deployment attempt cannot supersede history")
        else:
            previous = self.uow.deployment_executions.get(
                prepared.tenant_id, supersedes["reference_id"] if supersedes else ""
            )
            if (
                not previous or previous["deployment_execution_id"] == prepared.subject_id
                or previous["record_version"] != supersedes["reference_version"]
                or previous["status"] not in TERMINAL_STATUSES
                or previous["execution_attempt"] + 1 != payload["execution_attempt"]
                or previous["engagement_id"] != prepared.engagement_id
                or previous["authority_binding"] != binding
            ):
                raise ValueError("exact terminal predecessor is required")
        rollback_of = payload.get("rollback_of_deployment_execution_reference")
        if payload["execution_action"] == "ROLLBACK_EXACT_ARTIFACT":
            original = self.uow.deployment_executions.get(
                prepared.tenant_id, rollback_of["reference_id"] if rollback_of else ""
            )
            if (
                not original or original["record_version"] != rollback_of["reference_version"]
                or original["status"] not in {"SUCCEEDED", "PARTIAL"}
                or original["engagement_id"] != prepared.engagement_id
            ):
                raise ValueError("rollback requires an exact completed deployment attempt")
        principal = context.human_principal_reference or context.principal_id
        record = {
            "deployment_execution_id": prepared.subject_id,
            "execution_attempt": payload["execution_attempt"],
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "authority_binding": copy.deepcopy(binding),
            "execution_action": payload["execution_action"],
            "status": "IN_PROGRESS",
            "execution_fingerprint": payload["execution_fingerprint"],
            "attribution": {
                "principal_reference": principal,
                "caller_type": context.caller_type,
                "recorded_by": context.principal_id,
            },
            "started_at": now,
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if supersedes:
            record["supersedes_deployment_execution_reference"] = copy.deepcopy(supersedes)
        if rollback_of:
            record["rollback_of_deployment_execution_reference"] = copy.deepcopy(rollback_of)
        if binding != _expected_binding(authority):
            raise ValueError("deployment authority binding changed")
        return self.uow.deployment_executions.create(record)

    def CompleteDeploymentExecution(self, prepared, context, now, command_id):
        payload = prepared.payload
        current = self.uow.deployment_executions.get(prepared.tenant_id, prepared.subject_id)
        if (
            not current or current["status"] != "IN_PROGRESS"
            or current["record_version"] != prepared.expected_record_version
            or current["execution_attempt"] != payload["execution_attempt"]
            or current["engagement_id"] != prepared.engagement_id
        ):
            raise ValueError("exact in-progress DeploymentExecution is required")
        expected_targets = {_target_key(item) for item in current["authority_binding"]["target_resources"]}
        actual_targets = [_target_key(item["target_resource"]) for item in payload["target_outcomes"]]
        if len(actual_targets) != len(set(actual_targets)) or set(actual_targets) != expected_targets:
            raise ValueError("every exact authorized target must have one outcome")
        for outcome in payload["target_outcomes"]:
            for evidence in outcome["evidence_references"]:
                if evidence["provenance_reference"] != context.principal_id:
                    raise ValueError("evidence provenance must match the trusted recorder")
        status, rollback = _terminal_truth(payload["target_outcomes"])
        terminal = copy.deepcopy(current)
        terminal.update(
            status=status,
            target_outcomes=copy.deepcopy(payload["target_outcomes"]),
            completion_summary=payload["completion_summary"],
            rollback_disposition=rollback,
            completed_at=now,
            record_version=current["record_version"] + 1,
            updated_at=now,
        )
        if status in {"FAILED", "PARTIAL"}:
            terminal["failure_summary"] = payload["completion_summary"]
        if status == "BLOCKED":
            terminal["blocker_summary"] = payload["completion_summary"]
        terminal["execution_digest"] = deployment_execution_digest(terminal)
        return self.uow.deployment_executions.complete(current, terminal)


class DeploymentExecutionReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, execution_id, generated_at):
        record = self.uow.deployment_executions.get(tenant_id, execution_id)
        if not record:
            return None
        terminal = record["status"] in TERMINAL_STATUSES
        return {
            "deployment_execution_reference": reference(
                "DEPLOYMENT_EXECUTION", execution_id, record["record_version"]
            ),
            "deployment_authorization_reference": copy.deepcopy(
                record["authority_binding"]["deployment_authorization_reference"]
            ),
            "status": record["status"],
            "operation_completed": terminal,
            "deployment_verified": False,
            "rollback_disposition": record.get("rollback_disposition", "NOT_EVALUATED"),
            "tenant_id": tenant_id,
            "engagement_id": record["engagement_id"],
            "generated_at": generated_at,
        }
