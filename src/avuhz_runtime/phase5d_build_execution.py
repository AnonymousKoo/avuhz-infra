"""Phase 5D-D1 exact build execution truth; it creates no later authority."""
from __future__ import annotations

import copy
import re

from .phase5c import canonical_digest, reference
from .phase5d_authorization import ImplementationAuthorizationReadService
from .phase5d_package import CodexBuildPackageReadService


BUILD_EXECUTION_COMMANDS = ("StartBuildExecution", "CompleteBuildExecution")
BUILD_EXECUTION_CAPABILITIES = {
    "StartBuildExecution": "build_execution:start",
    "CompleteBuildExecution": "build_execution:complete",
}
BUILD_EXECUTION_EVENTS = {
    "StartBuildExecution": "build_execution.started",
    "CompleteBuildExecution": "build_execution.completed",
}
BUILD_EXECUTION_CALLERS = {
    command: frozenset({"HUMAN", "INTERNAL_SERVICE"})
    for command in BUILD_EXECUTION_COMMANDS
}

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|implementation_authority)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_AUTHORITY_OR_DEPLOYMENT = re.compile(
    r"(?i)\b(?:qa\s+passed|client\s+accepted|deployment\s+(?:allowed|authorized)|"
    r"production\s+(?:change\s+)?(?:allowed|authorized)|deploy\s+to\s+production|cutover)\b"
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
            raise ValueError("credential or secret-bearing material is prohibited")
        if _AUTHORITY_OR_DEPLOYMENT.search(value):
            raise ValueError("QA, acceptance, deployment, or production authority claim is prohibited")


def _target_set(values):
    return {(value["target_reference_id"], value["target_class"]) for value in values}


def _exact_sources(uow, tenant_id, engagement_id, payload, now):
    package_ref = payload["codex_build_package_reference"]
    package = uow.codex_build_packages.get_version(
        tenant_id, package_ref["reference_id"], package_ref["reference_version"]
    )
    if (
        not package
        or package.get("engagement_id") != engagement_id
        or package.get("state") != "RELEASED"
        or package_ref != reference(
            "CODEX_BUILD_PACKAGE",
            package["codex_build_package_id"],
            package["package_version"],
        )
        or package.get("package_digest") != payload["package_digest"]
    ):
        raise ValueError("exact released CodexBuildPackage version and digest are required")
    readiness = CodexBuildPackageReadService(uow).readiness(
        tenant_id, package["codex_build_package_id"], package["package_version"], now
    )
    if not readiness or not readiness["codex_build_package_ready"]:
        raise ValueError("exact CodexBuildPackage is not ready")

    authorization_ref = payload["implementation_authorization_reference"]
    implementation_authority = uow.implementation_authorizations.get_version(
        tenant_id,
        authorization_ref["reference_id"],
        authorization_ref["reference_version"],
    )
    if (
        not implementation_authority
        or implementation_authority.get("engagement_id") != engagement_id
        or implementation_authority.get("state") != "ACTIVE"
        or authorization_ref != package["implementation_authorization_reference"]
        or authorization_ref != reference(
            "IMPLEMENTATION_AUTHORIZATION",
            implementation_authority["implementation_authorization_id"],
            implementation_authority["authorization_version"],
        )
        or implementation_authority.get("implementation_authority_digest")
        != payload["implementation_authority_digest"]
        or package.get("implementation_authority_digest")
        != payload["implementation_authority_digest"]
    ):
        raise ValueError("exact active ImplementationAuthorization version and digest are required")
    status = ImplementationAuthorizationReadService(uow).status(
        tenant_id,
        implementation_authority["implementation_authorization_id"],
        implementation_authority["authorization_version"],
        now,
    )
    if not status or not status["implementation_authorization_usable"]:
        raise ValueError("exact ImplementationAuthorization is not usable")
    if _target_set(package["allowed_targets"]) != _target_set(implementation_authority["target_references"]):
        raise ValueError("package and implementation_authority target boundaries differ")
    if not set(implementation_authority["permitted_action_classes"]) <= {
        "READ_REPOSITORY", "CREATE_CODE", "MODIFY_CODE", "CREATE_TEST", "MODIFY_TEST",
        "RUN_TEST", "CREATE_DOCUMENTATION", "MODIFY_DOCUMENTATION",
        "BUILD_NON_PRODUCTION_ARTIFACT",
    }:
        raise ValueError("ImplementationAuthorization action boundary is invalid")
    return package, implementation_authority


def build_execution_digest(current, completion):
    """Canonical terminal attempt digest including immutable authority bindings."""
    return canonical_digest({
        "build_execution_result_id": current["build_execution_result_id"],
        "execution_attempt": current["execution_attempt"],
        "tenant_id": current["tenant_id"],
        "engagement_id": current["engagement_id"],
        "codex_build_package_reference": current["codex_build_package_reference"],
        "package_digest": current["package_digest"],
        "implementation_authorization_reference": current["implementation_authorization_reference"],
        "implementation_authority_digest": current["implementation_authority_digest"],
        "execution_fingerprint": current["execution_fingerprint"],
        "supersedes_build_execution_reference": current.get("supersedes_build_execution_reference"),
        "attribution": current["attribution"],
        "status": completion["status"],
        "changed_targets": completion["changed_targets"],
        "artifact_references": completion["artifact_references"],
        "test_result_references": completion["test_result_references"],
        "failure_summary": completion.get("failure_summary"),
    })


class BuildExecutionResultHandler:
    def __init__(self, uow):
        self.uow = uow

    def execute(self, command_type, prepared, context, now, command_id):
        if context.caller_type not in BUILD_EXECUTION_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for build execution")
        _safe_payload(prepared.payload)
        return getattr(self, command_type)(prepared, context, now, command_id)

    def StartBuildExecution(self, prepared, context, now, command_id):
        payload = prepared.payload
        if payload["build_execution_result_id"] != prepared.subject_id:
            raise ValueError("BuildExecutionResult payload must identify the command subject")
        package, _ = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload, now
        )
        if self.uow.build_execution_results.get(prepared.tenant_id, prepared.subject_id):
            raise ValueError("BuildExecutionResult identity already exists")
        supersedes = payload.get("supersedes_build_execution_reference")
        if payload["execution_attempt"] == 1:
            if supersedes is not None:
                raise ValueError("initial build attempt cannot supersede history")
        else:
            if not supersedes or supersedes["reference_id"] == prepared.subject_id:
                raise ValueError("correction requires a distinct exact predecessor")
            previous = self.uow.build_execution_results.get(
                prepared.tenant_id, supersedes["reference_id"]
            )
            if (
                not previous
                or previous["record_version"] != supersedes["reference_version"]
                or previous["status"] not in ("SUCCEEDED", "FAILED")
                or previous["execution_attempt"] + 1 != payload["execution_attempt"]
                or previous["engagement_id"] != prepared.engagement_id
                or previous["codex_build_package_reference"]
                != payload["codex_build_package_reference"]
                or previous["package_digest"] != payload["package_digest"]
                or previous["implementation_authorization_reference"]
                != payload["implementation_authorization_reference"]
                or previous["implementation_authority_digest"]
                != payload["implementation_authority_digest"]
            ):
                raise ValueError("exact terminal predecessor is required")
        record = {
            "build_execution_result_id": prepared.subject_id,
            "execution_attempt": payload["execution_attempt"],
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "codex_build_package_reference": copy.deepcopy(payload["codex_build_package_reference"]),
            "package_digest": payload["package_digest"],
            "implementation_authorization_reference": copy.deepcopy(
                payload["implementation_authorization_reference"]
            ),
            "implementation_authority_digest": payload["implementation_authority_digest"],
            "status": "IN_PROGRESS",
            "execution_fingerprint": payload["execution_fingerprint"],
            "attribution": {
                "principal_reference": context.human_principal_reference or context.principal_id,
                "caller_type": context.caller_type,
                "recorded_by": context.principal_id,
            },
            "started_at": now,
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if supersedes:
            record["supersedes_build_execution_reference"] = copy.deepcopy(supersedes)
        if package["package_digest"] != record["package_digest"]:
            raise ValueError("package binding changed")
        return self.uow.build_execution_results.create(record)

    def CompleteBuildExecution(self, prepared, context, now, command_id):
        payload = prepared.payload
        if payload["build_execution_result_id"] != prepared.subject_id:
            raise ValueError("BuildExecutionResult payload must identify the command subject")
        current = self.uow.build_execution_results.get(prepared.tenant_id, prepared.subject_id)
        if (
            not current
            or current["status"] != "IN_PROGRESS"
            or current["record_version"] != prepared.expected_record_version
            or current["execution_attempt"] != payload["execution_attempt"]
            or current["engagement_id"] != prepared.engagement_id
            or current["attribution"]["principal_reference"]
            != (context.human_principal_reference or context.principal_id)
            or current["attribution"]["caller_type"] != context.caller_type
        ):
            raise ValueError("exact in-progress BuildExecutionResult and executor are required")
        source_payload = {
            "codex_build_package_reference": current["codex_build_package_reference"],
            "package_digest": current["package_digest"],
            "implementation_authorization_reference": current["implementation_authorization_reference"],
            "implementation_authority_digest": current["implementation_authority_digest"],
        }
        package, implementation_authority = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, source_payload, now
        )
        allowed = _target_set(package["allowed_targets"])
        requested = _target_set(payload["changed_targets"])
        if len(requested) != len(payload["changed_targets"]) or not requested <= allowed:
            raise ValueError("changed repository/component exceeds exact package targets")
        if not requested <= _target_set(implementation_authority["target_references"]):
            raise ValueError("changed repository/component exceeds exact implementation_authority targets")
        expected_digest = build_execution_digest(current, payload)
        if payload["execution_digest"] != expected_digest:
            raise ValueError("BuildExecutionResult digest does not match exact terminal truth")
        terminal = copy.deepcopy(current)
        terminal.update(
            status=payload["status"],
            changed_targets=copy.deepcopy(payload["changed_targets"]),
            artifact_references=copy.deepcopy(payload["artifact_references"]),
            test_result_references=copy.deepcopy(payload["test_result_references"]),
            execution_digest=payload["execution_digest"],
            completed_at=now,
            record_version=current["record_version"] + 1,
            updated_at=now,
        )
        if payload["status"] == "FAILED":
            terminal["failure_summary"] = payload["failure_summary"]
        return self.uow.build_execution_results.complete(current, terminal)


class BuildExecutionResultReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, result_id, generated_at):
        result = self.uow.build_execution_results.get(tenant_id, result_id)
        if not result:
            return None
        package_ref = result["codex_build_package_reference"]
        package = self.uow.codex_build_packages.get_version(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        authorization_ref = result["implementation_authorization_reference"]
        implementation_authority = self.uow.implementation_authorizations.get_version(
            tenant_id, authorization_ref["reference_id"], authorization_ref["reference_version"]
        )
        bindings_exact = bool(
            package
            and implementation_authority
            and package.get("package_digest") == result["package_digest"]
            and package.get("implementation_authorization_reference") == authorization_ref
            and implementation_authority.get("implementation_authority_digest")
            == result["implementation_authority_digest"]
        )
        reasons = [] if bindings_exact else ["SOURCE_BINDING_INVALID"]
        return {
            "build_execution_reference": reference(
                "BUILD_EXECUTION_RESULT", result_id, result["record_version"]
            ),
            "package_reference": copy.deepcopy(package_ref),
            "implementation_authorization_reference": copy.deepcopy(authorization_ref),
            "status": result["status"],
            "bindings_exact": bindings_exact,
            "terminal": result["status"] in ("SUCCEEDED", "FAILED"),
            "build_succeeded": result["status"] == "SUCCEEDED",
            "qa_passed": False,
            "client_accepted": False,
            "deployment_authorized": False,
            "reasons": reasons,
            "tenant_id": tenant_id,
            "engagement_id": result["engagement_id"],
            "generated_at": generated_at,
        }
