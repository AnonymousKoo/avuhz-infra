"""Phase 5D-D2 exact criterion-level QA truth; it creates no later authority."""
from __future__ import annotations

import copy
import re

from .phase5c import canonical_digest, reference
from .phase5d_build_execution import _exact_sources as _exact_build_sources


QA_RESULT_COMMANDS = ("RecordQAResult",)
QA_RESULT_CAPABILITIES = {"RecordQAResult": "qa_result:record"}
QA_RESULT_EVENTS = {"RecordQAResult": "qa_result.recorded"}
QA_RESULT_CALLERS = {"RecordQAResult": frozenset({"HUMAN", "INTERNAL_SERVICE"})}

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_AUTHORITY_CLAIM = re.compile(
    r"(?i)\b(?:client\s+(?:is\s+)?accepted|deployment\s+(?:is\s+)?(?:allowed|authorized)|"
    r"production\s+(?:change\s+)?(?:is\s+)?(?:allowed|authorized)|"
    r"deploy\s+to\s+production|cutover)\b"
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
            raise ValueError("credential or secret-bearing QA material is prohibited")
        if _AUTHORITY_CLAIM.search(value):
            raise ValueError("client, deployment, or production authority claim is prohibited")


def derive_overall_status(criterion_results):
    results = {item["result"] for item in criterion_results}
    if "FAIL" in results:
        return "FAILED"
    if "BLOCKED" in results:
        return "BLOCKED"
    return "PASSED"


def qa_result_digest(tenant_id, engagement_id, payload, attribution):
    """Canonical digest over exact sources, criterion truth, and trusted attribution."""
    return canonical_digest({
        "qa_result_id": payload["qa_result_id"],
        "qa_attempt": payload["qa_attempt"],
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "build_execution_reference": payload["build_execution_reference"],
        "build_execution_digest": payload["build_execution_digest"],
        "codex_build_package_reference": payload["codex_build_package_reference"],
        "package_digest": payload["package_digest"],
        "criterion_results": payload["criterion_results"],
        "overall_status": payload["overall_status"],
        "supersedes_qa_result_reference": payload.get("supersedes_qa_result_reference"),
        "attribution": attribution,
    })


def _exact_sources(uow, tenant_id, engagement_id, payload, now):
    build_ref = payload["build_execution_reference"]
    build = uow.build_execution_results.get(tenant_id, build_ref["reference_id"])
    if (
        not build
        or build.get("engagement_id") != engagement_id
        or build.get("status") != "SUCCEEDED"
        or build_ref != reference(
            "BUILD_EXECUTION_RESULT",
            build["build_execution_result_id"],
            build["record_version"],
        )
        or build.get("execution_digest") != payload["build_execution_digest"]
    ):
        raise ValueError("exact successful BuildExecutionResult version and digest are required")

    package_ref = payload["codex_build_package_reference"]
    package = uow.codex_build_packages.get_version(
        tenant_id, package_ref["reference_id"], package_ref["reference_version"]
    )
    if (
        not package
        or package.get("engagement_id") != engagement_id
        or package.get("state") != "RELEASED"
        or package_ref != build["codex_build_package_reference"]
        or package_ref != reference(
            "CODEX_BUILD_PACKAGE",
            package["codex_build_package_id"],
            package["package_version"],
        )
        or package.get("package_digest") != payload["package_digest"]
        or build.get("package_digest") != payload["package_digest"]
    ):
        raise ValueError("exact released CodexBuildPackage version and digest are required")

    build_history = uow.build_execution_results.list_by_package(
        tenant_id, package["codex_build_package_id"], package["package_version"]
    )
    if any(item["execution_attempt"] > build["execution_attempt"] for item in build_history):
        raise ValueError("superseded BuildExecutionResult cannot establish new QA truth")

    _exact_build_sources(
        uow,
        tenant_id,
        engagement_id,
        {
            "codex_build_package_reference": build["codex_build_package_reference"],
            "package_digest": build["package_digest"],
            "implementation_authorization_reference": build[
                "implementation_authorization_reference"
            ],
            "implementation_authority_digest": build["implementation_authority_digest"],
        },
        now,
    )
    return build, package


def _validate_criteria(package, build, payload):
    expected = {item["criterion_id"]: item for item in package["acceptance_criteria"]}
    recorded = payload["criterion_results"]
    recorded_ids = [item["criterion_id"] for item in recorded]
    if len(recorded_ids) != len(set(recorded_ids)) or set(recorded_ids) != set(expected):
        raise ValueError("every exact package acceptance criterion must be recorded once")
    if any(item["criterion_package_version"] != package["package_version"] for item in recorded):
        raise ValueError("criterion package version is stale or incorrect")
    if payload["overall_status"] != derive_overall_status(recorded):
        raise ValueError("overall QA status must be derived from criterion results")

    test_evidence = {
        (item["test_result_reference_id"], item["result_digest"])
        for item in build["test_result_references"]
    }
    for criterion in recorded:
        for evidence in criterion["evidence_references"]:
            if evidence["evidence_class"] == "TEST_RESULT" and (
                evidence["evidence_reference_id"], evidence["evidence_digest"]
            ) not in test_evidence:
                raise ValueError("test evidence is not bound to the exact build result")


class QAResultHandler:
    def __init__(self, uow):
        self.uow = uow

    def execute(self, command_type, prepared, context, now, command_id):
        if context.caller_type not in QA_RESULT_CALLERS[command_type]:
            raise ValueError("caller type is not authoritative for QA recording")
        _safe_payload(prepared.payload)
        return self.RecordQAResult(prepared, context, now, command_id)

    def RecordQAResult(self, prepared, context, now, command_id):
        payload = prepared.payload
        if payload["qa_result_id"] != prepared.subject_id:
            raise ValueError("QAResult payload must identify the command subject")
        if prepared.expected_record_version is not None:
            raise ValueError("immutable QA creation does not accept an expected record version")
        if self.uow.qa_results.get(prepared.tenant_id, prepared.subject_id):
            raise ValueError("QAResult identity already exists")

        build, package = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload, now
        )
        _validate_criteria(package, build, payload)

        supersedes = payload.get("supersedes_qa_result_reference")
        if payload["qa_attempt"] == 1:
            if supersedes is not None:
                raise ValueError("initial QA result cannot supersede history")
        else:
            if not supersedes or supersedes["reference_id"] == prepared.subject_id:
                raise ValueError("QA retest requires a distinct exact predecessor")
            previous = self.uow.qa_results.get(
                prepared.tenant_id, supersedes["reference_id"]
            )
            history = self.uow.qa_results.list_by_package(
                prepared.tenant_id,
                package["codex_build_package_id"],
                package["package_version"],
            )
            if (
                not previous
                or previous["record_version"] != supersedes["reference_version"]
                or previous["qa_attempt"] + 1 != payload["qa_attempt"]
                or previous["engagement_id"] != prepared.engagement_id
                or previous["codex_build_package_reference"]
                != payload["codex_build_package_reference"]
                or previous["package_digest"] != payload["package_digest"]
                or not history
                or history[-1]["qa_result_id"] != previous["qa_result_id"]
            ):
                raise ValueError("exact latest QA predecessor is required")

        attribution = {
            "principal_reference": context.human_principal_reference or context.principal_id,
            "caller_type": context.caller_type,
            "recorded_by": context.principal_id,
        }
        expected_digest = qa_result_digest(
            prepared.tenant_id, prepared.engagement_id, payload, attribution
        )
        if payload["qa_digest"] != expected_digest:
            raise ValueError("QAResult digest does not match exact criterion truth")

        record = {
            "qa_result_id": prepared.subject_id,
            "qa_attempt": payload["qa_attempt"],
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "build_execution_reference": copy.deepcopy(payload["build_execution_reference"]),
            "build_execution_digest": payload["build_execution_digest"],
            "codex_build_package_reference": copy.deepcopy(
                payload["codex_build_package_reference"]
            ),
            "package_digest": payload["package_digest"],
            "criterion_results": copy.deepcopy(payload["criterion_results"]),
            "overall_status": payload["overall_status"],
            "qa_digest": payload["qa_digest"],
            "attribution": attribution,
            "recorded_at": now,
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if supersedes:
            record["supersedes_qa_result_reference"] = copy.deepcopy(supersedes)
        return self.uow.qa_results.create(record)


class QAResultReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, qa_result_id, generated_at):
        result = self.uow.qa_results.get(tenant_id, qa_result_id)
        if not result:
            return None
        package_ref = result["codex_build_package_reference"]
        package = self.uow.codex_build_packages.get_version(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        build_ref = result["build_execution_reference"]
        build = self.uow.build_execution_results.get(tenant_id, build_ref["reference_id"])
        expected_ids = (
            {item["criterion_id"] for item in package.get("acceptance_criteria", [])}
            if package else set()
        )
        recorded_ids = [item["criterion_id"] for item in result["criterion_results"]]
        criteria_complete = bool(
            expected_ids
            and len(recorded_ids) == len(set(recorded_ids))
            and set(recorded_ids) == expected_ids
        )
        reasons = []
        if not (
            package
            and package.get("state") == "RELEASED"
            and package.get("package_digest") == result["package_digest"]
            and build
            and build.get("status") == "SUCCEEDED"
            and reference(
                "BUILD_EXECUTION_RESULT",
                build["build_execution_result_id"],
                build["record_version"],
            ) == build_ref
            and build.get("execution_digest") == result["build_execution_digest"]
            and build.get("codex_build_package_reference") == package_ref
        ):
            reasons.append("SOURCE_BINDING_INVALID")
        if not criteria_complete:
            reasons.append("CRITERIA_INCOMPLETE")
        if build and any(
            item["execution_attempt"] > build["execution_attempt"]
            for item in self.uow.build_execution_results.list_by_package(
                tenant_id, package_ref["reference_id"], package_ref["reference_version"]
            )
        ):
            reasons.append("BUILD_SUPERSEDED")
        history = self.uow.qa_results.list_by_package(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        if history and history[-1]["qa_result_id"] != qa_result_id:
            reasons.append("QA_SUPERSEDED")
        return {
            "qa_result_reference": reference("QA_RESULT", qa_result_id, result["record_version"]),
            "build_execution_reference": copy.deepcopy(build_ref),
            "package_reference": copy.deepcopy(package_ref),
            "overall_status": result["overall_status"],
            "criteria_expected": len(expected_ids),
            "criteria_recorded": len(recorded_ids),
            "criteria_complete": criteria_complete,
            "qa_passed": result["overall_status"] == "PASSED" and not reasons,
            "client_accepted": False,
            "deployment_authorized": False,
            "reasons": reasons,
            "tenant_id": tenant_id,
            "engagement_id": result["engagement_id"],
            "generated_at": generated_at,
        }
