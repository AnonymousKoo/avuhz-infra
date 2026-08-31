"""Phase 5D-D3 explicit client-human acceptance; it creates no deployment authority."""
from __future__ import annotations

import copy
import re

from .implementation_handoff import canonical_digest
from .phase5d_brief import reference
from .phase5d_qa_result import _exact_sources as _exact_qa_sources


CLIENT_ACCEPTANCE_COMMANDS = ("RecordClientAcceptance",)
CLIENT_ACCEPTANCE_CAPABILITIES = {"RecordClientAcceptance": "client_acceptance:record"}
CLIENT_ACCEPTANCE_EVENTS = {"RecordClientAcceptance": "client_acceptance.recorded"}
CLIENT_ACCEPTANCE_CALLERS = {"RecordClientAcceptance": frozenset({"HUMAN"})}
CLIENT_ACCEPTANCE_AUTHORITY_ROLE = "CLIENT_ACCEPTANCE_AUTHORITY"

_SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}"
)
_AUTHENTICATED_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@")
_AUTHORITY_CLAIM = re.compile(
    r"(?i)\b(?:deployment\s+(?:is\s+)?(?:allowed|authorized)|"
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
            raise ValueError("credential or secret-bearing acceptance material is prohibited")
        if _AUTHORITY_CLAIM.search(value):
            raise ValueError("deployment or production authority claim is prohibited")


def client_acceptance_digest(tenant_id, engagement_id, payload, attribution):
    """Canonical digest over the exact decision, sources, artifact, and trusted human."""
    return canonical_digest({
        "client_acceptance_id": payload["client_acceptance_id"],
        "acceptance_version": payload["acceptance_version"],
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "codex_build_package_reference": payload["codex_build_package_reference"],
        "package_digest": payload["package_digest"],
        "build_execution_reference": payload["build_execution_reference"],
        "build_execution_digest": payload["build_execution_digest"],
        "qa_result_reference": payload["qa_result_reference"],
        "qa_result_digest": payload["qa_result_digest"],
        "artifact_reference": payload["artifact_reference"],
        "decision": payload["decision"],
        "decision_rationale": payload["decision_rationale"],
        "supersedes_client_acceptance_reference": payload.get(
            "supersedes_client_acceptance_reference"
        ),
        "attribution": attribution,
    })


def _exact_sources(uow, tenant_id, engagement_id, payload, now):
    build, package = _exact_qa_sources(uow, tenant_id, engagement_id, payload, now)
    qa_ref = payload["qa_result_reference"]
    qa = uow.qa_results.get(tenant_id, qa_ref["reference_id"])
    if (
        not qa
        or qa.get("engagement_id") != engagement_id
        or qa.get("overall_status") != "PASSED"
        or qa_ref != reference("QA_RESULT", qa["qa_result_id"], qa["record_version"])
        or qa.get("qa_digest") != payload["qa_result_digest"]
        or qa.get("codex_build_package_reference")
        != payload["codex_build_package_reference"]
        or qa.get("package_digest") != payload["package_digest"]
        or qa.get("build_execution_reference") != payload["build_execution_reference"]
        or qa.get("build_execution_digest") != payload["build_execution_digest"]
    ):
        raise ValueError("exact passing QAResult version and digest are required")
    qa_history = uow.qa_results.list_by_package(
        tenant_id, package["codex_build_package_id"], package["package_version"]
    )
    if not qa_history or qa_history[-1]["qa_result_id"] != qa["qa_result_id"]:
        raise ValueError("superseded QAResult cannot establish client acceptance")
    if payload["artifact_reference"] not in build["artifact_references"]:
        raise ValueError("acceptance artifact is not an exact build artifact")
    return build, package, qa


class ClientAcceptanceHandler:
    def __init__(self, uow):
        self.uow = uow

    def execute(self, command_type, prepared, context, now, command_id):
        if context.caller_type not in CLIENT_ACCEPTANCE_CALLERS[command_type]:
            raise ValueError("client acceptance requires a trusted human caller")
        if (
            not context.human_principal_reference
            or not context.human_organization_reference
            or context.human_authority_role != CLIENT_ACCEPTANCE_AUTHORITY_ROLE
        ):
            raise ValueError("trusted client acceptance authority is required")
        _safe_payload(prepared.payload)
        return self.RecordClientAcceptance(prepared, context, now, command_id)

    def RecordClientAcceptance(self, prepared, context, now, command_id):
        payload = prepared.payload
        if payload["client_acceptance_id"] != prepared.subject_id:
            raise ValueError("ClientAcceptance payload must identify the command subject")
        if prepared.expected_record_version is not None:
            raise ValueError("immutable acceptance creation does not accept expected version")
        if self.uow.client_acceptances.get_version(
            prepared.tenant_id, prepared.subject_id, payload["acceptance_version"]
        ):
            raise ValueError("ClientAcceptance identity and version already exist")

        _, package, _ = _exact_sources(
            self.uow, prepared.tenant_id, prepared.engagement_id, payload, now
        )
        history = self.uow.client_acceptances.list_by_package(
            prepared.tenant_id,
            package["codex_build_package_id"],
            package["package_version"],
        )
        supersedes = payload.get("supersedes_client_acceptance_reference")
        if payload["acceptance_version"] == 1:
            if supersedes is not None or history:
                raise ValueError("initial acceptance cannot supersede existing history")
        else:
            if (
                not supersedes
                or supersedes["reference_id"] != prepared.subject_id
                or supersedes["reference_version"] != payload["acceptance_version"] - 1
                or not history
            ):
                raise ValueError("later acceptance requires the exact preceding version")
            previous = self.uow.client_acceptances.get_version(
                prepared.tenant_id,
                supersedes["reference_id"],
                supersedes["reference_version"],
            )
            if (
                not previous
                or history[-1]["client_acceptance_id"] != previous["client_acceptance_id"]
                or history[-1]["acceptance_version"] != previous["acceptance_version"]
                or previous["codex_build_package_reference"]
                != payload["codex_build_package_reference"]
                or previous["package_digest"] != payload["package_digest"]
            ):
                raise ValueError("exact latest ClientAcceptance predecessor is required")

        attribution = {
            "principal_reference": context.human_principal_reference,
            "organization_reference": context.human_organization_reference,
            "authority_role": CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
        }
        expected_digest = client_acceptance_digest(
            prepared.tenant_id, prepared.engagement_id, payload, attribution
        )
        if payload["client_acceptance_digest"] != expected_digest:
            raise ValueError("ClientAcceptance digest does not match exact decision truth")

        record = {
            "client_acceptance_id": prepared.subject_id,
            "acceptance_version": payload["acceptance_version"],
            "tenant_id": prepared.tenant_id,
            "engagement_id": prepared.engagement_id,
            "codex_build_package_reference": copy.deepcopy(
                payload["codex_build_package_reference"]
            ),
            "package_digest": payload["package_digest"],
            "build_execution_reference": copy.deepcopy(
                payload["build_execution_reference"]
            ),
            "build_execution_digest": payload["build_execution_digest"],
            "qa_result_reference": copy.deepcopy(payload["qa_result_reference"]),
            "qa_result_digest": payload["qa_result_digest"],
            "artifact_reference": copy.deepcopy(payload["artifact_reference"]),
            "decision": payload["decision"],
            "decision_rationale": payload["decision_rationale"],
            "client_acceptance_digest": payload["client_acceptance_digest"],
            "attribution": attribution,
            "recorded_at": now,
            "record_version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if supersedes:
            record["supersedes_client_acceptance_reference"] = copy.deepcopy(supersedes)
        return self.uow.client_acceptances.create(record)


class ClientAcceptanceReadService:
    def __init__(self, uow):
        self.uow = uow

    def status(self, tenant_id, client_acceptance_id, acceptance_version, generated_at):
        acceptance = self.uow.client_acceptances.get_version(
            tenant_id, client_acceptance_id, acceptance_version
        )
        if not acceptance:
            return None
        package_ref = acceptance["codex_build_package_reference"]
        build_ref = acceptance["build_execution_reference"]
        qa_ref = acceptance["qa_result_reference"]
        package = self.uow.codex_build_packages.get_version(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        build = self.uow.build_execution_results.get(tenant_id, build_ref["reference_id"])
        qa = self.uow.qa_results.get(tenant_id, qa_ref["reference_id"])
        sources_exact = bool(
            package
            and package.get("state") == "RELEASED"
            and package.get("package_digest") == acceptance["package_digest"]
            and build
            and build.get("status") == "SUCCEEDED"
            and reference("BUILD_EXECUTION_RESULT", build["build_execution_result_id"], build["record_version"]) == build_ref
            and build.get("execution_digest") == acceptance["build_execution_digest"]
            and build.get("codex_build_package_reference") == package_ref
            and acceptance["artifact_reference"] in build.get("artifact_references", [])
            and qa
            and qa.get("overall_status") == "PASSED"
            and reference("QA_RESULT", qa["qa_result_id"], qa["record_version"]) == qa_ref
            and qa.get("qa_digest") == acceptance["qa_result_digest"]
            and qa.get("build_execution_reference") == build_ref
            and qa.get("build_execution_digest") == acceptance["build_execution_digest"]
            and qa.get("codex_build_package_reference") == package_ref
            and qa.get("package_digest") == acceptance["package_digest"]
        )
        reasons = []
        if not sources_exact:
            reasons.append("SOURCE_BINDING_INVALID")
        if build and any(
            item["execution_attempt"] > build["execution_attempt"]
            for item in self.uow.build_execution_results.list_by_package(
                tenant_id, package_ref["reference_id"], package_ref["reference_version"]
            )
        ):
            reasons.append("BUILD_SUPERSEDED")
        qa_history = self.uow.qa_results.list_by_package(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        if qa_history and qa_history[-1]["qa_result_id"] != qa_ref["reference_id"]:
            reasons.append("QA_SUPERSEDED")
        acceptance_history = self.uow.client_acceptances.list_by_package(
            tenant_id, package_ref["reference_id"], package_ref["reference_version"]
        )
        if acceptance_history and (
            acceptance_history[-1]["client_acceptance_id"] != client_acceptance_id
            or acceptance_history[-1]["acceptance_version"] != acceptance_version
        ):
            reasons.append("ACCEPTANCE_SUPERSEDED")
        stale = bool(reasons)
        return {
            "client_acceptance_reference": reference(
                "CLIENT_ACCEPTANCE", client_acceptance_id, acceptance_version
            ),
            "package_reference": copy.deepcopy(package_ref),
            "build_execution_reference": copy.deepcopy(build_ref),
            "qa_result_reference": copy.deepcopy(qa_ref),
            "decision": acceptance["decision"],
            "sources_exact": sources_exact,
            "stale": stale,
            "client_accepted": acceptance["decision"] == "ACCEPTED" and not stale,
            "deployment_authorized": False,
            "reasons": reasons,
            "tenant_id": tenant_id,
            "engagement_id": acceptance["engagement_id"],
            "generated_at": generated_at,
        }
