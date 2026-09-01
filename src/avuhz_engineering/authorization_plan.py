"""Provider-neutral, local-only enforcement for bounded authorization plans."""
from __future__ import annotations

import copy
import re
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry


PLAN_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan:v1"
APPROVAL_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-approval:v1"
PROGRESS_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-progress:v1"
_SECRET_KEYS = frozenset({
    "access_token", "refresh_token", "credential_value", "password", "private_key",
    "secret_value", "service_role_key",
})
_SECRET_VALUE = re.compile(
    r"(?i)(?:password|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization)\s*[:=]\s*\S+|bearer\s+[a-z0-9._~+/=-]{8,}|"
    r"\b(?:https?|postgres(?:ql)?)://[^\s/:]+:[^\s/@]+@"
)


class AuthorizationPlanError(ValueError):
    """Contract or immutable-binding defect."""


class AuthorizationPlanStop(AuthorizationPlanError):
    """Fail-closed step decision that requires review or a new plan."""


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AuthorizationPlanError("TIMESTAMP_INVALID")
    return parsed


def _reject_sensitive(value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("-", "_") in _SECRET_KEYS:
                raise AuthorizationPlanError("SENSITIVE_FIELD_PROHIBITED")
            _reject_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive(child)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise AuthorizationPlanError("SENSITIVE_VALUE_PROHIBITED")


def plan_digest(plan: dict) -> str:
    return canonical_digest({key: copy.deepcopy(value) for key, value in plan.items() if key != "plan_digest"})


def approval_digest(approval: dict) -> str:
    return canonical_digest({key: copy.deepcopy(value) for key, value in approval.items() if key != "approval_digest"})


def progress_digest(progress: dict) -> str:
    return canonical_digest({key: copy.deepcopy(value) for key, value in progress.items() if key != "progress_digest"})


def _schema_validate(value: dict, schema_id: str, schema_root: Path) -> None:
    registry = SchemaRegistry(schema_root)
    validator = Draft202012Validator(registry.expanded(schema_id), format_checker=FormatChecker())
    if list(validator.iter_errors(value)):
        raise AuthorizationPlanError("SCHEMA_INVALID")


def validate_plan(plan: dict, schema_root: Path) -> None:
    _reject_sensitive(plan)
    _schema_validate(plan, PLAN_SCHEMA_ID, schema_root)
    if plan["plan_digest"] != plan_digest(plan):
        raise AuthorizationPlanError("PLAN_DIGEST_INVALID")
    steps = plan["steps"]
    step_ids = [step["step_id"] for step in steps]
    if step_ids != plan["ordered_step_ids"]:
        raise AuthorizationPlanError("STEP_ORDER_INVALID")
    if [step["ordinal"] for step in steps] != list(range(1, len(steps) + 1)):
        raise AuthorizationPlanError("STEP_ORDINAL_INVALID")
    prior: set[str] = set()
    unresolved = plan["authorization_window"]["binding_state"] == "UNRESOLVED_BLOCKER"
    for index, step in enumerate(steps):
        dependencies = set(step["dependency_step_ids"])
        if not dependencies <= prior or (index and step_ids[index - 1] not in dependencies):
            raise AuthorizationPlanError("STEP_DEPENDENCY_INVALID")
        if not index and dependencies:
            raise AuthorizationPlanError("STEP_DEPENDENCY_INVALID")
        for evidence in step["required_evidence"]:
            source = evidence["source_step_id"]
            if source is not None and source not in prior:
                raise AuthorizationPlanError("EVIDENCE_DEPENDENCY_INVALID")
            if evidence["binding_state"] == "BOUND" and evidence["exact_digest"] is None:
                raise AuthorizationPlanError("EVIDENCE_BINDING_INVALID")
            if evidence["binding_state"] == "DERIVED_FROM_SOURCE_STEP" and source is None:
                raise AuthorizationPlanError("EVIDENCE_BINDING_INVALID")
            unresolved = unresolved or evidence["binding_state"] == "UNRESOLVED_BLOCKER"
        credentials = step["credential_policy"]
        if (not credentials["permitted"] and credentials["allowed_classes"] != ["NONE"]) or (
            credentials["permitted"] and "NONE" in credentials["allowed_classes"]
        ):
            raise AuthorizationPlanError("CREDENTIAL_POLICY_INVALID")
        unresolved = unresolved or bool(step["unresolved_bindings"])
        unresolved = unresolved or step["resource"]["binding_state"] == "UNRESOLVED_BLOCKER"
        prior.add(step["step_id"])
    expected = "DRAFT_BLOCKED" if unresolved else "READY_FOR_APPROVAL"
    if plan["definition_status"] != expected:
        raise AuthorizationPlanError("DEFINITION_STATUS_INVALID")
    window = plan["authorization_window"]
    if window["binding_state"] == "BOUND":
        if window["starts_at"] is None or window["expires_at"] is None:
            raise AuthorizationPlanError("AUTHORIZATION_WINDOW_INVALID")
        if _utc(window["starts_at"]) >= _utc(window["expires_at"]):
            raise AuthorizationPlanError("AUTHORIZATION_WINDOW_INVALID")
    elif window["starts_at"] is not None or window["expires_at"] is not None:
        raise AuthorizationPlanError("AUTHORIZATION_WINDOW_INVALID")


def validate_approval(plan: dict, approval: dict, schema_root: Path, now: str) -> None:
    validate_plan(plan, schema_root)
    _reject_sensitive(approval)
    _schema_validate(approval, APPROVAL_SCHEMA_ID, schema_root)
    if plan["definition_status"] != "READY_FOR_APPROVAL":
        raise AuthorizationPlanStop("PLAN_UNRESOLVED")
    if approval["approval_digest"] != approval_digest(approval):
        raise AuthorizationPlanStop("APPROVAL_DIGEST_INVALID")
    exact = (
        approval["plan_id"] == plan["plan_id"]
        and approval["plan_version"] == plan["plan_version"]
        and approval["plan_digest"] == plan["plan_digest"]
        and approval["owner_identity"] == plan["owner_identity"]
        and approval["environment"] == plan["environment"]
        and approval["effective_at"] == plan["authorization_window"]["starts_at"]
        and approval["expires_at"] == plan["authorization_window"]["expires_at"]
    )
    if not exact:
        raise AuthorizationPlanStop("APPROVAL_BINDING_MISMATCH")
    if approval["status"] != "ACTIVE":
        raise AuthorizationPlanStop("APPROVAL_NOT_ACTIVE")
    approved = _utc(approval["approved_at"])
    effective = _utc(approval["effective_at"])
    expires = _utc(approval["expires_at"])
    evaluated = _utc(now)
    if approved > effective or not effective <= evaluated < expires:
        raise AuthorizationPlanStop("PLAN_AUTHORIZATION_EXPIRED")


def initial_progress(plan: dict, schema_root: Path, progress_id: str, now: str) -> dict:
    validate_plan(plan, schema_root)
    progress = {
        "progress_id": progress_id,
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "record_version": 1,
        "overall_state": "NOT_STARTED",
        "step_states": [
            {
                "step_id": step_id,
                "authorization_state": "PENDING",
                "execution_state": "NOT_STARTED",
                "verification_state": "NOT_STARTED",
                "authorization_consumed": False,
                "evidence": [],
                "observed_postcondition": None,
                "safe_error_code": None,
            }
            for step_id in plan["ordered_step_ids"]
        ],
        "updated_at": now,
        "progress_digest": "sha256:" + "0" * 64,
    }
    progress["progress_digest"] = progress_digest(progress)
    validate_progress(plan, progress, schema_root)
    return progress


def validate_progress(plan: dict, progress: dict, schema_root: Path) -> None:
    _reject_sensitive(progress)
    _schema_validate(progress, PROGRESS_SCHEMA_ID, schema_root)
    if progress["progress_digest"] != progress_digest(progress):
        raise AuthorizationPlanError("PROGRESS_DIGEST_INVALID")
    if (
        progress["plan_id"],
        progress["plan_version"],
        progress["plan_digest"],
    ) != (plan["plan_id"], plan["plan_version"], plan["plan_digest"]):
        raise AuthorizationPlanError("PROGRESS_BINDING_MISMATCH")
    if [state["step_id"] for state in progress["step_states"]] != plan["ordered_step_ids"]:
        raise AuthorizationPlanError("PROGRESS_STEP_ORDER_INVALID")
    seen_incomplete = False
    completed_count = 0
    for state in progress["step_states"]:
        completed = (
            state["authorization_state"] == "CONSUMED"
            and state["authorization_consumed"]
            and state["execution_state"] == "SUCCEEDED"
            and state["verification_state"] == "PASS"
        )
        if seen_incomplete and completed:
            raise AuthorizationPlanError("PROGRESS_SEQUENCE_INVALID")
        completed_count += int(completed)
        seen_incomplete = seen_incomplete or not completed
    if progress["overall_state"] == "NOT_STARTED" and (
        completed_count or any(state["authorization_state"] != "PENDING" for state in progress["step_states"])
    ):
        raise AuthorizationPlanError("PROGRESS_STATE_INVALID")
    if progress["overall_state"] == "COMPLETED" and completed_count != len(progress["step_states"]):
        raise AuthorizationPlanError("PROGRESS_STATE_INVALID")


def _next_index(progress: dict) -> int | None:
    for index, state in enumerate(progress["step_states"]):
        if not (
            state["authorization_consumed"]
            and state["execution_state"] == "SUCCEEDED"
            and state["verification_state"] == "PASS"
        ):
            return index
    return None


def authorize_step(
    plan: dict,
    approval: dict,
    progress: dict,
    request: dict,
    schema_root: Path,
    now: str,
) -> dict:
    validate_approval(plan, approval, schema_root, now)
    validate_progress(plan, progress, schema_root)
    _reject_sensitive(request)
    if progress["overall_state"] in {"STOPPED", "COMPLETED", "EXPIRED"}:
        raise AuthorizationPlanStop("PLAN_NOT_CONTINUABLE")
    index = _next_index(progress)
    if index is None:
        raise AuthorizationPlanStop("PLAN_ALREADY_COMPLETED")
    step = plan["steps"][index]
    state = progress["step_states"][index]
    exact_request = {
        "plan_id", "plan_version", "plan_digest", "environment", "provider_reference",
        "project_reference", "responsibility", "issuer_reference", "audience_reference",
        "step_id", "resource_reference",
        "resource_version", "resource_digest", "operation", "execution_class",
        "credential_class", "required_evidence", "prior_evidence_digests", "unexpected_remote_state",
        "extra_privileges", "unauthorized_migration_surface", "scope_expansion",
    }
    if set(request) != exact_request:
        raise AuthorizationPlanStop("PREFLIGHT_SURFACE_INVALID")
    if any(
        request[flag]
        for flag in (
            "unexpected_remote_state", "extra_privileges",
            "unauthorized_migration_surface", "scope_expansion",
        )
    ):
        raise AuthorizationPlanStop("PREFLIGHT_DRIFT")
    expected = {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
    }
    if any(request[key] != value for key, value in expected.items()):
        raise AuthorizationPlanStop("PREFLIGHT_BINDING_MISMATCH")
    if step["unresolved_bindings"] or step["resource"]["binding_state"] != "BOUND":
        raise AuthorizationPlanStop("STEP_UNRESOLVED")
    if any(item["binding_state"] == "UNRESOLVED_BLOCKER" for item in step["required_evidence"]):
        raise AuthorizationPlanStop("EVIDENCE_UNRESOLVED")
    allowed = step["credential_policy"]["allowed_classes"]
    if request["credential_class"] not in allowed:
        raise AuthorizationPlanStop("CREDENTIAL_CLASS_NOT_ALLOWED")
    prior_digests = [
        evidence["evidence_digest"]
        for prior in progress["step_states"][:index]
        for evidence in prior["evidence"]
    ]
    if request["prior_evidence_digests"] != prior_digests:
        raise AuthorizationPlanStop("PRIOR_EVIDENCE_MISMATCH")
    expected_evidence = []
    for requirement in step["required_evidence"]:
        if requirement["source_step_id"] is None:
            digest = requirement["exact_digest"]
        else:
            source_index = plan["ordered_step_ids"].index(requirement["source_step_id"])
            matches = [
                item for item in progress["step_states"][source_index]["evidence"]
                if item["evidence_type"] == requirement["evidence_type"]
            ]
            if len(matches) != 1:
                raise AuthorizationPlanStop("REQUIRED_EVIDENCE_MISSING")
            digest = matches[0]["evidence_digest"]
            if requirement["exact_digest"] is not None and digest != requirement["exact_digest"]:
                raise AuthorizationPlanStop("REQUIRED_EVIDENCE_MISMATCH")
        expected_evidence.append({
            "evidence_type": requirement["evidence_type"],
            "evidence_digest": digest,
        })
    if request["required_evidence"] != expected_evidence:
        raise AuthorizationPlanStop("REQUIRED_EVIDENCE_MISMATCH")
    if (
        state["authorization_state"] != "PENDING"
        or state["authorization_consumed"]
        or state["execution_state"] != "NOT_STARTED"
    ):
        raise AuthorizationPlanStop("STEP_REPLAY_PROHIBITED")
    updated = copy.deepcopy(progress)
    updated_state = updated["step_states"][index]
    updated_state["authorization_state"] = "AUTHORIZED"
    updated["overall_state"] = "IN_PROGRESS"
    updated["record_version"] += 1
    updated["updated_at"] = now
    updated["progress_digest"] = progress_digest(updated)
    validate_progress(plan, updated, schema_root)
    return updated


def record_step_outcome(
    plan: dict,
    approval: dict,
    progress: dict,
    step_id: str,
    execution_state: str,
    verification_state: str,
    evidence: list[dict],
    observed_postcondition: str,
    safe_error_code: str | None,
    schema_root: Path,
    now: str,
) -> dict:
    validate_approval(plan, approval, schema_root, now)
    validate_progress(plan, progress, schema_root)
    index = _next_index(progress)
    if index is None or plan["ordered_step_ids"][index] != step_id:
        raise AuthorizationPlanStop("STEP_REPLAY_OR_REORDER_PROHIBITED")
    current = progress["step_states"][index]
    if current["authorization_state"] != "AUTHORIZED" or current["authorization_consumed"]:
        raise AuthorizationPlanStop("STEP_NOT_AUTHORIZED")
    if execution_state not in {"SUCCEEDED", "FAILED", "PARTIAL", "AMBIGUOUS"}:
        raise AuthorizationPlanError("EXECUTION_OUTCOME_INVALID")
    if verification_state not in {"PASS", "FAIL", "AMBIGUOUS"} or not evidence:
        raise AuthorizationPlanError("VERIFICATION_OUTCOME_INVALID")
    updated = copy.deepcopy(progress)
    state = updated["step_states"][index]
    state["execution_state"] = execution_state
    state["verification_state"] = verification_state
    state["authorization_state"] = "CONSUMED"
    state["authorization_consumed"] = True
    state["evidence"] = copy.deepcopy(evidence)
    state["observed_postcondition"] = observed_postcondition
    state["safe_error_code"] = safe_error_code
    expected = plan["steps"][index]["expected_postcondition"]
    success = execution_state == "SUCCEEDED" and verification_state == "PASS" and observed_postcondition == expected
    if success and safe_error_code is None:
        updated["overall_state"] = "COMPLETED" if index == len(plan["steps"]) - 1 else "IN_PROGRESS"
    else:
        if safe_error_code is None:
            raise AuthorizationPlanError("STOP_EVIDENCE_CODE_REQUIRED")
        updated["overall_state"] = "STOPPED"
        for later in updated["step_states"][index + 1:]:
            later["authorization_state"] = "BLOCKED"
    updated["record_version"] += 1
    updated["updated_at"] = now
    updated["progress_digest"] = progress_digest(updated)
    validate_progress(plan, updated, schema_root)
    return updated
