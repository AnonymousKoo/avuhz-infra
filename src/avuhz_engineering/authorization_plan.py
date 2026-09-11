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
_JWT_VALUE = re.compile(r"^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_DIGEST_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID_VALUE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PREAPPROVAL_UUID_VALUE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PREAPPROVAL_REFERENCE_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{2,159}$")
_PREAPPROVAL_VALUE_CLASSES = frozenset({
    "STABLE_REFERENCE", "UUID_IDENTIFIER", "CONTENT_DIGEST",
    "PROCEDURE_REFERENCE", "CONFIGURATION_REFERENCE",
})
_SANITIZED_REFERENCE_VALUE = re.compile(
    r"^[a-z][a-z0-9_-]{1,39}(?:[.:][a-z][a-z0-9_-]{1,79}){1,7}$"
)
_SANITIZED_REFERENCE_PROHIBITED = re.compile(
    r"(access[_-]?token|refresh[_-]?token|password|api[_-]?key|service[_-]?role|private[_-]?key|authorization|bearer|credential|secret|token|jwt|connection[_-]?string|provider[_-]?payload)"
)
_BINDING_ASSERTION_FIELDS = frozenset({
    "binding_id", "phase", "value_class", "source_step_id", "evidence_type",
    "evidence_digest", "digest_policy", "persistence_policy", "sanitized_value",
    "value_digest", "recorded_at",
})
_RUNTIME_INPUT_PHASES = frozenset({
    "DERIVED_FROM_SOURCE_STEP", "RESOLVED_BY_STEP_PREFLIGHT", "EPHEMERAL_HANDOFF",
})


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
    elif isinstance(value, str) and (_SECRET_VALUE.search(value) or _JWT_VALUE.fullmatch(value)):
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


def _binding_declarations(step: dict) -> list[dict]:
    return step.get("binding_declarations", [])


def _produced_evidence_declarations(step: dict) -> list[dict]:
    return step.get("produced_evidence", [])


def _is_typed_plan(plan: dict) -> bool:
    return any(
        "binding_declarations" in step or "produced_evidence" in step
        for step in plan["steps"]
    )


def _produced_evidence_matches(step: dict, binding_id: str, evidence_type: str) -> list[dict]:
    return [
        declaration
        for declaration in _produced_evidence_declarations(step)
        if declaration["evidence_type"] == evidence_type
        and binding_id in declaration["established_binding_ids"]
    ]


def _validate_exact_preapproval_value(declaration: dict) -> tuple[str, ...] | None:
    if "preapproval_value" not in declaration:
        return None
    exact = declaration["preapproval_value"]
    if (
        declaration["phase"] != "PREAPPROVAL_BOUND"
        or declaration["value_class"] not in _PREAPPROVAL_VALUE_CLASSES
        or declaration["source_step_id"] is not None
        or declaration["evidence_type"] is not None
        or declaration["digest_policy"] != "REQUIRED"
        or declaration["persistence_policy"]
        not in {"SANITIZED_VALUE_ALLOWED", "DIGEST_ONLY"}
        or not isinstance(exact, dict)
        or set(exact) != {"value", "exact_digest"}
    ):
        raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
    value = exact["value"]
    exact_digest = exact["exact_digest"]
    value_class = declaration["value_class"]
    if not isinstance(value, str) or not 3 <= len(value) <= 160:
        raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
    if value_class == "UUID_IDENTIFIER":
        value_valid = bool(_PREAPPROVAL_UUID_VALUE.fullmatch(value))
    elif value_class == "CONTENT_DIGEST":
        value_valid = bool(_DIGEST_VALUE.fullmatch(value))
    else:
        value_valid = bool(_PREAPPROVAL_REFERENCE_VALUE.fullmatch(value))
    if (
        not value_valid
        or not isinstance(exact_digest, str)
        or not _DIGEST_VALUE.fullmatch(exact_digest)
        or exact_digest != canonical_digest(value)
    ):
        raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
    return (
        value_class,
        value,
        exact_digest,
        declaration["digest_policy"],
        declaration["persistence_policy"],
    )


def _validate_typed_plan(steps: list[dict], step_ids: list[str]) -> bool:
    if not any(
        "binding_declarations" in step or "produced_evidence" in step
        for step in steps
    ):
        return False
    positions = {step_id: index for index, step_id in enumerate(step_ids)}
    declarations_by_step = [_binding_declarations(step) for step in steps]
    preapproval_authorities: dict[str, tuple[str, ...]] = {}
    for step, declarations in zip(steps, declarations_by_step, strict=True):
        binding_ids = [declaration["binding_id"] for declaration in declarations]
        if len(binding_ids) != len(set(binding_ids)):
            raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
        evidence_types = [
            declaration["evidence_type"]
            for declaration in _produced_evidence_declarations(step)
        ]
        if len(evidence_types) != len(set(evidence_types)):
            raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")

    unresolved = False
    for index, (step, declarations) in enumerate(zip(steps, declarations_by_step, strict=True)):
        for declaration in declarations:
            binding_id = declaration["binding_id"]
            evidence_type = declaration["evidence_type"]
            phase = declaration["phase"]
            preapproval_authority = _validate_exact_preapproval_value(declaration)
            if preapproval_authority is not None:
                prior_authority = preapproval_authorities.get(binding_id)
                if (
                    prior_authority is not None
                    and prior_authority != preapproval_authority
                ):
                    raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
                preapproval_authorities[binding_id] = preapproval_authority
            if phase == "PREAPPROVAL_BOUND":
                if (
                    step["resource"]["binding_state"] != "BOUND"
                    or step["unresolved_bindings"]
                ):
                    raise AuthorizationPlanError("BINDING_DECLARATION_INVALID")
            elif phase == "UNRESOLVED_BLOCKER":
                unresolved = True
            elif phase == "PRODUCED_BY_CURRENT_STEP":
                evidence_matches = _produced_evidence_matches(
                    step, binding_id, evidence_type
                )
                if (
                    len(evidence_matches) != 1
                    or evidence_matches[0]["digest_policy"] != "REQUIRED"
                ):
                    raise AuthorizationPlanError("PRODUCED_EVIDENCE_UNDECLARED")
            elif phase in {"DERIVED_FROM_SOURCE_STEP", "EPHEMERAL_HANDOFF"}:
                source_step_id = declaration["source_step_id"]
                if source_step_id not in positions or positions[source_step_id] >= index:
                    raise AuthorizationPlanError("BINDING_SOURCE_INVALID")
                source_index = positions[source_step_id]
                source_step = steps[source_index]
                evidence_matches = _produced_evidence_matches(
                    source_step, binding_id, evidence_type
                )
                if (
                    len(evidence_matches) != 1
                    or evidence_matches[0]["digest_policy"] != "REQUIRED"
                ):
                    raise AuthorizationPlanError("BINDING_SOURCE_INVALID")
                if phase == "DERIVED_FROM_SOURCE_STEP":
                    source_declarations = [
                        source
                        for source in declarations_by_step[source_index]
                        if source["binding_id"] == binding_id
                        and source["phase"] == "PRODUCED_BY_CURRENT_STEP"
                    ]
                    if len(source_declarations) != 1:
                        raise AuthorizationPlanError("BINDING_SOURCE_INVALID")
                    source = source_declarations[0]
                    if any(
                        source[field] != declaration[field]
                        for field in ("value_class", "evidence_type", "digest_policy", "persistence_policy")
                    ):
                        raise AuthorizationPlanError("BINDING_SOURCE_INVALID")

        for evidence_declaration in _produced_evidence_declarations(step):
            for binding_id in evidence_declaration["established_binding_ids"]:
                current_targets = [
                    declaration
                    for declaration in declarations
                    if declaration["binding_id"] == binding_id
                    and declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
                    and declaration["evidence_type"] == evidence_declaration["evidence_type"]
                ]
                future_targets = [
                    declaration
                    for future_index in range(index + 1, len(steps))
                    for declaration in declarations_by_step[future_index]
                    if declaration["binding_id"] == binding_id
                    and declaration["phase"] in {"DERIVED_FROM_SOURCE_STEP", "EPHEMERAL_HANDOFF"}
                    and declaration["source_step_id"] == step["step_id"]
                    and declaration["evidence_type"] == evidence_declaration["evidence_type"]
                ]
                if not current_targets and not future_targets:
                    raise AuthorizationPlanError("PRODUCED_EVIDENCE_UNDECLARED")
    return unresolved


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
    typed_unresolved = _validate_typed_plan(steps, step_ids)
    prior: set[str] = set()
    unresolved = (
        plan["authorization_window"]["binding_state"] == "UNRESOLVED_BLOCKER"
        or typed_unresolved
    )
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


def _state_successful(step: dict, state: dict) -> bool:
    return (
        state["authorization_state"] == "CONSUMED"
        and state["authorization_consumed"]
        and state["execution_state"] == "SUCCEEDED"
        and state["verification_state"] == "PASS"
        and state["observed_postcondition"] == step["expected_postcondition"]
        and state["safe_error_code"] is None
    )


def _raise_binding(code: str, stop: bool) -> None:
    exception = AuthorizationPlanStop if stop else AuthorizationPlanError
    raise exception(code)


def _binding_value_matches_class(assertion: dict) -> bool:
    value = assertion["sanitized_value"]
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    value_class = assertion["value_class"]
    if value_class in {
        "STABLE_REFERENCE", "PROCEDURE_REFERENCE", "CONFIGURATION_REFERENCE"
    }:
        return bool(
            _SANITIZED_REFERENCE_VALUE.fullmatch(value)
            and not _SANITIZED_REFERENCE_PROHIBITED.search(value)
        )
    if value_class == "UUID_IDENTIFIER":
        return bool(_UUID_VALUE.fullmatch(value))
    if value_class == "CONTENT_DIGEST":
        return bool(_DIGEST_VALUE.fullmatch(value))
    return False


def _validate_binding_assertion(
    assertion: dict,
    declaration: dict,
    *,
    stop: bool = False,
) -> None:
    if not isinstance(assertion, dict) or set(assertion) != _BINDING_ASSERTION_FIELDS:
        _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    _reject_sensitive(assertion)
    for field in (
        "binding_id", "phase", "value_class", "source_step_id", "evidence_type",
        "digest_policy", "persistence_policy",
    ):
        if assertion[field] != declaration[field]:
            _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    for field in ("evidence_digest", "value_digest"):
        value = assertion[field]
        if value is not None and (
            not isinstance(value, str) or not _DIGEST_VALUE.fullmatch(value)
        ):
            _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    try:
        _utc(assertion["recorded_at"])
    except (AttributeError, TypeError, ValueError):
        _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    if not _binding_value_matches_class(assertion):
        _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    persistence = declaration["persistence_policy"]
    digest_policy = declaration["digest_policy"]
    if persistence == "SANITIZED_VALUE_ALLOWED":
        if assertion["sanitized_value"] is None:
            _raise_binding("BINDING_ASSERTION_MISSING", stop)
    elif persistence == "DIGEST_ONLY":
        if assertion["sanitized_value"] is not None:
            _raise_binding("BINDING_PERSISTENCE_PROHIBITED", stop)
    elif (
        assertion["sanitized_value"] is not None
        or assertion["value_digest"] is not None
    ):
        if declaration["phase"] == "EPHEMERAL_HANDOFF":
            _raise_binding("EPHEMERAL_BINDING_PERSISTENCE_PROHIBITED", stop)
        _raise_binding("BINDING_PERSISTENCE_PROHIBITED", stop)
    if digest_policy == "REQUIRED" and assertion["value_digest"] is None:
        _raise_binding("BINDING_ASSERTION_MISSING", stop)
    if digest_policy == "PROHIBITED" and assertion["value_digest"] is not None:
        _raise_binding("BINDING_DIGEST_PROHIBITED", stop)
    if declaration["evidence_type"] is None:
        if assertion["evidence_digest"] is not None:
            _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    elif assertion["evidence_digest"] is None:
        _raise_binding("BINDING_ASSERTION_MISSING", stop)


def _exact_evidence(state: dict, evidence_type: str, *, stop: bool) -> dict:
    matches = [
        evidence
        for evidence in state["evidence"]
        if evidence["evidence_type"] == evidence_type
    ]
    if not matches:
        _raise_binding("BINDING_ASSERTION_MISSING", stop)
    if len(matches) != 1:
        _raise_binding("BINDING_ASSERTION_DUPLICATE", stop)
    return matches[0]


def _source_material(
    plan: dict,
    progress: dict,
    consumer_index: int,
    declaration: dict,
    *,
    stop: bool,
) -> tuple[dict, dict | None]:
    source_step_id = declaration["source_step_id"]
    step_ids = plan["ordered_step_ids"]
    if source_step_id not in step_ids:
        _raise_binding("BINDING_SOURCE_INVALID", stop)
    source_index = step_ids.index(source_step_id)
    if source_index >= consumer_index:
        _raise_binding("BINDING_SOURCE_INVALID", stop)
    source_step = plan["steps"][source_index]
    source_state = progress["step_states"][source_index]
    if not _state_successful(source_step, source_state):
        _raise_binding("BINDING_ASSERTION_MISSING", stop)
    evidence = _exact_evidence(source_state, declaration["evidence_type"], stop=stop)
    if declaration["phase"] == "EPHEMERAL_HANDOFF":
        return evidence, None
    source_declarations = [
        item
        for item in _binding_declarations(source_step)
        if item["binding_id"] == declaration["binding_id"]
        and item["phase"] == "PRODUCED_BY_CURRENT_STEP"
    ]
    if len(source_declarations) != 1:
        _raise_binding("BINDING_SOURCE_INVALID", stop)
    source_assertions = [
        item
        for item in source_state.get("binding_assertions", [])
        if item["binding_id"] == declaration["binding_id"]
        and item["phase"] == "PRODUCED_BY_CURRENT_STEP"
    ]
    if not source_assertions:
        _raise_binding("BINDING_ASSERTION_MISSING", stop)
    if len(source_assertions) != 1:
        _raise_binding("BINDING_ASSERTION_DUPLICATE", stop)
    source_assertion = source_assertions[0]
    _validate_binding_assertion(source_assertion, source_declarations[0], stop=stop)
    if (
        source_assertion["evidence_type"] != evidence["evidence_type"]
        or source_assertion["evidence_digest"] != evidence["evidence_digest"]
    ):
        _raise_binding("BINDING_ASSERTION_MISMATCH", stop)
    return evidence, source_assertion



def _validate_typed_progress(plan: dict, progress: dict) -> None:
    typed = _is_typed_plan(plan)
    if not typed:
        if any("binding_assertions" in state for state in progress["step_states"]):
            raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
        return
    for index, (step, state) in enumerate(
        zip(plan["steps"], progress["step_states"], strict=True)
    ):
        if "binding_assertions" not in state:
            raise AuthorizationPlanError("BINDING_ASSERTION_MISSING")
        assertions = state["binding_assertions"]
        assertion_ids = [assertion["binding_id"] for assertion in assertions]
        if len(assertion_ids) != len(set(assertion_ids)):
            raise AuthorizationPlanError("BINDING_ASSERTION_DUPLICATE")
        if state["authorization_state"] in {"PENDING", "BLOCKED", "EXPIRED"} and assertions:
            raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
        if not state["authorization_consumed"] and state["evidence"]:
            raise AuthorizationPlanError("PRODUCED_EVIDENCE_UNDECLARED")
        declarations = _binding_declarations(step)
        for assertion in assertions:
            matches = [
                declaration
                for declaration in declarations
                if declaration["binding_id"] == assertion["binding_id"]
                and declaration["phase"] == assertion["phase"]
            ]
            if len(matches) != 1 or assertion["phase"] not in (
                _RUNTIME_INPUT_PHASES | {"PRODUCED_BY_CURRENT_STEP"}
            ):
                raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
            declaration = matches[0]
            _validate_binding_assertion(assertion, declaration)
            if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP":
                if not _state_successful(step, state):
                    raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
                evidence = _exact_evidence(
                    state, declaration["evidence_type"], stop=False
                )
                if assertion["evidence_digest"] != evidence["evidence_digest"]:
                    raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
            elif declaration["phase"] in {
                "DERIVED_FROM_SOURCE_STEP", "EPHEMERAL_HANDOFF"
            }:
                evidence, source_assertion = _source_material(
                    plan, progress, index, declaration, stop=False
                )
                if assertion["evidence_digest"] != evidence["evidence_digest"]:
                    raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
                if source_assertion is not None and any(
                    assertion[field] != source_assertion[field]
                    for field in ("sanitized_value", "value_digest")
                ):
                    raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")
        if state["authorization_consumed"]:
            actual_types = [
                evidence["evidence_type"] for evidence in state["evidence"]
            ]
            declared_types = [
                declaration["evidence_type"]
                for declaration in _produced_evidence_declarations(step)
            ]
            if (
                len(actual_types) != len(set(actual_types))
                or set(actual_types) != set(declared_types)
            ):
                raise AuthorizationPlanError("PRODUCED_EVIDENCE_MISSING")
            produced_ids = {
                declaration["binding_id"]
                for declaration in declarations
                if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
            }
            asserted_produced_ids = {
                assertion["binding_id"]
                for assertion in assertions
                if assertion["phase"] == "PRODUCED_BY_CURRENT_STEP"
            }
            if _state_successful(step, state):
                if asserted_produced_ids != produced_ids:
                    raise AuthorizationPlanError("BINDING_ASSERTION_MISSING")
            elif asserted_produced_ids:
                raise AuthorizationPlanError("BINDING_ASSERTION_MISMATCH")

def initial_progress(plan: dict, schema_root: Path, progress_id: str, now: str) -> dict:
    validate_plan(plan, schema_root)
    step_states = [
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
    ]
    if _is_typed_plan(plan):
        for state in step_states:
            state["binding_assertions"] = []
    progress = {
        "progress_id": progress_id,
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "record_version": 1,
        "overall_state": "NOT_STARTED",
        "step_states": step_states,
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
    _validate_typed_progress(plan, progress)
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



def _typed_authorization_assertions(
    plan: dict,
    progress: dict,
    index: int,
    trusted_preflight_assertions: list[dict] | None,
    now: str,
) -> list[dict]:
    step = plan["steps"][index]
    declarations = _binding_declarations(step)
    supplied = (
        [] if trusted_preflight_assertions is None else trusted_preflight_assertions
    )
    _reject_sensitive(supplied)
    if not isinstance(supplied, list):
        raise AuthorizationPlanStop("PREFLIGHT_BINDING_MISMATCH")
    supplied_ids = [
        assertion.get("binding_id")
        for assertion in supplied
        if isinstance(assertion, dict)
    ]
    if (
        len(supplied_ids) != len(supplied)
        or len(supplied_ids) != len(set(supplied_ids))
    ):
        raise AuthorizationPlanStop("BINDING_ASSERTION_DUPLICATE")
    preflight_declarations = [
        declaration
        for declaration in declarations
        if declaration["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    ]
    if set(supplied_ids) != {
        declaration["binding_id"] for declaration in preflight_declarations
    }:
        raise AuthorizationPlanStop("PREFLIGHT_BINDING_MISMATCH")
    supplied_by_id = {assertion["binding_id"]: assertion for assertion in supplied}
    resolved: list[dict] = []
    for declaration in declarations:
        phase = declaration["phase"]
        if phase == "RESOLVED_BY_STEP_PREFLIGHT":
            assertion = supplied_by_id[declaration["binding_id"]]
            _validate_binding_assertion(assertion, declaration, stop=True)
            if assertion["recorded_at"] != now:
                raise AuthorizationPlanStop("PREFLIGHT_BINDING_MISMATCH")
            resolved.append(copy.deepcopy(assertion))
        elif phase in {"DERIVED_FROM_SOURCE_STEP", "EPHEMERAL_HANDOFF"}:
            evidence, source_assertion = _source_material(
                plan, progress, index, declaration, stop=True
            )
            if source_assertion is None:
                sanitized_value = None
                value_digest = None
            else:
                sanitized_value = copy.deepcopy(source_assertion["sanitized_value"])
                value_digest = source_assertion["value_digest"]
            assertion = {
                "binding_id": declaration["binding_id"],
                "phase": phase,
                "value_class": declaration["value_class"],
                "source_step_id": declaration["source_step_id"],
                "evidence_type": declaration["evidence_type"],
                "evidence_digest": evidence["evidence_digest"],
                "digest_policy": declaration["digest_policy"],
                "persistence_policy": declaration["persistence_policy"],
                "sanitized_value": sanitized_value,
                "value_digest": value_digest,
                "recorded_at": now,
            }
            _validate_binding_assertion(assertion, declaration, stop=True)
            resolved.append(assertion)
    return resolved


def authorize_step(
    plan: dict,
    approval: dict,
    progress: dict,
    request: dict,
    schema_root: Path,
    now: str,
    trusted_preflight_assertions: list[dict] | None = None,
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
    typed = _is_typed_plan(plan)
    if not typed and trusted_preflight_assertions is not None:
        raise AuthorizationPlanStop("PREFLIGHT_SURFACE_INVALID")
    exact_request = {
        "plan_id", "plan_version", "plan_digest", "environment", "provider_reference",
        "project_reference", "responsibility", "issuer_reference", "audience_reference",
        "step_id", "resource_reference",
        "resource_version", "resource_digest", "operation", "execution_class",
        "credential_class", "required_evidence", "prior_evidence_digests",
        "unexpected_remote_state", "extra_privileges",
        "unauthorized_migration_surface", "scope_expansion",
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
    if any(
        item["binding_state"] == "UNRESOLVED_BLOCKER"
        for item in step["required_evidence"]
    ):
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
            source_index = plan["ordered_step_ids"].index(
                requirement["source_step_id"]
            )
            matches = [
                item
                for item in progress["step_states"][source_index]["evidence"]
                if item["evidence_type"] == requirement["evidence_type"]
            ]
            if len(matches) != 1:
                raise AuthorizationPlanStop("REQUIRED_EVIDENCE_MISSING")
            digest = matches[0]["evidence_digest"]
            if (
                requirement["exact_digest"] is not None
                and digest != requirement["exact_digest"]
            ):
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
    resolved_assertions = (
        _typed_authorization_assertions(
            plan, progress, index, trusted_preflight_assertions, now
        )
        if typed
        else None
    )
    updated = copy.deepcopy(progress)
    updated_state = updated["step_states"][index]
    updated_state["authorization_state"] = "AUTHORIZED"
    if typed:
        updated_state["binding_assertions"] = resolved_assertions
    updated["overall_state"] = "IN_PROGRESS"
    updated["record_version"] += 1
    updated["updated_at"] = now
    updated["progress_digest"] = progress_digest(updated)
    validate_progress(plan, updated, schema_root)
    return updated


def _typed_outcome_assertions(
    step: dict,
    evidence: list[dict],
    binding_assertions: list[dict] | None,
    success: bool,
    now: str,
) -> list[dict]:
    _reject_sensitive(evidence)
    assertions = [] if binding_assertions is None else binding_assertions
    _reject_sensitive(assertions)
    if not isinstance(evidence, list) or not isinstance(assertions, list):
        raise AuthorizationPlanStop("BINDING_ASSERTION_MISMATCH")
    declared_evidence = _produced_evidence_declarations(step)
    declared_types = [
        declaration["evidence_type"] for declaration in declared_evidence
    ]
    actual_types = [
        item.get("evidence_type")
        for item in evidence
        if isinstance(item, dict)
    ]
    if len(actual_types) != len(evidence) or len(actual_types) != len(set(actual_types)):
        raise AuthorizationPlanStop("DUPLICATE_OR_MISMATCHED_EVIDENCE")
    undeclared = set(actual_types) - set(declared_types)
    if undeclared:
        raise AuthorizationPlanStop("PRODUCED_EVIDENCE_UNDECLARED")
    if set(actual_types) != set(declared_types):
        raise AuthorizationPlanStop("PRODUCED_EVIDENCE_MISSING")
    for item in evidence:
        digest = item.get("evidence_digest")
        if not isinstance(digest, str) or not _DIGEST_VALUE.fullmatch(digest):
            raise AuthorizationPlanStop("DUPLICATE_OR_MISMATCHED_EVIDENCE")
    if not success:
        if assertions:
            raise AuthorizationPlanStop("BINDING_ASSERTION_MISMATCH")
        return []
    produced = [
        declaration
        for declaration in _binding_declarations(step)
        if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
    ]
    assertion_ids = [
        assertion.get("binding_id")
        for assertion in assertions
        if isinstance(assertion, dict)
    ]
    if (
        len(assertion_ids) != len(assertions)
        or len(assertion_ids) != len(set(assertion_ids))
    ):
        raise AuthorizationPlanStop("BINDING_ASSERTION_DUPLICATE")
    produced_ids = {declaration["binding_id"] for declaration in produced}
    if set(assertion_ids) != produced_ids:
        code = (
            "BINDING_ASSERTION_MISSING"
            if set(assertion_ids) < produced_ids
            else "BINDING_ASSERTION_MISMATCH"
        )
        raise AuthorizationPlanStop(code)
    by_id = {assertion["binding_id"]: assertion for assertion in assertions}
    evidence_by_type = {item["evidence_type"]: item for item in evidence}
    validated = []
    for declaration in produced:
        assertion = by_id[declaration["binding_id"]]
        _validate_binding_assertion(assertion, declaration, stop=True)
        if assertion["recorded_at"] != now:
            raise AuthorizationPlanStop("BINDING_ASSERTION_MISMATCH")
        evidence_declarations = _produced_evidence_matches(
            step, declaration["binding_id"], declaration["evidence_type"]
        )
        matching_evidence = evidence_by_type.get(declaration["evidence_type"])
        if (
            len(evidence_declarations) != 1
            or evidence_declarations[0]["digest_policy"] != "REQUIRED"
            or matching_evidence is None
            or assertion["evidence_digest"] != matching_evidence["evidence_digest"]
        ):
            raise AuthorizationPlanStop("BINDING_ASSERTION_MISMATCH")
        validated.append(copy.deepcopy(assertion))
    return validated

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
    binding_assertions: list[dict] | None = None,
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
    step = plan["steps"][index]
    expected = step["expected_postcondition"]
    success = (
        execution_state == "SUCCEEDED"
        and verification_state == "PASS"
        and observed_postcondition == expected
        and safe_error_code is None
    )
    typed = _is_typed_plan(plan)
    if typed:
        produced_assertions = _typed_outcome_assertions(
            step, evidence, binding_assertions, success, now
        )
    else:
        if binding_assertions is not None:
            raise AuthorizationPlanStop("BINDING_ASSERTION_MISMATCH")
        produced_assertions = []
    updated = copy.deepcopy(progress)
    state = updated["step_states"][index]
    state["execution_state"] = execution_state
    state["verification_state"] = verification_state
    state["authorization_state"] = "CONSUMED"
    state["authorization_consumed"] = True
    state["evidence"] = copy.deepcopy(evidence)
    state["observed_postcondition"] = observed_postcondition
    state["safe_error_code"] = safe_error_code
    if typed:
        state["binding_assertions"].extend(produced_assertions)
    if success:
        updated["overall_state"] = (
            "COMPLETED" if index == len(plan["steps"]) - 1 else "IN_PROGRESS"
        )
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
