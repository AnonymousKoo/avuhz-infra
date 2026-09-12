#!/usr/bin/env python3
"""Certify the provider-neutral typed v8 authorization contract surface."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    approval_digest,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/authorization-plan.cases.json"
LEGACY_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration.plan.json"
LEGACY_PROGRESS_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration.progress.json"
)
V8_PLAN_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v8.plan.json"
)
V8_PROGRESS_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v8.progress.json"
)
V8_APPROVAL_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v8.approval.json"
)

PLAN_SCHEMA_ID = (
    "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan:v1"
)
APPROVAL_SCHEMA_ID = (
    "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-approval:v1"
)
PROGRESS_SCHEMA_ID = (
    "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-progress:v1"
)
SCHEMA_IDS = (PLAN_SCHEMA_ID, APPROVAL_SCHEMA_ID, PROGRESS_SCHEMA_ID)

EXPECTED_PLAN_ID = "a7100000-0000-4000-8000-000000000101"
EXPECTED_PLAN_VERSION = 8
EXPECTED_PLAN_DIGEST = (
    "sha256:f0626b57e55ab2d7c81f47a29b5fc3d1eaf8d7c3e755c08a6ce18f9447aa8b39"
)
EXPECTED_PLAN_FILE_SHA256 = (
    "2a0df0c66c1c118d319f0546edd38e1031c1fcb59cbf6873820b800eda2300a9"
)
EXPECTED_PROGRESS_ID = "a04097ee-b9ac-4a71-bf44-f04d5b0ddc40"
EXPECTED_APPROVAL_ID = "64e98bff-0f2a-4b45-858c-c381189fdb90"
EXPECTED_APPROVAL_DIGEST = (
    "sha256:5c15058a08cf4ff9d343ffaf4afdcb0bc9cfbf88a4fe566e72866c99fb8e9d9b"
)
EXPECTED_APPROVAL_FILE_SHA256 = (
    "8cde9dbbc139ce04ac1d6853c90753869360fe640cf23e1d694a20c0adbd1d5d"
)
EXPECTED_APPROVED_AT = "2026-09-11T20:49:31Z"
EXPECTED_AUTHORIZATION_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-12T14:00:00Z",
    "expires_at": "2026-09-12T16:00:00Z",
}
EXPECTED_TENANT_VALUE = "afca531c-79fd-58e7-a54a-687879f10153"
EXPECTED_TENANT_DIGEST = (
    "sha256:e09d751794dd357aa55ebc326e824c946453255cba78c4432a6c63a72436600b"
)
EXPECTED_DELIVERY_PROCEDURE = (
    "procedure.development.auth.synthetic-ephemeral-token-owner-session.v1"
)
EXPECTED_DELIVERY_PROCEDURE_DIGEST = (
    "sha256:bb73cfa2a0827c26cea668e3a677a817efa16c947f04717885cf2a845878088d"
)
EXPECTED_STEPS = [
    "development.auth.step.01.local-hook-migration",
    "development.auth.step.02.bootstrap-migration-identity",
    "development.auth.step.03.apply-hook-migration",
    "development.auth.step.04.seal-migration-identity",
    "development.auth.step.05.verify-disabled-hook",
    "development.auth.step.06.create-synthetic-identity",
    "development.auth.step.07.bind-synthetic-tenant",
    "development.auth.step.08.bind-server-capability",
    "development.auth.step.09.enable-hook",
    "development.auth.step.10.issue-ephemeral-token",
    "development.auth.step.11.fetch-jwks",
    "development.auth.step.12.validate-token-locally",
    "development.auth.step.13.record-evidence-and-terminate",
]

EXPECTED_PHASES = {
    "PREAPPROVAL_BOUND",
    "DERIVED_FROM_SOURCE_STEP",
    "PRODUCED_BY_CURRENT_STEP",
    "RESOLVED_BY_STEP_PREFLIGHT",
    "EPHEMERAL_HANDOFF",
    "UNRESOLVED_BLOCKER",
}
EXPECTED_VALUE_CLASSES = {
    "STABLE_REFERENCE",
    "UUID_IDENTIFIER",
    "CONTENT_DIGEST",
    "PROCEDURE_REFERENCE",
    "CONFIGURATION_REFERENCE",
    "EPHEMERAL_SENSITIVE",
}
EXPECTED_PREAPPROVAL_VALUE_CLASSES = {
    "STABLE_REFERENCE",
    "UUID_IDENTIFIER",
    "CONTENT_DIGEST",
    "PROCEDURE_REFERENCE",
    "CONFIGURATION_REFERENCE",
}
EXPECTED_DIGEST_POLICIES = {"REQUIRED", "OPTIONAL", "PROHIBITED"}
EXPECTED_PERSISTENCE_POLICIES = {
    "SANITIZED_VALUE_ALLOWED",
    "DIGEST_ONLY",
    "PROHIBITED",
}
LEGACY_POSITIVE_CASES = {
    "exact plan-bound owner approval",
    "ordered one-resource step progression",
    "verified resume from next incomplete boundary",
    "provider-neutral target classes",
}
LEGACY_NEGATIVE_CASES = {
    "plan digest drift",
    "target or operation scope drift",
    "missing or stale evidence",
    "skipped or replayed step",
    "expired approval",
    "failed or ambiguous mutation retry",
    "credential class widening",
    "caller JWT authority injection",
    "secret-bearing state",
}
TYPED_POSITIVE_CASES = {
    "typed v8 fully bound PREAPPROVAL_BOUND approval readiness",
    "typed v8 DERIVED_FROM_SOURCE_STEP from verified earlier source evidence",
    "typed v8 PRODUCED_BY_CURRENT_STEP with declared produced evidence and binding assertion",
    "typed v8 RESOLVED_BY_STEP_PREFLIGHT with trusted provenance",
    "typed v8 EPHEMERAL_HANDOFF with provenance only and no persisted value or value digest",
    "typed v8 sanitized stable reference persistence when declared",
    "typed v8 digest-only persistence when declared",
    "legacy untyped v7 plan and progress compatibility",
}
TYPED_NEGATIVE_CASES = {
    "typed v8 missing PREAPPROVAL_BOUND value",
    "typed v8 UNRESOLVED_BLOCKER at approval",
    "typed v8 malformed runtime binding declaration",
    "typed v8 missing source step",
    "typed v8 future source step",
    "typed v8 source step not SUCCEEDED and PASS",
    "typed v8 missing source evidence",
    "typed v8 duplicate source evidence",
    "typed v8 mismatched source evidence type",
    "typed v8 mismatched source evidence digest",
    "typed v8 undeclared binding assertion",
    "typed v8 arbitrary caller binding injection",
    "typed v8 caller JWT authority injection",
    "typed v8 untrusted preflight provenance",
    "typed v8 undeclared produced evidence",
    "typed v8 missing required produced evidence",
    "typed v8 missing required produced binding assertion",
    "typed v8 duplicate or conflicting produced binding assertion",
    "typed v8 incorrect observed postcondition",
    "typed v8 sanitized value with wrong value class",
    "typed v8 digest-only assertion containing a sanitized value",
    "typed v8 no-persistence assertion containing a value",
    "typed v8 prohibited ephemeral binding-value digest",
    "typed v8 secret-bearing persisted value",
    "typed v8 unknown binding identifier",
    "typed v8 wrong binding phase",
    "typed v8 wrong source provenance",
    "typed v8 skipped or replayed step",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.relative_to(ROOT)}")
    return value


def phase_constraint(definition: dict[str, Any], phase: str) -> dict[str, Any]:
    for rule in definition.get("allOf", []):
        actual = (
            rule.get("if", {})
            .get("properties", {})
            .get("phase", {})
            .get("const")
        )
        if actual == phase:
            return rule.get("then", {}).get("properties", {})
    return {}


def persistence_constraint(
    definition: dict[str, Any], policy: str
) -> dict[str, Any]:
    for rule in definition.get("allOf", []):
        actual = (
            rule.get("if", {})
            .get("properties", {})
            .get("persistence_policy", {})
            .get("const")
        )
        if actual == policy:
            return rule.get("then", {}).get("properties", {})
    return {}


def main() -> int:
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    try:
        registry = SchemaRegistry(SCHEMA_ROOT)
        for schema_id in SCHEMA_IDS:
            schema = registry.resolve(schema_id)
            Draft202012Validator.check_schema(schema)
            registry.expanded(schema_id)
    except Exception as exc:
        failures.append(f"local Draft 2020-12 schema registration failed: {exc}")
        registry = None

    if registry is None:
        plan_schema = {}
        progress_schema = {}
        expanded_plan_schema = {}
    else:
        plan_schema = registry.resolve(PLAN_SCHEMA_ID)
        progress_schema = registry.resolve(PROGRESS_SCHEMA_ID)
        expanded_plan_schema = registry.expanded(PLAN_SCHEMA_ID)

    plan_defs = plan_schema.get("$defs", {})
    progress_defs = progress_schema.get("$defs", {})
    binding = plan_defs.get("bindingDeclaration", {})
    binding_properties = binding.get("properties", {})
    preapproval_value = plan_defs.get("preapprovalValue", {})
    preapproval_value_properties = preapproval_value.get("properties", {})
    produced = plan_defs.get("producedEvidenceDeclaration", {})
    produced_properties = produced.get("properties", {})
    step = plan_defs.get("step", {})
    step_properties = step.get("properties", {})

    require(binding.get("additionalProperties") is False,
            "typed binding declarations must reject extra properties")
    require(
        set(binding.get("required", []))
        == {
            "binding_id", "phase", "value_class", "source_step_id",
            "evidence_type", "digest_policy", "persistence_policy",
        },
        "typed binding declaration fields changed",
    )
    require(
        set(binding_properties)
        == {
            "binding_id", "phase", "value_class", "source_step_id",
            "evidence_type", "digest_policy", "persistence_policy",
            "preapproval_value",
        },
        "typed binding declaration exposes an unexpected field",
    )
    require(
        set(binding_properties.get("phase", {}).get("enum", []))
        == EXPECTED_PHASES,
        "typed binding phase contract changed",
    )
    require(
        set(binding_properties.get("value_class", {}).get("enum", []))
        == EXPECTED_VALUE_CLASSES,
        "typed binding value-class contract changed",
    )
    require(
        set(plan_defs.get("bindingDigestPolicy", {}).get("enum", []))
        == EXPECTED_DIGEST_POLICIES,
        "binding digest-policy contract changed",
    )
    require(
        set(plan_defs.get("bindingPersistencePolicy", {}).get("enum", []))
        == EXPECTED_PERSISTENCE_POLICIES,
        "binding persistence-policy contract changed",
    )
    require("value" not in binding_properties,
            "typed binding declaration exposes a raw value field")
    require("preapproval_value" not in binding.get("required", []),
            "exact preapproval values became mandatory for legacy bindings")
    require(
        binding_properties.get("preapproval_value", {}).get("$ref")
        == "#/$defs/preapprovalValue",
        "typed binding declaration does not use the bounded preapproval value model",
    )
    require(
        preapproval_value.get("type") == "object"
        and preapproval_value.get("additionalProperties") is False
        and set(preapproval_value.get("required", [])) == {"value", "exact_digest"}
        and set(preapproval_value_properties) == {"value", "exact_digest"},
        "exact preapproval value model is not a closed two-field object",
    )
    preapproval_scalar = preapproval_value_properties.get("value", {})
    require(
        preapproval_scalar.get("type") == "string"
        and preapproval_scalar.get("minLength") == 3
        and preapproval_scalar.get("maxLength") == 160
        and "non-secret" in preapproval_scalar.get("description", "").lower(),
        "exact preapproval value is not a bounded non-secret scalar",
    )
    require(
        preapproval_value_properties.get("exact_digest", {}).get("$ref")
        == "#/$defs/digest"
        and plan_defs.get("digest", {}).get("pattern")
        == "^sha256:[0-9a-f]{64}$",
        "exact preapproval digest is not required to use canonical sha256 format",
    )
    preapproval_dependency = (
        binding.get("dependentSchemas", {}).get("preapproval_value", {})
    )
    preapproval_dependency_properties = preapproval_dependency.get("properties", {})
    require(
        set(preapproval_dependency.get("required", []))
        == {"phase", "value_class", "digest_policy"}
        and preapproval_dependency_properties.get("phase", {}).get("const")
        == "PREAPPROVAL_BOUND"
        and set(
            preapproval_dependency_properties.get("value_class", {}).get("enum", [])
        ) == EXPECTED_PREAPPROVAL_VALUE_CLASSES
        and preapproval_dependency_properties.get("digest_policy", {}).get("const")
        == "REQUIRED",
        "exact preapproval value phase, class, or digest-policy restriction changed",
    )

    value_class_constraints: dict[str, dict[str, Any]] = {}
    for rule in binding.get("allOf", []):
        condition = rule.get("if", {})
        required = set(condition.get("required", []))
        value_class_condition = condition.get("properties", {}).get("value_class", {})
        if "preapproval_value" not in required:
            continue
        constrained_classes = value_class_condition.get("enum", [])
        if "const" in value_class_condition:
            constrained_classes = [value_class_condition["const"]]
        value_rule = (
            rule.get("then", {}).get("properties", {})
            .get("preapproval_value", {}).get("properties", {}).get("value", {})
        )
        for value_class in constrained_classes:
            value_class_constraints[value_class] = value_rule
    require(
        value_class_constraints.get("UUID_IDENTIFIER", {}).get("$ref")
        == "urn:avuhz:schema:contracts:common:identifiers:v1#/$defs/canonicalUuid",
        "canonical UUID preapproval values are not structurally constrained",
    )
    require(
        all(
            value_class_constraints.get(value_class, {}).get("$ref")
            == "#/$defs/reference"
            for value_class in {
                "STABLE_REFERENCE", "PROCEDURE_REFERENCE", "CONFIGURATION_REFERENCE"
            }
        ),
        "symbolic preapproval references are not structurally bounded",
    )
    require(
        value_class_constraints.get("CONTENT_DIGEST", {}).get("$ref")
        == "#/$defs/digest",
        "content-digest preapproval values are not structurally constrained",
    )

    preapproval = phase_constraint(binding, "PREAPPROVAL_BOUND")
    derived = phase_constraint(binding, "DERIVED_FROM_SOURCE_STEP")
    current = phase_constraint(binding, "PRODUCED_BY_CURRENT_STEP")
    preflight = phase_constraint(binding, "RESOLVED_BY_STEP_PREFLIGHT")
    ephemeral = phase_constraint(binding, "EPHEMERAL_HANDOFF")
    unresolved = phase_constraint(binding, "UNRESOLVED_BLOCKER")
    require(preapproval.get("source_step_id", {}).get("type") == "null",
            "preapproval binding may claim future source provenance")
    require(
        derived.get("source_step_id", {}).get("$ref") == "#/$defs/reference"
        and derived.get("evidence_type", {}).get("$ref") == "#/$defs/reference",
        "derived binding provenance contract is incomplete",
    )
    require(
        current.get("source_step_id", {}).get("type") == "null"
        and current.get("evidence_type", {}).get("$ref") == "#/$defs/reference",
        "current-step produced binding contract is incomplete",
    )
    require(
        preflight.get("source_step_id", {}).get("type") == "null"
        and preflight.get("evidence_type", {}).get("$ref") == "#/$defs/reference",
        "trusted preflight binding contract is incomplete",
    )
    require(
        ephemeral.get("value_class", {}).get("const") == "EPHEMERAL_SENSITIVE"
        and ephemeral.get("digest_policy", {}).get("const") == "PROHIBITED"
        and ephemeral.get("persistence_policy", {}).get("const") == "PROHIBITED",
        "ephemeral binding non-persistence contract is incomplete",
    )
    require(
        unresolved.get("digest_policy", {}).get("const") == "PROHIBITED"
        and unresolved.get("persistence_policy", {}).get("const") == "PROHIBITED",
        "unresolved binding does not remain fail closed",
    )

    expanded_binding = (
        expanded_plan_schema.get("$defs", {}).get("bindingDeclaration", {})
    )
    binding_validator = Draft202012Validator(expanded_binding)

    def binding_is_valid(candidate: dict[str, Any]) -> bool:
        return not list(binding_validator.iter_errors(candidate))

    exact_digest = "sha256:" + ("a" * 64)
    uuid_binding = {
        "binding_id": "binding.fictional.tenant",
        "phase": "PREAPPROVAL_BOUND",
        "value_class": "UUID_IDENTIFIER",
        "source_step_id": None,
        "evidence_type": None,
        "digest_policy": "REQUIRED",
        "persistence_policy": "SANITIZED_VALUE_ALLOWED",
        "preapproval_value": {
            "value": "00000000-0000-4000-8000-000000000001",
            "exact_digest": exact_digest,
        },
    }
    reference_binding = {
        **uuid_binding,
        "binding_id": "binding.fictional.procedure",
        "value_class": "PROCEDURE_REFERENCE",
        "preapproval_value": {
            "value": "procedure.fictional.auth.owner-session.v1",
            "exact_digest": exact_digest,
        },
    }
    require(binding_is_valid(uuid_binding),
            "canonical UUID preapproval contract case is rejected")
    require(binding_is_valid(reference_binding),
            "bounded reference preapproval contract case is rejected")

    runtime_cases = {
        "DERIVED_FROM_SOURCE_STEP": {
            "value_class": "STABLE_REFERENCE",
            "source_step_id": "step.fictional.source",
            "evidence_type": "evidence.fictional.source",
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
        },
        "PRODUCED_BY_CURRENT_STEP": {
            "value_class": "STABLE_REFERENCE",
            "source_step_id": None,
            "evidence_type": "evidence.fictional.produced",
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
        },
        "RESOLVED_BY_STEP_PREFLIGHT": {
            "value_class": "STABLE_REFERENCE",
            "source_step_id": None,
            "evidence_type": "evidence.fictional.preflight",
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
        },
        "EPHEMERAL_HANDOFF": {
            "value_class": "EPHEMERAL_SENSITIVE",
            "source_step_id": "step.fictional.source",
            "evidence_type": "evidence.fictional.handoff",
            "digest_policy": "PROHIBITED",
            "persistence_policy": "PROHIBITED",
        },
        "UNRESOLVED_BLOCKER": {
            "value_class": "STABLE_REFERENCE",
            "source_step_id": None,
            "evidence_type": None,
            "digest_policy": "PROHIBITED",
            "persistence_policy": "PROHIBITED",
        },
    }
    invalid_bindings: list[tuple[str, dict[str, Any]]] = []
    for phase, fields in runtime_cases.items():
        invalid_bindings.append(
            (
                f"{phase} binding carrying preapproval_value",
                {
                    "binding_id": "binding.fictional.runtime",
                    "phase": phase,
                    **fields,
                    "preapproval_value": {
                        "value": "reference.fictional.runtime",
                        "exact_digest": exact_digest,
                    },
                },
            )
        )
    invalid_bindings.extend(
        [
            (
                "preapproval value missing exact digest",
                {**reference_binding, "preapproval_value": {"value": "reference.fictional"}},
            ),
            (
                "preapproval value with malformed digest",
                {
                    **reference_binding,
                    "preapproval_value": {
                        "value": "reference.fictional",
                        "exact_digest": "sha256:not-a-digest",
                    },
                },
            ),
            (
                "preapproval value with arbitrary object payload",
                {
                    **reference_binding,
                    "preapproval_value": {
                        "value": {"unexpected": "object"},
                        "exact_digest": exact_digest,
                    },
                },
            ),
            (
                "preapproval value with ephemeral value class",
                {**reference_binding, "value_class": "EPHEMERAL_SENSITIVE"},
            ),
            (
                "preapproval value with unexpected property",
                {
                    **reference_binding,
                    "preapproval_value": {
                        **reference_binding["preapproval_value"],
                        "unexpected": "field",
                    },
                },
            ),
            (
                "preapproval value with prohibited digest policy",
                {**reference_binding, "digest_policy": "PROHIBITED"},
            ),
        ]
    )
    for label, candidate in invalid_bindings:
        require(not binding_is_valid(candidate), f"validator accepted {label}")

    require(produced.get("additionalProperties") is False,
            "produced evidence declarations must reject extra properties")
    require(
        set(produced.get("required", []))
        == {"evidence_type", "established_binding_ids", "digest_policy"},
        "produced evidence declaration fields changed",
    )
    require(
        set(produced_properties)
        == {"evidence_type", "established_binding_ids", "digest_policy"},
        "produced evidence declaration exposes an unexpected field",
    )
    require(
        produced_properties.get("established_binding_ids", {})
        .get("uniqueItems") is True,
        "produced evidence binding identifiers must be unique",
    )
    require(
        set(produced_properties.get("digest_policy", {}).get("enum", []))
        == {"REQUIRED", "OPTIONAL"},
        "produced evidence digest policy changed",
    )
    require("binding_declarations" not in step.get("required", []),
            "typed binding declarations became mandatory for legacy plans")
    require("produced_evidence" not in step.get("required", []),
            "produced evidence declarations became mandatory for legacy plans")
    require(
        step_properties.get("binding_declarations", {}).get("items", {}).get("$ref")
        == "#/$defs/bindingDeclaration",
        "step typed binding declaration surface is missing",
    )
    require(
        step_properties.get("produced_evidence", {}).get("items", {}).get("$ref")
        == "#/$defs/producedEvidenceDeclaration",
        "step produced evidence declaration surface is missing",
    )

    resource_states = set(
        plan_defs.get("resource", {}).get("properties", {})
        .get("binding_state", {}).get("enum", [])
    )
    require(
        {"BOUND", "UNRESOLVED_BLOCKER"} <= resource_states,
        "legacy resource binding-state contract changed",
    )

    assertion = progress_defs.get("bindingAssertion", {})
    assertion_properties = assertion.get("properties", {})
    assertion_required = {
        "binding_id", "phase", "value_class", "source_step_id",
        "evidence_type", "evidence_digest", "digest_policy",
        "persistence_policy", "sanitized_value", "value_digest", "recorded_at",
    }
    require(assertion.get("additionalProperties") is False,
            "typed progress assertions must reject extra properties")
    require(set(assertion.get("required", [])) == assertion_required,
            "typed progress assertion fields changed")
    require(set(assertion_properties) == assertion_required,
            "typed progress assertion exposes an unexpected field")
    require(
        set(assertion_properties.get("phase", {}).get("enum", []))
        == EXPECTED_PHASES,
        "progress assertion phase contract differs from plan contract",
    )
    require(
        set(assertion_properties.get("value_class", {}).get("enum", []))
        == EXPECTED_VALUE_CLASSES,
        "progress assertion value classes differ from plan contract",
    )
    require(
        set(assertion_properties.get("digest_policy", {}).get("enum", []))
        == EXPECTED_DIGEST_POLICIES,
        "progress assertion digest policies differ from plan contract",
    )
    require(
        set(assertion_properties.get("persistence_policy", {}).get("enum", []))
        == EXPECTED_PERSISTENCE_POLICIES,
        "progress assertion persistence policies differ from plan contract",
    )
    require("value" not in assertion_properties and "payload" not in assertion_properties,
            "progress assertion exposes an unrestricted value or payload field")
    sanitized_forms = assertion_properties.get("sanitized_value", {}).get("oneOf", [])
    sanitized_string = next(
        (item for item in sanitized_forms if item.get("type") == "string"), {}
    )
    require(
        sanitized_string.get("maxLength") == 160
        and any(item.get("type") == "null" for item in sanitized_forms),
        "sanitized progress value is not a bounded scalar-or-null surface",
    )

    step_state = progress_defs.get("stepState", {})
    assertion_list = step_state.get("properties", {}).get("binding_assertions", {})
    require("binding_assertions" not in step_state.get("required", []),
            "typed assertions became mandatory for legacy progress")
    require(
        assertion_list.get("type") == "array"
        and assertion_list.get("uniqueItems") is True
        and assertion_list.get("items", {}).get("$ref")
        == "#/$defs/bindingAssertion",
        "typed progress assertion collection is not bounded and unique",
    )

    progress_ephemeral = phase_constraint(assertion, "EPHEMERAL_HANDOFF")
    no_persistence = persistence_constraint(assertion, "PROHIBITED")
    require(
        progress_ephemeral.get("sanitized_value", {}).get("type") == "null"
        and progress_ephemeral.get("value_digest", {}).get("type") == "null"
        and progress_ephemeral.get("digest_policy", {}).get("const")
        == "PROHIBITED"
        and progress_ephemeral.get("persistence_policy", {}).get("const")
        == "PROHIBITED",
        "ephemeral progress assertion may persist value material",
    )
    require(
        no_persistence.get("sanitized_value", {}).get("type") == "null"
        and no_persistence.get("value_digest", {}).get("type") == "null",
        "no-persistence policy permits value or binding-value digest retention",
    )

    sensitive_property_names = {
        "access_token", "refresh_token", "password", "api_key",
        "service_role_key", "private_key", "authorization_header",
        "authenticated_connection_string", "raw_provider_payload", "jwt",
        "credential_value", "provider_payload",
    }
    typed_property_names = (
        set(binding_properties)
        | set(preapproval_value_properties)
        | set(produced_properties)
        | set(assertion_properties)
    )
    require(
        sensitive_property_names.isdisjoint(typed_property_names),
        "typed contract exposes a credential or raw-provider storage field",
    )

    try:
        require(V8_PLAN_PATH.is_file(), "immutable v8 plan file is missing")
        require(V8_PROGRESS_PATH.is_file(), "initial v8 progress file is missing")
        require(V8_APPROVAL_PATH.is_file(), "exact v8 approval file is missing")
        actual_plan = load_json(V8_PLAN_PATH)
        actual_progress = load_json(V8_PROGRESS_PATH)
        actual_approval = load_json(V8_APPROVAL_PATH)
        progress_snapshot = json.loads(json.dumps(actual_progress))

        require(
            hashlib.sha256(V8_PLAN_PATH.read_bytes()).hexdigest()
            == EXPECTED_PLAN_FILE_SHA256,
            "immutable v8 plan file bytes changed",
        )
        require(actual_plan.get("plan_id") == EXPECTED_PLAN_ID,
                "immutable v8 plan identifier changed")
        require(actual_plan.get("plan_version") == EXPECTED_PLAN_VERSION,
                "immutable v8 plan version changed")
        require(actual_plan.get("plan_digest") == EXPECTED_PLAN_DIGEST,
                "immutable v8 stored plan digest changed")
        require(actual_plan.get("plan_digest") == plan_digest(actual_plan),
                "immutable v8 plan canonical digest mismatch")
        require(actual_plan.get("definition_status") == "READY_FOR_APPROVAL",
                "immutable v8 plan is not ready for approval")
        require(actual_plan.get("environment") == "DEVELOPMENT",
                "immutable v8 plan environment changed")
        require(actual_plan.get("owner_identity") == "github:AnonymousKoo",
                "immutable v8 plan owner changed")
        require(
            actual_plan.get("authority_effect")
            == "NONE_UNTIL_SEPARATELY_APPROVED",
            "immutable v8 plan grants authority before separate approval",
        )
        require(
            actual_plan.get("target")
            == {
                "provider_class": "identity.provider",
                "provider_reference": "supabase",
                "project_reference": "pwlhruwutoitnieactol",
                "responsibility": "AUTH",
                "issuer_reference":
                    "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
                "audience_reference":
                    "audience.avuhz.command-service.development",
            },
            "immutable v8 AUTH target namespace changed or includes DATA",
        )
        require(
            actual_plan.get("authorization_window")
            == EXPECTED_AUTHORIZATION_WINDOW,
            "immutable v8 authorization window changed",
        )
        approval_candidates = set(
            V8_PLAN_PATH.parent.glob(
                "development-auth-integration-v8*approval*.json"
            )
        )
        require(
            approval_candidates == {V8_APPROVAL_PATH},
            "v8 approval artifact set differs from the exact authorized record",
        )
        require(
            hashlib.sha256(V8_APPROVAL_PATH.read_bytes()).hexdigest()
            == EXPECTED_APPROVAL_FILE_SHA256,
            "exact v8 approval file bytes changed",
        )
        require(
            actual_approval
            == {
                "approval_id": EXPECTED_APPROVAL_ID,
                "plan_id": EXPECTED_PLAN_ID,
                "plan_version": EXPECTED_PLAN_VERSION,
                "plan_digest": EXPECTED_PLAN_DIGEST,
                "owner_identity": "github:AnonymousKoo",
                "decision": "APPROVE",
                "environment": "DEVELOPMENT",
                "effective_at": EXPECTED_AUTHORIZATION_WINDOW["starts_at"],
                "expires_at": EXPECTED_AUTHORIZATION_WINDOW["expires_at"],
                "approved_at": EXPECTED_APPROVED_AT,
                "status": "ACTIVE",
                "authority_scope": "EXACT_PLAN_ONLY",
                "approval_digest": EXPECTED_APPROVAL_DIGEST,
            },
            "exact v8 approval semantics changed",
        )
        require(
            actual_approval.get("approval_digest")
            == approval_digest(actual_approval)
            == EXPECTED_APPROVAL_DIGEST,
            "exact v8 approval canonical digest mismatch",
        )
        require(
            actual_approval.get("plan_id") == actual_plan.get("plan_id")
            and actual_approval.get("plan_version")
            == actual_plan.get("plan_version")
            and actual_approval.get("plan_digest")
            == actual_plan.get("plan_digest")
            and actual_approval.get("owner_identity")
            == actual_plan.get("owner_identity")
            and actual_approval.get("environment")
            == actual_plan.get("environment")
            and actual_approval.get("effective_at")
            == actual_plan.get("authorization_window", {}).get("starts_at")
            and actual_approval.get("expires_at")
            == actual_plan.get("authorization_window", {}).get("expires_at"),
            "exact v8 approval is not bound to the loaded immutable plan",
        )
        actual_steps = actual_plan.get("steps", [])
        require(actual_plan.get("ordered_step_ids") == EXPECTED_STEPS,
                "immutable v8 ordered step identifiers changed")
        require(
            [step.get("step_id") for step in actual_steps] == EXPECTED_STEPS,
            "immutable v8 step order changed",
        )
        require(len(actual_steps) == 13,
                "immutable v8 plan must contain exactly 13 steps")

        declarations = [
            declaration
            for step in actual_steps
            for declaration in step.get("binding_declarations", [])
        ]

        def exact_binding(
            binding_id: str, phase: str | None = None
        ) -> dict[str, Any]:
            matches = [
                declaration
                for declaration in declarations
                if declaration.get("binding_id") == binding_id
                and (phase is None or declaration.get("phase") == phase)
            ]
            require(len(matches) == 1,
                    f"immutable v8 binding count mismatch: {binding_id}")
            return matches[0] if len(matches) == 1 else {}

        tenant_binding = exact_binding(
            "binding.development.auth.synthetic-tenant",
            "PREAPPROVAL_BOUND",
        )
        tenant_value = tenant_binding.get("preapproval_value", {})
        require(
            tenant_binding.get("value_class") == "UUID_IDENTIFIER"
            and tenant_value.get("value") == EXPECTED_TENANT_VALUE
            and tenant_value.get("exact_digest") == EXPECTED_TENANT_DIGEST
            and canonical_digest(tenant_value.get("value"))
            == EXPECTED_TENANT_DIGEST,
            "immutable v8 tenant preapproval binding changed",
        )
        procedure_binding = exact_binding(
            "binding.development.auth.credential-delivery-procedure",
            "PREAPPROVAL_BOUND",
        )
        procedure_value = procedure_binding.get("preapproval_value", {})
        require(
            procedure_binding.get("value_class") == "PROCEDURE_REFERENCE"
            and procedure_value.get("value") == EXPECTED_DELIVERY_PROCEDURE
            and procedure_value.get("exact_digest")
            == EXPECTED_DELIVERY_PROCEDURE_DIGEST
            and canonical_digest(procedure_value.get("value"))
            == EXPECTED_DELIVERY_PROCEDURE_DIGEST,
            "immutable v8 credential-delivery preapproval binding changed",
        )

        step_by_id = {step["step_id"]: step for step in actual_steps}
        step2_declarations = step_by_id.get(EXPECTED_STEPS[1], {}).get(
            "binding_declarations", []
        )
        require(
            any(
                declaration.get("binding_id")
                == "binding.development.auth.executor-preflight"
                and declaration.get("phase") == "RESOLVED_BY_STEP_PREFLIGHT"
                and declaration.get("evidence_type")
                == "provider.executor.preflight.observed"
                for declaration in step2_declarations
            ),
            "immutable v8 Step 2 fresh trusted preflight binding is missing",
        )
        subject_binding = exact_binding(
            "binding.development.auth.synthetic-subject",
            "PRODUCED_BY_CURRENT_STEP",
        )
        require(
            subject_binding.get("evidence_type") == "synthetic.identity.created",
            "provider-created synthetic subject was preinvented",
        )
        ephemeral_binding = exact_binding(
            "binding.development.auth.ephemeral-token-handoff",
            "EPHEMERAL_HANDOFF",
        )
        require(
            ephemeral_binding.get("value_class") == "EPHEMERAL_SENSITIVE"
            and ephemeral_binding.get("digest_policy") == "PROHIBITED"
            and ephemeral_binding.get("persistence_policy") == "PROHIBITED"
            and "preapproval_value" not in ephemeral_binding,
            "ephemeral token handoff permits persisted or preinvented material",
        )
        require(
            all(
                "preapproval_value" not in declaration
                for declaration in declarations
                if declaration.get("phase") != "PREAPPROVAL_BOUND"
            ),
            "runtime-derived binding contains preapproval authority",
        )
        require(
            {
                declaration.get("binding_id")
                for declaration in declarations
                if "preapproval_value" in declaration
            }
            == {
                "binding.development.auth.synthetic-tenant",
                "binding.development.auth.credential-delivery-procedure",
            },
            "immutable v8 plan contains an unexpected exact preapproval value",
        )
        require(
            all(
                not step.get("unresolved_bindings")
                and step.get("resource", {}).get("binding_state") == "BOUND"
                for step in actual_steps
            )
            and not any(
                declaration.get("phase") == "UNRESOLVED_BLOCKER"
                for declaration in declarations
            ),
            "immutable v8 plan retains a false runtime blocker",
        )

        require(actual_progress.get("progress_id") == EXPECTED_PROGRESS_ID,
                "initial v8 progress identifier changed")
        require(actual_progress.get("plan_id") == actual_plan.get("plan_id"),
                "initial v8 progress plan identifier mismatch")
        require(
            actual_progress.get("plan_version")
            == actual_plan.get("plan_version"),
            "initial v8 progress plan version mismatch",
        )
        require(
            actual_progress.get("plan_digest") == actual_plan.get("plan_digest"),
            "initial v8 progress plan digest mismatch",
        )
        require(
            actual_progress.get("progress_digest")
            == progress_digest(actual_progress),
            "initial v8 progress canonical digest mismatch",
        )
        require(actual_progress.get("overall_state") == "NOT_STARTED",
                "initial v8 progress is not pristine")
        step_states = actual_progress.get("step_states", [])
        require(len(step_states) == 13,
                "initial v8 progress must contain exactly 13 step states")
        require(
            [state.get("step_id") for state in step_states] == EXPECTED_STEPS,
            "initial v8 progress step order changed",
        )
        require(
            all(
                state.get("authorization_state") == "PENDING"
                and state.get("execution_state") == "NOT_STARTED"
                and state.get("verification_state") == "NOT_STARTED"
                and state.get("authorization_consumed") is False
                and state.get("evidence") == []
                and state.get("binding_assertions") == []
                and state.get("observed_postcondition") is None
                and state.get("safe_error_code") is None
                for state in step_states
            ),
            "initial v8 progress contains authority, execution, or runtime state",
        )
        validate_approval(
            actual_plan,
            actual_approval,
            SCHEMA_ROOT,
            EXPECTED_AUTHORIZATION_WINDOW["starts_at"],
        )
        try:
            validate_approval(
                actual_plan,
                actual_approval,
                SCHEMA_ROOT,
                EXPECTED_APPROVED_AT,
            )
        except AuthorizationPlanStop:
            pass
        else:
            require(False, "exact v8 approval permits pre-window authority")
        require(
            actual_progress == progress_snapshot,
            "approval certification mutated initial v8 progress",
        )
        require(
            step_states
            and step_states[0].get("authorization_state") == "PENDING"
            and step_states[0].get("execution_state") == "NOT_STARTED"
            and step_states[0].get("authorization_consumed") is False,
            "exact owner approval alone authorizes or executes Step 1",
        )

        def property_names(value: Any) -> set[str]:
            if isinstance(value, dict):
                names = {str(key).lower() for key in value}
                for child in value.values():
                    names.update(property_names(child))
                return names
            if isinstance(value, list):
                names: set[str] = set()
                for child in value:
                    names.update(property_names(child))
                return names
            return set()

        instance_sensitive_names = sensitive_property_names | {
            "customer_pii", "customer_email", "customer_phone",
        }
        require(
            instance_sensitive_names.isdisjoint(property_names(actual_plan)),
            "immutable v8 plan contains a prohibited secret or PII field",
        )
        require(
            instance_sensitive_names.isdisjoint(property_names(actual_progress)),
            "initial v8 progress contains a prohibited secret or PII field",
        )
        require(
            instance_sensitive_names.isdisjoint(property_names(actual_approval)),
            "exact v8 approval contains a prohibited secret or PII field",
        )

        if registry is not None:
            plan_errors = list(
                Draft202012Validator(registry.expanded(PLAN_SCHEMA_ID))
                .iter_errors(actual_plan)
            )
            progress_errors = list(
                Draft202012Validator(registry.expanded(PROGRESS_SCHEMA_ID))
                .iter_errors(actual_progress)
            )
            approval_errors = list(
                Draft202012Validator(registry.expanded(APPROVAL_SCHEMA_ID))
                .iter_errors(actual_approval)
            )
            require(not plan_errors,
                    "immutable v8 plan fails its Draft 2020-12 schema")
            require(not progress_errors,
                    "initial v8 progress fails its Draft 2020-12 schema")
            require(not approval_errors,
                    "exact v8 approval fails its Draft 2020-12 schema")
        validate_plan(actual_plan, SCHEMA_ROOT)
        validate_progress(actual_plan, actual_progress, SCHEMA_ROOT)
    except Exception as exc:
        failures.append(f"actual v8 plan/progress certification failed: {exc}")

    try:
        fixtures = load_json(FIXTURE_PATH)
        positive = fixtures.get("positive", [])
        negative = fixtures.get("negative", [])
        require(fixtures.get("fixture_set") == "bounded-authorization-plan-v1",
                "authorization fixture-set identity changed")
        require(fixtures.get("fictional_only") is True,
                "authorization fixtures are not explicitly fictional")
        require(isinstance(positive, list) and len(positive) == len(set(positive)),
                "positive fixture cases must be a unique list")
        require(isinstance(negative, list) and len(negative) == len(set(negative)),
                "negative fixture cases must be a unique list")
        require(LEGACY_POSITIVE_CASES <= set(positive),
                "legacy positive authorization fixture cases changed")
        require(LEGACY_NEGATIVE_CASES <= set(negative),
                "legacy negative authorization fixture cases changed")
        require(TYPED_POSITIVE_CASES <= set(positive),
                "typed v8 positive fixture matrix is incomplete")
        require(TYPED_NEGATIVE_CASES <= set(negative),
                "typed v8 negative fixture matrix is incomplete")
        require(
            set(positive) == LEGACY_POSITIVE_CASES | TYPED_POSITIVE_CASES,
            "positive authorization fixture matrix has unexpected cases",
        )
        require(
            set(negative) == LEGACY_NEGATIVE_CASES | TYPED_NEGATIVE_CASES,
            "negative authorization fixture matrix has unexpected cases",
        )
    except Exception as exc:
        failures.append(f"authorization fixture validation failed: {exc}")

    if registry is not None:
        try:
            legacy_plan = load_json(LEGACY_PLAN_PATH)
            legacy_progress = load_json(LEGACY_PROGRESS_PATH)
            plan_errors = list(
                Draft202012Validator(registry.expanded(PLAN_SCHEMA_ID))
                .iter_errors(legacy_plan)
            )
            progress_errors = list(
                Draft202012Validator(registry.expanded(PROGRESS_SCHEMA_ID))
                .iter_errors(legacy_progress)
            )
            require(not plan_errors,
                    "typed additions reject the canonical legacy v7 plan")
            require(not progress_errors,
                    "typed additions reject the canonical legacy v7 progress")
        except Exception as exc:
            failures.append(f"legacy v7 schema compatibility check failed: {exc}")

    if failures:
        for failure in failures:
            print(
                f"DEVELOPMENT_AUTH_V8_CONTRACT_CERTIFICATION=FAIL: {failure}",
                file=sys.stderr,
            )
        return 1

    print("DEVELOPMENT_AUTH_V8_CONTRACT_CERTIFICATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
