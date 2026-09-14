#!/usr/bin/env python3
"""Certify the DEVELOPMENT-only Supabase Auth-admin ephemeral credential model."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_SCHEMA_PATH = (
    ROOT
    / "contracts/schemas/v1/orchestration/bounded-authorization-plan-v2.schema.json"
)
V20_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.plan.json"
V20_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.progress.json"
BASELINE_PATH = ROOT / "scripts/check-baseline.sh"

CREDENTIAL_CLASS = "SUPABASE_AUTH_ADMIN_EPHEMERAL"
CAPABILITY_EVIDENCE = "auth.admin-executor-capability.observed"
HANDLING = {
    "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",
    "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",
    "control_plane_visibility": "CLASS_LABEL_ONLY",
    "material_digest": "PROHIBITED",
    "persistence": "PROHIBITED",
    "logging": "PROHIBITED",
    "return_policy": "PROHIBITED",
    "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",
}
REQUIRED_PROHIBITIONS = {
    "credential.persist",
    "credential.expose",
    "credential.log",
    "credential.return",
    "credential.digest",
    "credential.copy",
    "credential.create",
    "credential.rotate",
    "credential.export",
}
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
PLAN_ID = "a7210000-0000-4000-8000-000000000001"
APPROVAL_ID = "a7210000-0000-4000-8000-000000000002"
PROGRESS_ID = "a7210000-0000-4000-8000-000000000003"
NOW = "2030-01-15T15:15:00Z"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def credential_policy() -> dict:
    return {
        "permitted": True,
        "allowed_classes": [CREDENTIAL_CLASS],
        "values_stored": False,
        "ephemeral_handling": copy.deepcopy(HANDLING),
    }


def plan() -> dict:
    prohibited = sorted(REQUIRED_PROHIBITIONS | {"scope.widen", "environment.change"})
    value = {
        "plan_id": PLAN_ID,
        "plan_version": 21,
        "plan_digest": DIGEST_A,
        "definition_status": "READY_FOR_APPROVAL",
        "environment": "DEVELOPMENT",
        "target": {
            "provider_class": "identity.provider",
            "provider_reference": "supabase",
            "project_reference": "project.fictional.auth-development",
            "responsibility": "AUTH",
            "issuer_reference": "https://auth.example.invalid/issuer",
            "audience_reference": "audience.fictional.command-service",
        },
        "owner_identity": "owner.fictional",
        "created_at": "2030-01-15T14:00:00Z",
        "authorization_window": {
            "binding_state": "BOUND",
            "starts_at": "2030-01-15T15:00:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
        },
        "ordered_step_ids": ["plan.step.01"],
        "steps": [{
            "step_id": "plan.step.01",
            "ordinal": 1,
            "resource": {
                "resource_type": "auth.synthetic-identity",
                "resource_reference": "identity.fictional.synthetic",
                "binding_state": "BOUND",
                "exact_version": "version.1",
                "exact_digest": None,
            },
            "operation": "provider.auth-identity.create-one",
            "dependency_step_ids": [],
            "required_evidence": [{
                "evidence_type": "auth.prerequisite.verified",
                "source_step_id": None,
                "binding_state": "BOUND",
                "exact_digest": DIGEST_A,
            }],
            "expected_postcondition": "one fictional passwordless auth identity exists",
            "prohibited_actions": prohibited,
            "stop_conditions": [
                "target.mismatch",
                "capability.attestation.missing",
                "outcome.ambiguous",
            ],
            "correction_reference": "correction.stop-for-owner-review",
            "execution_class": "PROVIDER_MUTATION",
            "credential_policy": credential_policy(),
            "binding_declarations": [{
                "binding_id": "binding.auth-admin.executor-capability",
                "phase": "RESOLVED_BY_STEP_PREFLIGHT",
                "value_class": "CONFIGURATION_REFERENCE",
                "source_step_id": None,
                "evidence_type": CAPABILITY_EVIDENCE,
                "digest_policy": "REQUIRED",
                "persistence_policy": "DIGEST_ONLY",
            }],
            "produced_evidence": [],
            "unresolved_bindings": [],
        }],
        "prohibited_actions": prohibited,
        "stop_conditions": [
            "scope.drift",
            "target.drift",
            "evidence.missing",
            "outcome.ambiguous",
        ],
        "authority_effect": "NONE_UNTIL_SEPARATELY_APPROVED",
    }
    value["plan_digest"] = plan_digest(value)
    return value


def approval(value: dict) -> dict:
    result = {
        "approval_id": APPROVAL_ID,
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "approval_digest": DIGEST_B,
        "owner_identity": value["owner_identity"],
        "decision": "APPROVE",
        "environment": value["environment"],
        "effective_at": value["authorization_window"]["starts_at"],
        "expires_at": value["authorization_window"]["expires_at"],
        "approved_at": "2030-01-15T14:55:00Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
    }
    result["approval_digest"] = approval_digest(result)
    return result


def request(value: dict) -> dict:
    step = value["steps"][0]
    return {
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "environment": value["environment"],
        "provider_reference": value["target"]["provider_reference"],
        "project_reference": value["target"]["project_reference"],
        "responsibility": value["target"]["responsibility"],
        "issuer_reference": value["target"]["issuer_reference"],
        "audience_reference": value["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": CREDENTIAL_CLASS,
        "required_evidence": [{
            "evidence_type": "auth.prerequisite.verified",
            "evidence_digest": DIGEST_A,
        }],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def capability_assertion() -> dict:
    return {
        "binding_id": "binding.auth-admin.executor-capability",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": CAPABILITY_EVIDENCE,
        "evidence_digest": DIGEST_B,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": canonical_digest("executor.fictional.auth-admin-capable"),
        "recorded_at": NOW,
    }


def expect_plan_failure(value: dict, expected: str) -> None:
    value["plan_digest"] = plan_digest(value)
    try:
        validate_plan(value, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == expected, (expected, str(exc))
    else:
        raise AssertionError(f"expected {expected}")


def main() -> int:
    schema = load(PLAN_SCHEMA_PATH)
    classes = (
        schema["$defs"]["credentialPolicy"]["properties"]
        ["allowed_classes"]["items"]["enum"]
    )
    assert classes == [
        "NONE",
        "OWNER_INTERACTIVE_SESSION",
        "MIGRATION_IDENTITY",
        "SYNTHETIC_IDENTITY",
        "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN",
        CREDENTIAL_CLASS,
    ]
    assert "SERVICE_ROLE" not in classes
    assert "SERVER_ADMIN_CREDENTIAL" not in classes

    handling = schema["$defs"]["authAdminEphemeralHandling"]
    assert set(handling["required"]) == set(HANDLING)
    for key, expected in HANDLING.items():
        assert handling["properties"][key]["const"] == expected

    value = plan()
    validate_plan(value, SCHEMA_ROOT)

    owner = approval(value)
    progress = initial_progress(value, SCHEMA_ROOT, PROGRESS_ID, NOW)
    authorized = authorize_step(
        value,
        owner,
        progress,
        request(value),
        SCHEMA_ROOT,
        NOW,
        [capability_assertion()],
    )
    assert authorized["step_states"][0]["authorization_state"] == "AUTHORIZED"
    assert authorized["step_states"][0]["binding_assertions"][0]["sanitized_value"] is None
    assert authorized["step_states"][0]["binding_assertions"][0]["evidence_type"] == CAPABILITY_EVIDENCE

    drift_cases = [
        ("STAGING", "supabase", "AUTH", "PROVIDER_MUTATION", "provider.auth-identity.create-one"),
        ("DEVELOPMENT", "provider.other", "AUTH", "PROVIDER_MUTATION", "provider.auth-identity.create-one"),
        ("DEVELOPMENT", "supabase", "DATA", "PROVIDER_MUTATION", "provider.auth-identity.create-one"),
        ("DEVELOPMENT", "supabase", "AUTH", "PROVIDER_READ", "provider.auth-identity.create-one"),
        ("DEVELOPMENT", "supabase", "AUTH", "PROVIDER_MUTATION", "provider.data.create-one"),
    ]
    for environment, provider, responsibility, execution_class, operation in drift_cases:
        bad = plan()
        bad["environment"] = environment
        bad["target"]["provider_reference"] = provider
        bad["target"]["responsibility"] = responsibility
        bad["steps"][0]["execution_class"] = execution_class
        bad["steps"][0]["operation"] = operation
        expect_plan_failure(bad, "SCHEMA_INVALID")

    for action in REQUIRED_PROHIBITIONS:
        bad = plan()
        bad["prohibited_actions"].remove(action)
        expect_plan_failure(bad, "SCHEMA_INVALID")
        bad = plan()
        bad["steps"][0]["prohibited_actions"].remove(action)
        expect_plan_failure(bad, "SCHEMA_INVALID")

    bad = plan()
    del bad["steps"][0]["credential_policy"]["ephemeral_handling"]
    expect_plan_failure(bad, "SCHEMA_INVALID")

    bad = plan()
    bad["steps"][0]["credential_policy"]["allowed_classes"].append(
        "OWNER_INTERACTIVE_SESSION"
    )
    expect_plan_failure(bad, "SCHEMA_INVALID")

    bad = plan()
    bad["steps"][0]["binding_declarations"][0]["persistence_policy"] = (
        "SANITIZED_VALUE_ALLOWED"
    )
    expect_plan_failure(bad, "SCHEMA_INVALID")

    bad = plan()
    bad["steps"][0]["binding_declarations"].append({
        "binding_id": "binding.auth-admin.material",
        "phase": "UNRESOLVED_BLOCKER",
        "value_class": "EPHEMERAL_SENSITIVE",
        "source_step_id": None,
        "evidence_type": None,
        "digest_policy": "PROHIBITED",
        "persistence_policy": "PROHIBITED",
    })
    expect_plan_failure(bad, "SCHEMA_INVALID")

    raw = plan()
    raw["steps"][0]["credential_policy"]["credential_value"] = "fictional"
    try:
        validate_plan(raw, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_FIELD_PROHIBITED"
    else:
        raise AssertionError("credential_value must fail closed")

    bad_request = request(value)
    bad_request["credential_value"] = "fictional"
    try:
        authorize_step(
            value,
            owner,
            progress,
            bad_request,
            SCHEMA_ROOT,
            NOW,
            [capability_assertion()],
        )
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_FIELD_PROHIBITED"
    else:
        raise AssertionError("request credential value must fail closed")

    wrong_class = request(value)
    wrong_class["credential_class"] = "OWNER_INTERACTIVE_SESSION"
    try:
        authorize_step(
            value,
            owner,
            progress,
            wrong_class,
            SCHEMA_ROOT,
            NOW,
            [capability_assertion()],
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "CREDENTIAL_CLASS_NOT_ALLOWED"
    else:
        raise AssertionError("credential class drift must stop")

    baseline = BASELINE_PATH.read_text(encoding="utf-8")
    assert "sb_secret_" in baseline

    v20_plan = load(V20_PLAN_PATH)
    v20_progress = load(V20_PROGRESS_PATH)
    validate_plan(v20_plan, SCHEMA_ROOT)
    validate_progress(v20_plan, v20_progress, SCHEMA_ROOT)
    assert v20_plan["definition_status"] == "DRAFT_BLOCKED"
    assert v20_plan["steps"][0]["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert v20_plan["steps"][0]["unresolved_bindings"] == [
        "binding.development.auth.v20.server-admin-credential-class"
    ]
    assert v20_progress["overall_state"] == "NOT_STARTED"

    print(
        "SUPABASE_AUTH_ADMIN_CREDENTIAL_MODEL=PASS "
        "(DEVELOPMENT/Supabase/AUTH/provider-mutation only; class-label-only control-plane "
        "visibility; server-executor-memory-only material; no material digest/persistence/log/"
        "return; non-secret capability attestation required; v20 remains blocked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
