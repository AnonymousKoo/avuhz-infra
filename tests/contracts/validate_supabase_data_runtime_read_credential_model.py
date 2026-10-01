#!/usr/bin/env python3
"""Certify the DEVELOPMENT DATA runtime-read credential model."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    AuthorizationPlanError,
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_SCHEMA_PATH = (
    ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan-v2.schema.json"
)
BASELINE_PATH = ROOT / "scripts/check-baseline.sh"

CREDENTIAL_CLASS = "SUPABASE_DATA_RUNTIME_READ"
OPERATION = "provider.data-catalog-rls.inspect-read-only"
PROJECT_REF = "project.fictional.data-development"
PLAN_ID = "da7a0000-0000-4000-8000-000000000001"
APPROVAL_ID = "da7a0000-0000-4000-8000-000000000002"
PROGRESS_ID = "da7a0000-0000-4000-8000-000000000003"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
NOW = "2030-02-01T15:15:00Z"

REQUIRED_PROHIBITIONS = {
    "provider.mutation",
    "business-row.read",
    "auth-data.read",
    "credential.persist",
    "credential.expose",
    "credential.log",
    "credential.return",
    "credential.digest",
    "credential.copy",
    "credential.create",
    "credential.rotate",
    "credential.export",
    "service-role.use",
    "migration-identity.use",
    "ddl.execute",
}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def plan() -> dict:
    prohibited = sorted(REQUIRED_PROHIBITIONS | {
        "scope.widen",
        "environment.change",
        "render.operation",
        "n8n.operation",
        "staging.target",
        "production.target",
    })
    value = {
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": DIGEST_A,
        "definition_status": "READY_FOR_APPROVAL",
        "environment": "DEVELOPMENT",
        "target": {
            "provider_class": "data.provider",
            "provider_reference": "supabase",
            "project_reference": PROJECT_REF,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
        },
        "owner_identity": "owner.fictional",
        "created_at": "2030-02-01T14:00:00Z",
        "authorization_window": {
            "binding_state": "BOUND",
            "starts_at": "2030-02-01T15:00:00Z",
            "expires_at": "2030-02-01T16:00:00Z",
        },
        "ordered_step_ids": ["plan.step.01"],
        "steps": [{
            "step_id": "plan.step.01",
            "ordinal": 1,
            "resource": {
                "resource_type": "database.catalog-rls-metadata",
                "resource_reference": "data.fictional.catalog-rls",
                "binding_state": "BOUND",
                "exact_version": "contract.v1",
                "exact_digest": DIGEST_B,
            },
            "operation": OPERATION,
            "dependency_step_ids": [],
            "required_evidence": [{
                "evidence_type": "data.runtime-login.created-and-verified",
                "source_step_id": None,
                "binding_state": "BOUND",
                "exact_digest": DIGEST_A,
            }],
            "expected_postcondition": (
                "restricted runtime DATA catalog, role, grant, and RLS metadata "
                "were inspected read-only"
            ),
            "prohibited_actions": prohibited,
            "stop_conditions": [
                "project.mismatch",
                "credential-resolution.failed",
                "runtime-role.mismatch",
                "rls-policy.mismatch",
                "scope.drift",
            ],
            "correction_reference": "correction.stop-for-owner-review",
            "execution_class": "PROVIDER_READ",
            "credential_policy": {
                "permitted": True,
                "allowed_classes": [CREDENTIAL_CLASS],
                "values_stored": False,
            },
            "unresolved_bindings": [],
        }],
        "prohibited_actions": prohibited,
        "stop_conditions": [
            "authorization.unbound",
            "evidence.missing",
            "scope.drift",
            "target.drift",
            "security.validation.failed",
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
        "approved_at": "2030-02-01T14:55:00Z",
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
            "evidence_type": "data.runtime-login.created-and-verified",
            "evidence_digest": DIGEST_A,
        }],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def expect_schema_failure(candidate: dict) -> None:
    candidate["plan_digest"] = plan_digest(candidate)
    try:
        validate_plan(candidate, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SCHEMA_INVALID", str(exc)
    else:
        raise AssertionError("invalid DATA runtime-read boundary must fail closed")


def main() -> int:
    schema = load(PLAN_SCHEMA_PATH)
    classes = (
        schema["$defs"]["credentialPolicy"]["properties"]
        ["allowed_classes"]["items"]["enum"]
    )
    assert classes[-1] == CREDENTIAL_CLASS
    assert "SERVICE_ROLE" not in classes
    assert "DATABASE_OWNER" not in classes

    value = plan()
    validate_plan(value, SCHEMA_ROOT)
    owner = approval(value)
    validate_approval(value, owner, SCHEMA_ROOT, NOW)
    progress = initial_progress(value, SCHEMA_ROOT, PROGRESS_ID, NOW)
    authorized = authorize_step(
        value,
        owner,
        progress,
        request(value),
        SCHEMA_ROOT,
        NOW,
    )
    assert authorized["step_states"][0]["authorization_state"] == "AUTHORIZED"
    assert authorized["step_states"][0]["authorization_consumed"] is False

    drift_cases = [
        ("STAGING", "data.provider", "supabase", "DATA", "PROVIDER_READ", OPERATION),
        ("DEVELOPMENT", "data.provider", "provider.other", "DATA", "PROVIDER_READ", OPERATION),
        ("DEVELOPMENT", "data.provider", "supabase", "AUTH", "PROVIDER_READ", OPERATION),
        ("DEVELOPMENT", "identity.provider", "supabase", "DATA", "PROVIDER_READ", OPERATION),
        ("DEVELOPMENT", "data.provider", "supabase", "DATA", "PROVIDER_MUTATION", OPERATION),
        (
            "DEVELOPMENT",
            "data.provider",
            "supabase",
            "DATA",
            "PROVIDER_READ",
            "provider.data.query-business-rows",
        ),
    ]
    for environment, provider_class, provider, responsibility, execution_class, operation in drift_cases:
        bad = plan()
        bad["environment"] = environment
        bad["target"]["provider_class"] = provider_class
        bad["target"]["provider_reference"] = provider
        bad["target"]["responsibility"] = responsibility
        bad["steps"][0]["execution_class"] = execution_class
        bad["steps"][0]["operation"] = operation
        expect_schema_failure(bad)

    bad = plan()
    bad["target"]["issuer_reference"] = "https://issuer.example.invalid"
    expect_schema_failure(bad)

    bad = plan()
    bad["target"]["audience_reference"] = "audience.fictional"
    expect_schema_failure(bad)

    bad = plan()
    bad["steps"][0]["credential_policy"]["allowed_classes"].append(
        "OWNER_INTERACTIVE_SESSION"
    )
    expect_schema_failure(bad)

    bad = plan()
    bad["steps"][0]["credential_policy"]["values_stored"] = True
    expect_schema_failure(bad)

    for action in REQUIRED_PROHIBITIONS:
        bad = plan()
        bad["prohibited_actions"].remove(action)
        expect_schema_failure(bad)
        bad = plan()
        bad["steps"][0]["prohibited_actions"].remove(action)
        expect_schema_failure(bad)

    sensitive_plan = plan()
    sensitive_plan["steps"][0]["credential_policy"]["password"] = "fictional"
    try:
        validate_plan(sensitive_plan, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_FIELD_PROHIBITED"
    else:
        raise AssertionError("password field must fail closed")

    sensitive_approval = approval(value)
    sensitive_approval["credential_value"] = "fictional"
    try:
        validate_approval(value, sensitive_approval, SCHEMA_ROOT, NOW)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_FIELD_PROHIBITED"
    else:
        raise AssertionError("approval credential material must fail closed")

    sensitive_request = request(value)
    sensitive_request["note"] = "postgresql://user:fictional@example.invalid/db"
    try:
        authorize_step(
            value,
            owner,
            progress,
            sensitive_request,
            SCHEMA_ROOT,
            NOW,
        )
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_VALUE_PROHIBITED"
    else:
        raise AssertionError("request connection material must fail closed")

    sensitive_progress = copy.deepcopy(progress)
    sensitive_progress["step_states"][0]["evidence"] = [{
        "evidence_type": "data.validation.observed",
        "evidence_reference": "password=fictional",
        "evidence_digest": DIGEST_A,
        "recorded_at": NOW,
    }]
    sensitive_progress["progress_digest"] = progress_digest(sensitive_progress)
    try:
        validate_progress(value, sensitive_progress, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SENSITIVE_VALUE_PROHIBITED"
    else:
        raise AssertionError("evidence credential material must fail closed")

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
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "CREDENTIAL_CLASS_NOT_ALLOWED"
    else:
        raise AssertionError("credential class drift must stop")

    baseline = BASELINE_PATH.read_text(encoding="utf-8")
    assert "validate_supabase_data_runtime_read_credential_model.py" in baseline
    assert "forbidden credential-shaped content" in baseline
    assert "Semgrep local secret rules" in baseline

    print(
        "SUPABASE_DATA_RUNTIME_READ_CREDENTIAL_MODEL=PASS "
        "(DEVELOPMENT/Supabase/DATA/provider-read only; class-label-only "
        "authorization; secret material prohibited from control-plane records)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
