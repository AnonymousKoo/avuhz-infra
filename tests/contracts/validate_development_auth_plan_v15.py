#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v15 through Step 3 authorization."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    authorize_step,
    initial_progress,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.execution-progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.approval.json"
STEP1_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v15-success.evidence.json"
STEP2_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step2-v15-success.evidence.json"
V14_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.plan.json"
V14_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.approval.json"
V14_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.execution-progress.json"
CURRENT = ROOT / "supabase/provider-artifacts/development-auth/current"
BOOTSTRAP = CURRENT / "development_auth_migration_identity_v3.sql"
HOOK = CURRENT / "development_auth_custom_access_token_hook_v2.sql"
SEAL = CURRENT / "development_auth_migration_identity_seal_v2.sql"

PLAN_ID = "fb56b1bd-ed95-468d-9189-4ac86616273f"
PROGRESS_ID = "47874259-3616-4c9c-af4b-3541b13b9a23"
PLAN_DIGEST = "sha256:abde80fd06d42949db231c6ea61bbabd368550eda82a5c4f9ff0064393a60727"
APPROVAL_DIGEST = "sha256:143c18558ceb5dd6e820b4103aebf71c3c3125e98177b6336b1a12518ca54f16"
INITIAL_PROGRESS_DIGEST = "sha256:d808788d47df88c426ea12817c42421abd1550ebb8aa4ceab7a5d894c08f780b"
STEP1_AUTH_DIGEST = "sha256:c3a569ecb9b7a33e2f14a84713f9cfc6bb35bb521c2ad7e98b878a133e74874e"
STEP1_SUCCESS_PROGRESS_DIGEST = "sha256:1c14770cdd6f2e704a98e338e5f6c225a3df519d1ac9f52e9a6476bc835ebed9"
STEP2_AUTH_DIGEST = "sha256:87cb1e3711c59db42ad2d6b555836966d28f86b4a5484d554c9794afd7a4635b"
STEP2_SUCCESS_PROGRESS_DIGEST = "sha256:3fa7994673ece4e152b75da50a9a93f1dde0c017cdc771136a059da18fa87bcc"
STEP3_AUTH_DIGEST = "sha256:220e56ee7513d37605e0e267e7963873ed8c10323bc74b5a1bde5b746957a8e0"
STEP1_EVIDENCE_DIGEST = "sha256:b2b69fbf11de44172ed85e4f0b81d4e461eb7dc8c1a2b8c9090203241f36945a"
STEP2_EVIDENCE_DIGEST = "sha256:b79ff1c1f3e401203ce5e53ee3587b91dc063bbe27bcd97ac2badbf0c11490d6"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:5e4e507040dae188f90a0db30b3f9e15654762ec6e76ea24cd3593623033a8da"
PREFLIGHT_VALUE_DIGEST = "sha256:fd7c811b8cc1f5c2c490a0a30fd25ab474a06c03df7bd3b084e6774e8f7ac2f7"
MIGRATION_IDENTITY_VALUE_DIGEST = "sha256:789255aa22baaf26013bec82c18c3db561ceeb9817f84705d8a6a0da5e7db56a"
HOOK_APPLICATION_VALUE_DIGEST = "sha256:da5eb90c25fde4d4d0dc9367862604d77acc9724062f169524b8e714c218814d"

STEP1_AUTH_AT = "2026-09-13T15:31:11Z"
STEP1_OUTCOME_AT = "2026-09-13T15:48:39Z"
STEP2_AUTH_AT = "2026-09-13T16:11:07Z"
STEP2_OUTCOME_AT = "2026-09-13T16:30:39Z"
STEP3_AUTH_AT = "2026-09-13T17:40:52Z"
WINDOW_START = "2026-09-13T15:15:00Z"
WINDOW_END = "2026-09-13T18:15:00Z"

STEPS = [
    "development.auth.v15.step.01.bootstrap-migration-identity-v3",
    "development.auth.v15.step.02.apply-hook-migration-v2",
    "development.auth.v15.step.03.seal-migration-identity-v2",
    "development.auth.v15.step.04.verify-disabled-hook",
]


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def base_request(plan: dict, step: dict, credential_class: str) -> dict:
    return {
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
        "credential_class": credential_class,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def main() -> None:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    execution = load(EXECUTION_PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    step1_evidence_file = load(STEP1_EVIDENCE_PATH)
    step2_evidence_file = load(STEP2_EVIDENCE_PATH)
    v14_plan = load(V14_PLAN_PATH)
    v14_approval = load(V14_APPROVAL_PATH)
    v14_execution = load(V14_EXECUTION_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution, SCHEMA_ROOT)
    for moment in (
        WINDOW_START,
        STEP1_AUTH_AT,
        STEP1_OUTCOME_AT,
        STEP2_AUTH_AT,
        STEP2_OUTCOME_AT,
        STEP3_AUTH_AT,
    ):
        validate_approval(plan, approval, SCHEMA_ROOT, moment)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["ordered_step_ids"] == STEPS
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    for action in ("data.operation", "staging.target", "production.target", "hook.enable"):
        assert action in plan["prohibited_actions"]

    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    expected_initial = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_initial
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST

    try:
        validate_approval(v14_plan, v14_approval, SCHEMA_ROOT, WINDOW_START)
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v14 must remain expired")
    assert v14_execution["overall_state"] == "STOPPED"
    assert v14_execution["step_states"][0]["safe_error_code"] == "FUNCTION_PRIVILEGE_MISMATCH"

    artifacts = {
        BOOTSTRAP: "sha256:9925621342859155998f14d82f6971694b71e4ad53d328c33f973c7a7be3b54a",
        HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
        SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
    }
    assert {path: raw_digest(path) for path in artifacts} == artifacts
    step1, step2, step3, step4 = plan["steps"]
    assert step1["resource"]["exact_digest"] == artifacts[BOOTSTRAP]
    assert step2["resource"]["exact_digest"] == artifacts[HOOK]
    assert step3["resource"]["exact_digest"] == artifacts[SEAL]
    assert step4["execution_class"] == "PROVIDER_READ"

    step1_request = base_request(plan, step1, "OWNER_INTERACTIVE_SESSION")
    step1_request["required_evidence"] = [{
        "evidence_type": "migration.identity.v3.artifact.certified",
        "evidence_digest": artifacts[BOOTSTRAP],
    }]
    step1_request["prior_evidence_digests"] = []
    step1_preflight = {
        "binding_id": "binding.development.auth.v15.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "evidence_digest": PREFLIGHT_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": PREFLIGHT_VALUE_DIGEST,
        "recorded_at": STEP1_AUTH_AT,
    }
    step1_authorized = authorize_step(
        plan,
        approval,
        progress,
        step1_request,
        SCHEMA_ROOT,
        STEP1_AUTH_AT,
        trusted_preflight_assertions=[step1_preflight],
    )
    assert step1_authorized["progress_digest"] == STEP1_AUTH_DIGEST

    assert raw_digest(STEP1_EVIDENCE_PATH) == STEP1_EVIDENCE_DIGEST
    assert step1_evidence_file["outcome"] == "SUCCEEDED_VERIFIED"
    step1_outcome_evidence = [{
        "evidence_type": "migration.identity.v3.bootstrap.verified",
        "evidence_reference": "provider.execution.v15.step1.attempt1.verified",
        "evidence_digest": STEP1_EVIDENCE_DIGEST,
        "recorded_at": STEP1_OUTCOME_AT,
    }]
    step1_binding = {
        "binding_id": "binding.development.auth.v15.migration-identity",
        "phase": "PRODUCED_BY_CURRENT_STEP",
        "value_class": "STABLE_REFERENCE",
        "source_step_id": None,
        "evidence_type": "migration.identity.v3.bootstrap.verified",
        "evidence_digest": STEP1_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": MIGRATION_IDENTITY_VALUE_DIGEST,
        "recorded_at": STEP1_OUTCOME_AT,
    }
    assert canonical_digest("postgres.role.avuhz_migration_service_dev") == (
        MIGRATION_IDENTITY_VALUE_DIGEST
    )
    step1_success = record_step_outcome(
        plan,
        approval,
        step1_authorized,
        STEPS[0],
        "SUCCEEDED",
        "PASS",
        step1_outcome_evidence,
        step1["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        STEP1_OUTCOME_AT,
        binding_assertions=[step1_binding],
    )
    assert step1_success["progress_digest"] == STEP1_SUCCESS_PROGRESS_DIGEST

    step2_request = base_request(plan, step2, "MIGRATION_IDENTITY")
    step2_request["required_evidence"] = [
        {
            "evidence_type": "migration.identity.v3.bootstrap.verified",
            "evidence_digest": STEP1_EVIDENCE_DIGEST,
        },
        {
            "evidence_type": "hook.migration.v2.artifact.certified",
            "evidence_digest": artifacts[HOOK],
        },
    ]
    step2_request["prior_evidence_digests"] = [STEP1_EVIDENCE_DIGEST]
    step2_authorized = authorize_step(
        plan, approval, step1_success, step2_request, SCHEMA_ROOT, STEP2_AUTH_AT
    )
    assert step2_authorized["progress_digest"] == STEP2_AUTH_DIGEST

    assert raw_digest(STEP2_EVIDENCE_PATH) == STEP2_EVIDENCE_DIGEST
    assert step2_evidence_file["outcome"] == "SUCCEEDED_VERIFIED"
    assert step2_evidence_file["provider_observation"]["hook_owner"] == (
        "avuhz_migration_service_dev"
    )
    assert step2_evidence_file["provider_observation"]["auth_admin_execute_acl_count"] == 1
    assert step2_evidence_file["provider_observation"]["public_execute_acl_count"] == 0
    assert step2_evidence_file["provider_observation"]["app_role_execute_acl_count"] == 0
    assert step2_evidence_file["verification_observation"]["provider_mutation_attempts"] == 1
    assert step2_evidence_file["verification_observation"]["hook_enable_action_performed"] is False
    assert step2_evidence_file["security_state"]["credential_retained"] is False
    assert step2_evidence_file["security_state"]["pii_retained"] is False
    assert step2_evidence_file["security_state"]["data_resource_touched"] is False

    step2_outcome_evidence = [{
        "evidence_type": "hook.migration.v2.application.verified",
        "evidence_reference": "provider.execution.v15.step2.attempt1.verified",
        "evidence_digest": STEP2_EVIDENCE_DIGEST,
        "recorded_at": STEP2_OUTCOME_AT,
    }]
    step2_binding = {
        "binding_id": "binding.development.auth.v15.hook-application",
        "phase": "PRODUCED_BY_CURRENT_STEP",
        "value_class": "CONTENT_DIGEST",
        "source_step_id": None,
        "evidence_type": "hook.migration.v2.application.verified",
        "evidence_digest": STEP2_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": HOOK_APPLICATION_VALUE_DIGEST,
        "recorded_at": STEP2_OUTCOME_AT,
    }
    assert canonical_digest(artifacts[HOOK]) == HOOK_APPLICATION_VALUE_DIGEST
    step2_success = record_step_outcome(
        plan,
        approval,
        step2_authorized,
        STEPS[1],
        "SUCCEEDED",
        "PASS",
        step2_outcome_evidence,
        step2["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        STEP2_OUTCOME_AT,
        binding_assertions=[step2_binding],
    )
    assert step2_success["progress_digest"] == STEP2_SUCCESS_PROGRESS_DIGEST

    step3_request = base_request(plan, step3, "OWNER_INTERACTIVE_SESSION")
    step3_request["required_evidence"] = [
        {
            "evidence_type": "hook.migration.v2.application.verified",
            "evidence_digest": STEP2_EVIDENCE_DIGEST,
        },
        {
            "evidence_type": "migration.identity.seal.v2.artifact.certified",
            "evidence_digest": artifacts[SEAL],
        },
    ]
    step3_request["prior_evidence_digests"] = [
        STEP1_EVIDENCE_DIGEST,
        STEP2_EVIDENCE_DIGEST,
    ]
    expected_step3_authorized = authorize_step(
        plan,
        approval,
        step2_success,
        step3_request,
        SCHEMA_ROOT,
        STEP3_AUTH_AT,
    )

    assert execution == expected_step3_authorized
    assert execution["record_version"] == 6
    assert execution["overall_state"] == "IN_PROGRESS"
    assert execution["updated_at"] == STEP3_AUTH_AT
    assert execution["progress_digest"] == STEP3_AUTH_DIGEST

    step1_state, step2_state, step3_state, step4_state = execution["step_states"]
    for state in (step1_state, step2_state):
        assert state["authorization_state"] == "CONSUMED"
        assert state["execution_state"] == "SUCCEEDED"
        assert state["verification_state"] == "PASS"
        assert state["authorization_consumed"] is True

    assert step3_state["authorization_state"] == "AUTHORIZED"
    assert step3_state["execution_state"] == "NOT_STARTED"
    assert step3_state["verification_state"] == "NOT_STARTED"
    assert step3_state["authorization_consumed"] is False
    assert step3_state["evidence"] == []
    assert step3_state["observed_postcondition"] is None
    assert step3_state["safe_error_code"] is None
    assert step3_state["binding_assertions"] == [{
        "binding_id": "binding.development.auth.v15.hook-application",
        "phase": "DERIVED_FROM_SOURCE_STEP",
        "value_class": "CONTENT_DIGEST",
        "source_step_id": STEPS[1],
        "evidence_type": "hook.migration.v2.application.verified",
        "evidence_digest": STEP2_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": HOOK_APPLICATION_VALUE_DIGEST,
        "recorded_at": STEP3_AUTH_AT,
    }]

    assert step4_state["authorization_state"] == "PENDING"
    assert step4_state["execution_state"] == "NOT_STARTED"
    assert step4_state["verification_state"] == "NOT_STARTED"
    assert step4_state["authorization_consumed"] is False
    assert step4_state["evidence"] == []
    assert step4_state["binding_assertions"] == []

    print(
        "DEVELOPMENT_AUTH_V15_CONTINUATION=PASS "
        "(v14 stopped; v15 Steps 1-2 consumed/succeeded/pass; "
        "Step 3 authorized only from exact Step 2 evidence and certified seal-v2 artifact; "
        "Step 3 unexecuted/unconsumed; Step 4 pending; hook enablement remains "
        "unauthorized/unperformed; DEVELOPMENT DATA untouched)"
    )


if __name__ == "__main__":
    main()
