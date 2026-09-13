#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v15 continuation and successful Step 1 provider outcome."""
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
SUCCESS_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v15-success.evidence.json"
V14_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.plan.json"
V14_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.approval.json"
V14_EXECUTION_PROGRESS_PATH = (
    ROOT / "contracts/plans/v1/development-auth-integration-v14.execution-progress.json"
)
CURRENT = ROOT / "supabase/provider-artifacts/development-auth/current"
BOOTSTRAP = CURRENT / "development_auth_migration_identity_v3.sql"
HOOK = CURRENT / "development_auth_custom_access_token_hook_v2.sql"
SEAL = CURRENT / "development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "fb56b1bd-ed95-468d-9189-4ac86616273f"
EXPECTED_PROGRESS_ID = "47874259-3616-4c9c-af4b-3541b13b9a23"
EXPECTED_APPROVAL_ID = "73a8dde2-149f-40a6-9045-105147081062"
EXPECTED_PLAN_DIGEST = "sha256:abde80fd06d42949db231c6ea61bbabd368550eda82a5c4f9ff0064393a60727"
EXPECTED_PROGRESS_DIGEST = "sha256:d808788d47df88c426ea12817c42421abd1550ebb8aa4ceab7a5d894c08f780b"
EXPECTED_AUTHORIZED_PROGRESS_DIGEST = "sha256:c3a569ecb9b7a33e2f14a84713f9cfc6bb35bb521c2ad7e98b878a133e74874e"
EXPECTED_EXECUTION_PROGRESS_DIGEST = "sha256:1c14770cdd6f2e704a98e338e5f6c225a3df519d1ac9f52e9a6476bc835ebed9"
EXPECTED_APPROVAL_DIGEST = "sha256:143c18558ceb5dd6e820b4103aebf71c3c3125e98177b6336b1a12518ca54f16"
EXPECTED_PREFLIGHT_EVIDENCE_DIGEST = "sha256:5e4e507040dae188f90a0db30b3f9e15654762ec6e76ea24cd3593623033a8da"
EXPECTED_PREFLIGHT_CONFIGURATION_DIGEST = "sha256:fd7c811b8cc1f5c2c490a0a30fd25ab474a06c03df7bd3b084e6774e8f7ac2f7"
EXPECTED_SUCCESS_EVIDENCE_DIGEST = "sha256:b2b69fbf11de44172ed85e4f0b81d4e461eb7dc8c1a2b8c9090203241f36945a"
EXPECTED_MIGRATION_IDENTITY_VALUE_DIGEST = "sha256:789255aa22baaf26013bec82c18c3db561ceeb9817f84705d8a6a0da5e7db56a"
AUTHORIZED_AT = "2026-09-13T15:31:11Z"
OUTCOME_AT = "2026-09-13T15:48:39Z"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-13T15:15:00Z",
    "expires_at": "2026-09-13T18:15:00Z",
}
EXPECTED_STEPS = [
    "development.auth.v15.step.01.bootstrap-migration-identity-v3",
    "development.auth.v15.step.02.apply-hook-migration-v2",
    "development.auth.v15.step.03.seal-migration-identity-v2",
    "development.auth.v15.step.04.verify-disabled-hook",
]
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:9925621342859155998f14d82f6971694b71e4ad53d328c33f973c7a7be3b54a",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    success_evidence = load(SUCCESS_EVIDENCE_PATH)
    v14_plan = load(V14_PLAN_PATH)
    v14_approval = load(V14_APPROVAL_PATH)
    v14_execution = load(V14_EXECUTION_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])
    validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)
    validate_approval(plan, approval, SCHEMA_ROOT, OUTCOME_AT)

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 15
    assert plan["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["authorization_window"] == EXPECTED_WINDOW
    assert plan["ordered_step_ids"] == EXPECTED_STEPS
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    for prohibited in (
        "batch.mutation",
        "data.operation",
        "staging.target",
        "production.target",
        "hook.enable",
        "v14.retry",
        "v14.stopped-authorization.execute",
    ):
        assert prohibited in plan["prohibited_actions"]

    assert approval == {
        "approval_id": EXPECTED_APPROVAL_ID,
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 15,
        "plan_digest": EXPECTED_PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": EXPECTED_WINDOW["starts_at"],
        "expires_at": EXPECTED_WINDOW["expires_at"],
        "approved_at": "2026-09-13T14:58:57Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": EXPECTED_APPROVAL_DIGEST,
    }

    expected_progress = initial_progress(
        plan, SCHEMA_ROOT, EXPECTED_PROGRESS_ID, plan["created_at"]
    )
    assert progress == expected_progress
    assert progress["record_version"] == 1
    assert progress["overall_state"] == "NOT_STARTED"
    assert progress["progress_digest"] == EXPECTED_PROGRESS_DIGEST

    try:
        validate_approval(
            v14_plan, v14_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"]
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v14 approval must be expired before v15 becomes effective")

    assert v14_execution["plan_version"] == 14
    assert v14_execution["record_version"] == 3
    assert v14_execution["overall_state"] == "STOPPED"
    assert v14_execution["step_states"][0]["authorization_state"] == "CONSUMED"
    assert v14_execution["step_states"][0]["execution_state"] == "FAILED"
    assert v14_execution["step_states"][0]["verification_state"] == "FAIL"
    assert v14_execution["step_states"][0]["safe_error_code"] == "FUNCTION_PRIVILEGE_MISMATCH"

    actual = {path: raw_digest(path) for path in EXPECTED_ARTIFACT_DIGESTS}
    assert actual == EXPECTED_ARTIFACT_DIGESTS
    bootstrap, hook, seal, verify = plan["steps"]
    assert bootstrap["resource"]["exact_digest"] == actual[BOOTSTRAP]
    assert bootstrap["resource"]["exact_version"] == "version.development-auth-bootstrap.v3"
    assert bootstrap["operation"] == "provider.migration.bootstrap-identity-hosted-v3-exact"
    assert bootstrap["required_evidence"] == [{
        "evidence_type": "migration.identity.v3.artifact.certified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": actual[BOOTSTRAP],
    }]
    assert hook["resource"]["exact_digest"] == actual[HOOK]
    assert hook["dependency_step_ids"] == [EXPECTED_STEPS[0]]
    assert seal["resource"]["exact_digest"] == actual[SEAL]
    assert seal["dependency_step_ids"] == [EXPECTED_STEPS[1]]
    assert verify["execution_class"] == "PROVIDER_READ"
    assert verify["dependency_step_ids"] == [EXPECTED_STEPS[2]]

    preflight_assertion = {
        "binding_id": "binding.development.auth.v15.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "evidence_digest": EXPECTED_PREFLIGHT_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": EXPECTED_PREFLIGHT_CONFIGURATION_DIGEST,
        "recorded_at": AUTHORIZED_AT,
    }
    authorization_request = {
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 15,
        "plan_digest": EXPECTED_PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": EXPECTED_STEPS[0],
        "resource_reference": "postgres.role.avuhz_migration_service_dev",
        "resource_version": "version.development-auth-bootstrap.v3",
        "resource_digest": actual[BOOTSTRAP],
        "operation": "provider.migration.bootstrap-identity-hosted-v3-exact",
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [{
            "evidence_type": "migration.identity.v3.artifact.certified",
            "evidence_digest": actual[BOOTSTRAP],
        }],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    expected_authorized = authorize_step(
        plan,
        approval,
        progress,
        authorization_request,
        SCHEMA_ROOT,
        AUTHORIZED_AT,
        trusted_preflight_assertions=[preflight_assertion],
    )
    assert expected_authorized["record_version"] == 2
    assert expected_authorized["progress_digest"] == EXPECTED_AUTHORIZED_PROGRESS_DIGEST

    expected_success_evidence = {
        "evidence_type": "migration.identity.v3.bootstrap.verified",
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "project_reference": "pwlhruwutoitnieactol",
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 15,
        "step_id": EXPECTED_STEPS[0],
        "attempt": 1,
        "outcome": "SUCCEEDED_VERIFIED",
        "provider_observation": {
            "project_status": "ACTIVE_HEALTHY",
            "postgresql_version": "17.6.1.166",
            "postgres_engine": "17",
            "session_user": "postgres",
            "current_user": "postgres",
            "current_database": "postgres",
            "postgres_is_superuser": False,
            "postgres_has_createrole": True,
            "migration_identity_exists": True,
            "role_attributes_exact": True,
            "bootstrap_admin_noset_membership_count": 1,
            "temporary_set_membership_count": 1,
            "total_role_membership_edges": 2,
            "public_schema_usage": True,
            "public_schema_create": True,
            "direct_database_acl_count": 0,
            "provider_schema_privilege_count": 0,
            "table_privilege_count": 0,
            "sequence_privilege_count": 0,
            "direct_function_execute_count": 0,
            "hook_function_exists": False,
            "migration_history_entry_count": 1,
            "migration_history_version": "20260913154411",
            "migration_history_name": "development_auth_migration_identity_v3",
        },
        "verification_observation": {
            "provider_mutation_attempts": 1,
            "provider_mutation_committed": True,
            "postcondition_verified": True,
            "read_only_verification_query_correction_required": True,
            "read_only_verification_query_correction_scope": "sequence_privilege_guard_only",
        },
        "security_state": {
            "credential_retained": False,
            "raw_provider_payload_retained": False,
            "pii_retained": False,
            "data_resource_touched": False,
            "hook_created": False,
            "hook_enabled": False,
        },
        "recorded_at": OUTCOME_AT,
    }
    assert success_evidence == expected_success_evidence
    assert raw_digest(SUCCESS_EVIDENCE_PATH) == EXPECTED_SUCCESS_EVIDENCE_DIGEST

    outcome_evidence = [{
        "evidence_type": "migration.identity.v3.bootstrap.verified",
        "evidence_reference": "provider.execution.v15.step1.attempt1.verified",
        "evidence_digest": EXPECTED_SUCCESS_EVIDENCE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }]
    migration_identity_assertion = {
        "binding_id": "binding.development.auth.v15.migration-identity",
        "phase": "PRODUCED_BY_CURRENT_STEP",
        "value_class": "STABLE_REFERENCE",
        "source_step_id": None,
        "evidence_type": "migration.identity.v3.bootstrap.verified",
        "evidence_digest": EXPECTED_SUCCESS_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": EXPECTED_MIGRATION_IDENTITY_VALUE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }
    assert canonical_digest("postgres.role.avuhz_migration_service_dev") == (
        EXPECTED_MIGRATION_IDENTITY_VALUE_DIGEST
    )

    expected_success = record_step_outcome(
        plan,
        approval,
        expected_authorized,
        EXPECTED_STEPS[0],
        "SUCCEEDED",
        "PASS",
        outcome_evidence,
        bootstrap["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        OUTCOME_AT,
        binding_assertions=[migration_identity_assertion],
    )
    assert execution_progress == expected_success
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "IN_PROGRESS"
    assert execution_progress["updated_at"] == OUTCOME_AT
    assert execution_progress["progress_digest"] == EXPECTED_EXECUTION_PROGRESS_DIGEST

    first_state = execution_progress["step_states"][0]
    assert first_state["authorization_state"] == "CONSUMED"
    assert first_state["execution_state"] == "SUCCEEDED"
    assert first_state["verification_state"] == "PASS"
    assert first_state["authorization_consumed"] is True
    assert first_state["evidence"] == outcome_evidence
    assert first_state["observed_postcondition"] == bootstrap["expected_postcondition"]
    assert first_state["safe_error_code"] is None
    assert first_state["binding_assertions"] == [
        preflight_assertion,
        migration_identity_assertion,
    ]
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in execution_progress["step_states"][1:]
    )

    print(
        "DEVELOPMENT_AUTH_V15_CONTINUATION=PASS "
        "(v14 stopped; v15 Step 1 authorized from fresh preflight, executed exactly once, "
        "bootstrap v3 committed and postcondition verified, Step 1 consumed/succeeded/pass; "
        "Steps 2-4 pending; hook absent; DEVELOPMENT DATA untouched; "
        "provider_mutation_attempts=1; provider_mutation_committed=true)"
    )


if __name__ == "__main__":
    main()
