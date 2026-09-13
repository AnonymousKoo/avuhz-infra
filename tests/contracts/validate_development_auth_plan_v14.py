#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v14 provider continuation and stopped Step 1 outcome."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.execution-progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.approval.json"
FAILURE_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v14-failure.evidence.json"
V13_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.plan.json"
V13_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.approval.json"
V13_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.progress.json"
HISTORY_V2 = ROOT / "supabase/provider-artifacts/development-auth/history/v2"
BOOTSTRAP = HISTORY_V2 / "20260912155000_development_auth_migration_identity_v2.sql"
HOOK = HISTORY_V2 / "20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = HISTORY_V2 / "20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "b78514b1-9fd6-4487-8da3-77d4598ef846"
EXPECTED_PROGRESS_ID = "258dcd9f-106a-4d25-8e28-8c0fa65ec62f"
EXPECTED_APPROVAL_ID = "d1840c61-40aa-4b64-b863-01e01db1e513"
EXPECTED_PLAN_DIGEST = "sha256:b419208260f0ab79c3e441e14fff2757dc98228b757912bdd13f3a7c380ecf79"
EXPECTED_APPROVAL_DIGEST = "sha256:4a7fc882a72d83e8f93fae933e9c1f8886e6347c10ef88942afa1966f1bc5099"
EXPECTED_PROGRESS_DIGEST = "sha256:628fed904bb468348b40d9478d921911ab808c5948599a6d0f3ed9618410ed4b"
EXPECTED_AUTHORIZED_PROGRESS_DIGEST = "sha256:5cc218d5d5824a8a967bdc49d970c5b533392002dfe373069487e13809d86864"
EXPECTED_EXECUTION_PROGRESS_DIGEST = "sha256:c53bc65e59ee687eea25b079458ec828ef1ee7a0629347b08b8134cea7206156"
EXPECTED_FAILURE_EVIDENCE_DIGEST = "sha256:2f6d6bb750117409649e266fc65845e50fb4aa9e863bfcf4d62585abfd38e0b4"
EXPECTED_PREFLIGHT_EVIDENCE_DIGEST = "sha256:5e4e507040dae188f90a0db30b3f9e15654762ec6e76ea24cd3593623033a8da"
EXPECTED_PREFLIGHT_CONFIGURATION_DIGEST = "sha256:fd7c811b8cc1f5c2c490a0a30fd25ab474a06c03df7bd3b084e6774e8f7ac2f7"
AUTHORIZED_AT = "2026-09-13T12:17:10Z"
OUTCOME_AT = "2026-09-13T12:41:55Z"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-13T12:00:00Z",
    "expires_at": "2026-09-13T15:00:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_STEPS = [
    "development.auth.v14.step.01.bootstrap-migration-identity-v2",
    "development.auth.v14.step.02.apply-hook-migration-v2",
    "development.auth.v14.step.03.seal-migration-identity-v2",
    "development.auth.v14.step.04.verify-disabled-hook",
]


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
    failure_evidence = load(FAILURE_EVIDENCE_PATH)
    v13_plan = load(V13_PLAN_PATH)
    v13_approval = load(V13_APPROVAL_PATH)
    v13_progress = load(V13_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])
    validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)
    validate_approval(plan, approval, SCHEMA_ROOT, OUTCOME_AT)

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 14
    assert plan["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == EXPECTED_WINDOW
    assert plan["ordered_step_ids"] == EXPECTED_STEPS
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert "data.operation" in plan["prohibited_actions"]
    assert "staging.target" in plan["prohibited_actions"]
    assert "production.target" in plan["prohibited_actions"]
    assert "v13.expired-authorization.execute" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 14
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == EXPECTED_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_WINDOW["expires_at"]
    assert approval["approved_at"] == "2026-09-13T11:47:17Z"
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == EXPECTED_APPROVAL_DIGEST

    expected_progress = initial_progress(
        plan, SCHEMA_ROOT, EXPECTED_PROGRESS_ID, plan["created_at"]
    )
    assert progress == expected_progress
    assert progress["record_version"] == 1
    assert progress["overall_state"] == "NOT_STARTED"
    assert progress["progress_digest"] == EXPECTED_PROGRESS_DIGEST
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in progress["step_states"]
    )

    try:
        validate_approval(
            v13_plan, v13_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"]
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v13 approval must be expired before v14 becomes effective")

    assert v13_progress["plan_version"] == 13
    assert v13_progress["record_version"] == 1
    assert v13_progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in v13_progress["step_states"]
    )

    actual = {path: raw_digest(path) for path in EXPECTED_ARTIFACT_DIGESTS}
    assert actual == EXPECTED_ARTIFACT_DIGESTS
    assert plan["steps"][0]["resource"]["exact_digest"] == actual[BOOTSTRAP]
    assert plan["steps"][1]["resource"]["exact_digest"] == actual[HOOK]
    assert plan["steps"][2]["resource"]["exact_digest"] == actual[SEAL]

    assert plan["steps"][0]["required_evidence"] == [{
        "evidence_type": "migration.identity.v2.artifact.recertified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
    }]
    assert plan["steps"][0]["binding_declarations"][0] == {
        "binding_id": "binding.development.auth.v14.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }

    preflight_assertion = {
        "binding_id": "binding.development.auth.v14.executor-preflight",
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
        "plan_version": 14,
        "plan_digest": EXPECTED_PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": EXPECTED_STEPS[0],
        "resource_reference": "postgres.role.avuhz_migration_service_dev",
        "resource_version": "version.20260912155000",
        "resource_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
        "operation": "provider.migration.bootstrap-identity-hosted-v2-exact",
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [
            {
                "evidence_type": "migration.identity.v2.artifact.recertified",
                "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
            }
        ],
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
    assert expected_authorized["overall_state"] == "IN_PROGRESS"
    assert expected_authorized["updated_at"] == AUTHORIZED_AT
    assert expected_authorized["progress_digest"] == EXPECTED_AUTHORIZED_PROGRESS_DIGEST
    assert expected_authorized["step_states"][0]["authorization_state"] == "AUTHORIZED"
    assert expected_authorized["step_states"][0]["authorization_consumed"] is False
    assert expected_authorized["step_states"][0]["binding_assertions"] == [preflight_assertion]

    expected_failure_evidence = {
        "evidence_type": "migration.identity.v2.bootstrap.verified",
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "project_reference": "pwlhruwutoitnieactol",
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 14,
        "step_id": EXPECTED_STEPS[0],
        "attempt": 1,
        "outcome": "FAILED_ROLLED_BACK",
        "safe_error_code": "FUNCTION_PRIVILEGE_MISMATCH",
        "provider_observation": {
            "project_status": "ACTIVE_HEALTHY",
            "postgresql_version": "17.6.1.166",
            "postgres_engine": "17",
            "session_user": "postgres",
            "current_user": "postgres",
            "current_database": "postgres",
            "postgres_is_superuser": False,
            "postgres_has_createrole": True,
            "migration_identity_exists_after_rollback": False,
            "hook_function_exists_after_rollback": False,
            "migration_history_entry_count_after_rollback": 0,
        },
        "failure_observation": {
            "provider_error_code": "P0001",
            "sanitized_error": (
                "Avuhz DEVELOPMENT Auth migration identity v2 has unexpected function privilege"
            ),
            "failed_postcondition": "function.privilege.unexpected",
            "transaction_rolled_back": True,
        },
        "root_cause_review": {
            "status": "HIGH_CONFIDENCE",
            "classification": "EFFECTIVE_PUBLIC_EXECUTE_FALSE_POSITIVE",
            "basis": [
                (
                    "The v2 bootstrap postcondition uses has_function_privilege for "
                    "avuhz_migration_service_dev across public, auth, and storage functions."
                ),
                (
                    "The hosted DEVELOPMENT AUTH baseline exposes EXECUTE on at least "
                    "20 auth/storage functions through PostgreSQL PUBLIC."
                ),
                (
                    "PUBLIC privileges are effective for every role, so "
                    "has_function_privilege can report EXECUTE even when the migration "
                    "role has no direct function ACL grant."
                ),
                (
                    "Rollback verification confirmed the migration identity and hook are "
                    "absent and no matching provider migration history entry remains."
                ),
            ],
            "correction_required": True,
            "retry_authorized": False,
        },
        "security_state": {
            "credential_retained": False,
            "raw_provider_payload_retained": False,
            "pii_retained": False,
            "data_resource_touched": False,
            "hook_created": False,
            "hook_enabled": False,
            "provider_mutation_committed": False,
        },
        "recorded_at": OUTCOME_AT,
    }
    assert failure_evidence == expected_failure_evidence
    assert canonical_digest(failure_evidence) == EXPECTED_FAILURE_EVIDENCE_DIGEST

    outcome_evidence = [{
        "evidence_type": "migration.identity.v2.bootstrap.verified",
        "evidence_reference": "provider.execution.v14.step1.attempt1.rollback-verified",
        "evidence_digest": EXPECTED_FAILURE_EVIDENCE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }]
    observed_postcondition = (
        "Bootstrap failed closed at the function-privilege postcondition. "
        "Transaction rollback verification confirmed the migration identity and hook "
        "are absent and no provider migration history entry remains."
    )
    expected_stopped = record_step_outcome(
        plan,
        approval,
        expected_authorized,
        EXPECTED_STEPS[0],
        "FAILED",
        "FAIL",
        outcome_evidence,
        observed_postcondition,
        "FUNCTION_PRIVILEGE_MISMATCH",
        SCHEMA_ROOT,
        OUTCOME_AT,
    )

    assert execution_progress == expected_stopped
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "STOPPED"
    assert execution_progress["updated_at"] == OUTCOME_AT
    assert execution_progress["progress_digest"] == EXPECTED_EXECUTION_PROGRESS_DIGEST

    first_state = execution_progress["step_states"][0]
    assert first_state["authorization_state"] == "CONSUMED"
    assert first_state["execution_state"] == "FAILED"
    assert first_state["verification_state"] == "FAIL"
    assert first_state["authorization_consumed"] is True
    assert first_state["evidence"] == outcome_evidence
    assert first_state["observed_postcondition"] == observed_postcondition
    assert first_state["safe_error_code"] == "FUNCTION_PRIVILEGE_MISMATCH"
    assert first_state["binding_assertions"] == [preflight_assertion]
    assert all(
        state["authorization_state"] == "BLOCKED"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in execution_progress["step_states"][1:]
    )

    print(
        "DEVELOPMENT_AUTH_V14_CONTINUATION=PASS "
        "(v13 expired pristine; v14 Step 1 authorization reconstructed from fresh "
        "read-only preflight; provider Step 1 attempted once and failed closed on "
        "effective PUBLIC EXECUTE privilege detection; transaction rollback verified "
        "no migration identity, hook, or history entry; v14 STOPPED; Steps 2-4 BLOCKED; "
        "retry_authorized=false; provider_mutation_attempted=true; "
        "provider_mutation_committed=false)"
    )


if __name__ == "__main__":
    main()
