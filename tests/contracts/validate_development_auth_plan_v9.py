#!/usr/bin/env python3
"""Validate the approved DEVELOPMENT AUTH v9 hosted-membership recovery plan."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    authorize_step,
    initial_progress,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.execution-progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.approval.json"
V8_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v8.execution-progress.json"
V8_FAILURE_PATH = ROOT / "contracts/plans/v1/development-auth-step2-v8-failure.evidence.json"
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"
REGRESSION = ROOT / "tests/migrations/test_development_auth_hosted_membership_v2.py"

EXPECTED_PLAN_ID = "ef8052c7-7a22-406f-ae74-e470aa7b39a4"
EXPECTED_PROGRESS_ID = "68bed069-a537-4a93-b528-8473fa852b81"
EXPECTED_APPROVAL_ID = "5521ee03-6fbc-4be9-a3b3-9605587cad47"
EXPECTED_PLAN_DIGEST = "sha256:7beaa95d02ee414091d85e1212b2646359850912e08ed8ce6ed450f2afe3a95f"
EXPECTED_APPROVAL_DIGEST = "sha256:2ae369d35cd0cb78a4d72e551821a0a1e1762158f2284e431f97940bef0dc2bc"
EXPECTED_EXECUTION_PROGRESS_DIGEST = "sha256:525cc64fb6c5f4de002ea8afae5f6ad2be061ba2609e04824fd1007408a1ce18"
EXPECTED_FAILURE_DIGEST = "sha256:ac1cb15f824cb588465af4c390c3f93b2be41bb83698ea5e839e81cf0574b68f"
AUTHORIZED_AT = "2026-09-12T16:55:56Z"
OUTCOME_AT = "2026-09-12T17:13:15Z"
EXPECTED_AUTHORIZATION_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-12T16:45:00Z",
    "expires_at": "2026-09-12T18:45:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_PACKAGE_DIGEST = "sha256:e01c1f5faf66b031685abe61384dbe813082335dd270bb14e9eeecb05ba1cfc5"
EXPECTED_STEPS = [
    "development.auth.v9.step.01.local-hosted-membership-correction",
    "development.auth.v9.step.02.bootstrap-migration-identity-v2",
    "development.auth.v9.step.03.apply-hook-migration-v2",
    "development.auth.v9.step.04.seal-migration-identity-v2",
    "development.auth.v9.step.05.verify-disabled-hook",
]
EXPECTED_STEP1_POSTCONDITION = (
    "The three v2 migration artifacts are digest-bound and disposable PostgreSQL 17 "
    "reproduces hosted NOSUPERUSER CREATEROLE bootstrap, temporary SET, hook creation, "
    "targeted seal, rollback, and post-seal SET ROLE denial without provider contact."
)


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
    v8_progress = load(V8_PROGRESS_PATH)
    failure = load(V8_FAILURE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)
    validate_approval(plan, approval, SCHEMA_ROOT, OUTCOME_AT)

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 9
    assert plan["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == EXPECTED_AUTHORIZATION_WINDOW
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == EXPECTED_STEPS
    assert "v8.retry" in plan["prohibited_actions"]
    assert "hook.enable" in plan["prohibited_actions"]
    assert "token.issue" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 9
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == EXPECTED_AUTHORIZATION_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_AUTHORIZATION_WINDOW["expires_at"]
    assert approval["approved_at"] == "2026-09-12T16:39:09Z"
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == EXPECTED_APPROVAL_DIGEST

    assert failure["outcome"] == "FAILED_ROLLED_BACK"
    assert failure["safe_error_code"] == "ROLE_MEMBERSHIP_MISMATCH"
    assert failure["root_cause_review"]["retry_authorized"] is False
    assert canonical_digest(failure) == EXPECTED_FAILURE_DIGEST
    first_required = plan["steps"][0]["required_evidence"][0]
    assert first_required["binding_state"] == "BOUND"
    assert first_required["exact_digest"] == EXPECTED_FAILURE_DIGEST

    step2 = v8_progress["step_states"][1]
    assert v8_progress["overall_state"] == "STOPPED"
    assert step2["authorization_state"] == "CONSUMED"
    assert step2["execution_state"] == "FAILED"
    assert step2["verification_state"] == "FAIL"
    assert step2["authorization_consumed"] is True
    assert step2["safe_error_code"] == "ROLE_MEMBERSHIP_MISMATCH"
    assert all(
        state["authorization_state"] == "BLOCKED"
        for state in v8_progress["step_states"][2:]
    )

    actual = {path: raw_digest(path) for path in EXPECTED_ARTIFACT_DIGESTS}
    assert actual == EXPECTED_ARTIFACT_DIGESTS
    package = {
        "bootstrap": actual[BOOTSTRAP],
        "hook": actual[HOOK],
        "seal": actual[SEAL],
    }
    assert canonical_digest(package) == EXPECTED_PACKAGE_DIGEST
    assert plan["steps"][0]["resource"]["exact_digest"] == EXPECTED_PACKAGE_DIGEST
    assert plan["steps"][1]["resource"]["exact_digest"] == actual[BOOTSTRAP]
    assert plan["steps"][2]["resource"]["exact_digest"] == actual[HOOK]
    assert plan["steps"][3]["resource"]["exact_digest"] == actual[SEAL]
    assert plan["steps"][0]["expected_postcondition"] == EXPECTED_STEP1_POSTCONDITION

    regression = REGRESSION.read_text(encoding="utf-8")
    for required in (
        "nosuperuser noinherit createrole",
        "1|0|1|0|0",
        "0|1|0|0|1",
        "permission denied to set role",
    ):
        assert required in regression.lower()

    expected_progress = initial_progress(
        plan, SCHEMA_ROOT, EXPECTED_PROGRESS_ID, plan["created_at"]
    )
    assert progress == expected_progress
    assert progress["record_version"] == 1
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        for state in progress["step_states"]
    )

    authorization_request = {
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 9,
        "plan_digest": EXPECTED_PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": EXPECTED_STEPS[0],
        "resource_reference": "development.auth.v9.hosted-membership-correction",
        "resource_version": "version.20260912155200",
        "resource_digest": EXPECTED_PACKAGE_DIGEST,
        "operation": "local.migration.validate-hosted-membership-correction",
        "execution_class": "LOCAL_ONLY",
        "credential_class": "NONE",
        "required_evidence": [
            {
                "evidence_type": "development.auth.v8.step2.failure-reviewed",
                "evidence_digest": EXPECTED_FAILURE_DIGEST,
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
    )
    assert expected_authorized["record_version"] == 2
    first_authorized = expected_authorized["step_states"][0]
    assert first_authorized["authorization_state"] == "AUTHORIZED"
    assert first_authorized["execution_state"] == "NOT_STARTED"
    assert first_authorized["authorization_consumed"] is False

    evidence = [
        {
            "evidence_type": "migration.identity.v2.artifact.validated",
            "evidence_reference": "github.actions.run.34707401633.attempt.1.migration-identity-v2",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
            "recorded_at": OUTCOME_AT,
        },
        {
            "evidence_type": "hook.migration.v2.artifact.validated",
            "evidence_reference": "github.actions.run.34707401633.attempt.1.hook-migration-v2",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[HOOK],
            "recorded_at": OUTCOME_AT,
        },
        {
            "evidence_type": "migration.identity.seal.v2.artifact.validated",
            "evidence_reference": "github.actions.run.34707401633.attempt.1.migration-identity-seal-v2",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[SEAL],
            "recorded_at": OUTCOME_AT,
        },
    ]
    binding_assertions = [
        {
            "binding_id": "binding.development.auth.v9.migration-identity-artifact",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "migration.identity.v2.artifact.validated",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
            "recorded_at": OUTCOME_AT,
        },
        {
            "binding_id": "binding.development.auth.v9.hook-migration-artifact",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "hook.migration.v2.artifact.validated",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[HOOK],
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": EXPECTED_ARTIFACT_DIGESTS[HOOK],
            "recorded_at": OUTCOME_AT,
        },
        {
            "binding_id": "binding.development.auth.v9.seal-migration-artifact",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "migration.identity.seal.v2.artifact.validated",
            "evidence_digest": EXPECTED_ARTIFACT_DIGESTS[SEAL],
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": EXPECTED_ARTIFACT_DIGESTS[SEAL],
            "recorded_at": OUTCOME_AT,
        },
    ]
    expected_outcome = record_step_outcome(
        plan,
        approval,
        expected_authorized,
        EXPECTED_STEPS[0],
        "SUCCEEDED",
        "PASS",
        evidence,
        EXPECTED_STEP1_POSTCONDITION,
        None,
        SCHEMA_ROOT,
        OUTCOME_AT,
        binding_assertions,
    )
    assert execution_progress == expected_outcome
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "IN_PROGRESS"
    assert execution_progress["updated_at"] == OUTCOME_AT
    assert execution_progress["progress_digest"] == EXPECTED_EXECUTION_PROGRESS_DIGEST

    first_state = execution_progress["step_states"][0]
    assert first_state["authorization_state"] == "CONSUMED"
    assert first_state["execution_state"] == "SUCCEEDED"
    assert first_state["verification_state"] == "PASS"
    assert first_state["authorization_consumed"] is True
    assert first_state["observed_postcondition"] == EXPECTED_STEP1_POSTCONDITION
    assert first_state["safe_error_code"] is None
    assert first_state["evidence"] == evidence
    assert first_state["binding_assertions"] == binding_assertions
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
        "DEVELOPMENT_AUTH_V9_RECOVERY_CONTRACT=PASS "
        "(Step 1 consumed/succeeded/pass from GitHub Actions run 34707401633; "
        "Steps 2-5 pending; no provider execution; v8 retry prohibited)"
    )


if __name__ == "__main__":
    main()
