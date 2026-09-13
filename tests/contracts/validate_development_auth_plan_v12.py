#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v12 provider continuation without provider contact."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    initial_progress,
    validate_approval,
    validate_plan,
    validate_progress,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.approval.json"
V11_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.plan.json"
V11_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.approval.json"
V11_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.execution-progress.json"
HISTORY_V2 = ROOT / "supabase/provider-artifacts/development-auth/history/v2"
BOOTSTRAP = HISTORY_V2 / "20260912155000_development_auth_migration_identity_v2.sql"
HOOK = HISTORY_V2 / "20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = HISTORY_V2 / "20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "6db4bb2b-2c8a-4494-b1cb-fede536d666e"
EXPECTED_PROGRESS_ID = "d4a31b63-7be7-4a55-9da2-25511eb0ed17"
EXPECTED_APPROVAL_ID = "679dcdab-6c47-4188-934b-559d601eda42"
EXPECTED_PLAN_DIGEST = "sha256:ae7a377738bb6ccd89abec81d521211f1befe57f5e17cb15d26601521f787537"
EXPECTED_APPROVAL_DIGEST = "sha256:3b8dea642316e99ecbedb12e3ce0198e1e58de90b1f1adbc4dfbef990a3daca4"
EXPECTED_PROGRESS_DIGEST = "sha256:25dbd2072d00f84e435b3876a5b9eec686a080c7a9d944f886195c9fb0ee0c2e"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-13T04:35:00Z",
    "expires_at": "2026-09-13T07:35:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_STEPS = [
    "development.auth.v12.step.01.bootstrap-migration-identity-v2",
    "development.auth.v12.step.02.apply-hook-migration-v2",
    "development.auth.v12.step.03.seal-migration-identity-v2",
    "development.auth.v12.step.04.verify-disabled-hook",
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
    approval = load(APPROVAL_PATH)
    v11_plan = load(V11_PLAN_PATH)
    v11_approval = load(V11_APPROVAL_PATH)
    v11_execution = load(V11_EXECUTION_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 12
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
    assert "v11.expired-authorization.execute" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 12
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == EXPECTED_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_WINDOW["expires_at"]
    assert approval["approved_at"] == "2026-09-13T04:32:47Z"
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
            v11_plan, v11_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"]
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v11 approval must be expired before v12 becomes effective")

    v11_step1 = v11_execution["step_states"][0]
    assert v11_execution["plan_version"] == 11
    assert v11_step1["authorization_state"] == "AUTHORIZED"
    assert v11_step1["execution_state"] == "NOT_STARTED"
    assert v11_step1["verification_state"] == "NOT_STARTED"
    assert v11_step1["authorization_consumed"] is False
    assert v11_step1["evidence"] == []
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        for state in v11_execution["step_states"][1:]
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
        "binding_id": "binding.development.auth.v12.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }

    print(
        "DEVELOPMENT_AUTH_V12_CONTINUATION=PASS "
        "(v11 Step 1 remained authorized but unexecuted/unconsumed through expiry; "
        "v12 binds unchanged v2 artifacts and restarts at bootstrap provider mutation; "
        "all v12 steps pending; provider_mutation_attempted=false)"
    )


if __name__ == "__main__":
    main()
