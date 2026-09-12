#!/usr/bin/env python3
"""Validate the blocked DEVELOPMENT AUTH v9 hosted-membership recovery plan."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.approval.json"
V8_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v8.execution-progress.json"
V8_FAILURE_PATH = ROOT / "contracts/plans/v1/development-auth-step2-v8-failure.evidence.json"
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"
REGRESSION = ROOT / "tests/migrations/test_development_auth_hosted_membership_v2.py"

EXPECTED_PLAN_ID = "ef8052c7-7a22-406f-ae74-e470aa7b39a4"
EXPECTED_PROGRESS_ID = "68bed069-a537-4a93-b528-8473fa852b81"
EXPECTED_PLAN_DIGEST = "sha256:f04df644079e774946bedb6834888c4408df2338ca2ca2969f58caa8878a969a"
EXPECTED_FAILURE_DIGEST = "sha256:ac1cb15f824cb588465af4c390c3f93b2be41bb83698ea5e839e81cf0574b68f"
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
    v8_progress = load(V8_PROGRESS_PATH)
    failure = load(V8_FAILURE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 9
    assert plan["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert plan["definition_status"] == "DRAFT_BLOCKED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "UNRESOLVED_BLOCKER",
        "starts_at": None,
        "expires_at": None,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == EXPECTED_STEPS
    assert not APPROVAL_PATH.exists()
    assert "v8.retry" in plan["prohibited_actions"]
    assert "hook.enable" in plan["prohibited_actions"]
    assert "token.issue" in plan["prohibited_actions"]

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
    assert all(state["authorization_state"] == "PENDING" for state in progress["step_states"])
    assert all(state["execution_state"] == "NOT_STARTED" for state in progress["step_states"])
    assert all(not state["authorization_consumed"] for state in progress["step_states"])

    print(
        "DEVELOPMENT_AUTH_V9_RECOVERY_CONTRACT=PASS "
        "(5 blocked steps; hosted membership v2 artifacts bound; v8 retry prohibited; zero authority)"
    )


if __name__ == "__main__":
    main()
