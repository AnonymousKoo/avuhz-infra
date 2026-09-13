#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v11 provider continuation without provider contact."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v11.approval.json"
V10_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.plan.json"
V10_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.approval.json"
V10_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.execution-progress.json"
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "a748b4d2-a55e-47f7-9aa7-db0014c51f67"
EXPECTED_PROGRESS_ID = "de7dd93b-5e75-470a-9f84-a0008b3b22be"
EXPECTED_APPROVAL_ID = "b05e9a6c-e743-47ff-9cf9-3f787ea156ca"
EXPECTED_PLAN_DIGEST = "sha256:4043fc847d659020ba7c345143f1900a8f2c8995574e827f9dd20b45d9e46e00"
EXPECTED_APPROVAL_DIGEST = "sha256:318fcb4c5620039dd59756f30e33693f7c68f219da312511b4aadbac0111b413"
EXPECTED_PROGRESS_DIGEST = "sha256:2ac53cab7cf5ec13085c25abe17698489ea0f2bca0e3fa0d576f46b736bd0210"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-13T01:30:00Z",
    "expires_at": "2026-09-13T04:30:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_STEPS = [
    "development.auth.v11.step.01.bootstrap-migration-identity-v2",
    "development.auth.v11.step.02.apply-hook-migration-v2",
    "development.auth.v11.step.03.seal-migration-identity-v2",
    "development.auth.v11.step.04.verify-disabled-hook",
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
    v10_plan = load(V10_PLAN_PATH)
    v10_approval = load(V10_APPROVAL_PATH)
    v10_execution = load(V10_EXECUTION_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 11
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
    assert "v10.expired-authorization.execute" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 11
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == EXPECTED_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_WINDOW["expires_at"]
    assert approval["approved_at"] == "2026-09-13T01:29:59Z"
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
            v10_plan, v10_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"]
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v10 approval must be expired before v11 becomes effective")

    v10_step1 = v10_execution["step_states"][0]
    assert v10_execution["plan_version"] == 10
    assert v10_step1["authorization_state"] == "CONSUMED"
    assert v10_step1["execution_state"] == "SUCCEEDED"
    assert v10_step1["verification_state"] == "PASS"
    assert v10_step1["authorization_consumed"] is True

    v10_evidence = {
        item["evidence_type"]: item["evidence_digest"]
        for item in v10_step1["evidence"]
    }
    assert v10_evidence == {
        "migration.identity.v2.artifact.recertified": EXPECTED_ARTIFACT_DIGESTS[BOOTSTRAP],
        "hook.migration.v2.artifact.recertified": EXPECTED_ARTIFACT_DIGESTS[HOOK],
        "migration.identity.seal.v2.artifact.recertified": EXPECTED_ARTIFACT_DIGESTS[SEAL],
    }

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
    assert plan["steps"][1]["required_evidence"][1] == {
        "evidence_type": "hook.migration.v2.artifact.recertified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": EXPECTED_ARTIFACT_DIGESTS[HOOK],
    }
    assert plan["steps"][2]["required_evidence"][1] == {
        "evidence_type": "migration.identity.seal.v2.artifact.recertified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": EXPECTED_ARTIFACT_DIGESTS[SEAL],
    }

    assert plan["steps"][0]["binding_declarations"][0] == {
        "binding_id": "binding.development.auth.v11.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }

    print(
        "DEVELOPMENT_AUTH_V11_CONTINUATION=PASS "
        "(v10 Step 1 immutable/consumed/succeeded/pass; v10 authority expired; "
        "v11 binds unchanged v2 artifacts and begins at bootstrap provider mutation; "
        "all v11 steps pending; provider_mutation_attempted=false)"
    )


if __name__ == "__main__":
    main()
