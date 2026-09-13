#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v13 provider continuation without provider contact."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.approval.json"
V12_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.plan.json"
V12_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.approval.json"
V12_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v12.progress.json"
HISTORY_V2 = ROOT / "supabase/provider-artifacts/development-auth/history/v2"
BOOTSTRAP = HISTORY_V2 / "20260912155000_development_auth_migration_identity_v2.sql"
HOOK = HISTORY_V2 / "20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = HISTORY_V2 / "20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "bd676ac0-20e2-4c53-ad8d-64e83b9c9b82"
EXPECTED_PROGRESS_ID = "7f78d8d7-4041-446e-9529-1dab5ec63a12"
EXPECTED_APPROVAL_ID = "15983f52-172e-4db8-8a99-acc10234b4bf"
EXPECTED_PLAN_DIGEST = "sha256:9c7a03ef22206a82c4d101d589c0b23a980772e072f1a726a9b3a9df6a0335b7"
EXPECTED_APPROVAL_DIGEST = "sha256:e24631d999fa6f9fd485abf5771e83dc11e2f94b41603c117cc596de5dca5f87"
EXPECTED_PROGRESS_DIGEST = "sha256:7142f9f881436e743c84b98630074a344f74e3e990fd192432145c8719efb9ca"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-13T08:00:00Z",
    "expires_at": "2026-09-13T11:00:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_STEPS = [
    "development.auth.v13.step.01.bootstrap-migration-identity-v2",
    "development.auth.v13.step.02.apply-hook-migration-v2",
    "development.auth.v13.step.03.seal-migration-identity-v2",
    "development.auth.v13.step.04.verify-disabled-hook",
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
    v12_plan = load(V12_PLAN_PATH)
    v12_approval = load(V12_APPROVAL_PATH)
    v12_progress = load(V12_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 13
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
    assert "v12.expired-authorization.execute" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 13
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == EXPECTED_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_WINDOW["expires_at"]
    assert approval["approved_at"] == "2026-09-13T07:35:37Z"
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
            v12_plan, v12_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"]
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v12 approval must be expired before v13 becomes effective")

    assert v12_progress["plan_version"] == 12
    assert v12_progress["record_version"] == 1
    assert v12_progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in v12_progress["step_states"]
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
        "binding_id": "binding.development.auth.v13.executor-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "provider.executor.preflight.observed",
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }

    print(
        "DEVELOPMENT_AUTH_V13_CONTINUATION=PASS "
        "(v12 expired pristine with all steps pending/unexecuted/unconsumed; "
        "v13 binds unchanged v2 artifacts and restarts at bootstrap provider mutation; "
        "all v13 steps pending; provider_mutation_attempted=false)"
    )


if __name__ == "__main__":
    main()
