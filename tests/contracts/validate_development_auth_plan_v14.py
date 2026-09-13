#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v14 provider continuation without provider contact."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v14.approval.json"
V13_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.plan.json"
V13_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.approval.json"
V13_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v13.progress.json"
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "b78514b1-9fd6-4487-8da3-77d4598ef846"
EXPECTED_PROGRESS_ID = "258dcd9f-106a-4d25-8e28-8c0fa65ec62f"
EXPECTED_APPROVAL_ID = "d1840c61-40aa-4b64-b863-01e01db1e513"
EXPECTED_PLAN_DIGEST = "sha256:b419208260f0ab79c3e441e14fff2757dc98228b757912bdd13f3a7c380ecf79"
EXPECTED_APPROVAL_DIGEST = "sha256:4a7fc882a72d83e8f93fae933e9c1f8886e6347c10ef88942afa1966f1bc5099"
EXPECTED_PROGRESS_DIGEST = "sha256:628fed904bb468348b40d9478d921911ab808c5948599a6d0f3ed9618410ed4b"
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
    approval = load(APPROVAL_PATH)
    v13_plan = load(V13_PLAN_PATH)
    v13_approval = load(V13_APPROVAL_PATH)
    v13_progress = load(V13_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])

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

    print(
        "DEVELOPMENT_AUTH_V14_CONTINUATION=PASS "
        "(v13 expired pristine with all steps pending/unexecuted/unconsumed; "
        "v14 binds unchanged v2 artifacts and restarts at bootstrap provider mutation; "
        "all v14 steps pending; provider_mutation_attempted=false)"
    )


if __name__ == "__main__":
    main()
