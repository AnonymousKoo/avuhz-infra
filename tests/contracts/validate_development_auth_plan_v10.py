#!/usr/bin/env python3
"""Validate the DEVELOPMENT AUTH v10 continuation plan without provider contact."""
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
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.execution-progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v10.approval.json"
V9_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.plan.json"
V9_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.approval.json"
V9_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v9.execution-progress.json"
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"

EXPECTED_PLAN_ID = "9144fcbc-473d-4ee0-8e04-d880f352994e"
EXPECTED_PROGRESS_ID = "ca594b27-613a-4738-8228-e0e544f0aac6"
EXPECTED_APPROVAL_ID = "d43ce978-6127-4b57-a400-1f9a845da23c"
EXPECTED_PLAN_DIGEST = "sha256:603027e96c8a1e071ed3f06b26555b8cc9b7d66c49e7d5b0fe54f6929fd0b857"
EXPECTED_APPROVAL_DIGEST = "sha256:1597a8ec75f4d39647a0c4e579e1945f8d9e7b3065ef8c7a595b0ed2e07dcfc8"
EXPECTED_PROGRESS_DIGEST = "sha256:0f3ae68182cd9990912670889dad583b5ae5b571c84df10ac5553022d3b7caaf"
EXPECTED_EXECUTION_PROGRESS_DIGEST = "sha256:4edde2626da02ffcf27f714c48fe44d24038fdf8a6e28755983aa25f8071b9b9"
EXPECTED_FAILURE_DIGEST = "sha256:ac1cb15f824cb588465af4c390c3f93b2be41bb83698ea5e839e81cf0574b68f"
AUTHORIZED_AT = "2026-09-12T21:44:22Z"
EXPECTED_WINDOW = {
    "binding_state": "BOUND",
    "starts_at": "2026-09-12T21:25:00Z",
    "expires_at": "2026-09-13T00:25:00Z",
}
EXPECTED_ARTIFACT_DIGESTS = {
    BOOTSTRAP: "sha256:2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997",
    HOOK: "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c",
    SEAL: "sha256:712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733",
}
EXPECTED_PACKAGE_DIGEST = "sha256:e01c1f5faf66b031685abe61384dbe813082335dd270bb14e9eeecb05ba1cfc5"
EXPECTED_STEPS = [
    "development.auth.v10.step.01.local-hosted-membership-recertification",
    "development.auth.v10.step.02.bootstrap-migration-identity-v2",
    "development.auth.v10.step.03.apply-hook-migration-v2",
    "development.auth.v10.step.04.seal-migration-identity-v2",
    "development.auth.v10.step.05.verify-disabled-hook",
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
    v9_plan = load(V9_PLAN_PATH)
    v9_approval = load(V9_APPROVAL_PATH)
    v9_execution = load(V9_EXECUTION_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)

    assert plan["plan_id"] == EXPECTED_PLAN_ID
    assert plan["plan_version"] == 10
    assert plan["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == EXPECTED_WINDOW
    assert plan["ordered_step_ids"] == EXPECTED_STEPS
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert "v9.expired-authorization.execute" in plan["prohibited_actions"]

    assert approval["approval_id"] == EXPECTED_APPROVAL_ID
    assert approval["plan_id"] == EXPECTED_PLAN_ID
    assert approval["plan_version"] == 10
    assert approval["plan_digest"] == EXPECTED_PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["effective_at"] == EXPECTED_WINDOW["starts_at"]
    assert approval["expires_at"] == EXPECTED_WINDOW["expires_at"]
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == EXPECTED_APPROVAL_DIGEST

    expected_progress = initial_progress(
        plan, SCHEMA_ROOT, EXPECTED_PROGRESS_ID, plan["created_at"]
    )
    assert progress == expected_progress
    assert progress["progress_digest"] == EXPECTED_PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        for state in progress["step_states"]
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

    assert v9_execution["record_version"] == 4
    assert v9_execution["overall_state"] == "IN_PROGRESS"
    assert v9_execution["step_states"][0]["authorization_state"] == "CONSUMED"
    assert v9_execution["step_states"][0]["execution_state"] == "SUCCEEDED"
    assert v9_execution["step_states"][0]["verification_state"] == "PASS"
    assert v9_execution["step_states"][1]["authorization_state"] == "AUTHORIZED"
    assert v9_execution["step_states"][1]["execution_state"] == "NOT_STARTED"
    assert v9_execution["step_states"][1]["authorization_consumed"] is False

    try:
        validate_approval(v9_plan, v9_approval, SCHEMA_ROOT, EXPECTED_WINDOW["starts_at"])
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v9 approval must be expired before v10 becomes effective")

    authorization_request = {
        "plan_id": EXPECTED_PLAN_ID,
        "plan_version": 10,
        "plan_digest": EXPECTED_PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": EXPECTED_STEPS[0],
        "resource_reference": "development.auth.v10.hosted-membership-recertification",
        "resource_version": "version.20260912155200",
        "resource_digest": EXPECTED_PACKAGE_DIGEST,
        "operation": "local.migration.recertify-hosted-membership-correction",
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
    assert execution_progress == expected_authorized
    assert execution_progress["record_version"] == 2
    assert execution_progress["overall_state"] == "IN_PROGRESS"
    assert execution_progress["updated_at"] == AUTHORIZED_AT
    assert execution_progress["progress_digest"] == EXPECTED_EXECUTION_PROGRESS_DIGEST
    first_state = execution_progress["step_states"][0]
    assert first_state["authorization_state"] == "AUTHORIZED"
    assert first_state["execution_state"] == "NOT_STARTED"
    assert first_state["verification_state"] == "NOT_STARTED"
    assert first_state["authorization_consumed"] is False
    assert first_state["evidence"] == []
    assert first_state["binding_assertions"] == []
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
        "DEVELOPMENT_AUTH_V10_CONTINUATION=PASS "
        "(v9 immutable/expired; v10 Step 1 authorized only; not executed; "
        "authorization unconsumed; Steps 2-5 pending; provider_contact_attempted=false)"
    )


if __name__ == "__main__":
    main()
