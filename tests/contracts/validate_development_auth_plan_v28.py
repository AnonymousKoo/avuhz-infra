#!/usr/bin/env python3
"""Validate pristine DEVELOPMENT AUTH v28 dashboard-bundle preparation."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_SERVICE_AUDIENCE

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v28.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v28.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v28.approval.json"
OBSERVATION_PATH = BASE / "development-auth-v28-dashboard-bundle.observation.json"
V16_PATH = BASE / "development-auth-step1-v16-success.evidence.json"
V24_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
V26_PATH = BASE / "development-auth-step1-v26-success.evidence.json"
RETIREMENT_PATH = BASE / "development-auth-admin-bootstrap-retirement.evidence.json"
V27_APPROVAL_PATH = BASE / "development-auth-integration-v27.approval.json"
V27_PROGRESS_PATH = BASE / "development-auth-integration-v27.progress.json"
HOOK_SQL = ROOT / "supabase/provider-artifacts/development-auth/current/development_auth_custom_access_token_hook_v2.sql"

PLAN_ID = "d65f18e6-ef65-42a9-96c3-d50a037c4866"
PLAN_DIGEST = "sha256:dd5414b753903501a4a7998d854288611ac9195f3199c405c29eb865dbd2d3db"
PROGRESS_ID = "facbecc8-e60f-4f3c-9c74-21e81d65092a"
PROGRESS_DIGEST = "sha256:a3d4ebd27e3dc6f1328fdb02934f1e8764a61986428fdc0664eae83703018e3b"
STEP_ID = "development.auth.v28.step.01.create-exact-custom-access-token-hook-bundle"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-15T20:30:00Z"
WINDOW_END = "2026-09-16T02:30:00Z"
HOOK_FUNCTION = "public.avuhz_development_custom_access_token_hook_v1(jsonb)"
HOOK_URI = "pg-functions://postgres/public/avuhz_development_custom_access_token_hook_v1"
HOOK_CONFIG_DIGEST = "sha256:c73dbf937dc150d883c6abd4b6f3593ee77846fa067ce7ebf1bed9b7890e1602"
BUNDLE_DIGEST = "sha256:f3c5463a0a443e4290da202d47184cf65f8174cda05de5e7c7dd1b1717924025"
STATE_DIGEST = "sha256:974b40e7f289136e3a309017ba0205917dd6fb179d4479b148a14e806e1d244c"
OBSERVATION_DIGEST = "sha256:c377b5b6fe8d312a8f380d1bbbe718f19771bf3ea078a9395bdd9e308f2ff463"
HOOK_SQL_DIGEST = "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c"
V16_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
V24_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
V26_DIGEST = "sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba"
RETIREMENT_DIGEST = "sha256:9e310b6b114b4b4a2b71f35a6f9b6324231f3f071a2fdecc5d589d7b91e635ef"
V27_APPROVAL_RAW_DIGEST = "sha256:c9fae3414c77863904a5f28c912edfc78c9756f186c040258e551be708922e00"
V27_PROGRESS_RAW_DIGEST = "sha256:9eac24d7bba644402143d6085a88a968d0ca77937f8b64405a12b843c669a3b7"
APPROVAL_ID = "e0d2c051-50c5-4306-91ac-6ef5b81a062e"
APPROVAL_DIGEST = "sha256:9d645db0eeba77e7908989ee2c96bd34280ba9bf13de756e381aab3f55a28ad5"
APPROVAL_FILE_DIGEST = "sha256:45c9dce1f521bd734b608d5a62fdc69043dca02c00508bfb5d9c05fa799e0f5d"
APPROVED_AT = "2026-09-15T20:03:41Z"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    observation = load(OBSERVATION_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-16T02:29:59Z")

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 28
    assert plan["plan_digest"] == PLAN_DIGEST and plan_digest(plan) == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert DEVELOPMENT_AUTH_PROJECT_REF == PROJECT
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "issuer_reference": DEVELOPMENT_AUTH_ISSUER,
        "audience_reference": DEVELOPMENT_SERVICE_AUDIENCE,
    }
    assert plan["authorization_window"] == {"binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END}
    assert plan["ordered_step_ids"] == [STEP_ID]

    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 28,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": WINDOW_START,
        "expires_at": WINDOW_END,
        "approved_at": APPROVED_AT,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": APPROVAL_DIGEST,
    }
    assert approval_digest(approval) == APPROVAL_DIGEST
    assert APPROVED_AT < WINDOW_START

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID and step["ordinal"] == 1
    assert step["operation"] == "provider.auth-hook.create-exact-dashboard-bundle"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["credential_policy"] == {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"], "values_stored": False}
    assert step["resource"] == {
        "resource_type": "auth.hook-dashboard-mutation-bundle",
        "resource_reference": "hook.development.custom-access-token",
        "binding_state": "BOUND",
        "exact_version": "version.2",
        "exact_digest": BUNDLE_DIGEST,
    }
    assert step["dependency_step_ids"] == [] and step["unresolved_bindings"] == []
    assert step["required_evidence"] == [
        {"evidence_type": "hook.v2.disabled-acl.verified", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V16_DIGEST},
        {"evidence_type": "auth.synthetic-identity.tenant-metadata.bound", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V24_DIGEST},
        {"evidence_type": "server.capability-policy.verified", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V26_DIGEST},
        {"evidence_type": "auth.admin-bootstrap.credential-retired", "source_step_id": None, "binding_state": "BOUND", "exact_digest": RETIREMENT_DIGEST},
        {"evidence_type": "auth.hook-dashboard-bundle.observed", "source_step_id": None, "binding_state": "BOUND", "exact_digest": OBSERVATION_DIGEST},
    ]

    exact_config = {
        "hook_type": "custom_access_token",
        "hook_function": HOOK_FUNCTION,
        "hook_uri": HOOK_URI,
        "enabled": True,
        "environment": "DEVELOPMENT",
        "project_reference": PROJECT,
    }
    expected_bundle = {
        "dashboard_action": "create_auth_hook",
        "hook_configuration": exact_config,
        "permission_effects": [
            {"object": f"function:{HOOK_FUNCTION}", "principal": "supabase_auth_admin", "capability": "EXECUTE", "desired_state": "PRESENT"},
            {"object": "schema:public", "principal": "supabase_auth_admin", "capability": "USAGE", "desired_state": "PRESENT"},
            {"object": f"function:{HOOK_FUNCTION}", "principal": "authenticated", "capability": "EXECUTE", "desired_state": "ABSENT"},
            {"object": f"function:{HOOK_FUNCTION}", "principal": "anon", "capability": "EXECUTE", "desired_state": "ABSENT"},
            {"object": f"function:{HOOK_FUNCTION}", "principal": "public", "capability": "EXECUTE", "desired_state": "ABSENT"},
        ],
        "expected_net_permission_change": False,
    }
    expected_state = {
        "public_execute": False,
        "anon_execute": False,
        "authenticated_execute": False,
        "service_role_execute": False,
        "supabase_auth_admin_execute": True,
        "supabase_auth_admin_public_usage": True,
    }
    assert canonical_digest(exact_config) == HOOK_CONFIG_DIGEST
    assert raw_digest(OBSERVATION_PATH) == OBSERVATION_DIGEST
    assert observation["evidence_type"] == "auth.hook-dashboard-bundle.observed"
    assert observation["environment"] == "DEVELOPMENT" and observation["project_reference"] == PROJECT
    assert observation["provider_reference"] == "supabase"
    assert observation["observation_basis"] == "OWNER_INTERACTIVE_DASHBOARD_SCREEN_PLUS_READ_ONLY_PROVIDER_PREFLIGHT"
    assert observation["dashboard_action_cancelled"] is True
    assert observation["dashboard_bundle"] == expected_bundle
    assert canonical_digest(observation["dashboard_bundle"]) == BUNDLE_DIGEST
    assert observation["preflight_permission_state"] == expected_state
    assert canonical_digest(observation["preflight_permission_state"]) == STATE_DIGEST
    assert all(value is False for value in observation["security_state"].values())

    bindings = {item["binding_id"]: item for item in step["binding_declarations"]}
    for binding_id, digest in (
        ("binding.development.auth.v28.target-hook-configuration", HOOK_CONFIG_DIGEST),
        ("binding.development.auth.v28.target-hook-configuration.bundle", BUNDLE_DIGEST),
        ("binding.development.auth.v28.target-hook-configuration.state", STATE_DIGEST),
    ):
        item = bindings[binding_id]
        assert item["phase"] == "PREAPPROVAL_BOUND"
        assert item["value_class"] == "CONTENT_DIGEST"
        assert item["persistence_policy"] == "DIGEST_ONLY"
        assert item["preapproval_value"] == {"value": digest, "exact_digest": canonical_digest(digest)}
    assert bindings["binding.development.auth.v28.hook-configuration-preflight"]["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert bindings["binding.development.auth.v28.hook-enablement"]["phase"] == "PRODUCED_BY_CURRENT_STEP"

    for action in (
        "other-hook.enable", "hook-body.modify", "hook-function.modify", "function-owner.modify",
        "audience.widen", "authority-claim.emit", "identity.modify", "tenant-metadata.modify",
        "token.issue", "session.issue", "credential.create", "credential.reuse", "credential.persist",
        "credential.expose", "data.operation", "render.operation", "staging.target", "production.target",
        "unlisted-provider-effect", "permission-state.widen",
    ):
        assert action in step["prohibited_actions"]
        assert action in plan["prohibited_actions"]
    assert "function-acl.modify" not in step["prohibited_actions"]
    assert "function-acl.modify" not in plan["prohibited_actions"]
    for condition in ("dashboard-bundle.mismatch", "bound-state.mismatch", "hook-function.acl-drift"):
        assert condition in step["stop_conditions"]
        assert condition in plan["stop_conditions"]

    assert raw_digest(V16_PATH) == V16_DIGEST
    assert raw_digest(V24_PATH) == V24_DIGEST
    assert raw_digest(V26_PATH) == V26_DIGEST
    assert raw_digest(RETIREMENT_PATH) == RETIREMENT_DIGEST
    assert raw_digest(HOOK_SQL) == HOOK_SQL_DIGEST
    assert raw_digest(V27_APPROVAL_PATH) == V27_APPROVAL_RAW_DIGEST
    assert raw_digest(V27_PROGRESS_PATH) == V27_PROGRESS_RAW_DIGEST

    v27_approval = load(V27_APPROVAL_PATH)
    v27_progress = load(V27_PROGRESS_PATH)
    assert v27_approval["approval_id"] == "671bb3cb-3555-44a2-b7e3-17bcb04eeb03"
    assert v27_approval["decision"] == "APPROVE" and v27_approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert v27_progress["overall_state"] == "NOT_STARTED"
    v27_state = v27_progress["step_states"][0]
    assert v27_state["authorization_state"] == "PENDING"
    assert v27_state["execution_state"] == "NOT_STARTED"
    assert v27_state["verification_state"] == "NOT_STARTED"
    assert v27_state["authorization_consumed"] is False

    expected = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected
    assert progress["progress_digest"] == PROGRESS_DIGEST
    state = progress["step_states"][0]
    assert progress["overall_state"] == "NOT_STARTED"
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == [] and state["binding_assertions"] == []

    for path in (
        BASE / "development-auth-integration-v28.execution-progress.json",
        BASE / "development-auth-step1-v28-preflight.evidence.json",
        BASE / "development-auth-step1-v28-success.evidence.json",
    ):
        assert not path.exists()
    assert not list((ROOT / ".github/workflows").glob("*v28*"))

    print(
        "DEVELOPMENT_AUTH_V28_APPROVAL=PASS "
        "(exact owner approval persisted before effective time; exact observed dashboard bundle retained; OWNER_INTERACTIVE_SESSION only; pristine/unexecuted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
