#!/usr/bin/env python3
"""Validate pristine DEVELOPMENT AUTH v27 exact hook-enablement preparation."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_SERVICE_AUDIENCE

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v27.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v27.progress.json"
V16_PATH = BASE / "development-auth-step1-v16-success.evidence.json"
V24_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
V26_PATH = BASE / "development-auth-step1-v26-success.evidence.json"
RETIREMENT_PATH = BASE / "development-auth-admin-bootstrap-retirement.evidence.json"
HOOK_SQL = ROOT / "supabase/provider-artifacts/development-auth/current/development_auth_custom_access_token_hook_v2.sql"

PLAN_ID = "cf30c352-08f2-4d17-98e5-9dbc5edc103e"
PLAN_DIGEST = "sha256:9d2ab111c08ed6455b847c578eb6aa949cee12707ccb104e666e5fbe7b08c1c6"
PROGRESS_ID = "5b3bd835-ceb8-4f14-b8a2-02e52487d4d2"
PROGRESS_DIGEST = "sha256:001d3d0dfd7d714ac7ae68da3d864014b658b76f4a09a0a0ba93939636b9233a"
STEP_ID = "development.auth.v27.step.01.enable-exact-custom-access-token-hook"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-15T18:30:00Z"
WINDOW_END = "2026-09-16T00:30:00Z"
HOOK_FUNCTION = "public.avuhz_development_custom_access_token_hook_v1(jsonb)"
HOOK_URI = "pg-functions://postgres/public/avuhz_development_custom_access_token_hook_v1"
HOOK_CONFIG_DIGEST = "sha256:c73dbf937dc150d883c6abd4b6f3593ee77846fa067ce7ebf1bed9b7890e1602"
HOOK_SQL_DIGEST = "sha256:facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c"
V16_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
V24_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
V26_DIGEST = "sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba"
RETIREMENT_DIGEST = "sha256:9e310b6b114b4b4a2b71f35a6f9b6324231f3f071a2fdecc5d589d7b91e635ef"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 27
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

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID and step["ordinal"] == 1
    assert step["operation"] == "provider.auth-hook.enable-exact"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["credential_policy"] == {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"], "values_stored": False}
    assert step["resource"] == {
        "resource_type": "auth.hook-configuration",
        "resource_reference": "hook.development.custom-access-token",
        "binding_state": "BOUND",
        "exact_version": "version.1",
        "exact_digest": HOOK_CONFIG_DIGEST,
    }
    assert step["dependency_step_ids"] == [] and step["unresolved_bindings"] == []
    assert step["required_evidence"] == [
        {"evidence_type": "hook.v2.disabled-acl.verified", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V16_DIGEST},
        {"evidence_type": "auth.synthetic-identity.tenant-metadata.bound", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V24_DIGEST},
        {"evidence_type": "server.capability-policy.verified", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V26_DIGEST},
        {"evidence_type": "auth.admin-bootstrap.credential-retired", "source_step_id": None, "binding_state": "BOUND", "exact_digest": RETIREMENT_DIGEST},
    ]

    exact_config = {
        "hook_type": "custom_access_token",
        "hook_function": HOOK_FUNCTION,
        "hook_uri": HOOK_URI,
        "enabled": True,
        "environment": "DEVELOPMENT",
        "project_reference": PROJECT,
    }
    assert canonical_digest(exact_config) == HOOK_CONFIG_DIGEST
    target = next(x for x in step["binding_declarations"] if x["binding_id"] == "binding.development.auth.v27.target-hook-configuration")
    assert target["phase"] == "PREAPPROVAL_BOUND"
    assert target["value_class"] == "CONTENT_DIGEST"
    assert target["preapproval_value"] == {"value": HOOK_CONFIG_DIGEST, "exact_digest": canonical_digest(HOOK_CONFIG_DIGEST)}
    preflight = next(x for x in step["binding_declarations"] if x["binding_id"] == "binding.development.auth.v27.hook-configuration-preflight")
    assert preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT" and preflight["persistence_policy"] == "DIGEST_ONLY"
    produced = next(x for x in step["binding_declarations"] if x["binding_id"] == "binding.development.auth.v27.hook-enablement")
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP" and produced["evidence_type"] == "hook.enablement.verified"

    for action in (
        "other-hook.enable", "hook-body.modify", "hook-function.modify", "function-owner.modify", "function-acl.modify",
        "audience.widen", "authority-claim.emit", "identity.modify", "tenant-metadata.modify", "token.issue", "session.issue",
        "credential.create", "credential.reuse", "credential.persist", "credential.expose", "data.operation", "render.operation",
        "staging.target", "production.target",
    ):
        assert action in step["prohibited_actions"]
        assert action in plan["prohibited_actions"]

    assert raw_digest(V16_PATH) == V16_DIGEST
    assert raw_digest(V24_PATH) == V24_DIGEST
    assert raw_digest(V26_PATH) == V26_DIGEST
    assert raw_digest(RETIREMENT_PATH) == RETIREMENT_DIGEST
    assert raw_digest(HOOK_SQL) == HOOK_SQL_DIGEST

    v16 = load(V16_PATH)
    assert v16["evidence_type"] == "hook.v2.disabled-acl.verified"
    assert v16["hosted_auth_observation"]["custom_access_token_hook_configured"] is False
    assert v16["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False
    provider = v16["provider_observation"]
    assert provider["hook_function_exists"] is True
    assert provider["function_body_matches_certified_v2"] is True
    assert provider["hook_owner"] == "avuhz_migration_service_dev"
    assert provider["auth_admin_can_execute"] is True
    assert provider["public_execute_acl_count"] == 0 and provider["app_role_execute_acl_count"] == 0

    v24 = load(V24_PATH)
    assert v24["evidence_type"] == "auth.synthetic-identity.tenant-metadata.bound"
    assert v24["verification_observation"]["tenant_metadata_postcondition_verified"] is True
    assert v24["security_state"]["hook_enable_action_performed"] is False

    v26 = load(V26_PATH)
    assert v26["evidence_type"] == "server.capability-policy.verified"
    assert v26["verification_observation"]["exact_tuple_verified"] is True
    assert v26["verification_observation"]["allowlist_entry_count_verified"] is True
    assert v26["security_state"]["hook_enable_action_performed"] is False

    retirement = load(RETIREMENT_PATH)
    assert retirement["outcome"] == "RETIRED"
    assert retirement["project_reference"] == PROJECT
    assert retirement["provider_secret_key_deletion"]["status"] == "OWNER_CONFIRMED_DELETED"
    assert retirement["github_environment_binding"]["status"] == "VERIFIED_ABSENT"
    assert retirement["local_temp_secret_material"]["status"] == "VERIFIED_ABSENT"
    assert retirement["security_state"]["credential_material_observed_by_control_plane"] is False

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

    assert not (BASE / "development-auth-integration-v27.approval.json").exists()
    assert not (BASE / "development-auth-integration-v27.execution-progress.json").exists()
    assert not (BASE / "development-auth-step1-v27-preflight.evidence.json").exists()
    assert not (BASE / "development-auth-step1-v27-success.evidence.json").exists()
    assert not list((ROOT / ".github/workflows").glob("*v27*"))

    print(
        "DEVELOPMENT_AUTH_V27_PREPARED=PASS "
        "(exact hook target digest-bound; OWNER_INTERACTIVE_SESSION only; pristine/unapproved/unexecuted; retired bootstrap credential cannot be reused)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
