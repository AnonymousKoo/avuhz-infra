#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v16 read-only Step 4 continuation and Step 1 authorization."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v16.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v16.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v16.execution-progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v16.approval.json"
PREFLIGHT_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-preflight.evidence.json"
V15_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.plan.json"
V15_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.approval.json"
V15_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.execution-progress.json"
STEP3_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step3-v15-success.evidence.json"

PLAN_ID = "c44a55d6-42e2-4b41-be8a-a497af163811"
PROGRESS_ID = "636742e7-6e24-4271-95ed-1836afdaf034"
PLAN_DIGEST = "sha256:efacd425b11952e4df7424ae01770db5fcc3307de80aa1c326c0dc9ed0c58e5d"
APPROVAL_DIGEST = "sha256:76b938dc5a3c87384d954eca694d9b9d8aeb863820362a7e6d57ebb8fe516237"
INITIAL_PROGRESS_DIGEST = "sha256:f43e64a508eb79df0a701de28f6eda68208fccf03a5392e952367cd473cf7003"
EXECUTION_PROGRESS_DIGEST = "sha256:030a65d4ecf777ca88270b3727988d813218bbe356a9b5ce9b138c6000b3b51e"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:f008475f6b174c54eece929b924c316f79f0be6f897e74ac45df389377c4f1d7"
PREFLIGHT_CONFIGURATION_DIGEST = "sha256:990910284aab8ac67043223aeed2131ceea31478290b74e1b47b673b13b84ad5"
V15_EXECUTION_DIGEST = "sha256:5317063acc230dc203273b6c28d65b36da5a83f7e0578f738bf44c7236a03e8e"
STEP3_EVIDENCE_DIGEST = "sha256:32ffeb323e266c113ce714a43a6daca651fcc0936c41439f4b13f65bf199c182"
STEP3_BINDING_VALUE_DIGEST = "sha256:cea84fe29540d8b0c08fec99efe94f84d652b0746ddea7cef386233a43222868"
PREAPPROVAL_DIGEST = "sha256:a9d687ae037ce577cee464b261f93d883d1d93da421cfa17c921a37411e16d91"
WINDOW_START = "2026-09-13T19:15:00Z"
WINDOW_END = "2026-09-13T22:15:00Z"
AUTHORIZED_AT = "2026-09-13T19:35:39Z"
STEP_ID = "development.auth.v16.step.01.verify-disabled-hook"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    preflight = load(PREFLIGHT_PATH)
    v15_plan = load(V15_PLAN_PATH)
    v15_approval = load(V15_APPROVAL_PATH)
    v15_execution = load(V15_EXECUTION_PATH)
    step3_evidence = load(STEP3_EVIDENCE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 16
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert len(plan["steps"]) == 1

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["ordinal"] == 1
    assert step["dependency_step_ids"] == []
    assert step["resource"] == {
        "resource_type": "database.function-and-acl",
        "resource_reference": "public.avuhz_development_custom_access_token_hook_v1(jsonb)",
        "binding_state": "BOUND",
        "exact_version": "version.1",
        "exact_digest": None,
    }
    assert step["operation"] == "provider.resource.verify-hosted-v2-disabled-and-acl"
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    for action in ("provider.mutation", "resource.repair", "hook.enable", "data.query"):
        assert action in step["prohibited_actions"]
    assert step["correction_reference"] == "correction.stop-for-owner-review"

    assert step["required_evidence"] == [{
        "evidence_type": "migration.identity.v2.seal.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": STEP3_EVIDENCE_DIGEST,
    }]
    preapproval = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["binding_id"] == "binding.development.auth.v16.v15-sealed-state"
    )
    assert preapproval["phase"] == "PREAPPROVAL_BOUND"
    assert preapproval["value_class"] == "CONTENT_DIGEST"
    assert preapproval["source_step_id"] is None
    assert preapproval["evidence_type"] is None
    assert preapproval["persistence_policy"] == "DIGEST_ONLY"
    assert preapproval["preapproval_value"] == {
        "value": STEP3_EVIDENCE_DIGEST,
        "exact_digest": PREAPPROVAL_DIGEST,
    }
    assert canonical_digest(STEP3_EVIDENCE_DIGEST) == PREAPPROVAL_DIGEST

    preflight_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["binding_id"] == "binding.development.auth.v16.hook-read-preflight"
    )
    assert preflight_declaration == {
        "binding_id": "binding.development.auth.v16.hook-read-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "hook.read-session.preflight.observed",
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }

    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_version"] == 16
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["effective_at"] == WINDOW_START
    assert approval["expires_at"] == WINDOW_END

    expected_initial = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_initial
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST
    state = progress["step_states"][0]
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []
    assert state["binding_assertions"] == []

    assert preflight["evidence_type"] == "hook.read-session.preflight.observed"
    assert preflight["observation_only"] is True
    assert preflight["environment"] == "DEVELOPMENT"
    assert preflight["provider_reference"] == "supabase"
    assert preflight["project_reference"] == "pwlhruwutoitnieactol"
    assert preflight["responsibility"] == "AUTH"
    assert preflight["plan_id"] == PLAN_ID
    assert preflight["plan_version"] == 16
    assert preflight["step_id"] == STEP_ID
    assert preflight["observed_at"] == AUTHORIZED_AT
    assert preflight["project_status"] == "ACTIVE_HEALTHY"
    assert preflight["project_region"] == "us-east-1"
    assert preflight["postgres_engine"] == "17"
    assert preflight["database_version"] == "17.6.1.166"
    assert preflight["source"] == {
        "source_method": "owner-dashboard-screenshot-plus-read-only-supabase-catalog-preflight",
        "source_scope": "DEVELOPMENT_AUTH_V16_STEP1_ONLY",
        "raw_provider_payload_retained": False,
        "credentials_retained": False,
        "dashboard_screenshot_committed": False,
        "provider_mutation_attempted": False,
    }
    assert preflight["database_observation"] == {
        "session_user": "postgres",
        "current_user": "postgres",
        "current_database": "postgres",
        "migration_identity": "avuhz_migration_service_dev",
        "role_attributes_exact": True,
        "bootstrap_admin_noset_membership_count": 1,
        "total_role_membership_edges": 1,
        "postgres_can_set_role": False,
        "migration_role_public_acl_count": 0,
        "provider_schema_privilege_count": 0,
        "table_privilege_count": 0,
    }
    assert preflight["hook_observation"] == {
        "hook_function": "public.avuhz_development_custom_access_token_hook_v1(jsonb)",
        "hook_function_exists": True,
        "hook_owner": "avuhz_migration_service_dev",
        "hook_security_invoker": True,
        "hook_stable": True,
        "hook_search_path_exact": True,
        "function_body_matches_certified_v2": True,
        "auth_admin_public_usage": True,
        "auth_admin_can_execute": True,
        "auth_admin_execute_acl_count": 1,
        "public_execute_acl_count": 0,
        "app_role_execute_acl_count": 0,
    }
    assert preflight["hosted_auth_observation"] == {
        "dashboard_project_reference": "pwlhruwutoitnieactol",
        "dashboard_project_label": "DEVELOPMENT AUTH",
        "auth_hooks_page_entries": 0,
        "custom_access_token_hook_configured": False,
        "custom_access_token_hook_enabled": False,
    }
    assert preflight["preflight_result"] == "PASS"
    assert preflight["evidence_digest"] == PREFLIGHT_EVIDENCE_DIGEST
    assert preflight["configuration_digest"] == PREFLIGHT_CONFIGURATION_DIGEST
    assert preflight["limitations"] == [
        "sanitized operator/tool observation evidence only",
        "dashboard screenshot is not persisted in the repository",
        "no provider mutation or repair is authorized by this evidence",
        "Step execution must re-confirm the exact database and hosted Auth-hook state immediately before consumption; mismatch is STOP",
    ]

    preflight_body = {
        key: value
        for key, value in preflight.items()
        if key not in {"evidence_digest", "configuration_digest"}
    }
    assert canonical_digest(preflight_body) == PREFLIGHT_EVIDENCE_DIGEST
    observed_configuration = {
        "project_reference": preflight["project_reference"],
        "session_user": preflight["database_observation"]["session_user"],
        "current_user": preflight["database_observation"]["current_user"],
        "current_database": preflight["database_observation"]["current_database"],
        "role_attributes_exact": preflight["database_observation"]["role_attributes_exact"],
        "bootstrap_admin_noset_membership_count": preflight["database_observation"]["bootstrap_admin_noset_membership_count"],
        "total_role_membership_edges": preflight["database_observation"]["total_role_membership_edges"],
        "postgres_can_set_role": preflight["database_observation"]["postgres_can_set_role"],
        "migration_role_public_acl_count": preflight["database_observation"]["migration_role_public_acl_count"],
        "provider_schema_privilege_count": preflight["database_observation"]["provider_schema_privilege_count"],
        "table_privilege_count": preflight["database_observation"]["table_privilege_count"],
        "hook_function_exists": preflight["hook_observation"]["hook_function_exists"],
        "hook_owner": preflight["hook_observation"]["hook_owner"],
        "hook_security_invoker": preflight["hook_observation"]["hook_security_invoker"],
        "hook_stable": preflight["hook_observation"]["hook_stable"],
        "hook_search_path_exact": preflight["hook_observation"]["hook_search_path_exact"],
        "function_body_matches_certified_v2": preflight["hook_observation"]["function_body_matches_certified_v2"],
        "auth_admin_public_usage": preflight["hook_observation"]["auth_admin_public_usage"],
        "auth_admin_can_execute": preflight["hook_observation"]["auth_admin_can_execute"],
        "auth_admin_execute_acl_count": preflight["hook_observation"]["auth_admin_execute_acl_count"],
        "public_execute_acl_count": preflight["hook_observation"]["public_execute_acl_count"],
        "app_role_execute_acl_count": preflight["hook_observation"]["app_role_execute_acl_count"],
        "auth_hooks_page_entries": preflight["hosted_auth_observation"]["auth_hooks_page_entries"],
        "custom_access_token_hook_configured": preflight["hosted_auth_observation"]["custom_access_token_hook_configured"],
        "custom_access_token_hook_enabled": preflight["hosted_auth_observation"]["custom_access_token_hook_enabled"],
    }
    assert canonical_digest(observed_configuration) == PREFLIGHT_CONFIGURATION_DIGEST

    preflight_assertion = {
        "binding_id": "binding.development.auth.v16.hook-read-preflight",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "hook.read-session.preflight.observed",
        "evidence_digest": PREFLIGHT_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": PREFLIGHT_CONFIGURATION_DIGEST,
        "recorded_at": AUTHORIZED_AT,
    }
    authorization_request = {
        "plan_id": PLAN_ID,
        "plan_version": 16,
        "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": STEP_ID,
        "resource_reference": "public.avuhz_development_custom_access_token_hook_v1(jsonb)",
        "resource_version": "version.1",
        "resource_digest": None,
        "operation": "provider.resource.verify-hosted-v2-disabled-and-acl",
        "execution_class": "PROVIDER_READ",
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [{
            "evidence_type": "migration.identity.v2.seal.verified",
            "evidence_digest": STEP3_EVIDENCE_DIGEST,
        }],
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
    assert execution_progress == expected_authorized
    assert execution_progress["record_version"] == 2
    assert execution_progress["overall_state"] == "IN_PROGRESS"
    assert execution_progress["updated_at"] == AUTHORIZED_AT
    assert execution_progress["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    authorized_state = execution_progress["step_states"][0]
    assert authorized_state["authorization_state"] == "AUTHORIZED"
    assert authorized_state["execution_state"] == "NOT_STARTED"
    assert authorized_state["verification_state"] == "NOT_STARTED"
    assert authorized_state["authorization_consumed"] is False
    assert authorized_state["evidence"] == []
    assert authorized_state["binding_assertions"] == [preflight_assertion]

    try:
        validate_approval(v15_plan, v15_approval, SCHEMA_ROOT, WINDOW_START)
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v15 authorization must remain expired")

    validate_progress(v15_plan, v15_execution, SCHEMA_ROOT)
    assert v15_execution["progress_digest"] == V15_EXECUTION_DIGEST
    assert v15_execution["overall_state"] == "IN_PROGRESS"
    for prior_state in v15_execution["step_states"][:3]:
        assert prior_state["authorization_state"] == "CONSUMED"
        assert prior_state["execution_state"] == "SUCCEEDED"
        assert prior_state["verification_state"] == "PASS"
        assert prior_state["authorization_consumed"] is True
    old_step4 = v15_execution["step_states"][3]
    assert old_step4["authorization_state"] == "PENDING"
    assert old_step4["execution_state"] == "NOT_STARTED"
    assert old_step4["verification_state"] == "NOT_STARTED"
    assert old_step4["authorization_consumed"] is False

    assert raw_digest(STEP3_EVIDENCE_PATH) == STEP3_EVIDENCE_DIGEST
    assert step3_evidence["evidence_type"] == "migration.identity.v2.seal.verified"
    assert step3_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert step3_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert step3_evidence["security_state"]["data_resource_touched"] is False
    assert step3_evidence["verification_observation"]["hook_enable_action_performed"] is False
    assert step3_evidence["verification_observation"]["final_service_level_disabled_verification_deferred_to_step4"] is True
    step3_state = v15_execution["step_states"][2]
    assert step3_state["evidence"] == [{
        "evidence_type": "migration.identity.v2.seal.verified",
        "evidence_reference": "provider.execution.v15.step3.attempt1.verified",
        "evidence_digest": STEP3_EVIDENCE_DIGEST,
        "recorded_at": "2026-09-13T18:05:06Z",
    }]
    seal_binding = next(
        assertion
        for assertion in step3_state["binding_assertions"]
        if assertion["binding_id"] == "binding.development.auth.v15.migration-identity-seal"
    )
    assert seal_binding["value_digest"] == STEP3_BINDING_VALUE_DIGEST

    for action in (
        "batch.mutation",
        "provider.mutation",
        "resource.repair",
        "data.operation",
        "production.target",
        "staging.target",
        "hook.enable",
        "synthetic-identity.operation",
        "token.issue",
        "v15.expired-authorization.execute",
        "v15.step4.execute",
    ):
        assert action in plan["prohibited_actions"]

    print(
        "DEVELOPMENT AUTH v16 Step 1 authorization: PASS "
        "(fresh read-only database/dashboard preflight bound; "
        "Step 1 AUTHORIZED/NOT_STARTED/unconsumed; provider mutation attempted=false)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
