#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v16 through final read-only Step 1 success."""
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
    record_step_outcome,
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
SUCCESS_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-success.evidence.json"
V15_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.plan.json"
V15_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.approval.json"
V15_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v15.execution-progress.json"
STEP3_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step3-v15-success.evidence.json"

PLAN_ID = "c44a55d6-42e2-4b41-be8a-a497af163811"
PROGRESS_ID = "636742e7-6e24-4271-95ed-1836afdaf034"
PLAN_DIGEST = "sha256:efacd425b11952e4df7424ae01770db5fcc3307de80aa1c326c0dc9ed0c58e5d"
APPROVAL_DIGEST = "sha256:76b938dc5a3c87384d954eca694d9b9d8aeb863820362a7e6d57ebb8fe516237"
INITIAL_PROGRESS_DIGEST = "sha256:f43e64a508eb79df0a701de28f6eda68208fccf03a5392e952367cd473cf7003"
AUTHORIZED_PROGRESS_DIGEST = "sha256:030a65d4ecf777ca88270b3727988d813218bbe356a9b5ce9b138c6000b3b51e"
SUCCESS_PROGRESS_DIGEST = "sha256:102766660c80b21fb5bc76d3fc67e15ad069af01b160059dba422c395726ac52"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:f008475f6b174c54eece929b924c316f79f0be6f897e74ac45df389377c4f1d7"
PREFLIGHT_CONFIGURATION_DIGEST = "sha256:990910284aab8ac67043223aeed2131ceea31478290b74e1b47b673b13b84ad5"
SUCCESS_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
DEPLOYED_STATE_DIGEST = "sha256:97f18e0a729762f9e9c7d72507a489aa828bbe03a138b25acfadcd72dd43a735"
DEPLOYED_STATE_VALUE_DIGEST = "sha256:2fc081713e1dd9288b6633eb484a80e157444241992588251f7f858fa06a0d9d"
V15_EXECUTION_DIGEST = "sha256:5317063acc230dc203273b6c28d65b36da5a83f7e0578f738bf44c7236a03e8e"
STEP3_EVIDENCE_DIGEST = "sha256:32ffeb323e266c113ce714a43a6daca651fcc0936c41439f4b13f65bf199c182"
STEP3_BINDING_VALUE_DIGEST = "sha256:cea84fe29540d8b0c08fec99efe94f84d652b0746ddea7cef386233a43222868"
PREAPPROVAL_DIGEST = "sha256:a9d687ae037ce577cee464b261f93d883d1d93da421cfa17c921a37411e16d91"
WINDOW_START = "2026-09-13T19:15:00Z"
WINDOW_END = "2026-09-13T22:15:00Z"
AUTHORIZED_AT = "2026-09-13T19:35:39Z"
OUTCOME_AT = "2026-09-13T19:51:40Z"
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
    success_evidence = load(SUCCESS_EVIDENCE_PATH)
    v15_plan = load(V15_PLAN_PATH)
    v15_approval = load(V15_APPROVAL_PATH)
    v15_execution = load(V15_EXECUTION_PATH)
    step3_evidence = load(STEP3_EVIDENCE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    for moment in (WINDOW_START, AUTHORIZED_AT, OUTCOME_AT):
        validate_approval(plan, approval, SCHEMA_ROOT, moment)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 16
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == "pwlhruwutoitnieactol"
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {"binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END}
    assert plan["ordered_step_ids"] == [STEP_ID]
    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == "provider.resource.verify-hosted-v2-disabled-and-acl"
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["expected_postcondition"] == ("Read-only verification proves only the bootstrap ADMIN/NOSET/NOINHERIT edge remains, postgres cannot SET ROLE, the migration role has no direct public or DATA authority, the hook owner/body/ACL match, and the hook is disabled.")
    for action in ("provider.mutation", "resource.repair", "hook.enable", "data.query"):
        assert action in step["prohibited_actions"]
    assert step["required_evidence"] == [{"evidence_type": "migration.identity.v2.seal.verified", "source_step_id": None, "binding_state": "BOUND", "exact_digest": STEP3_EVIDENCE_DIGEST}]
    preapproval = next(item for item in step["binding_declarations"] if item["binding_id"] == "binding.development.auth.v16.v15-sealed-state")
    assert preapproval["preapproval_value"] == {"value": STEP3_EVIDENCE_DIGEST, "exact_digest": PREAPPROVAL_DIGEST}
    assert canonical_digest(STEP3_EVIDENCE_DIGEST) == PREAPPROVAL_DIGEST
    assert next(item for item in step["produced_evidence"] if item["evidence_type"] == "hook.v2.disabled-acl.verified")["established_binding_ids"] == ["binding.development.auth.v16.hook-deployed-state"]

    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    expected_initial = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_initial
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST

    assert preflight["evidence_type"] == "hook.read-session.preflight.observed"
    assert preflight["preflight_result"] == "PASS"
    assert preflight["project_reference"] == "pwlhruwutoitnieactol"
    assert preflight["evidence_digest"] == PREFLIGHT_EVIDENCE_DIGEST
    assert preflight["configuration_digest"] == PREFLIGHT_CONFIGURATION_DIGEST
    preflight_assertion = {"binding_id": "binding.development.auth.v16.hook-read-preflight", "phase": "RESOLVED_BY_STEP_PREFLIGHT", "value_class": "CONFIGURATION_REFERENCE", "source_step_id": None, "evidence_type": "hook.read-session.preflight.observed", "evidence_digest": PREFLIGHT_EVIDENCE_DIGEST, "digest_policy": "REQUIRED", "persistence_policy": "DIGEST_ONLY", "sanitized_value": None, "value_digest": PREFLIGHT_CONFIGURATION_DIGEST, "recorded_at": AUTHORIZED_AT}
    authorization_request = {"plan_id": PLAN_ID, "plan_version": 16, "plan_digest": PLAN_DIGEST, "environment": "DEVELOPMENT", "provider_reference": "supabase", "project_reference": "pwlhruwutoitnieactol", "responsibility": "AUTH", "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1", "audience_reference": "audience.avuhz.command-service.development", "step_id": STEP_ID, "resource_reference": "public.avuhz_development_custom_access_token_hook_v1(jsonb)", "resource_version": "version.1", "resource_digest": None, "operation": "provider.resource.verify-hosted-v2-disabled-and-acl", "execution_class": "PROVIDER_READ", "credential_class": "OWNER_INTERACTIVE_SESSION", "required_evidence": [{"evidence_type": "migration.identity.v2.seal.verified", "evidence_digest": STEP3_EVIDENCE_DIGEST}], "prior_evidence_digests": [], "unexpected_remote_state": False, "extra_privileges": False, "unauthorized_migration_surface": False, "scope_expansion": False}
    expected_authorized = authorize_step(plan, approval, progress, authorization_request, SCHEMA_ROOT, AUTHORIZED_AT, trusted_preflight_assertions=[preflight_assertion])
    assert expected_authorized["progress_digest"] == AUTHORIZED_PROGRESS_DIGEST

    assert raw_digest(SUCCESS_EVIDENCE_PATH) == SUCCESS_EVIDENCE_DIGEST
    assert success_evidence["evidence_type"] == "hook.v2.disabled-acl.verified"
    assert success_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert success_evidence["project_reference"] == "pwlhruwutoitnieactol"
    provider = success_evidence["provider_observation"]
    assert provider["role_attributes_exact"] is True
    assert provider["bootstrap_admin_noset_membership_count"] == 1
    assert provider["temporary_set_membership_count"] == 0
    assert provider["total_role_membership_edges"] == 1
    assert provider["postgres_can_set_role"] is False
    assert provider["migration_role_public_acl_count"] == 0
    assert provider["provider_schema_privilege_count"] == 0
    assert provider["table_privilege_count"] == 0
    assert provider["hook_function_exists"] is True
    assert provider["hook_owner"] == "avuhz_migration_service_dev"
    assert provider["hook_security_invoker"] is True
    assert provider["hook_stable"] is True
    assert provider["hook_search_path_exact"] is True
    assert provider["function_body_matches_certified_v2"] is True
    assert provider["auth_admin_execute_acl_count"] == 1
    assert provider["public_execute_acl_count"] == 0
    assert provider["app_role_execute_acl_count"] == 0
    hosted = success_evidence["hosted_auth_observation"]
    assert hosted["auth_hooks_page_entries"] == 0
    assert hosted["custom_access_token_hook_configured"] is False
    assert hosted["custom_access_token_hook_enabled"] is False
    assert hosted["dashboard_screenshot_committed"] is False
    verification = success_evidence["verification_observation"]
    assert verification["provider_read_only"] is True
    assert verification["provider_mutation_attempts"] == 0
    assert verification["provider_mutation_committed"] is False
    assert verification["database_state_verified"] is True
    assert verification["hosted_auth_state_verified"] is True
    assert verification["postcondition_verified"] is True
    assert verification["hook_enable_action_performed"] is False
    assert verification["deployed_state_digest"] == DEPLOYED_STATE_DIGEST
    security = success_evidence["security_state"]
    assert security["credential_retained"] is False and security["raw_provider_payload_retained"] is False
    assert security["pii_retained"] is False and security["data_resource_touched"] is False
    assert security["dashboard_screenshot_committed"] is False and security["hook_enable_action_performed"] is False
    assert success_evidence["recorded_at"] == OUTCOME_AT

    deployed_state = {"project_reference": "pwlhruwutoitnieactol", "migration_role_attributes_exact": provider["role_attributes_exact"], "bootstrap_admin_noset_noinherit_edges": provider["bootstrap_admin_noset_membership_count"], "total_role_membership_edges": provider["total_role_membership_edges"], "postgres_can_set_role": provider["postgres_can_set_role"], "migration_role_direct_public_acl_count": provider["migration_role_public_acl_count"], "migration_role_auth_storage_direct_acl_count": provider["provider_schema_privilege_count"], "migration_role_table_privilege_count": provider["table_privilege_count"], "hook_function_exists": provider["hook_function_exists"], "hook_owner": provider["hook_owner"], "hook_security_invoker": provider["hook_security_invoker"], "hook_stable": provider["hook_stable"], "hook_search_path_exact": provider["hook_search_path_exact"], "function_body_matches_certified_v2": provider["function_body_matches_certified_v2"], "auth_admin_execute_acl_count": provider["auth_admin_execute_acl_count"], "public_execute_acl_count": provider["public_execute_acl_count"], "app_role_execute_acl_count": provider["app_role_execute_acl_count"], "custom_access_token_hook_configured": hosted["custom_access_token_hook_configured"], "custom_access_token_hook_enabled": hosted["custom_access_token_hook_enabled"]}
    assert canonical_digest(deployed_state) == DEPLOYED_STATE_DIGEST
    assert canonical_digest(DEPLOYED_STATE_DIGEST) == DEPLOYED_STATE_VALUE_DIGEST

    outcome_evidence = [{"evidence_type": "hook.v2.disabled-acl.verified", "evidence_reference": "provider.execution.v16.step1.attempt1.verified", "evidence_digest": SUCCESS_EVIDENCE_DIGEST, "recorded_at": OUTCOME_AT}]
    deployed_state_binding = {"binding_id": "binding.development.auth.v16.hook-deployed-state", "phase": "PRODUCED_BY_CURRENT_STEP", "value_class": "CONTENT_DIGEST", "source_step_id": None, "evidence_type": "hook.v2.disabled-acl.verified", "evidence_digest": SUCCESS_EVIDENCE_DIGEST, "digest_policy": "REQUIRED", "persistence_policy": "DIGEST_ONLY", "sanitized_value": None, "value_digest": DEPLOYED_STATE_VALUE_DIGEST, "recorded_at": OUTCOME_AT}
    expected_success = record_step_outcome(plan, approval, expected_authorized, STEP_ID, "SUCCEEDED", "PASS", outcome_evidence, step["expected_postcondition"], None, SCHEMA_ROOT, OUTCOME_AT, binding_assertions=[deployed_state_binding])
    assert execution_progress == expected_success
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "COMPLETED"
    assert execution_progress["progress_digest"] == SUCCESS_PROGRESS_DIGEST
    state = execution_progress["step_states"][0]
    assert state["authorization_state"] == "CONSUMED" and state["execution_state"] == "SUCCEEDED" and state["verification_state"] == "PASS"
    assert state["authorization_consumed"] is True and state["safe_error_code"] is None
    assert state["evidence"] == outcome_evidence
    assert state["binding_assertions"] == [preflight_assertion, deployed_state_binding]

    try:
        validate_approval(v15_plan, v15_approval, SCHEMA_ROOT, WINDOW_START)
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v15 authorization must remain expired")
    validate_progress(v15_plan, v15_execution, SCHEMA_ROOT)
    assert v15_execution["progress_digest"] == V15_EXECUTION_DIGEST
    assert raw_digest(STEP3_EVIDENCE_PATH) == STEP3_EVIDENCE_DIGEST
    assert step3_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    seal_binding = next(item for item in v15_execution["step_states"][2]["binding_assertions"] if item["binding_id"] == "binding.development.auth.v15.migration-identity-seal")
    assert seal_binding["value_digest"] == STEP3_BINDING_VALUE_DIGEST

    for action in ("batch.mutation", "provider.mutation", "resource.repair", "data.operation", "production.target", "staging.target", "hook.enable", "synthetic-identity.operation", "token.issue", "v15.expired-authorization.execute", "v15.step4.execute"):
        assert action in plan["prohibited_actions"]
    print("DEVELOPMENT AUTH v16 final verification: PASS (Step 1 consumed/succeeded/pass; database and hosted Auth-hook state verified; hook disabled; provider mutation attempted=false; DEVELOPMENT DATA untouched)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
