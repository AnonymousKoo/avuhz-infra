#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v24 through verified tenant-metadata persistence."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    authorize_step,
    initial_progress,
    plan_digest,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v24.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v24.progress.json"
EXECUTION_PATH = BASE / "development-auth-integration-v24.execution-progress.json"
PREFLIGHT_PATH = BASE / "development-auth-step1-v24-preflight.evidence.json"
SUCCESS_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
APPROVAL_PATH = BASE / "development-auth-integration-v24.approval.json"
V21_SUCCESS_PATH = BASE / "development-auth-step1-v21-success.evidence.json"
V16_SUCCESS_PATH = BASE / "development-auth-step1-v16-success.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v24-tenant-metadata-execution.yml"
READ_ONLY_REFERENCE_PATH = ROOT / ".github/workflows/d4c4d2c-read-only-certification.yml"

PLAN_ID = "777a4d74-d56d-4ba2-b16b-5ce7ea79b7b1"
PLAN_VERSION = 24
PLAN_DIGEST = "sha256:90a85d960741ecc74559774d1b946a71297a1c837c3230fafd55e392bf908719"
STEP_ID = "development.auth.v24.step.01.bind-synthetic-tenant-app-metadata"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
WINDOW_START = "2026-09-15T00:00:00Z"
WINDOW_END = "2026-09-15T03:00:00Z"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TARGET_METADATA_DIGEST = "sha256:cd89c12abf5ed8c3dc03f4766a6d7cd9f1b8388b9e98468e9673233550a910a6"
V21_SUCCESS_DIGEST = "sha256:16fbd6f2b1b779a4879f9eca7b5469267822884740dab7a02d3a0f8c7211fffa"
V16_SUCCESS_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
HOOK_SIGNATURE = "public.avuhz_development_custom_access_token_hook_v1(jsonb)"
PROVIDER_READ_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"
AUTH_ADMIN_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_ADMIN_EPHEMERAL"
PROGRESS_ID = "546152c1-e32d-44b8-b3be-aca5cc1489cb"
APPROVAL_DIGEST = "sha256:e0e2aaf98920bde28e5cd3e070adf7b8ac262832067f0f04191f0fe09028e223"
INITIAL_PROGRESS_DIGEST = "sha256:f86884c6ddd1d73f3604f64154f250b2b70ea9640e7e196c227f8be4b6b3b4ef"
AUTHORIZED_PROGRESS_DIGEST = "sha256:33abfbac1460c39798b3c012a956efb28319eb6423b4b18bc919a7bd54e0d092"
SUCCESS_PROGRESS_DIGEST = "sha256:1e0a008dab126f6922503071e29324074cd9a7ca49536947864543bfd2fd0d01"
BASELINE_METADATA_DIGEST = "sha256:5b0bfedb37484704aa0240dc706cc13b4d6c47f967a417f4babd5dc4bc10ad65"
CAP_CONFIG_DIGEST = "sha256:007ed4605dcc1245eb0ad6b7b37e85441195c95232dd6e617dd5cca27aa5262d"
CAP_EVIDENCE_DIGEST = "sha256:8842d29d21bb8a8de11c11e64cc79ce8ef07ae7b096082185ca46d46b0aafd8d"
LIVE_CONFIG_DIGEST = "sha256:8cb75569e341a77ec6212b537cf8c051a302f16cdd444122e4e7a58c1715deef"
LIVE_EVIDENCE_DIGEST = "sha256:2ae1053953068a6b2d3dc90aacb9a3100f01b230eac3962fd13dde185d55e52e"
META_CONFIG_DIGEST = "sha256:90b58119c0502d197314ffc69265550eb300fa75bcec73e213849fa7fc38b7fe"
META_EVIDENCE_DIGEST = "sha256:e998bde6e56511e9604feee5e153be9a5f90408ff0e49ba17481785d8fdafd51"
PREFLIGHT_RAW_DIGEST = "sha256:0b6f4f45173d9dce5f80984c79e7be56350668b3cab0620871d392aed71e160a"
SUCCESS_EVIDENCE_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
EXECUTION_CONFIG_DIGEST = "sha256:a8a8b79ce4c1d0c6ff78d842cb7ad14cebf979a948f3d373d24c8269b79042c5"
RUN_ID = 34918764216
RUN_SHA = "0a48268a5f37e863c75a195a4c1a8226e2275d63"
AUTH_AT = "2026-09-15T01:49:23Z"
OUTCOME_AT = "2026-09-15T01:49:24Z"

BASELINE_APP_METADATA = {"provider": "email", "providers": ["email"]}

TARGET_APP_METADATA = {
    "provider": "email",
    "providers": ["email"],
    "avuhz_tenant_id": TENANT_ID,
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def component_digest(value: dict) -> str:
    body = dict(value)
    body.pop("evidence_digest")
    return canonical_digest(body)


def declaration(step: dict, binding_id: str) -> dict:
    matches = [
        item for item in step["binding_declarations"]
        if item["binding_id"] == binding_id
    ]
    assert len(matches) == 1, binding_id
    return matches[0]


def main() -> int:
    plan = load(PLAN_PATH)
    validate_plan(plan, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == PLAN_VERSION
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan_digest(plan) == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "issuer_reference": f"https://{PROJECT}.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert len(plan["steps"]) == 1

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["ordinal"] == 1
    assert step["operation"] == "provider.auth-identity.app-metadata.bind-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["resource"]["resource_reference"] == "identity.development.synthetic-avuhz"
    assert step["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert step["credential_policy"]["values_stored"] is False
    assert step["unresolved_bindings"] == []

    required = {
        item["evidence_type"]: item["exact_digest"]
        for item in step["required_evidence"]
    }
    assert required == {
        "auth.synthetic-identity.created": V21_SUCCESS_DIGEST,
        "hook.v2.disabled-acl.verified": V16_SUCCESS_DIGEST,
    }

    for required_stop in (
        "identity.session-state.drift",
        "identity.refresh-token-state.drift",
        "hook.state.drift",
        "hook.acl.drift",
        "hosted-auth.config.drift",
        "provider-read.preflight.failed",
        "credential-material.observed",
    ):
        assert required_stop in step["stop_conditions"]

    for prohibited in (
        "read-only-preflight.bypass",
        "v23.credential.reuse",
    ):
        assert prohibited in step["prohibited_actions"]
        assert prohibited in plan["prohibited_actions"]

    subject = declaration(step, "binding.development.auth.v24.synthetic-subject-digest")
    assert subject["phase"] == "PREAPPROVAL_BOUND"
    assert subject["persistence_policy"] == "DIGEST_ONLY"
    assert subject["preapproval_value"]["value"] == SUBJECT_DIGEST
    assert subject["preapproval_value"]["exact_digest"] == canonical_digest(SUBJECT_DIGEST)

    tenant = declaration(step, "binding.development.auth.v24.canonical-tenant")
    assert tenant["phase"] == "PREAPPROVAL_BOUND"
    assert tenant["persistence_policy"] == "SANITIZED_VALUE_ALLOWED"
    assert tenant["preapproval_value"]["value"] == TENANT_ID
    assert tenant["preapproval_value"]["exact_digest"] == canonical_digest(TENANT_ID)

    metadata = declaration(step, "binding.development.auth.v24.target-app-metadata")
    assert canonical_digest(TARGET_APP_METADATA) == TARGET_METADATA_DIGEST
    assert metadata["preapproval_value"]["value"] == TARGET_METADATA_DIGEST
    assert metadata["preapproval_value"]["exact_digest"] == canonical_digest(TARGET_METADATA_DIGEST)

    capability = declaration(step, "binding.development.auth.v24.admin-executor-capability")
    assert capability["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert capability["evidence_type"] == "auth.admin-executor-capability.observed"

    live_preflight = declaration(step, "binding.development.auth.v24.live-read-only-preflight")
    assert live_preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert live_preflight["evidence_type"] == "auth.synthetic-identity.live-preflight.observed"
    assert live_preflight["persistence_policy"] == "DIGEST_ONLY"

    metadata_preflight = declaration(step, "binding.development.auth.v24.tenant-metadata-preflight")
    assert metadata_preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert metadata_preflight["evidence_type"] == "auth.synthetic-identity.tenant-metadata-preflight.observed"

    produced = declaration(step, "binding.development.auth.v24.tenant-metadata")
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["evidence_type"] == "auth.synthetic-identity.tenant-metadata.bound"

    v21 = load(V21_SUCCESS_PATH)
    assert raw_digest(V21_SUCCESS_PATH) == V21_SUCCESS_DIGEST
    assert v21["outcome"] == "SUCCEEDED_VERIFIED"
    provider = v21["provider_observation"]
    assert provider["auth_user_count"] == 1
    assert provider["synthetic_identity_match_count"] == 1
    assert provider["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert provider["synthetic_email_confirmed"] is True
    assert provider["app_metadata_exact_provider_shape"] is True
    assert provider["session_count"] == 0
    assert provider["refresh_token_count"] == 0

    v16 = load(V16_SUCCESS_PATH)
    assert raw_digest(V16_SUCCESS_PATH) == V16_SUCCESS_DIGEST
    assert v16["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16["project_reference"] == PROJECT
    hook = v16["provider_observation"]
    assert hook["hook_function_exists"] is True
    assert hook["hook_owner"] == "avuhz_migration_service_dev"
    assert hook["hook_schema"] == "public"
    assert hook["hook_arguments"] == "event jsonb"
    assert hook["hook_result"] == "jsonb"
    assert hook["hook_security_invoker"] is True
    assert hook["hook_stable"] is True
    assert hook["hook_search_path_exact"] is True
    assert hook["auth_admin_execute_acl_count"] == 1
    assert hook["public_execute_acl_count"] == 0
    assert hook["app_role_execute_acl_count"] == 0
    hosted = v16["hosted_auth_observation"]
    assert hosted["dashboard_project_reference"] == PROJECT
    assert hosted["auth_hooks_page_entries"] == 0
    assert hosted["custom_access_token_hook_configured"] is False
    assert hosted["custom_access_token_hook_enabled"] is False

    assert PROGRESS_PATH.exists(), "v24 progress artifact is required before PR gate"
    progress = load(PROGRESS_PATH)
    validate_progress(plan, progress, SCHEMA_ROOT)
    expected_progress = initial_progress(
        plan,
        SCHEMA_ROOT,
        progress["progress_id"],
        plan["created_at"],
    )
    assert progress == expected_progress
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert state["step_id"] == STEP_ID
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []
    assert state["binding_assertions"] == []

    approval = load(APPROVAL_PATH)
    for moment in (WINDOW_START, AUTH_AT, OUTCOME_AT):
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_version"] == PLAN_VERSION
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == WINDOW_START
    assert approval["expires_at"] == WINDOW_END
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"

    assert progress["progress_id"] == PROGRESS_ID
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST

    preflight = load(PREFLIGHT_PATH)
    assert raw_digest(PREFLIGHT_PATH) == PREFLIGHT_RAW_DIGEST
    assert preflight["observation_only"] is True
    assert preflight["plan_id"] == PLAN_ID and preflight["plan_version"] == 24
    assert preflight["project_reference"] == PROJECT
    assert preflight["step_id"] == STEP_ID
    capability_observation = preflight["capability_attestation"]
    live_observation = preflight["live_read_only_preflight"]
    metadata_observation = preflight["tenant_metadata_preflight"]
    for observed, expected_type, expected_digest in (
        (capability_observation, "auth.admin-executor-capability.observed", CAP_EVIDENCE_DIGEST),
        (live_observation, "auth.synthetic-identity.live-preflight.observed", LIVE_EVIDENCE_DIGEST),
        (metadata_observation, "auth.synthetic-identity.tenant-metadata-preflight.observed", META_EVIDENCE_DIGEST),
    ):
        assert observed["evidence_type"] == expected_type
        assert observed["source"]["workflow_run_id"] == RUN_ID
        assert observed["source"]["workflow_head_sha"] == RUN_SHA
        assert observed["source"]["workflow_conclusion"] == "success"
        assert observed["source"]["provider_mutation_attempted"] is False
        assert observed["source"]["credential_material_observed_by_control_plane"] is False
        assert observed["result"] == "PASS"
        assert observed["evidence_digest"] == expected_digest
        assert component_digest(observed) == expected_digest

    cap_config = {
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "credential_shape": "sb_secret_*",
        "project_reference": PROJECT,
        "workflow_environment": "development",
    }
    assert canonical_digest(cap_config) == CAP_CONFIG_DIGEST
    assert capability_observation["configuration_digest"] == CAP_CONFIG_DIGEST

    live_keys = (
        "project_reference", "read_only_execution_identity", "auth_user_count",
        "synthetic_identity_match_count", "synthetic_subject_digest",
        "synthetic_email_confirmed", "user_metadata_exact_provider_shape",
        "app_metadata_exact_pretenant_shape", "session_count", "refresh_token_count",
        "hosted_auth_custom_access_token_hook_disabled",
        "hosted_auth_custom_access_token_hook_unconfigured", "hook_function_exists",
        "hook_owner", "hook_security_invoker", "hook_stable", "hook_search_path_exact",
        "hook_function_body_verified", "auth_admin_execute_acl_count",
        "public_execute_acl_count", "app_role_execute_acl_count",
    )
    assert canonical_digest({key: live_observation[key] for key in live_keys}) == LIVE_CONFIG_DIGEST
    assert live_observation["configuration_digest"] == LIVE_CONFIG_DIGEST
    assert live_observation["read_only_execution_identity"] == "supabase_read_only_user"
    assert live_observation["auth_user_count"] == 1
    assert live_observation["synthetic_identity_match_count"] == 1
    assert live_observation["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert live_observation["session_count"] == 0 and live_observation["refresh_token_count"] == 0
    assert live_observation["hook_owner"] == "avuhz_migration_service_dev"
    assert live_observation["auth_admin_execute_acl_count"] == 1
    assert live_observation["public_execute_acl_count"] == 0
    assert live_observation["app_role_execute_acl_count"] == 0

    metadata_keys = (
        "project_reference", "synthetic_subject_digest", "baseline_app_metadata_digest",
        "target_app_metadata_digest", "canonical_tenant_id", "identity_count",
        "user_metadata_unchanged_required", "email_unchanged_required",
        "role_unchanged_required",
    )
    assert canonical_digest({key: metadata_observation[key] for key in metadata_keys}) == META_CONFIG_DIGEST
    assert canonical_digest(BASELINE_APP_METADATA) == BASELINE_METADATA_DIGEST
    assert metadata_observation["configuration_digest"] == META_CONFIG_DIGEST
    assert metadata_observation["baseline_app_metadata_digest"] == BASELINE_METADATA_DIGEST
    assert metadata_observation["target_app_metadata_digest"] == TARGET_METADATA_DIGEST
    assert metadata_observation["canonical_tenant_id"] == TENANT_ID
    assert metadata_observation["identity_count"] == 1

    preflight_security = preflight["security_state"]
    for key in (
        "credential_material_retained_by_execution_artifacts",
        "credential_material_observed_by_control_plane", "raw_provider_payload_retained",
        "raw_provider_subject_retained", "pii_retained", "provider_mutation_attempted",
        "data_resource_touched", "render_touched",
    ):
        assert preflight_security[key] is False, key
    assert preflight_security["ephemeral_admin_secret_retirement_pending"] is True

    assertions = []
    for binding_id, observed in (
        ("binding.development.auth.v24.admin-executor-capability", capability_observation),
        ("binding.development.auth.v24.live-read-only-preflight", live_observation),
        ("binding.development.auth.v24.tenant-metadata-preflight", metadata_observation),
    ):
        binding = declaration(step, binding_id)
        assertions.append({
            "binding_id": binding_id,
            "phase": binding["phase"],
            "value_class": binding["value_class"],
            "source_step_id": None,
            "evidence_type": binding["evidence_type"],
            "evidence_digest": observed["evidence_digest"],
            "digest_policy": binding["digest_policy"],
            "persistence_policy": binding["persistence_policy"],
            "sanitized_value": None,
            "value_digest": observed["configuration_digest"],
            "recorded_at": AUTH_AT,
        })

    request = {
        "plan_id": PLAN_ID, "plan_version": 24, "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT", "provider_reference": "supabase",
        "project_reference": PROJECT, "responsibility": "AUTH",
        "issuer_reference": f"https://{PROJECT}.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": STEP_ID, "resource_reference": "identity.development.synthetic-avuhz",
        "resource_version": "version.1", "resource_digest": None,
        "operation": "provider.auth-identity.app-metadata.bind-one",
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": [
            {"evidence_type": "auth.synthetic-identity.created", "evidence_digest": V21_SUCCESS_DIGEST},
            {"evidence_type": "hook.v2.disabled-acl.verified", "evidence_digest": V16_SUCCESS_DIGEST},
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False, "extra_privileges": False,
        "unauthorized_migration_surface": False, "scope_expansion": False,
    }
    authorized = authorize_step(
        plan, approval, progress, request, SCHEMA_ROOT, AUTH_AT,
        trusted_preflight_assertions=assertions,
    )
    assert authorized["progress_digest"] == AUTHORIZED_PROGRESS_DIGEST

    success = load(SUCCESS_PATH)
    assert raw_digest(SUCCESS_PATH) == SUCCESS_EVIDENCE_DIGEST
    assert success["evidence_type"] == "auth.synthetic-identity.tenant-metadata.bound"
    assert success["outcome"] == "SUCCEEDED_VERIFIED"
    assert success["plan_id"] == PLAN_ID and success["plan_version"] == 24
    assert success["step_id"] == STEP_ID
    observed_execution = success["execution_observation"]
    assert observed_execution["workflow_run_id"] == RUN_ID
    assert observed_execution["workflow_head_sha"] == RUN_SHA
    assert observed_execution["workflow_conclusion"] == "success"
    assert observed_execution["provider_mutation_attempts"] == 1
    assert observed_execution["provider_mutation_committed"] is True
    assert observed_execution["live_read_only_preflight_verified"] is True
    assert observed_execution["target_app_metadata_digest"] == TARGET_METADATA_DIGEST
    execution_config = {
        "plan_digest": PLAN_DIGEST, "project_reference": PROJECT,
        "workflow_run_id": RUN_ID, "workflow_head_sha": RUN_SHA,
        "target_app_metadata_digest": TARGET_METADATA_DIGEST,
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    }
    assert canonical_digest(execution_config) == EXECUTION_CONFIG_DIGEST
    assert observed_execution["execution_configuration_digest"] == EXECUTION_CONFIG_DIGEST
    for key in (
        "user_metadata_changed", "email_changed", "role_changed",
        "token_or_session_requested", "hook_change_attempted",
        "data_resource_touched", "render_touched",
    ):
        assert observed_execution[key] is False, key

    provider_after = success["provider_observation"]
    assert provider_after["auth_user_count"] == 1
    assert provider_after["synthetic_identity_match_count"] == 1
    assert provider_after["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert provider_after["synthetic_email_confirmed"] is True
    assert provider_after["user_metadata_exact_provider_shape"] is True
    assert provider_after["app_metadata_exact_target_shape"] is True
    assert provider_after["canonical_tenant_id"] == TENANT_ID
    assert provider_after["session_count"] == 0 and provider_after["refresh_token_count"] == 0
    assert provider_after["hook_function_exists"] is True
    assert provider_after["hook_owner_exact"] is True
    assert provider_after["hook_security_invoker"] is True
    assert provider_after["hook_stable"] is True
    assert provider_after["hook_search_path_exact"] is True
    assert provider_after["hook_function_body_verified"] is True
    assert provider_after["auth_admin_execute_acl_count"] == 1
    assert provider_after["public_execute_acl_count"] == 0
    assert provider_after["app_role_execute_acl_count"] == 0
    assert provider_after["hosted_auth_custom_access_token_hook_disabled"] is True
    assert provider_after["hosted_auth_custom_access_token_hook_unconfigured"] is True

    verified = success["verification_observation"]
    for key in (
        "post_mutation_user_readback_verified", "post_mutation_identity_count_verified",
        "provider_subject_digest_verified", "tenant_metadata_postcondition_verified",
        "postcondition_verified",
    ):
        assert verified[key] is True, key
    assert verified["provider_mutation_retried"] is False
    success_security = success["security_state"]
    for key in (
        "credential_material_retained_by_execution_artifacts",
        "credential_material_observed_by_control_plane", "raw_provider_payload_retained",
        "raw_provider_subject_retained", "pii_retained", "session_retained",
        "token_retained", "data_resource_touched", "render_touched",
        "hook_enable_action_performed",
    ):
        assert success_security[key] is False, key
    assert success_security["ephemeral_admin_secret_retirement_pending"] is True

    produced_binding = {
        "binding_id": "binding.development.auth.v24.tenant-metadata",
        "phase": "PRODUCED_BY_CURRENT_STEP",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "auth.synthetic-identity.tenant-metadata.bound",
        "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": TARGET_METADATA_DIGEST,
        "recorded_at": OUTCOME_AT,
    }
    outcome_evidence = [{
        "evidence_type": "auth.synthetic-identity.tenant-metadata.bound",
        "evidence_reference": "provider.execution.v24.step1.attempt1.verified",
        "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }]
    expected_execution = record_step_outcome(
        plan, approval, authorized, STEP_ID, "SUCCEEDED", "PASS",
        outcome_evidence, step["expected_postcondition"], None, SCHEMA_ROOT, OUTCOME_AT,
        binding_assertions=[produced_binding],
    )
    execution = load(EXECUTION_PATH)
    validate_progress(plan, execution, SCHEMA_ROOT)
    assert execution == expected_execution
    assert execution["record_version"] == 3
    assert execution["overall_state"] == "COMPLETED"
    assert execution["progress_digest"] == SUCCESS_PROGRESS_DIGEST
    execution_state = execution["step_states"][0]
    assert execution_state["authorization_state"] == "CONSUMED"
    assert execution_state["execution_state"] == "SUCCEEDED"
    assert execution_state["verification_state"] == "PASS"
    assert execution_state["authorization_consumed"] is True
    assert execution_state["safe_error_code"] is None
    assert execution_state["binding_assertions"] == assertions + [produced_binding]

    assert READ_ONLY_REFERENCE_PATH.exists()
    read_only_reference = READ_ONLY_REFERENCE_PATH.read_text(encoding="utf-8")
    for fragment in (
        PROVIDER_READ_SECRET,
        "supabase_read_only_user",
        "/database/query/read-only",
        "database_mutation_attempted=false",
    ):
        assert fragment in read_only_reference, fragment

    assert WORKFLOW_PATH.exists(), "v24 executor workflow is required before PR gate"
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    required_workflow_fragments = (
        "name: DEVELOPMENT AUTH v24 Tenant Metadata Execution",
        "workflow_dispatch:",
        "EXECUTE_V24_TENANT_METADATA",
        "contents: read",
        "actions: read",
        "if: github.ref == 'refs/heads/main'",
        "environment: development",
        f"AVUHZ_PROJECT_REF: {PROJECT}",
        f"AVUHZ_PLAN_ID: {PLAN_ID}",
        "AVUHZ_PLAN_VERSION: '24'",
        f"AVUHZ_PLAN_DIGEST: {PLAN_DIGEST}",
        f"AVUHZ_WINDOW_START: '{WINDOW_START}'",
        f"AVUHZ_WINDOW_END: '{WINDOW_END}'",
        f"AVUHZ_TARGET_EMAIL: {TARGET_EMAIL}",
        f"AVUHZ_TENANT_ID: {TENANT_ID}",
        f"AVUHZ_SUBJECT_DIGEST: {SUBJECT_DIGEST}",
        f"AVUHZ_TARGET_APP_METADATA_DIGEST: {TARGET_METADATA_DIGEST}",
        f"${{{{ secrets.{PROVIDER_READ_SECRET} }}}}",
        f"${{{{ secrets.{AUTH_ADMIN_SECRET} }}}}",
        "/database/query/read-only",
        "/config/auth",
        "supabase_read_only_user",
        "auth.sessions",
        "auth.refresh_tokens",
        HOOK_SIGNATURE,
        "--request POST",
        "--request PUT",
        f'"https://${{AVUHZ_PROJECT_REF}}.supabase.co/auth/v1/admin/users/${{target_user_id}}"',
        'json.dump({"app_metadata": app_metadata}, handle, separators=(",", ":"))',
        "read_only_preflight_passed=true",
        "provider_mutation_attempts=1",
        "user_metadata_changed=false",
        "email_changed=false",
        "role_changed=false",
        "token_or_session_requested=false",
        "hook_change_attempted=false",
        "data_resource_touched=false",
        "render_touched=false",
        "credential_material_observed_by_control_plane=false",
        "raw_provider_payload_retained=false",
    )
    for fragment in required_workflow_fragments:
        assert fragment in workflow, fragment

    assert workflow.count("--request PUT") == 1
    assert workflow.count("--request POST") == 1
    assert "--request PATCH" not in workflow
    assert "--request DELETE" not in workflow
    assert DATA_PROJECT not in workflow
    assert "/rest/v1" not in workflow
    assert "/storage/v1" not in workflow
    assert "api.render.com" not in workflow
    assert "n8n" not in workflow.lower()
    assert re.search(r"sb_secret_[A-Za-z0-9_-]{16,}", workflow) is None
    assert re.search(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", workflow) is None

    print(
        "DEVELOPMENT_AUTH_V24_OUTCOME=PASS "
        "(tenant app metadata bound and verified; one bounded mutation; zero sessions/refresh tokens; "
        "no DATA/Render/hook mutation; ephemeral admin secret retirement remains a separate action)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
