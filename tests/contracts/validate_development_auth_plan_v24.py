#!/usr/bin/env python3
"""Validate the fresh DEVELOPMENT AUTH v24 continuation before execution."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v24.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v24.progress.json"
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

TARGET_APP_METADATA = {
    "provider": "email",
    "providers": ["email"],
    "avuhz_tenant_id": TENANT_ID,
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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

    if APPROVAL_PATH.exists():
        approval = load(APPROVAL_PATH)
        validate_approval(plan, approval, SCHEMA_ROOT, approval["effective_at"])
        assert approval["plan_id"] == PLAN_ID
        assert approval["plan_version"] == PLAN_VERSION
        assert approval["plan_digest"] == PLAN_DIGEST
        assert approval["owner_identity"] == "github:AnonymousKoo"
        assert approval["decision"] == "APPROVE"
        assert approval["environment"] == "DEVELOPMENT"
        assert approval["effective_at"] == WINDOW_START
        assert approval["expires_at"] == WINDOW_END
        assert approval["status"] == "ACTIVE"
        assert approval["authority_scope"] == "EXACT_PLAN_ONLY"

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

    for forbidden in (
        BASE / "development-auth-integration-v24.execution-progress.json",
        BASE / "development-auth-step1-v24-preflight.evidence.json",
        BASE / "development-auth-step1-v24-success.evidence.json",
    ):
        assert not forbidden.exists(), forbidden

    print(
        "DEVELOPMENT_AUTH_V24_EXECUTOR_PREPARED=PASS "
        "(fresh forward-only plan, pristine progress, mandatory live read-only preflight, "
        "single bounded metadata mutation, and no v24 execution evidence present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
