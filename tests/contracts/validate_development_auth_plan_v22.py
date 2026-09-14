#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v22 after capability certification, before execution."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    approval_digest,
    initial_progress,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v22.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v22.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v22.approval.json"
V21_SUCCESS_PATH = BASE / "development-auth-step1-v21-success.evidence.json"
V16_SUCCESS_PATH = BASE / "development-auth-step1-v16-success.evidence.json"
CAPABILITY_PATH = BASE / "development-auth-v22-admin-capability.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v22-tenant-metadata-execution.yml"

PLAN_ID = "9dec1b7c-198b-4590-9750-80e68106db98"
PROGRESS_ID = "a8967e0b-f465-4a56-8083-6404fc53ba80"
APPROVAL_ID = "992dfd16-6f9d-4f39-8c56-a53b7e3a1094"
PLAN_DIGEST = "sha256:d45d82a3fe6ff702044b2f976178f947e2db8399da08c3f7d5f6931612ddbd9d"
PROGRESS_DIGEST = "sha256:a81b2a689079515720472ad0188b3cf23fb22d2b5f423e7abf538eb462c24f8d"
APPROVAL_DIGEST = "sha256:28726aa2424ca8436088ac9530642416c56e045a8e2fff2b0ca9897499bfa3d5"
STEP_ID = "development.auth.v22.step.01.bind-synthetic-tenant-app-metadata"
PROJECT = "pwlhruwutoitnieactol"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TARGET_METADATA_DIGEST = "sha256:cd89c12abf5ed8c3dc03f4766a6d7cd9f1b8388b9e98468e9673233550a910a6"
V21_SUCCESS_DIGEST = "sha256:16fbd6f2b1b779a4879f9eca7b5469267822884740dab7a02d3a0f8c7211fffa"
V16_SUCCESS_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
CAPABILITY_RAW_DIGEST = "sha256:8cee24d2802a06982c00ad12fb14ebd130ef8b1a6b9547989df6fb522e1ea719"
CAPABILITY_EVIDENCE_DIGEST = "sha256:6f0d17815581401b01bf60a296fc79381141d7747b4f13d57acd1055f17b5160"
CAPABILITY_CONFIG_DIGEST = "sha256:ed3be015f92dd36839403f24ac31cded47a9521f85643a1a1cf7f1382c103d50"
CAPABILITY_RUN_ID = 34895225473
CAPABILITY_HEAD_SHA = "58437583f582d10f184f987c023b9536cc32012f"
PREFLIGHT_REFERENCE_DIGEST = "sha256:372355dfe9257db6670b0a64109933a1b738ddfb980f6d5a9a72a344f8a48184"
EXECUTION_REFERENCE_DIGEST = "sha256:692e4cdf332ca728a392c63442153ad78e0137c1a3a65df1c40c45d565876588"
APPROVED_AT = "2026-09-14T19:23:16Z"
EFFECTIVE_AT = "2026-09-14T19:30:00Z"
EXPIRES_AT = "2026-09-14T22:30:00Z"

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
    assert len(matches) == 1
    return matches[0]


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    v21 = load(V21_SUCCESS_PATH)
    v16 = load(V16_SUCCESS_PATH)
    capability_evidence = load(CAPABILITY_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, EFFECTIVE_AT)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-14T22:29:59Z")

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 22
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": EFFECTIVE_AT,
        "expires_at": EXPIRES_AT,
    }
    assert plan["ordered_step_ids"] == [STEP_ID]

    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_version"] == 22
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["approved_at"] == APPROVED_AT
    assert approval["effective_at"] == EFFECTIVE_AT
    assert approval["expires_at"] == EXPIRES_AT
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval_digest(approval) == APPROVAL_DIGEST

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == "provider.auth-identity.app-metadata.bind-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["resource"]["resource_reference"] == "identity.development.synthetic-avuhz"
    assert step["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert step["credential_policy"]["values_stored"] is False
    assert step["unresolved_bindings"] == []

    assert raw_digest(V21_SUCCESS_PATH) == V21_SUCCESS_DIGEST
    assert v21["outcome"] == "SUCCEEDED_VERIFIED"
    assert v21["provider_observation"]["synthetic_identity_match_count"] == 1
    assert v21["provider_observation"]["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert v21["provider_observation"]["synthetic_email_confirmed"] is True
    assert v21["provider_observation"]["app_metadata_exact_provider_shape"] is True
    assert v21["provider_observation"]["session_count"] == 0
    assert v21["provider_observation"]["refresh_token_count"] == 0

    assert raw_digest(V16_SUCCESS_PATH) == V16_SUCCESS_DIGEST
    assert v16["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False

    required = {
        item["evidence_type"]: item["exact_digest"]
        for item in step["required_evidence"]
    }
    assert required == {
        "auth.synthetic-identity.created": V21_SUCCESS_DIGEST,
        "hook.v2.disabled-acl.verified": V16_SUCCESS_DIGEST,
    }

    subject_binding = declaration(
        step, "binding.development.auth.v22.synthetic-subject-digest"
    )
    assert subject_binding["preapproval_value"]["value"] == SUBJECT_DIGEST
    assert subject_binding["preapproval_value"]["exact_digest"] == canonical_digest(SUBJECT_DIGEST)

    tenant_binding = declaration(
        step, "binding.development.auth.v22.canonical-tenant"
    )
    assert tenant_binding["preapproval_value"]["value"] == TENANT_ID
    assert tenant_binding["preapproval_value"]["exact_digest"] == canonical_digest(TENANT_ID)
    assert tenant_binding["persistence_policy"] == "SANITIZED_VALUE_ALLOWED"

    metadata_binding = declaration(
        step, "binding.development.auth.v22.target-app-metadata"
    )
    assert canonical_digest(TARGET_APP_METADATA) == TARGET_METADATA_DIGEST
    assert metadata_binding["preapproval_value"]["value"] == TARGET_METADATA_DIGEST
    assert (
        metadata_binding["preapproval_value"]["exact_digest"]
        == canonical_digest(TARGET_METADATA_DIGEST)
    )

    preflight = declaration(
        step, "binding.development.auth.v22.tenant-metadata-preflight"
    )
    assert preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert preflight["evidence_type"] == "auth.synthetic-identity.tenant-metadata-preflight.observed"

    capability = declaration(
        step, "binding.development.auth.v22.admin-executor-capability"
    )
    assert capability["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert capability["evidence_type"] == "auth.admin-executor-capability.observed"

    produced = declaration(
        step, "binding.development.auth.v22.tenant-metadata"
    )
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["evidence_type"] == "auth.synthetic-identity.tenant-metadata.bound"

    assert raw_digest(CAPABILITY_PATH) == CAPABILITY_RAW_DIGEST
    assert capability_evidence["evidence_type"] == "auth.admin-executor-capability.observed"
    assert capability_evidence["observation_only"] is True
    assert capability_evidence["environment"] == "DEVELOPMENT"
    assert capability_evidence["provider_reference"] == "supabase"
    assert capability_evidence["project_reference"] == PROJECT
    assert capability_evidence["responsibility"] == "AUTH"
    assert capability_evidence["plan_id"] == PLAN_ID
    assert capability_evidence["plan_version"] == 22
    assert capability_evidence["step_id"] == STEP_ID
    assert capability_evidence["observed_at"] == "2026-09-14T20:49:42Z"
    assert capability_evidence["configuration_digest"] == CAPABILITY_CONFIG_DIGEST
    assert capability_evidence["result"] == "PASS"
    assert capability_evidence["evidence_digest"] == CAPABILITY_EVIDENCE_DIGEST
    capability_body = dict(capability_evidence)
    capability_body.pop("evidence_digest")
    assert canonical_digest(capability_body) == CAPABILITY_EVIDENCE_DIGEST
    capability_source = capability_evidence["source"]
    assert capability_source == {
        "workflow_run_id": CAPABILITY_RUN_ID,
        "workflow_head_sha": CAPABILITY_HEAD_SHA,
        "workflow_conclusion": "success",
        "provider_mutation_attempted": False,
        "credential_material_observed_by_control_plane": False,
    }

    expected_progress = initial_progress(
        plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"]
    )
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []
    assert state["binding_assertions"] == []

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    required_workflow_fragments = (
        "name: DEVELOPMENT AUTH v22 Tenant Metadata Execution",
        "workflow_dispatch:",
        "EXECUTE_V22_TENANT_METADATA",
        "contents: read",
        "actions: read",
        "if: github.ref == 'refs/heads/main'",
        "environment: development",
        "AVUHZ_PROJECT_REF: pwlhruwutoitnieactol",
        f"AVUHZ_PLAN_ID: {PLAN_ID}",
        f"AVUHZ_PLAN_DIGEST: {PLAN_DIGEST}",
        f"AVUHZ_APPROVAL_ID: {APPROVAL_ID}",
        f"AVUHZ_APPROVAL_DIGEST: {APPROVAL_DIGEST}",
        f"AVUHZ_TENANT_ID: {TENANT_ID}",
        f"AVUHZ_SUBJECT_DIGEST: {SUBJECT_DIGEST}",
        f"AVUHZ_TARGET_APP_METADATA_DIGEST: {TARGET_METADATA_DIGEST}",
        f"AVUHZ_CAPABILITY_RUN_ID: '{CAPABILITY_RUN_ID}'",
        f"AVUHZ_CAPABILITY_HEAD_SHA: {CAPABILITY_HEAD_SHA}",
        f"AVUHZ_CAPABILITY_EVIDENCE_DIGEST: {CAPABILITY_EVIDENCE_DIGEST}",
        f"AVUHZ_CAPABILITY_EVIDENCE_RAW_DIGEST: {CAPABILITY_RAW_DIGEST}",
        f"AVUHZ_CAPABILITY_REFERENCE_DIGEST: {CAPABILITY_CONFIG_DIGEST}",
        f"AVUHZ_PREFLIGHT_REFERENCE_DIGEST: {PREFLIGHT_REFERENCE_DIGEST}",
        f"AVUHZ_EXECUTION_REFERENCE_DIGEST: {EXECUTION_REFERENCE_DIGEST}",
        "${{ secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_ADMIN_EPHEMERAL }}",
        "--request PUT",
        '"https://${AVUHZ_PROJECT_REF}.supabase.co/auth/v1/admin/users/${target_user_id}"',
        'json.dump({"app_metadata": app_metadata}, handle, separators=(",", ":"))',
        "outcome is ambiguous. Do not retry.",
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
    assert "--request POST" not in workflow
    assert "--request PATCH" not in workflow
    assert "--request DELETE" not in workflow
    assert "gnuqaefotwgkwurjpyik" not in workflow
    assert "/rest/v1" not in workflow
    assert "/storage/v1" not in workflow
    assert "api.render.com" not in workflow
    assert "n8n" not in workflow.lower()
    assert re.search(r"sb_secret_[A-Za-z0-9_-]{16,}", workflow) is None

    for forbidden in (
        BASE / "development-auth-integration-v22.execution-progress.json",
        BASE / "development-auth-step1-v22-preflight.evidence.json",
        BASE / "development-auth-step1-v22-success.evidence.json",
    ):
        assert not forbidden.exists(), forbidden

    print(
        "DEVELOPMENT_AUTH_V22_EXECUTOR_PREPARED=PASS "
        "(exact capability evidence and bounded executor present; plan remains pristine, "
        "authorization unconsumed, and no v22 execution/preflight/success evidence exists)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
