#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v22 tenant metadata plan after owner approval, before execution."""
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

    for forbidden in (
        BASE / "development-auth-integration-v22.execution-progress.json",
        BASE / "development-auth-step1-v22-preflight.evidence.json",
        BASE / "development-auth-step1-v22-success.evidence.json",
        ROOT / ".github/workflows/development-auth-v22-tenant-metadata-execution.yml",
    ):
        assert not forbidden.exists(), forbidden

    print(
        "DEVELOPMENT_AUTH_V22_APPROVAL=PASS "
        "(exact-plan owner approval active only for 19:30Z-22:30Z; "
        "no provider execution or executor workflow present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
