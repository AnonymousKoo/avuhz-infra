#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v21 through synthetic identity success persistence."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    authorize_step,
    initial_progress,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v21.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v21.progress.json"
EXECUTION_PATH = BASE / "development-auth-integration-v21.execution-progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v21.approval.json"
PREFLIGHT_PATH = BASE / "development-auth-step1-v21-preflight.evidence.json"
SUCCESS_PATH = BASE / "development-auth-step1-v21-success.evidence.json"
V16_PATH = BASE / "development-auth-step1-v16-success.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v21-synthetic-identity-execution.yml"

PLAN_ID = "e818f636-5470-4f39-a040-12f7e723b6c3"
PROGRESS_ID = "01813bf8-cf24-48c2-aad2-af87c8aab6e6"
STEP_ID = "development.auth.v21.step.01.create-synthetic-identity-admin"
PLAN_DIGEST = "sha256:1e7499dccdb1d245c427114dda018983221ddc75941310e32ddb93fd84494f0a"
APPROVAL_DIGEST = "sha256:7f3344ed21daec73c8877615f3366bcd430ccd63c1ad0e29c32bbc75fd8b9164"
INITIAL_PROGRESS_DIGEST = "sha256:de228d038b4f5cd2cae216b429f4ec8e0022ca502191be426991b58f3845cf25"
AUTHORIZED_PROGRESS_DIGEST = "sha256:da0aab1d48eb40ea5710c71332d46608365076e07a9203fcca99d69334861225"
SUCCESS_PROGRESS_DIGEST = "sha256:13340bda7d8ff8b059494fc390e47f37684153ccbef43eb62acdea56e38b89eb"
V16_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
CAP_EVIDENCE_DIGEST = "sha256:2b3bd96c745a56879b348b4d538c64106bba69a5a8a152724a1660fc7243d775"
CAP_CONFIG_DIGEST = "sha256:a3487c9bb0850b814f2ee90911fc29077ecdd066e3b09ebc29a952b71db643a8"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:d1769c076ec68b792a3622b38c856c2bb2939c13f2f0b7aa75d19db6e825731a"
PREFLIGHT_CONFIG_DIGEST = "sha256:fd32ea9a5cc7e44c0117969b88b54682222ca640233278e3b76bc1bef19d5e9d"
PREFLIGHT_RAW_DIGEST = "sha256:671c9c9d7720b3377310c4d82986a5b3604db05ca13976f659ada4d9381cc423"
SUCCESS_EVIDENCE_DIGEST = "sha256:16fbd6f2b1b779a4879f9eca7b5469267822884740dab7a02d3a0f8c7211fffa"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
SUBJECT_VALUE_DIGEST = "sha256:9123b537af3bb3e2b543fd24a5510e30fd8f4f0ab27b8056421397ad0a9081a0"
EXECUTION_CONFIG_DIGEST = "sha256:8411f3205e87db06ff359fa65ba205f68a3c395170e8239c3ce1f4e2d94ef49f"
PROJECT = "pwlhruwutoitnieactol"
AUTH_AT = "2026-09-14T15:50:56Z"
OUTCOME_AT = "2026-09-14T16:24:06Z"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def component_digest(value: dict) -> str:
    body = dict(value)
    body.pop("evidence_digest")
    return canonical_digest(body)


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    execution = load(EXECUTION_PATH)
    approval = load(APPROVAL_PATH)
    preflight = load(PREFLIGHT_PATH)
    success = load(SUCCESS_PATH)
    v16 = load(V16_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution, SCHEMA_ROOT)
    for moment in ("2026-09-14T14:00:00Z", AUTH_AT, OUTCOME_AT):
        validate_approval(plan, approval, SCHEMA_ROOT, moment)

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 21
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["ordered_step_ids"] == [STEP_ID]
    step = plan["steps"][0]
    assert step["operation"] == "provider.auth-identity.create-one"
    assert step["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert approval["approval_digest"] == APPROVAL_DIGEST

    expected_initial = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_initial
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST
    assert raw_digest(V16_PATH) == V16_EVIDENCE_DIGEST
    assert v16["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False

    assert raw_digest(PREFLIGHT_PATH) == PREFLIGHT_RAW_DIGEST
    capability = preflight["capability_attestation"]
    empty_target = preflight["identity_create_preflight"]
    assert preflight["observation_only"] is True
    assert capability["source"]["workflow_run_id"] == 34861618340
    assert capability["source"]["workflow_conclusion"] == "success"
    assert capability["configuration_digest"] == CAP_CONFIG_DIGEST
    assert capability["evidence_digest"] == CAP_EVIDENCE_DIGEST
    assert component_digest(capability) == CAP_EVIDENCE_DIGEST
    assert empty_target["source"]["workflow_run_id"] == 34864827864
    assert empty_target["auth_user_count"] == 0
    assert empty_target["synthetic_identity_match_count"] == 0
    assert empty_target["configuration_digest"] == PREFLIGHT_CONFIG_DIGEST
    assert empty_target["evidence_digest"] == PREFLIGHT_EVIDENCE_DIGEST
    assert component_digest(empty_target) == PREFLIGHT_EVIDENCE_DIGEST
    assert preflight["security_state"]["credential_retained"] is False
    assert preflight["security_state"]["credential_material_observed_by_control_plane"] is False
    assert preflight["security_state"]["provider_mutation_attempted"] is False

    assertions = [
        {
            "binding_id": "binding.development.auth.v21.admin-executor-capability",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "auth.admin-executor-capability.observed",
            "evidence_digest": CAP_EVIDENCE_DIGEST,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": CAP_CONFIG_DIGEST,
            "recorded_at": AUTH_AT,
        },
        {
            "binding_id": "binding.development.auth.v21.identity-create-preflight",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "auth.synthetic-identity.create-preflight.observed",
            "evidence_digest": PREFLIGHT_EVIDENCE_DIGEST,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": PREFLIGHT_CONFIG_DIGEST,
            "recorded_at": AUTH_AT,
        },
    ]
    request = {
        "plan_id": PLAN_ID,
        "plan_version": 21,
        "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
        "step_id": STEP_ID,
        "resource_reference": "identity.development.synthetic-avuhz",
        "resource_version": "version.1",
        "resource_digest": None,
        "operation": "provider.auth-identity.create-one",
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": [{"evidence_type": "hook.v2.disabled-acl.verified", "evidence_digest": V16_EVIDENCE_DIGEST}],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    authorized = authorize_step(
        plan, approval, progress, request, SCHEMA_ROOT, AUTH_AT,
        trusted_preflight_assertions=assertions,
    )
    assert authorized["progress_digest"] == AUTHORIZED_PROGRESS_DIGEST

    assert raw_digest(SUCCESS_PATH) == SUCCESS_EVIDENCE_DIGEST
    assert success["evidence_type"] == "auth.synthetic-identity.created"
    assert success["outcome"] == "SUCCEEDED_VERIFIED"
    provider = success["provider_observation"]
    assert provider["auth_user_count"] == 1
    assert provider["synthetic_identity_match_count"] == 1
    assert provider["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert provider["synthetic_email_confirmed"] is True
    assert provider["user_metadata_exact_provider_shape"] is True
    assert provider["app_metadata_exact_provider_shape"] is True
    assert provider["session_count"] == 0 and provider["refresh_token_count"] == 0
    assert provider["hook_function_exists"] is True
    assert provider["hook_owner_exact"] is True
    assert provider["hook_security_invoker"] is True
    assert provider["hook_stable"] is True
    assert provider["hook_search_path_exact"] is True
    assert provider["auth_admin_execute_acl_count"] == 1
    assert provider["public_execute_acl_count"] == 0

    observed_execution = success["execution_observation"]
    assert observed_execution["provider_mutation_attempts"] == 1
    assert observed_execution["provider_mutation_committed"] is True
    assert observed_execution["initial_workflow_conclusion"] == "failure"
    assert observed_execution["initial_workflow_failure_scope"] == "post-create-provider-managed-metadata-validation"
    assert observed_execution["execution_configuration_digest"] == EXECUTION_CONFIG_DIGEST
    for key in (
        "password_supplied", "user_metadata_supplied", "app_metadata_supplied",
        "tenant_metadata_supplied", "invitation_requested", "session_or_token_requested",
    ):
        assert observed_execution[key] is False

    verified = success["verification_observation"]
    assert verified["independent_post_create_read_only_verification"] is True
    assert verified["corrected_validator_commit"] == "85e1c4561ab462b79d98e53178161066a87ab689"
    assert verified["provider_managed_metadata_verified"] is True
    assert verified["avuhz_metadata_binding_performed"] is False
    assert verified["postcondition_verified"] is True
    assert verified["provider_mutation_retried"] is False
    for key, value in success["security_state"].items():
        assert value is False, key

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert 'body = {"email": os.environ["AVUHZ_TARGET_EMAIL"], "email_confirm": True}' in workflow
    assert 'user.get("user_metadata") != {"email_verified": True}' in workflow
    assert 'user.get("app_metadata") != {"provider": "email", "providers": ["email"]}' in workflow

    subject_binding = {
        "binding_id": "binding.development.auth.v21.synthetic-identity",
        "phase": "PRODUCED_BY_CURRENT_STEP",
        "value_class": "STABLE_REFERENCE",
        "source_step_id": None,
        "evidence_type": "auth.synthetic-identity.created",
        "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": SUBJECT_VALUE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }
    assert canonical_digest(SUBJECT_DIGEST) == SUBJECT_VALUE_DIGEST
    outcome_evidence = [{
        "evidence_type": "auth.synthetic-identity.created",
        "evidence_reference": "provider.execution.v21.step1.attempt1.verified",
        "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
        "recorded_at": OUTCOME_AT,
    }]
    expected = record_step_outcome(
        plan, approval, authorized, STEP_ID, "SUCCEEDED", "PASS",
        outcome_evidence, step["expected_postcondition"], None, SCHEMA_ROOT, OUTCOME_AT,
        binding_assertions=[subject_binding],
    )
    assert execution == expected
    assert execution["record_version"] == 3
    assert execution["overall_state"] == "COMPLETED"
    assert execution["progress_digest"] == SUCCESS_PROGRESS_DIGEST
    state = execution["step_states"][0]
    assert state["authorization_state"] == "CONSUMED"
    assert state["execution_state"] == "SUCCEEDED"
    assert state["verification_state"] == "PASS"
    assert state["authorization_consumed"] is True
    assert state["safe_error_code"] is None
    assert state["binding_assertions"] == assertions + [subject_binding]

    forbidden_execution = BASE / "development-auth-integration-v22.execution-progress.json"
    assert not forbidden_execution.exists(), forbidden_execution

    print(
        "DEVELOPMENT_AUTH_V21_OUTCOME=PASS "
        "(one passwordless synthetic identity verified; provider-managed metadata only; "
        "zero sessions/refresh tokens; raw provider subject not persisted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
