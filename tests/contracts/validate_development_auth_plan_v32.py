#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v32 forward-only synthetic-token preparation."""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    approval_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v32.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v32.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v32.approval.json"
EXECUTION_PROGRESS_PATH = BASE / "development-auth-integration-v32.execution-progress.json"
STEP1_SUCCESS_PATH = BASE / "development-auth-step1-v32-success.evidence.json"
STEP2_FAILURE_PATH = BASE / "development-auth-step2-v32-failure.evidence.json"
V31_PLAN_PATH = BASE / "development-auth-integration-v31.plan.json"
V31_EXECUTION_PATH = BASE / "development-auth-integration-v31.execution-progress.json"
V31_FAILURE_PATH = BASE / "development-auth-step1-v31-failure.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v32-token-validation.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v32_token_executor.py"
CORRECTED_LIFECYCLE_PATH = (
    ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
)

PLAN_ID = "e8cd574a-a532-4c95-ab5d-5c069c1bbb96"
PLAN_DIGEST = "sha256:c43b0b906bfb0c03e763d6cc5a13d47a900b40eb4db8fd904c799c524ec6c37c"
PROGRESS_DIGEST = "sha256:7539fdec222abaddce8fc6fce1ffd5299c793db34aa97a05932adccc253825f3"
EXECUTION_PROGRESS_DIGEST = "sha256:d40704265985889923e8dbd013274ff151717ea1f5880e9269e4107b96e022f7"
STEP1_SUCCESS_DIGEST = "sha256:dfa0583adc85bddb3a40d60da1708f9e8591b07d203ed90f4ce08b43be57a30d"
STEP2_FAILURE_DIGEST = "sha256:e56af517533e0b6f4f05d7c7dbb33f1b39a8cc09669180b9874d506a5f0850e9"
APPROVAL_ID = "22afae15-0eb0-4d29-927d-ed2d6405eb02"
APPROVED_AT = "2026-09-16T15:01:37Z"
APPROVAL_DIGEST = "sha256:6c3e89a1beb71b6c6d4265ea768fe18e0635b7469d32ac244cd4a650e7743bee"
V31_PLAN_DIGEST = "sha256:8ea09f44c3c5e65a6a8d86b0df6579b0f4476b63ae6c167a6194948c86aab043"
V31_EXECUTION_DIGEST = "sha256:88d8021f785120d91d4314d7c14028ca5bd8467db2f38b4ac7dea866d6399190"
V31_FAILURE_DIGEST = "sha256:1ed8a2fcbdb7d168e48387a42096be23bee05c3eb8732735b4502374b0dbb034"
WINDOW_START = "2026-09-17T15:00:00Z"
WINDOW_END = "2026-09-17T21:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
WORKFLOW_RUN_ID = 35240314854
EXECUTION_SHA = "1fa628abba14acef4b58a1a983c95edafeac44a4"
RECORDED_AT = "2026-09-17T15:27:19Z"
BASE_EXECUTOR_SHA256 = "6e3e8e79cdc8f726b3f0b3981fdf00045a3beac70dece3898d91c3c81bf5d9a5"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def normalized_scope(plan: dict) -> dict:
    value = copy.deepcopy(plan)
    value.pop("plan_digest")
    value["plan_id"] = "PLAN_ID"
    value["plan_version"] = 0
    value["created_at"] = "CREATED_AT"
    value["authorization_window"] = {
        "binding_state": "BOUND",
        "starts_at": "START",
        "expires_at": "END",
    }

    def normalize(item):
        if isinstance(item, str):
            return re.sub(r"([vV])(?:31|32)", r"\1XX", item)
        if isinstance(item, list):
            return [normalize(child) for child in item if child != "v31.retry"]
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in item.items()}
        return item

    return normalize(value)


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    step1_success = load(STEP1_SUCCESS_PATH)
    step2_failure = load(STEP2_FAILURE_PATH)
    v31_plan = load(V31_PLAN_PATH)
    v31_execution = load(V31_EXECUTION_PATH)
    v31_failure = load(V31_FAILURE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    validate_plan(v31_plan, SCHEMA_ROOT)
    validate_progress(v31_plan, v31_execution, SCHEMA_ROOT)

    assert v31_plan["plan_digest"] == V31_PLAN_DIGEST
    assert v31_execution["progress_digest"] == V31_EXECUTION_DIGEST
    assert canonical_digest(v31_failure) == V31_FAILURE_DIGEST
    assert v31_execution["overall_state"] == "STOPPED"
    v31_step1 = v31_execution["step_states"][0]
    assert (
        v31_step1["authorization_state"],
        v31_step1["execution_state"],
        v31_step1["verification_state"],
        v31_step1["authorization_consumed"],
    ) == ("CONSUMED", "FAILED", "FAIL", True)
    assert all(
        state["authorization_state"] == "BLOCKED"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        for state in v31_execution["step_states"][1:]
    )
    assert v31_failure["execution_observation"]["provider_mutation_outcome"] == "AMBIGUOUS"
    assert v31_failure["root_cause_review"]["retry_authorized"] is False
    assert v31_failure["root_cause_review"]["forward_only_correction_required"] is True
    assert (
        v31_failure["root_cause_review"]["exact_historical_provider_response_classification"]
        == "UNKNOWN"
    )

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 32
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert "v31.retry" in plan["steps"][0]["prohibited_actions"]
    assert normalized_scope(plan) == normalized_scope(v31_plan)

    assert progress["plan_id"] == PLAN_ID
    assert progress["plan_version"] == 32
    assert progress["plan_digest"] == PLAN_DIGEST
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["record_version"] == 1
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in progress["step_states"]
    )

    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 32,
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
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    assert canonical_digest(step1_success) == STEP1_SUCCESS_DIGEST
    assert (
        step1_success["environment"],
        step1_success["responsibility"],
        step1_success["provider_reference"],
        step1_success["project_reference"],
        step1_success["plan_id"],
        step1_success["plan_version"],
        step1_success["plan_digest"],
        step1_success["step_id"],
        step1_success["attempt"],
        step1_success["outcome"],
    ) == (
        "DEVELOPMENT",
        "AUTH",
        "supabase",
        PROJECT,
        PLAN_ID,
        32,
        PLAN_DIGEST,
        "development.auth.v32.step.01.generate-existing-user-recovery-link",
        1,
        "SUCCEEDED_VERIFIED",
    )
    assert step1_success["execution_observation"] == {
        "workflow_run_id": WORKFLOW_RUN_ID,
        "execution_sha": EXECUTION_SHA,
        "execution_class": "PROVIDER_MUTATION",
        "provider_mutation_attempts": 1,
        "recovery_link_generation_completed": True,
        "existing_user_required": True,
        "email_sent": False,
        "step_2_lifecycle_reached": True,
    }
    assert step1_success["verification_observation"] == {
        "recovery_link_generation_verified": True,
        "post_generation_session_count": 0,
        "post_generation_refresh_token_count": 0,
        "recovery_link_consumption_attempted_once": True,
    }
    assert step1_success["authority_state"] == {
        "step_1_authorization": "CONSUMED",
        "step_1_authorization_consumed": True,
        "retry_authorized": False,
    }
    assert not any(step1_success["security_state"].values())
    assert step1_success["recorded_at"] == RECORDED_AT

    assert canonical_digest(step2_failure) == STEP2_FAILURE_DIGEST
    assert (
        step2_failure["environment"],
        step2_failure["responsibility"],
        step2_failure["provider_reference"],
        step2_failure["project_reference"],
        step2_failure["plan_id"],
        step2_failure["plan_version"],
        step2_failure["plan_digest"],
        step2_failure["step_id"],
        step2_failure["attempt"],
        step2_failure["outcome"],
        step2_failure["safe_error_code"],
    ) == (
        "DEVELOPMENT",
        "AUTH",
        "supabase",
        PROJECT,
        PLAN_ID,
        32,
        PLAN_DIGEST,
        "development.auth.v32.step.02.consume-token-and-revoke-session",
        1,
        "FAILED_AMBIGUOUS",
        "V32_SESSION_RESPONSE_MISSING",
    )
    assert step2_failure["execution_observation"] == {
        "workflow_run_id": WORKFLOW_RUN_ID,
        "execution_sha": EXECUTION_SHA,
        "execution_class": "PROVIDER_MUTATION",
        "recovery_link_consumption_attempts": 1,
        "recovery_link_consumption_attempted": True,
        "session_response_parsed": False,
        "access_token_captured": False,
        "refresh_token_captured": False,
        "local_logout_performed": False,
        "emergency_cleanup_reported": "NOT_NEEDED",
        "post_failure_provider_readback_performed": False,
        "step_3_jwt_validation_reached": False,
    }
    assert step2_failure["failure_observation"] == {
        "provider_session_outcome": "AMBIGUOUS",
        "session_state": "UNVERIFIED",
        "refresh_token_state": "UNVERIFIED",
        "cleanup_verification": "NOT_PERFORMED",
        "zero_sessions_proven": False,
        "zero_refresh_tokens_proven": False,
    }
    assert step2_failure["root_cause_review"]["status"] == "CONFIRMED_EXECUTOR_WEAKNESS"
    assert (
        step2_failure["root_cause_review"]["classification"]
        == "ACCESS_TOKEN_GATED_EMERGENCY_CLEANUP_WITHOUT_INDEPENDENT_READBACK"
    )
    assert step2_failure["root_cause_review"]["retry_authorized"] is False
    assert step2_failure["root_cause_review"]["forward_only_correction_required"] is True
    assert step2_failure["authority_state"] == {
        "step_2_authorization": "CONSUMED",
        "step_2_authorization_consumed": True,
        "v32_retry_authorized": False,
        "forward_only_correction_required": True,
    }
    assert not any(step2_failure["security_state"].values())
    assert step2_failure["recorded_at"] == RECORDED_AT

    assert execution_progress["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    assert execution_progress["record_version"] == 5
    assert execution_progress["overall_state"] == "STOPPED"
    assert execution_progress["updated_at"] == RECORDED_AT
    step1, step2, step3 = execution_progress["step_states"]
    assert (
        step1["authorization_state"],
        step1["execution_state"],
        step1["verification_state"],
        step1["authorization_consumed"],
        step1["safe_error_code"],
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True, None)
    assert step1["observed_postcondition"] == plan["steps"][0]["expected_postcondition"]
    assert step1["evidence"] == [{
        "evidence_type": "auth.synthetic-recovery-link.generated",
        "evidence_reference": "github.actions.run.35240314854.step1.attempt1.verified",
        "evidence_digest": STEP1_SUCCESS_DIGEST,
        "recorded_at": RECORDED_AT,
    }]
    assert step1["binding_assertions"] == []
    assert (
        step2["authorization_state"],
        step2["execution_state"],
        step2["verification_state"],
        step2["authorization_consumed"],
        step2["safe_error_code"],
    ) == ("CONSUMED", "FAILED", "FAIL", True, "V32_SESSION_RESPONSE_MISSING")
    assert step2["evidence"] == [{
        "evidence_type": "auth.synthetic-session.lifecycle-completed",
        "evidence_reference": "github.actions.run.35240314854.step2.attempt1.failed-ambiguous",
        "evidence_digest": STEP2_FAILURE_DIGEST,
        "recorded_at": RECORDED_AT,
    }]
    assert step2["binding_assertions"] == []
    assert "ambiguous/unverified" in step2["observed_postcondition"]
    assert (
        step3["authorization_state"],
        step3["execution_state"],
        step3["verification_state"],
        step3["authorization_consumed"],
    ) == ("BLOCKED", "NOT_STARTED", "NOT_STARTED", False)
    assert step3["evidence"] == []
    assert step3["binding_assertions"] == []


    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    for required in (
        "DEVELOPMENT AUTH v32 Synthetic Token Validation",
        "EXECUTE_V32_SYNTHETIC_TOKEN_VALIDATION",
        "environment: development",
        PLAN_ID,
        PLAN_DIGEST,
        WINDOW_START,
        WINDOW_END,
        "development-auth-integration-v32.approval.json",
        "scripts/development_auth_v32_token_executor.py",
        "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V32_EPHEMERAL",
    ):
        assert required in workflow
    for prohibited in (
        "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V31_EPHEMERAL",
        "development-auth-integration-v31.approval.json",
        "scripts/development_auth_v31_token_executor.py",
    ):
        assert prohibited not in workflow

    for required in (
        BASE_EXECUTOR_SHA256,
        "development_auth_v30_token_executor.py",
        "OLD_PLAN_ID",
        "NEW_PLAN_ID",
        'source.replace("v30", "v32").replace("V30", "V32")',
        "V32_BASE_EXECUTOR_DIGEST_MISMATCH",
        "OLD_PLAN_VERSION_GUARD",
        "NEW_PLAN_VERSION_GUARD",
    ):
        assert required in executor

    spec = importlib.util.spec_from_file_location(
        "development_auth_v32_token_executor", EXECUTOR_PATH
    )
    assert spec is not None and spec.loader is not None
    executor_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(executor_module)
    derived = executor_module.derived_source()
    assert 'plan["plan_version"] != 32' in derived
    assert 'plan["plan_version"] != 31' not in derived
    for required in (
        "request_generate_recovery_link",
        "parse_generate_recovery_link_response",
        "V32_RECOVERY_LINK_PROVIDER_REJECTED",
        "V32_RECOVERY_LINK_REQUEST_FAILED",
        "V32_RECOVERY_LINK_RESPONSE_INVALID",
        "V32_RECOVERY_LINK_RESPONSE_SHAPE_INVALID",
        "redirect = get_redirect_without_following(recovery_link, publishable_key)",
        "access_token, refresh_token, expires_in = parse_session_redirect(redirect)",
        'emergency_cleanup = "NOT_NEEDED"',
        "if lifecycle_authorized and access_token is not None",
    ):
        assert required in derived

    # v32 is immutable historical evidence of the browser-oriented failure.
    # The reusable forward-only lifecycle must instead follow the current
    # Supabase direct verification contract and retain no redirect parser.
    corrected_lifecycle = CORRECTED_LIFECYCLE_PATH.read_text(encoding="utf-8")
    for required in (
        'VERIFY_PATH = "/auth/v1/verify"',
        'VERIFY_METHOD = "POST"',
        'VERIFY_TYPE = "recovery"',
        'payload.get("hashed_token")',
        '"token_hash": credential._text()',
        "parse_recovery_verification_response",
        "SESSION_CLEANUP_VERIFIED",
        "SESSION_CLEANUP_UNAVAILABLE",
        "SESSION_STATE_UNVERIFIED",
        "read_session_state",
        "validate_development_synthetic_access_jwt",
    ):
        assert required in corrected_lifecycle
    for prohibited in (
        "get_redirect_without_following(",
        "parse_session_redirect(",
        "HTTPRedirectHandler",
        "urllib.parse",
        'emergency_cleanup = "NOT_NEEDED"',
    ):
        assert prohibited not in corrected_lifecycle

    for path in (
        BASE / "development-auth-step1-v32-preflight.evidence.json",
        BASE / "development-auth-step1-v32-failure.evidence.json",
        BASE / "development-auth-step2-v32-success.evidence.json",
        BASE / "development-auth-step3-v32-success.evidence.json",
    ):
        assert not path.exists()

    print(
        "DEVELOPMENT_AUTH_V32_FAILED_CONSUMED=PASS "
        "(exact DEVELOPMENT AUTH project; pristine original progress preserved; "
        "Step 1 CONSUMED/SUCCEEDED/PASS; Step 2 CONSUMED/FAILED/FAIL with "
        "V32_SESSION_RESPONSE_MISSING and ambiguous/unverified session state; "
        "Step 3 BLOCKED and unconsumed; v32 retry unauthorized)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
