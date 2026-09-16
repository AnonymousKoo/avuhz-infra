#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v31 forward-only synthetic-token continuation."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v31.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v31.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v31.approval.json"
EXECUTION_PROGRESS_PATH = BASE / "development-auth-integration-v31.execution-progress.json"
FAILURE_EVIDENCE_PATH = BASE / "development-auth-step1-v31-failure.evidence.json"
V30_PLAN_PATH = BASE / "development-auth-integration-v30.plan.json"
V30_PROGRESS_PATH = BASE / "development-auth-integration-v30.progress.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v31-token-validation.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v31_token_executor.py"

PLAN_ID = "c2a83103-7177-4bf4-855f-c3428b2d5b73"
PLAN_DIGEST = "sha256:8ea09f44c3c5e65a6a8d86b0df6579b0f4476b63ae6c167a6194948c86aab043"
PROGRESS_DIGEST = "sha256:c72006da9f3c8c108a0dcc97f9dd2b5c5f426f6c83bb14b3ebe9f496c90b92a5"
EXECUTION_PROGRESS_DIGEST = "sha256:88d8021f785120d91d4314d7c14028ca5bd8467db2f38b4ac7dea866d6399190"
FAILURE_EVIDENCE_DIGEST = "sha256:1ed8a2fcbdb7d168e48387a42096be23bee05c3eb8732735b4502374b0dbb034"
WINDOW_START = "2026-09-16T00:15:00Z"
WINDOW_END = "2026-09-16T06:15:00Z"
PROJECT = "pwlhruwutoitnieactol"
BASE_EXECUTOR_SHA256 = "6e3e8e79cdc8f726b3f0b3981fdf00045a3beac70dece3898d91c3c81bf5d9a5"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    failure_evidence = load(FAILURE_EVIDENCE_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 31
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert progress["plan_id"] == PLAN_ID
    assert progress["plan_version"] == 31
    assert progress["plan_digest"] == PLAN_DIGEST
    assert progress["progress_digest"] == PROGRESS_DIGEST
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

    v30_plan = load(V30_PLAN_PATH)
    v30_progress = load(V30_PROGRESS_PATH)
    assert v30_plan["plan_version"] == 30
    assert v30_plan["authorization_window"]["starts_at"] == "2026-09-15T23:00:00Z"
    assert v30_progress["overall_state"] == "NOT_STARTED"
    assert not (BASE / "development-auth-integration-v30.approval.json").exists()

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    for required in (
        "DEVELOPMENT AUTH v31 Synthetic Token Validation",
        "EXECUTE_V31_SYNTHETIC_TOKEN_VALIDATION",
        "environment: development",
        PLAN_ID,
        PLAN_DIGEST,
        WINDOW_START,
        WINDOW_END,
        "development-auth-integration-v31.approval.json",
        "scripts/development_auth_v31_token_executor.py",
        "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V31_EPHEMERAL",
    ):
        assert required in workflow
    for required in (
        BASE_EXECUTOR_SHA256,
        "development_auth_v30_token_executor.py",
        "OLD_PLAN_ID",
        "NEW_PLAN_ID",
        "source.replace(\"v30\", \"v31\").replace(\"V30\", \"V31\")",
        "V31_BASE_EXECUTOR_DIGEST_MISMATCH",
        "OLD_PLAN_VERSION_GUARD",
        "NEW_PLAN_VERSION_GUARD",
    ):
        assert required in executor

    spec = importlib.util.spec_from_file_location("development_auth_v31_token_executor", EXECUTOR_PATH)
    assert spec is not None and spec.loader is not None
    executor_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(executor_module)
    derived = executor_module.derived_source()
    assert 'plan["plan_version"] != 31' in derived
    assert 'plan["plan_version"] != 30' not in derived
    for required in (
        "request_generate_recovery_link",
        "parse_generate_recovery_link_response",
        "V31_RECOVERY_LINK_PROVIDER_REJECTED",
        "V31_RECOVERY_LINK_REQUEST_FAILED",
        "V31_RECOVERY_LINK_RESPONSE_INVALID",
        "V31_RECOVERY_LINK_RESPONSE_SHAPE_INVALID",
    ):
        assert required in derived

    assert failure_evidence == {
        "evidence_type": "auth.synthetic-recovery-link.generated",
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "plan_id": PLAN_ID,
        "plan_version": 31,
        "plan_digest": PLAN_DIGEST,
        "step_id": "development.auth.v31.step.01.generate-existing-user-recovery-link",
        "attempt": 1,
        "outcome": "FAILED_AMBIGUOUS",
        "safe_error_code": "V31_RECOVERY_LINK_GENERATION_FAILED",
        "execution_observation": {
            "workflow_run_id": 35046258011,
            "execution_sha": "1b156d906522923b301f1e7feccc7fd15f9adfa8",
            "execution_class": "PROVIDER_MUTATION",
            "provider_mutation_attempts": 1,
            "provider_mutation_outcome": "AMBIGUOUS",
            "step_2_lifecycle_reached": False,
            "step_3_jwt_validation_reached": False,
            "session_issuance_reached": False,
            "emergency_cleanup": "NOT_NEEDED",
            "post_failure_provider_readback_performed": False,
        },
        "preflight_observation": {
            "session_count": 0,
            "refresh_token_count": 0,
            "zero_sessions_verified": True,
            "zero_refresh_tokens_verified": True,
        },
        "failure_observation": {
            "exact_historical_provider_response_classification": "UNKNOWN",
            "collapsed_safe_code_conditions": [
                "PROVIDER_OR_HTTP_REJECTION",
                "REQUEST_OR_NETWORK_FAILURE",
                "INVALID_JSON",
                "SUCCESSFUL_RAW_SUPABASE_RESPONSE_REJECTED_AS_UNEXPECTED_SHAPE",
            ],
        },
        "root_cause_review": {
            "status": "CONFIRMED_EXECUTOR_DEFECT",
            "classification": "DIRECT_AUTH_HTTP_RESPONSE_PARSED_AS_SDK_TRANSFORMED_RESPONSE_SHAPE",
            "correction_reference": "github.pull-request.110",
            "correction_commit": "fb9c2c6061528c3fb56c97f5307366306a3fb275",
            "basis": [
                "The v31 executor called the direct Supabase Auth HTTP endpoint but expected the SDK-transformed nested response shape.",
                "The old executor mapped provider or HTTP rejection, request or network failure, invalid JSON, and rejection of a successful raw Supabase response shape to the same safe error code.",
                "PR 110 corrected the parser and error classification, but the sanitized historical record cannot distinguish which condition occurred in workflow run 35046258011.",
            ],
            "exact_historical_provider_response_classification": "UNKNOWN",
            "retry_authorized": False,
            "forward_only_correction_required": True,
        },
        "authority_state": {
            "step_1_authorization": "CONSUMED",
            "step_1_authorization_consumed": True,
            "retry_authorized": False,
            "forward_only_correction_required": True,
        },
        "security_state": {
            "secret_material_recorded": False,
            "token_material_recorded": False,
            "recovery_link_material_recorded": False,
            "raw_provider_response_recorded": False,
            "pii_recorded": False,
            "data_resource_touched": False,
            "render_touched": False,
            "n8n_touched": False,
            "staging_touched": False,
            "production_touched": False,
        },
        "recorded_at": "2026-09-16T02:00:13Z",
    }
    assert canonical_digest(failure_evidence) == FAILURE_EVIDENCE_DIGEST

    assert execution_progress["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "STOPPED"
    assert execution_progress["updated_at"] == "2026-09-16T02:00:13Z"
    step1 = execution_progress["step_states"][0]
    assert step1["authorization_state"] == "CONSUMED"
    assert step1["execution_state"] == "FAILED"
    assert step1["verification_state"] == "FAIL"
    assert step1["authorization_consumed"] is True
    assert step1["safe_error_code"] == "V31_RECOVERY_LINK_GENERATION_FAILED"
    assert step1["evidence"] == [{
        "evidence_type": "auth.synthetic-recovery-link.generated",
        "evidence_reference": "github.actions.run.35046258011.step1.attempt1.failed-ambiguous",
        "evidence_digest": FAILURE_EVIDENCE_DIGEST,
        "recorded_at": "2026-09-16T02:00:13Z",
    }]
    assert step1["binding_assertions"] == []
    assert all(
        state["authorization_state"] == "BLOCKED"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and state["evidence"] == []
        and state["binding_assertions"] == []
        for state in execution_progress["step_states"][1:]
    )

    for path in (
        BASE / "development-auth-step1-v31-preflight.evidence.json",
        BASE / "development-auth-step1-v31-success.evidence.json",
        BASE / "development-auth-step2-v31-success.evidence.json",
        BASE / "development-auth-step3-v31-success.evidence.json",
    ):
        assert not path.exists()

    if APPROVAL_PATH.exists():
        approval = load(APPROVAL_PATH)
        assert approval["plan_id"] == PLAN_ID
        assert approval["plan_version"] == 31
        assert approval["plan_digest"] == PLAN_DIGEST
        assert approval["effective_at"] == WINDOW_START
        assert approval["expires_at"] == WINDOW_END
        assert utc(approval["approved_at"]) <= utc(WINDOW_START)
        validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
        state = "APPROVED"
    else:
        state = "PREPARED"

    print(
        f"DEVELOPMENT_AUTH_V31_{state}=PASS "
        "(exact AUTH project; pristine original progress preserved; Step 1 "
        "CONSUMED/FAILED/FAIL with ambiguous provider mutation outcome and retry "
        "unauthorized; Steps 2-3 BLOCKED and unconsumed; forward-only correction required)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
