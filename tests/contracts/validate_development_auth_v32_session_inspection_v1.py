#!/usr/bin/env python3
"""Validate the consumed/failed DEVELOPMENT AUTH v32 inspection state."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_auth_session_inspection import (
    PROVIDER_READ_CREDENTIAL_CLASS,
    PROVIDER_READ_ENV_REFERENCE,
    READ_ONLY_SQL_PATH,
    SESSION_STATE_QUERY,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
)


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.execution-progress.json"
FAILURE_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1-failure.evidence.json"
V32_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v32.execution-progress.json"
V32_FAILURE_PATH = ROOT / "contracts/plans/v1/development-auth-step2-v32-failure.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v32-session-inspection-v1.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v32_session_inspection_v1.py"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"

PLAN_ID = "8a1300d3-4bfb-461c-90c4-a22a53a11647"
APPROVAL_ID = "bf911bca-3187-4fef-a828-24728a844a05"
PROGRESS_ID = "3f12b9c0-b21a-430f-aeb6-ae4a5fc7b0aa"
PLAN_DIGEST = "sha256:c397fc40fe5622047ab38d435ebad57f119a2b7882103ef0d175e39ee0d5bdf1"
APPROVAL_DIGEST = "sha256:81f5e22a86183e95067bd55e93706aa7dbab2bf58af3db8ce3f57f972e245b5c"
PROGRESS_DIGEST = "sha256:2d64cadde4b6b3686b13e00fd3d2fe2e92066d53ce2c51c0c27d56b0cb253d60"
EXECUTION_PROGRESS_DIGEST = "sha256:ed7312e7a29f192a5f6f84c8f838c857391282af08c177e8011993e8d2a165d9"
FAILURE_DIGEST = "sha256:c48c892c69a447eefcc499cc1f3f19d27a5f659a6ca2e52a5152a34487c303d1"
STEP_ID = "development.auth.v32-session-inspection-v1.step.01.inspect-session-state-read-only"
V32_FAILURE_RAW_DIGEST = "sha256:45cddb8d3c0753f4b48e323e7983843f918b194f811b511848bd26f7908c6dc5"
QUERY_DIGEST = "sha256:831937f80dfefc4de6e57b814bf6a70de98e629262bdb10ddd08495401a630a6"
CREATED_AT = "2026-09-17T20:45:00Z"
APPROVED_AT = "2026-09-17T21:13:41Z"
WINDOW_START = "2026-09-18T15:00:00Z"
WINDOW_END = "2026-09-18T21:00:00Z"
WORKFLOW_RUN_ID = 35370969272
EXECUTION_SHA = "005e3d97dd31feb53a1314880a77c1fae96d569c"
RECORDED_AT = "2026-09-18T16:52:03Z"
SAFE_ERROR_CODE = "SESSION_INSPECTION_PROJECT_READ_FAILED"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def expect_plan_failure(plan: dict) -> None:
    changed = copy.deepcopy(plan)
    changed["plan_digest"] = plan_digest(changed)
    try:
        validate_plan(changed, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SCHEMA_INVALID", str(exc)
    else:
        raise AssertionError("provider-read credential constraints must fail closed")


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    progress = load(PROGRESS_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    failure = load(FAILURE_PATH)
    v32_progress = load(V32_PROGRESS_PATH)
    v32_failure = load(V32_FAILURE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 1,
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
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == "provider.auth-session-state.inspect-read-only"
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["dependency_step_ids"] == []
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": [PROVIDER_READ_CREDENTIAL_CLASS],
        "values_stored": False,
    }
    assert step["resource"]["exact_digest"] == QUERY_DIGEST
    assert canonical_digest(SESSION_STATE_QUERY) == QUERY_DIGEST
    assert step["required_evidence"] == [
        {
            "evidence_type": "auth.synthetic-session.lifecycle-completed",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": V32_FAILURE_RAW_DIGEST,
        }
    ]
    for action in (
        "provider.mutation",
        "session.cleanup",
        "session.delete",
        "session.issue",
        "token.issue",
        "v32.retry",
        "v33.prepare",
        "data.operation",
        "render.operation",
        "n8n.operation",
        "staging.target",
        "production.target",
    ):
        assert action in step["prohibited_actions"]
        assert action in plan["prohibited_actions"]

    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    state = progress["step_states"][0]
    assert progress["overall_state"] == "NOT_STARTED"
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []

    assert canonical_digest(failure) == FAILURE_DIGEST
    assert (
        failure["environment"],
        failure["responsibility"],
        failure["provider_reference"],
        failure["project_reference"],
        failure["plan_id"],
        failure["plan_version"],
        failure["plan_digest"],
        failure["approval_id"],
        failure["approval_digest"],
        failure["step_id"],
        failure["attempt"],
        failure["outcome"],
        failure["safe_error_code"],
        failure["inspection_classification"],
    ) == (
        "DEVELOPMENT",
        "AUTH",
        "supabase",
        "pwlhruwutoitnieactol",
        PLAN_ID,
        1,
        PLAN_DIGEST,
        APPROVAL_ID,
        APPROVAL_DIGEST,
        STEP_ID,
        1,
        "FAILED_UNVERIFIED",
        SAFE_ERROR_CODE,
        "SESSION_STATE_UNVERIFIED",
    )
    observation = failure["execution_observation"]
    assert observation == {
        "workflow_run_id": WORKFLOW_RUN_ID,
        "execution_sha": EXECUTION_SHA,
        "execution_class": "PROVIDER_READ",
        "workflow_dispatch_attempts": 1,
        "authority_validation_passed": True,
        "provider_read_credential_present": True,
        "executor_entered": True,
        "provider_read_attempted": True,
        "first_provider_operation": {
            "method": "GET",
            "endpoint": "https://api.supabase.com/v1/projects/pwlhruwutoitnieactol",
            "attempted": True,
            "succeeded": False,
        },
        "sql_session_state_inspection_reached": False,
        "auth_sessions_query_reached": False,
        "auth_refresh_tokens_query_reached": False,
        "expected_subject_binding_evaluated": False,
        "cleanup_attempted": False,
        "provider_mutation_attempted": False,
    }
    assert failure["failure_observation"] == {
        "exact_project_read_failure_cause": "UNDETERMINED_BY_SANITIZED_EXECUTOR",
        "session_state": "SESSION_STATE_UNVERIFIED",
        "refresh_token_state": "SESSION_STATE_UNVERIFIED",
        "provider_session_refresh_state": "UNRESOLVED",
        "session_count_established": False,
        "session_count": None,
        "refresh_token_count_established": False,
        "refresh_token_count": None,
        "expected_subject_binding_status": "NOT_EVALUATED",
        "sql_session_state_inspection_executed": False,
    }
    assert failure["authority_state"] == {
        "inspection_authorization": "CONSUMED",
        "authorization_consumed": True,
        "retry_authorized": False,
    }
    assert not any(failure["security_state"].values())
    assert failure["recorded_at"] == RECORDED_AT
    assert "http_status" not in json.dumps(failure, sort_keys=True).lower()

    assert execution_progress["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    assert execution_progress["record_version"] == 3
    assert execution_progress["overall_state"] == "STOPPED"
    assert execution_progress["updated_at"] == RECORDED_AT
    executed_state = execution_progress["step_states"][0]
    assert (
        executed_state["authorization_state"],
        executed_state["execution_state"],
        executed_state["verification_state"],
        executed_state["authorization_consumed"],
        executed_state["safe_error_code"],
    ) == ("CONSUMED", "FAILED", "FAIL", True, SAFE_ERROR_CODE)
    assert executed_state["evidence"] == [{
        "evidence_type": "auth.session-state.inspected-read-only",
        "evidence_reference": "github.actions.run.35370969272.step1.attempt1.failed-unverified",
        "evidence_digest": FAILURE_DIGEST,
        "recorded_at": RECORDED_AT,
    }]
    assert "before the SQL session-state inspection" in executed_state["observed_postcondition"]
    assert len(executed_state["binding_assertions"]) == 1
    preflight = executed_state["binding_assertions"][0]
    assert preflight["binding_id"].endswith(".provider-read-executor")
    assert preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert preflight["evidence_type"] == "provider.read-executor-capability.observed"
    assert preflight["sanitized_value"] is None
    assert preflight["recorded_at"] == RECORDED_AT

    assert v32_progress["overall_state"] == "STOPPED"
    v32_states = v32_progress["step_states"]
    assert [
        (item["authorization_state"], item["execution_state"], item["verification_state"])
        for item in v32_states
    ] == [
        ("CONSUMED", "SUCCEEDED", "PASS"),
        ("CONSUMED", "FAILED", "FAIL"),
        ("BLOCKED", "NOT_STARTED", "NOT_STARTED"),
    ]
    assert v32_failure["failure_observation"]["provider_session_outcome"] == "AMBIGUOUS"
    assert v32_failure["failure_observation"]["session_state"] == "UNVERIFIED"
    assert v32_failure["failure_observation"]["refresh_token_state"] == "UNVERIFIED"
    assert v32_failure["authority_state"]["v32_retry_authorized"] is False
    assert raw_digest(V32_FAILURE_PATH) == V32_FAILURE_RAW_DIGEST

    expected_subject = DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0].subject_digest
    subject_binding = next(
        item
        for item in step["binding_declarations"]
        if item["binding_id"].endswith(".expected-subject")
    )
    assert subject_binding["preapproval_value"]["value"] == expected_subject
    assert subject_binding["preapproval_value"]["exact_digest"] == canonical_digest(expected_subject)

    assert APPROVAL_PATH.exists()
    assert EXECUTION_PROGRESS_PATH.exists()
    assert list(PLAN_PATH.parent.glob("development-auth-v32-session-inspection-v1*.evidence.json")) == [
        FAILURE_PATH
    ]

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    lifecycle = LIFECYCLE_PATH.read_text(encoding="utf-8")
    assert PROVIDER_READ_ENV_REFERENCE in workflow
    assert workflow.count(f"secrets.{PROVIDER_READ_ENV_REFERENCE}") == 1
    assert "workflow_dispatch" in workflow
    assert "development-auth-v32-session-inspection-v1.approval.json" in workflow
    assert "service_role" not in workflow.lower()
    assert "AUTH_TOKEN_VALIDATION_V32_EPHEMERAL" not in workflow
    assert "SUPABASE_PUBLISHABLE_KEY" not in workflow
    assert READ_ONLY_SQL_PATH == (
        "/v1/projects/pwlhruwutoitnieactol/database/query/read-only"
    )
    for forbidden in ("/auth/v1/logout", "request_local_session_logout", "run_recovery_session_lifecycle"):
        assert forbidden not in executor
    assert "request_direct_recovery_verification" in lifecycle
    assert "get_redirect_without_following" not in lifecycle

    wrong_execution = copy.deepcopy(plan)
    wrong_execution["steps"][0]["execution_class"] = "PROVIDER_MUTATION"
    expect_plan_failure(wrong_execution)
    wrong_operation = copy.deepcopy(plan)
    wrong_operation["steps"][0]["operation"] = "provider.resource.verify"
    expect_plan_failure(wrong_operation)
    mixed_class = copy.deepcopy(plan)
    mixed_class["steps"][0]["credential_policy"]["allowed_classes"].append(
        "OWNER_INTERACTIVE_SESSION"
    )
    expect_plan_failure(mixed_class)

    print(
        "DEVELOPMENT_AUTH_V32_SESSION_INSPECTION_V1_FAILED_CONSUMED=PASS "
        "(STOPPED; CONSUMED/FAILED/FAIL; SESSION_STATE_UNVERIFIED; SQL inspection "
        "not reached; retry unauthorized; no provider mutation or cleanup)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
