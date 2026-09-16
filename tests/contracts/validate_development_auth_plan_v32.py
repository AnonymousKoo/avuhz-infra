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
V31_PLAN_PATH = BASE / "development-auth-integration-v31.plan.json"
V31_EXECUTION_PATH = BASE / "development-auth-integration-v31.execution-progress.json"
V31_FAILURE_PATH = BASE / "development-auth-step1-v31-failure.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v32-token-validation.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v32_token_executor.py"

PLAN_ID = "e8cd574a-a532-4c95-ab5d-5c069c1bbb96"
PLAN_DIGEST = "sha256:c43b0b906bfb0c03e763d6cc5a13d47a900b40eb4db8fd904c799c524ec6c37c"
PROGRESS_DIGEST = "sha256:7539fdec222abaddce8fc6fce1ffd5299c793db34aa97a05932adccc253825f3"
APPROVAL_ID = "22afae15-0eb0-4d29-927d-ed2d6405eb02"
APPROVED_AT = "2026-09-16T15:01:37Z"
APPROVAL_DIGEST = "sha256:6c3e89a1beb71b6c6d4265ea768fe18e0635b7469d32ac244cd4a650e7743bee"
V31_PLAN_DIGEST = "sha256:8ea09f44c3c5e65a6a8d86b0df6579b0f4476b63ae6c167a6194948c86aab043"
V31_EXECUTION_DIGEST = "sha256:88d8021f785120d91d4314d7c14028ca5bd8467db2f38b4ac7dea866d6399190"
V31_FAILURE_DIGEST = "sha256:1ed8a2fcbdb7d168e48387a42096be23bee05c3eb8732735b4502374b0dbb034"
WINDOW_START = "2026-09-17T15:00:00Z"
WINDOW_END = "2026-09-17T21:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
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
    v31_plan = load(V31_PLAN_PATH)
    v31_execution = load(V31_EXECUTION_PATH)
    v31_failure = load(V31_FAILURE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
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
    ):
        assert required in derived

    for path in (
        BASE / "development-auth-integration-v32.execution-progress.json",
        BASE / "development-auth-step1-v32-preflight.evidence.json",
        BASE / "development-auth-step1-v32-success.evidence.json",
        BASE / "development-auth-step2-v32-success.evidence.json",
        BASE / "development-auth-step3-v32-success.evidence.json",
    ):
        assert not path.exists()

    print(
        "DEVELOPMENT_AUTH_V32_APPROVED=PASS "
        "(v31 stopped/consumed and retry unauthorized; corrected direct-HTTP parser "
        "pinned; exact DEVELOPMENT AUTH project; pristine/approved/unexecuted; "
        "v32 secret referenced by name only; no provider contact)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
