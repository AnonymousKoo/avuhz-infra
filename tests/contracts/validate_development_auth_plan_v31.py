#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v31 forward-only synthetic-token continuation."""
from __future__ import annotations

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

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v31.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v31.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v31.approval.json"
V30_PLAN_PATH = BASE / "development-auth-integration-v30.plan.json"
V30_PROGRESS_PATH = BASE / "development-auth-integration-v30.progress.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v31-token-validation.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v31_token_executor.py"

PLAN_ID = "c2a83103-7177-4bf4-855f-c3428b2d5b73"
PLAN_DIGEST = "sha256:8ea09f44c3c5e65a6a8d86b0df6579b0f4476b63ae6c167a6194948c86aab043"
PROGRESS_DIGEST = "sha256:c72006da9f3c8c108a0dcc97f9dd2b5c5f426f6c83bb14b3ebe9f496c90b92a5"
WINDOW_START = "2026-09-16T00:15:00Z"
WINDOW_END = "2026-09-16T06:15:00Z"
PROJECT = "pwlhruwutoitnieactol"
BASE_EXECUTOR_SHA256 = "a32ae8d3598c615cc6e96f6673274c1bdd43c4ded569046b2547ceb24acc22c4"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

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
        "secrets.AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V30_EPHEMERAL",
    ):
        assert required in workflow
    for required in (
        BASE_EXECUTOR_SHA256,
        "development_auth_v30_token_executor.py",
        OLD if False else "OLD_PLAN_ID",
        "NEW_PLAN_ID",
        "source.replace(\"v30\", \"v31\").replace(\"V30\", \"V31\")",
        "V31_BASE_EXECUTOR_DIGEST_MISMATCH",
    ):
        assert required in executor

    for path in (
        BASE / "development-auth-integration-v31.execution-progress.json",
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
        "(forward-only timing continuation of unapproved v30; exact AUTH project; "
        "pristine progress; no provider execution evidence)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
