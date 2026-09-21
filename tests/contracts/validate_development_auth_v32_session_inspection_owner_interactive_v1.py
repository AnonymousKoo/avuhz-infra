#!/usr/bin/env python3
"""Validate the pristine owner-interactive DEVELOPMENT AUTH v32 inspection."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    initial_progress,
    plan_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-session-inspection-owner-interactive-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PATH = BASE / f"{BOUNDARY}.execution-progress.json"

PLAN_ID = "4bb906a5-1210-4564-aae2-81530f33661a"
PROGRESS_ID = "cf384dab-3f69-414f-8175-753e50f2216c"
PLAN_DIGEST = "sha256:406b8f09b668bd32c0ac94715b317680c1d530344fe07c195bb7530403603e5e"
PROGRESS_DIGEST = "sha256:0c8a41220b72367495046ab6dd0f1782858016bae586423556ca47d3de618e2b"
CREATED_AT = "2026-09-21T23:20:17Z"
WINDOW_START = "2026-09-22T15:00:00Z"
WINDOW_END = "2026-09-22T21:00:00Z"
PROJECT_REF = "pwlhruwutoitnieactol"
STEP_ID = (
    "development.auth.v32-session-inspection-owner-interactive-v1.step.01."
    "inspect-session-refresh-counts"
)
SESSION_SQL = "select count(*) as session_count\nfrom auth.sessions;"
REFRESH_SQL = (
    "select count(*) as refresh_token_count\nfrom auth.refresh_tokens;"
)
INSPECTION_CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "ordered_statements": [SESSION_SQL, REFRESH_SQL],
    "aggregate_only": True,
    "stop_after_first_nonzero_count": True,
    "zero_classification": "SESSION_STATE_ZERO_CONFIRMED",
    "nonzero_classification": "SESSION_STATE_NONZERO_OWNER_REVIEW_REQUIRED",
}
CONTRACT_DIGEST = "sha256:ac58b759f8a3ba8d8853f231955a0d6b6dd456792f9d2f9d16779790f0070443"

HISTORICAL_RAW_DIGESTS = {
    "development-auth-integration-v31.plan.json": (
        "sha256:a1700adfef42ae412720c637c4dfb5d2f00aafd7d3562590a58a6c47e466f86f"
    ),
    "development-auth-integration-v31.execution-progress.json": (
        "sha256:d7ec17953b8ea206935f1d01afee5f7e3bcd8497a72dbe61979628f4c4938e9e"
    ),
    "development-auth-integration-v32.plan.json": (
        "sha256:7b97bf0790ad0e0eab85ce377808165f63a87d9d44834ad0e26d284bfbb9c1d7"
    ),
    "development-auth-integration-v32.execution-progress.json": (
        "sha256:718530864fc018a48c856269c45758d16299d5cc8ce7550a5ea8155d976e1360"
    ),
    "development-auth-v32-session-inspection-v1.plan.json": (
        "sha256:3dbfcdcd125347b000c0d9858be7baf4fca1c360fb42d05e234baeb10946f3b6"
    ),
    "development-auth-v32-session-inspection-v1.execution-progress.json": (
        "sha256:9d4c13df7a4a87b4517baacde65a1e865661753cd6123875fee3e58d59de3f37"
    ),
    "development-auth-provider-read-diagnostic-v1.plan.json": (
        "sha256:06d73a1846bf1480b34fc42d1af0fd216edc83893015307471f3a18b9a6a2902"
    ),
    "development-auth-provider-read-diagnostic-v1.progress.json": (
        "sha256:caddfcb340e1434205a40af89f7f7c1bd9fde9c379eb9a4cbda9532d8f9eec43"
    ),
    "development-auth-provider-read-diagnostic-v2.plan.json": (
        "sha256:29c955cbf73bf78510c5decbbec1045cccf4daf78258fd0a0b6d795a29ece9d8"
    ),
    "development-auth-provider-read-diagnostic-v2.progress.json": (
        "sha256:14d9748de3472ec1b29108f075388316c92a7d359d2269588b7ba71defb62d1c"
    ),
}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    assert plan_digest(plan) == PLAN_DIGEST
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT_REF,
        "responsibility": "AUTH",
        "issuer_reference": f"https://{PROJECT_REF}.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }

    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == (
        "provider.auth-session-state.inspect-owner-interactive-read-only"
    )
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "auth.session-refresh-aggregate-counts",
        "resource_reference": (
            "supabase:pwlhruwutoitnieactol:auth-session-refresh-counts"
        ),
        "binding_state": "BOUND",
        "exact_version": "owner-interactive.v1",
        "exact_digest": CONTRACT_DIGEST,
    }
    assert canonical_digest(INSPECTION_CONTRACT) == CONTRACT_DIGEST

    # The contract permits only the two exact aggregate SELECTs, in order.
    assert INSPECTION_CONTRACT["ordered_statements"] == [SESSION_SQL, REFRESH_SQL]
    aggregate_pattern = re.compile(
        r"\Aselect count\(\*\) as (session_count|refresh_token_count)\n"
        r"from auth\.(sessions|refresh_tokens);\Z"
    )
    for statement in INSPECTION_CONTRACT["ordered_statements"]:
        assert aggregate_pattern.fullmatch(statement)
        lowered = statement.lower()
        for forbidden in (
            " auth.users",
            "insert ",
            "update ",
            "delete ",
            "truncate ",
            "alter ",
            "create ",
            "drop ",
            "grant ",
            "revoke ",
        ):
            assert forbidden not in lowered
    assert INSPECTION_CONTRACT["stop_after_first_nonzero_count"] is True
    assert "first-count.nonzero" in step["stop_conditions"]
    assert "additional.sql.after-nonzero" in step["prohibited_actions"]
    assert "raw-row.read" in step["prohibited_actions"]
    assert "auth.users.query" in step["prohibited_actions"]
    assert "provider.mutation" in step["prohibited_actions"]
    assert "data.operation" in step["prohibited_actions"]

    assert progress == initial_progress(
        plan,
        SCHEMA_ROOT,
        PROGRESS_ID,
        CREATED_AT,
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert (
        state["authorization_state"],
        state["execution_state"],
        state["verification_state"],
        state["authorization_consumed"],
    ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
    assert state["evidence"] == []

    assert not APPROVAL_PATH.exists()
    assert not EXECUTION_PATH.exists()
    assert not list(BASE.glob(f"{BOUNDARY}*.evidence.json"))
    assert not list((ROOT / ".github/workflows").glob(f"*{BOUNDARY}*"))
    assert not list((ROOT / "scripts").glob(f"*{BOUNDARY}*"))

    for relative, digest in HISTORICAL_RAW_DIGESTS.items():
        assert raw_digest(BASE / relative) == digest

    print(
        "DEVELOPMENT AUTH owner-interactive v32 session inspection validation: "
        "PASS (pristine, unapproved, unexecuted; exact aggregate SELECTs only)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
