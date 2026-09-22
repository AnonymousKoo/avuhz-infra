#!/usr/bin/env python3
"""Validate the pristine owner-interactive v32 session attribution boundary."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-session-attribution-owner-interactive-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PATH = BASE / f"{BOUNDARY}.execution-progress.json"

PLAN_ID = "4962f8b6-dad1-45d3-b020-2d60d41409c3"
PROGRESS_ID = "4d4a2f69-78c6-4a33-b6ac-4a4b6e1d30f5"
PLAN_DIGEST = "sha256:6977cafc9894894dbb28e0f0f6c8fd3bcc609cdd014eba4144b1d335c4928c7a"
PROGRESS_DIGEST = "sha256:481bfb127db17518dafb21b780b6cf0904099a3e7c8420be8f3f141e8e03b027"
APPROVAL_ID = "ef85b6ea-3b5d-44f4-bd04-0fd71a31a0ba"
APPROVED_AT = "2026-09-22T00:17:58Z"
APPROVAL_DIGEST = "sha256:df3964782c3c7c28b9b79b677aaa0fd9ec9b99f2377ac0ae296276b3b6c46c27"
APPROVAL_FILE_DIGEST = "sha256:6fcc8148b7fcafec3213baf26240eeaa147bc4242bdf8653ca4425e9561f2755"
CONTRACT_DIGEST = "sha256:5f7de4d7bfce089165e5c2add5df702731b25f4342ace9a11a0bc717a52adcb5"
CREATED_AT = "2026-09-21T23:55:49Z"
WINDOW_START = "2026-09-22T15:00:00Z"
WINDOW_END = "2026-09-22T21:00:00Z"
PROJECT_REF = "pwlhruwutoitnieactol"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
STEP_ID = (
    "development.auth.v32-session-attribution-owner-interactive-v1.step.01."
    "inspect-session-attribution-counts"
)
ATTRIBUTION_SQL = """select
  count(*) as session_count,
  count(*) filter (
    where u.email = 'avuhz-development-synthetic@example.invalid'
  ) as synthetic_session_count
from auth.sessions as s
left join auth.users as u on u.id = s.user_id;"""
ATTRIBUTION_CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "query": ATTRIBUTION_SQL,
    "query_count": 1,
    "result_fields": ["session_count", "synthetic_session_count"],
    "aggregate_only": True,
    "synthetic_identity_predicate": SYNTHETIC_EMAIL,
    "classifications": {
        "1/1": "SYNTHETIC_SESSION_ATTRIBUTED",
        "0/*": "SESSION_DISAPPEARED_REVIEW_REQUIRED",
        "other": "SESSION_ATTRIBUTION_MISMATCH_REVIEW_REQUIRED",
    },
}

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
    "development-auth-v32-session-inspection-owner-interactive-v1.plan.json": (
        "sha256:209b2e23aa38abf686b2815acf92e48e5b6bac74ef6adb9b7b32d34d741c94d7"
    ),
    "development-auth-v32-session-inspection-owner-interactive-v1.progress.json": (
        "sha256:d5d5537f943691fc5c1df089436d918e42d7060762ed75c4ee10acca99f4f746"
    ),
}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def classify(session_count: int, synthetic_session_count: int) -> str:
    assert session_count >= 0
    assert synthetic_session_count >= 0
    if session_count == 1 and synthetic_session_count == 1:
        return "SYNTHETIC_SESSION_ATTRIBUTED"
    if session_count == 0:
        return "SESSION_DISAPPEARED_REVIEW_REQUIRED"
    return "SESSION_ATTRIBUTION_MISMATCH_REVIEW_REQUIRED"


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-22T20:59:59Z")
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
    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST
    assert APPROVED_AT < WINDOW_START
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
        "provider.auth-session-state.attribute-owner-interactive-read-only"
    )
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "auth.session-attribution-aggregate-counts",
        "resource_reference": (
            "supabase:pwlhruwutoitnieactol:auth-session-attribution-counts"
        ),
        "binding_state": "BOUND",
        "exact_version": "owner-interactive.v1",
        "exact_digest": CONTRACT_DIGEST,
    }
    assert canonical_digest(ATTRIBUTION_CONTRACT) == CONTRACT_DIGEST

    # One aggregate SELECT returns only two counts. The canonical example.invalid
    # address is a fixed predicate and cannot appear in the result projection.
    assert ATTRIBUTION_CONTRACT["query_count"] == 1
    assert ATTRIBUTION_SQL.count(";") == 1
    assert ATTRIBUTION_SQL.count(SYNTHETIC_EMAIL) == 1
    projection, relations = ATTRIBUTION_SQL.split("from auth.sessions as s\n", 1)
    assert projection.strip().startswith("select\n  count(*) as session_count,")
    assert "as synthetic_session_count" in projection
    assert f"where u.email = '{SYNTHETIC_EMAIL}'" in projection
    assert " as email" not in projection
    assert relations == "left join auth.users as u on u.id = s.user_id;"
    assert "auth.refresh_tokens" not in ATTRIBUTION_SQL
    for forbidden in (
        "insert ",
        "update ",
        "delete ",
        "truncate ",
        "alter ",
        "create ",
        "drop ",
        "grant ",
        "revoke ",
        "returning ",
    ):
        assert forbidden not in ATTRIBUTION_SQL.lower()
    assert ATTRIBUTION_CONTRACT["result_fields"] == [
        "session_count",
        "synthetic_session_count",
    ]
    assert "additional.sql.execute" in step["prohibited_actions"]
    assert "auth.refresh-tokens.query" in step["prohibited_actions"]
    assert "auth.sessions.raw-row-query" in step["prohibited_actions"]
    assert "auth.users.raw-row-query" in step["prohibited_actions"]
    assert "synthetic-email.return" in step["prohibited_actions"]
    assert "provider.mutation" in step["prohibited_actions"]
    assert "data.operation" in step["prohibited_actions"]

    assert classify(1, 1) == "SYNTHETIC_SESSION_ATTRIBUTED"
    assert classify(0, 0) == "SESSION_DISAPPEARED_REVIEW_REQUIRED"
    assert classify(0, 1) == "SESSION_DISAPPEARED_REVIEW_REQUIRED"
    for counts in ((1, 0), (1, 2), (2, 1), (2, 2)):
        assert classify(*counts) == "SESSION_ATTRIBUTION_MISMATCH_REVIEW_REQUIRED"

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

    assert not EXECUTION_PATH.exists()
    assert not list(BASE.glob(f"{BOUNDARY}*.evidence.json"))
    assert not list((ROOT / ".github/workflows").glob(f"*{BOUNDARY}*"))
    assert not list((ROOT / "scripts").glob(f"*{BOUNDARY}*"))

    for relative, digest in HISTORICAL_RAW_DIGESTS.items():
        assert raw_digest(BASE / relative) == digest

    print(
        "DEVELOPMENT AUTH owner-interactive v32 session attribution validation: "
        "PASS (exact approval recorded before effective time; pristine and "
        "unexecuted; one aggregate SELECT only)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
