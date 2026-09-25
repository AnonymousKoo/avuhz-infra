#!/usr/bin/env python3
"""Validate the approved, unexecuted owner-interactive AUTH rebaseline."""
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
BOUNDARY = "development-auth-v32-session-state-rebaseline-owner-interactive-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
PLAN_ID = "8f9c771e-6dde-4bc8-bc20-8605c8b05c36"
PROGRESS_ID = "2e120dc3-91a9-485d-ad61-34d04dd201c5"
PLAN_DIGEST = "sha256:01610fb22d4755dcb175d37b1c8cd1985ba5c89aa5aca568ab23591de0502e70"
PROGRESS_DIGEST = "sha256:359b388f93fb075d738c85e8995b6ec8559879f4be696a1e3eda2d5e30f52e2c"
PROGRESS_FILE_DIGEST = "sha256:ed17d3ac7e03dc8263970d9bbe962a93b0fb69d2e3b9175b833dea0d1353ca53"
APPROVAL_ID = "064ad292-040f-4d62-8ee8-ddfb4d671591"
APPROVED_AT = "2026-09-25T20:53:38Z"
APPROVAL_DIGEST = "sha256:2091cd66308b04938564eac9d879c53701177fb1e3a20fa9422fe73ec7211061"
APPROVAL_FILE_DIGEST = "sha256:9973a0880bba000298b3f87b21118bb35e4411161d5c96291619100acec46a60"
CREATED_AT = "2026-09-25T19:26:17Z"
WINDOW_START = "2026-09-26T15:00:00Z"
WINDOW_END = "2026-09-26T21:00:00Z"
PROJECT_REF = "pwlhruwutoitnieactol"
V2_FAILURE_DIGEST = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
V2_PROGRESS_DIGEST = "sha256:a942c1fa84f32e96619f916c1686ccb8d8ec1a6f3dd7393a0fa6cc992f167468"
STEP_ID = (
    "development.auth.v32-session-state-rebaseline-owner-interactive-v1.step.01."
    "inspect-session-refresh-aggregate"
)
QUERY = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""
CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "query": QUERY,
    "query_count": 1,
    "result_fields": ["session_count", "refresh_token_count"],
    "aggregate_only": True,
    "classifications": {
        "0/0": "SESSION_CLEANUP_ALREADY_VERIFIED",
        "nonzero": "SESSION_CLEANUP_REQUIRED",
        "malformed_or_unavailable": "SESSION_STATE_UNVERIFIED",
    },
    "nonzero_followup": "STOP_REQUIRES_SEPARATE_EXACT_PLAN",
}
RESOURCE_DIGEST = "sha256:095900c5eb2498b92672c0d4eef4905b6d0c9d8e5232ae3ae20d0f0fee58b7d0"
HISTORICAL_FILES = {
    "development-auth-v32-synthetic-session-cleanup-v2.plan.json":
        "sha256:9be863eb813210c2b534f3afc7e6e55c6e0f89fb599631447486fd755830306d",
    "development-auth-v32-synthetic-session-cleanup-v2-step2-failure.evidence.json":
        V2_FAILURE_DIGEST,
    "development-auth-v32-synthetic-session-cleanup-v2.execution-progress.json":
        "sha256:e4745b85ba5c18eb0b62181bd1286291453159226943a0ed3e3a961ab358c108",
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
    approval = load(APPROVAL_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-26T20:59:59Z")

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
    assert APPROVED_AT < WINDOW_START
    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == (
        "provider.auth-session-state.rebaseline-owner-interactive-read-only"
    )
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "auth.session-refresh-aggregate-rebaseline",
        "resource_reference": "supabase:pwlhruwutoitnieactol:auth-session-refresh-rebaseline",
        "binding_state": "BOUND",
        "exact_version": "owner-interactive.v1",
        "exact_digest": RESOURCE_DIGEST,
    }
    assert canonical_digest(CONTRACT) == RESOURCE_DIGEST
    assert QUERY.count(";") == 1
    assert QUERY.lower().startswith("select")
    assert "auth.sessions" in QUERY and "auth.refresh_tokens" in QUERY
    assert "auth.users" not in QUERY
    for forbidden_sql in (
        "insert ", "update ", "delete ", "truncate ", "alter ", "create ",
        "drop ", "grant ", "revoke ",
    ):
        assert forbidden_sql not in QUERY.lower()
    assert CONTRACT["result_fields"] == ["session_count", "refresh_token_count"]
    assert CONTRACT["classifications"]["0/0"] == "SESSION_CLEANUP_ALREADY_VERIFIED"
    assert CONTRACT["classifications"]["nonzero"] == "SESSION_CLEANUP_REQUIRED"
    assert CONTRACT["classifications"]["malformed_or_unavailable"] == "SESSION_STATE_UNVERIFIED"
    assert step["required_evidence"] == [
        {
            "evidence_type": "auth.synthetic-session.global-revocation.accepted",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": V2_FAILURE_DIGEST,
        },
        {
            "evidence_type": "authorization-plan.execution-progress",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": V2_PROGRESS_DIGEST,
        },
    ]
    for action in (
        "provider.mutation", "session.cleanup", "session.delete", "session.issue",
        "token.issue", "auth.users.query", "data.operation", "render.operation",
        "n8n.operation", "staging.target", "production.target", "cleanup-v1.retry",
        "cleanup-v2.retry", "v32.retry", "v33.prepare",
    ):
        assert action in step["prohibited_actions"]
        assert action in plan["prohibited_actions"]
    assert "additional.sql.execute" in step["prohibited_actions"]
    assert "credential.create" in step["prohibited_actions"]
    assert "credential.rotate" in step["prohibited_actions"]
    assert "service_role" not in json.dumps(plan).lower()

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_FILE_DIGEST
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
    for filename, digest in HISTORICAL_FILES.items():
        assert raw_digest(BASE / filename) == digest, filename
    prior_plan = load(BASE / "development-auth-v32-synthetic-session-cleanup-v2.plan.json")
    prior_progress = load(BASE / "development-auth-v32-synthetic-session-cleanup-v2.execution-progress.json")
    assert prior_plan["plan_digest"] == "sha256:4afea8848bc07967d93be6905b142d6d6c995cd43f204a610c439c0efee50df3"
    assert prior_progress["progress_digest"] == V2_PROGRESS_DIGEST
    assert prior_progress["overall_state"] == "STOPPED"

    print(
        "DEVELOPMENT AUTH v32 session-state rebaseline approval: PASS "
        "(exact plan approved; pristine and unexecuted; one aggregate read only)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
