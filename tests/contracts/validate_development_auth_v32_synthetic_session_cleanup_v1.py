#!/usr/bin/env python3
"""Validate the pristine DEVELOPMENT AUTH v32 synthetic-session cleanup plan."""
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
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
PLAN_ID = "daa207fd-1426-455f-a921-1dc69d8f2d65"
PROGRESS_ID = "a75eec04-ffa1-4a49-9099-0f8a25d9e13b"
PLAN_DIGEST = "sha256:19bc9c0182da26f3a4b56339f70211966aaa74957c910d5a5830f0f26d1a832e"
PROGRESS_DIGEST = "sha256:a3b0f0b477747af83a0cbe3b8aa660ff43d0258d763e0283c7877e129bf002c7"
APPROVAL_ID = "7fa7cd4e-5448-4af3-9d29-4478a0c90cee"
APPROVED_AT = "2026-09-22T20:20:21Z"
APPROVAL_DIGEST = "sha256:bd9756345ccaa63f82dd6ec4d8398b90574d3ba5b4049d0e7ddab738fe92e09f"
APPROVAL_FILE_DIGEST = "sha256:f73aa8bd87768cf944a266316ac2779ae7b7a9b9868ff331a73cabbe6d7aeaa8"
PLAN_RAW_DIGEST = "sha256:6880d642628eab13c18cfa3ab6f3bd5f1f09af282f538659fa70644c9d1a5f41"
PROGRESS_RAW_DIGEST = "sha256:d30e7dc67e3783e8ce59ae08e5fe2d9ba1c68dd381b76b772da7bb589f799de3"
EXECUTOR_RAW_DIGEST = "sha256:a3e883ca5798bd60094181419c188a28f46cbcc8f648366e60cad29fa02fc7e4"
WORKFLOW_RAW_DIGEST = "sha256:28f5b16586e64b1bad389a62c40e2172950e59f9814a3b0c0fe428800ebd929f"
LIFECYCLE_RAW_DIGEST = "sha256:55503f13489944b0b4b51e3dc24875d5c6e83c69e8fc6a8aed6a03fdb0736749"
CREATED_AT = "2026-09-22T15:40:34Z"
WINDOW_START = "2026-09-23T15:00:00Z"
WINDOW_END = "2026-09-23T21:00:00Z"
PROJECT_REF = "pwlhruwutoitnieactol"
DATA_PROJECT_REF = "gnuqaefotwgkwurjpyik"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
ATTRIBUTION_EVIDENCE_DIGEST = "sha256:87448d893e3d6f013cd6a20bdf05eef25b5d1c3425513377469c62eab40dffcc"
ATTRIBUTION_PROGRESS_DIGEST = "sha256:d97ded08e2e31417382392f99875956b8e75c496f3b5404470191dd13779ff76"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1_EPHEMERAL"
PUBLISHABLE_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "REVOKE_V32_SYNTHETIC_SESSIONS_GLOBAL"
STEP2_ID = (
    "development.auth.v32-synthetic-session-cleanup-v1.step.02."
    "revoke-synthetic-sessions-global"
)
EXECUTOR_PATH = ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v1.py"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v1.yml"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"

PRECHECK_SQL = """select
  count(*) as session_count,
  count(*) filter (
    where u.email = 'avuhz-development-synthetic@example.invalid'
  ) as synthetic_session_count
from auth.sessions as s
left join auth.users as u on u.id = s.user_id;"""
VERIFY_SQL = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""

PRECHECK_CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "query": PRECHECK_SQL,
    "query_count": 1,
    "result_fields": ["session_count", "synthetic_session_count"],
    "required_result": {"session_count": 1, "synthetic_session_count": 1},
    "success_classification": "PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED",
}

# Public contract evidence, checked without contacting the project:
# - https://supabase.com/docs/guides/auth/signout
# - https://supabase.com/docs/guides/auth/sessions
# - https://github.com/supabase/auth/blob/master/openapi.yaml
# - https://github.com/supabase/auth/blob/master/internal/api/logout.go
# Supabase's global sign-out revokes every refresh token/session for the bearer
# user. A valid user JWT is required, so the unavailable historical v32 JWT
# cannot be reconstructed and one bounded temporary session is necessary.
CLEANUP_CONTRACT = {
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_MUTATION",
    "synthetic_identity": SYNTHETIC_EMAIL,
    "existing_user_only": True,
    "maximum_temporary_sessions": 1,
    "credential_classes": [
        "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "SUPABASE_PUBLISHABLE",
        "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN",
    ],
    "credential_references": [
        ADMIN_REFERENCE,
        PUBLISHABLE_REFERENCE,
        "EXECUTOR_MEMORY_ONLY",
    ],
    "generate_link": {
        "method": "POST",
        "path": "/auth/v1/admin/generate_link",
        "type": "recovery",
        "send_email": False,
        "raw_field": "hashed_token",
        "headers": [
            "apikey:admin-ephemeral",
            "Authorization:Bearer admin-ephemeral",
            "Content-Type:application/json",
        ],
    },
    "verify": {
        "method": "POST",
        "path": "/auth/v1/verify",
        "body_fields": ["type", "token_hash"],
        "type": "recovery",
        "session_response": "top-level-access_token-refresh_token-expires_in-user",
        "headers": [
            "apikey:publishable",
            "Authorization:Bearer publishable",
            "Content-Type:application/json",
        ],
    },
    "jwt_policy": {
        "algorithm": "ES256",
        "issuer": f"https://{PROJECT_REF}.supabase.co/auth/v1",
        "audience": "audience.avuhz.command-service.development",
        "caller_kind": "HUMAN",
        "scopes": ["engagement:read"],
        "authority_roles": [],
        "aal": "aal1",
        "authenticated": True,
        "anonymous": False,
    },
    "logout": {
        "method": "POST",
        "path": "/auth/v1/logout?scope=global",
        "success_status": 204,
        "bearer": "temporary-access-jwt",
        "headers": [
            "apikey:publishable",
            "Authorization:Bearer temporary-access-jwt",
        ],
    },
    "success_classification": "SESSION_REVOCATION_REQUEST_ACCEPTED",
    "direct_auth_schema_delete": False,
    "retry_authorized": False,
    "sensitive_material_retained": False,
    "sources": [
        "https://supabase.com/docs/guides/auth/signout",
        "https://supabase.com/docs/guides/auth/sessions",
        "https://github.com/supabase/auth/blob/master/openapi.yaml",
        "https://github.com/supabase/auth/blob/master/internal/api/logout.go",
    ],
}

VERIFY_CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT_REF,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "query": VERIFY_SQL,
    "query_count": 1,
    "result_fields": ["session_count", "refresh_token_count"],
    "required_result": {"session_count": 0, "refresh_token_count": 0},
    "success_classification": "SESSION_CLEANUP_VERIFIED",
    "nonzero_classification": "SESSION_CLEANUP_NOT_VERIFIED",
    "unverified_classification": "SESSION_STATE_UNVERIFIED",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def assert_select_only(query: str) -> None:
    assert query.lstrip().lower().startswith("select")
    assert query.count(";") == 1
    for forbidden in (
        "insert ", "update ", "delete ", "truncate ", "alter ", "create ",
        "drop ", "grant ", "revoke ", "returning ",
    ):
        assert forbidden not in query.lower()


def main(*, execution_surface_only: bool = False) -> None:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-23T20:59:59Z")

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT_REF
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
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
    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST
    assert APPROVED_AT < WINDOW_START
    assert len(plan["steps"]) == 3

    precheck, cleanup, verify = plan["steps"]
    assert [s["ordinal"] for s in plan["steps"]] == [1, 2, 3]
    assert plan["ordered_step_ids"] == [s["step_id"] for s in plan["steps"]]
    assert [s["execution_class"] for s in plan["steps"]] == [
        "PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_READ"
    ]
    assert precheck["resource"]["exact_digest"] == canonical_digest(PRECHECK_CONTRACT)
    assert cleanup["resource"]["exact_digest"] == canonical_digest(CLEANUP_CONTRACT)
    assert verify["resource"]["exact_digest"] == canonical_digest(VERIFY_CONTRACT)

    assert raw_digest(
        BASE / "development-auth-v32-session-attribution-owner-interactive-v1-success.evidence.json"
    ) == ATTRIBUTION_EVIDENCE_DIGEST
    attributed = load(
        BASE / "development-auth-v32-session-attribution-owner-interactive-v1.execution-progress.json"
    )
    assert attributed["progress_digest"] == ATTRIBUTION_PROGRESS_DIGEST
    assert precheck["required_evidence"] == [{
        "evidence_type": "auth.session-attribution.owner-interactive-inspected",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": ATTRIBUTION_EVIDENCE_DIGEST,
    }]

    assert_select_only(PRECHECK_SQL)
    assert_select_only(VERIFY_SQL)
    assert PRECHECK_CONTRACT["required_result"] == {
        "session_count": 1, "synthetic_session_count": 1
    }
    assert VERIFY_CONTRACT["required_result"] == {
        "session_count": 0, "refresh_token_count": 0
    }
    assert "auth.refresh_tokens" not in PRECHECK_SQL
    assert "auth.users" not in VERIFY_SQL

    assert cleanup["operation"] == "provider.auth-session.recover-once-validate-and-logout-global"
    assert cleanup["credential_policy"]["allowed_classes"] == [
        "SUPABASE_AUTH_ADMIN_EPHEMERAL"
    ]
    assert CLEANUP_CONTRACT["maximum_temporary_sessions"] == 1
    assert CLEANUP_CONTRACT["generate_link"]["raw_field"] == "hashed_token"
    assert CLEANUP_CONTRACT["verify"]["body_fields"] == ["type", "token_hash"]
    assert CLEANUP_CONTRACT["logout"] == {
        "method": "POST",
        "path": "/auth/v1/logout?scope=global",
        "success_status": 204,
        "bearer": "temporary-access-jwt",
        "headers": [
            "apikey:publishable",
            "Authorization:Bearer temporary-access-jwt",
        ],
    }
    assert CLEANUP_CONTRACT["direct_auth_schema_delete"] is False
    assert CLEANUP_CONTRACT["retry_authorized"] is False
    assert CLEANUP_CONTRACT["sensitive_material_retained"] is False

    all_prohibited = set(plan["prohibited_actions"])
    for action in (
        "auth.sessions.delete-sql", "auth.refresh-tokens.delete-sql",
        "identity.create", "identity.delete", "identity.modify", "hook.modify",
        "tenant-metadata.modify", "data.operation", "render.operation",
        "n8n.operation", "staging.target", "production.target", "v32.retry",
        "v33.prepare", "credential.persist", "credential.expose",
        "raw-provider-payload.persist",
    ):
        assert action in all_prohibited
    serialized = json.dumps({"plan": plan, "progress": progress}, sort_keys=True)
    assert DATA_PROJECT_REF not in serialized
    assert "/database/query" not in serialized

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (s["authorization_state"], s["execution_state"], s["verification_state"],
         s["authorization_consumed"], s["evidence"])
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False, [])
        for s in progress["step_states"]
    )

    if not execution_surface_only:
        assert not (BASE / f"{BOUNDARY}.execution-progress.json").exists()
        assert not list(BASE.glob(f"{BOUNDARY}*.evidence.json"))
    assert raw_digest(EXECUTOR_PATH) == EXECUTOR_RAW_DIGEST
    assert raw_digest(WORKFLOW_PATH) == WORKFLOW_RAW_DIGEST
    assert raw_digest(LIFECYCLE_PATH) == LIFECYCLE_RAW_DIGEST

    executor_source = EXECUTOR_PATH.read_text(encoding="utf-8")
    workflow_source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert CONFIRMATION in executor_source and CONFIRMATION in workflow_source
    assert STEP2_ID in executor_source
    assert "request_generate_recovery_credential" in executor_source
    assert "request_direct_recovery_verification" in executor_source
    assert "validate_development_synthetic_access_jwt" in executor_source
    assert "request_global_session_logout" in executor_source
    assert executor_source.index("validate_jwt(session._access_text())") < executor_source.index(
        "logout_global("
    )
    for prohibited in (
        "/database/query", "delete from auth.sessions", "delete from auth.refresh_tokens",
        "request_local_session_logout", "run_recovery_session_lifecycle",
    ):
        assert prohibited not in executor_source.lower()

    assert "environment: development" in workflow_source
    assert "if: github.ref == 'refs/heads/main'" in workflow_source
    assert "permissions:\n  contents: read" in workflow_source
    assert "persist-credentials: false" in workflow_source
    assert "cancel-in-progress: false" in workflow_source
    assert "SESSION_CLEANUP_STEP2_PREREQUISITE_ABSENT" in workflow_source
    assert "SESSION_CLEANUP_AUTHORIZATION_WINDOW_INACTIVE" in workflow_source
    assert workflow_source.count("scripts/development_auth_v32_synthetic_session_cleanup_v1.py") == 1
    assert "auth.sessions" not in workflow_source
    assert "auth.refresh_tokens" not in workflow_source
    assert "/database/query" not in workflow_source
    assert "workflow_call:" not in workflow_source
    assert "schedule:" not in workflow_source
    assert "push:" not in workflow_source

    print("DEVELOPMENT AUTH v32 synthetic-session cleanup v1 execution path: VALID")


if __name__ == "__main__":
    main(execution_surface_only="--execution-surface-only" in sys.argv[1:])
