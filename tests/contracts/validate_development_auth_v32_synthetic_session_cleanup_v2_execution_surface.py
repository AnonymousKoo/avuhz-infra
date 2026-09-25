#!/usr/bin/env python3
"""Pin and inspect the dormant cleanup-v2 Step 2 implementation surface."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
PLAN = BASE / "development-auth-v32-synthetic-session-cleanup-v2.plan.json"
EXECUTOR = ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v2.py"
WORKFLOW = ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v2.yml"
LIFECYCLE = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
PLAN_ID = "55b1ac96-b338-4821-bcb3-02f4ab1a0958"
PLAN_DIGEST = "sha256:4afea8848bc07967d93be6905b142d6d6c995cd43f204a610c439c0efee50df3"
WINDOW = ("2026-09-25T15:00:00Z", "2026-09-25T21:00:00Z")
CONFIRMATION = "REVOKE_V32_SYNTHETIC_SESSIONS_GLOBAL_V2"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
LIFECYCLE_DIGEST = "sha256:55503f13489944b0b4b51e3dc24875d5c6e83c69e8fc6a8aed6a03fdb0736749"
EXECUTOR_DIGEST = "sha256:e46e4d3f94ffa641e84a85e882e8378c04fb3ce84d2e3381c077f26d4bc2e76b"
WORKFLOW_DIGEST = "sha256:9b53fef820c1c8c84b2bed91d5bb5d13cdebfbfa2479636e8c3b08eebae51dfe"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    executor = EXECUTOR.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert digest(EXECUTOR) == EXECUTOR_DIGEST
    assert digest(WORKFLOW) == WORKFLOW_DIGEST
    assert plan["plan_id"] == PLAN_ID and plan["plan_digest"] == PLAN_DIGEST
    assert plan["authorization_window"]["starts_at"] == WINDOW[0]
    assert plan["authorization_window"]["expires_at"] == WINDOW[1]
    assert digest(LIFECYCLE) == LIFECYCLE_DIGEST
    assert "cleanup.v2" in executor and PLAN_ID in executor and PLAN_DIGEST in executor
    assert ADMIN_ENV in executor and PUBLISHABLE_ENV in executor
    assert "DEVELOPMENT_AUTH_PROJECT_REF" in executor and "pwlhruwutoitnieactol" in executor
    assert """cleanup-v1""" not in executor.lower()
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1" not in executor
    assert "step1-success.evidence.json" in executor
    assert "_assert_repair_bindings()" in executor
    assert "_load_and_authorize(_now())" in executor
    assert executor.index("_load_and_authorize(_now())") < executor.index("env.get(ADMIN_ENV)")
    assert executor.index("env.get(ADMIN_ENV)") < executor.index("print(json.dumps(execute_cleanup(")
    for primitive in (
        "request_generate_recovery_credential", "request_direct_recovery_verification",
        "validate_development_synthetic_access_jwt", "request_global_session_logout",
    ):
        assert primitive in executor
    assert executor.index("generate(") < executor.index("verify(") < executor.index("validate_jwt(") < executor.index("logout_global(")
    assert '"SESSION_REVOCATION_REQUEST_ACCEPTED"' in executor
    assert '"cleanup_verified": False' in executor
    assert '"step3_readback_required": True' in executor
    assert '"retry_authorized": False' in executor
    assert "auth.sessions" not in executor and "auth.refresh_tokens" not in executor
    assert not re.search(r"(?i)\bdelete\s+from\s+auth\.(sessions|refresh_tokens)", executor)
    assert "service_role" not in executor.lower()
    assert "retry" not in executor.lower() or "retry_authorized" in executor.lower()

    assert "workflow_dispatch:" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert '[[ "${GITHUB_RUN_NUMBER}" != "1" ]]' in workflow
    assert '[[ "${GITHUB_RUN_ATTEMPT}" != "1" ]]' in workflow
    assert "environment: development" in workflow
    assert CONFIRMATION in workflow and PLAN_ID in workflow and PLAN_DIGEST in workflow
    assert all(value in workflow for value in WINDOW)
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "persist-credentials: false" in workflow
    assert workflow.count("${{ secrets.") == 2
    assert f"${{{{ secrets.{ADMIN_ENV} }}}}" in workflow
    assert f"${{{{ secrets.{PUBLISHABLE_ENV} }}}}" in workflow
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1" not in workflow
    assert workflow.index("Validate approval and fresh Step 1 authority") < workflow.index("Execute exact Step 2 once")
    assert "--preflight-only" in workflow
    assert "_validate_invocation" in executor
    assert 'env.get("GITHUB_RUN_NUMBER") != "1"' in executor
    assert 'env.get("GITHUB_RUN_ATTEMPT") != "1"' in executor
    print("DEVELOPMENT AUTH cleanup-v2 Step 2 execution surface: PASS (pinned, dormant, exact plan/window, fail-closed preflight)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
