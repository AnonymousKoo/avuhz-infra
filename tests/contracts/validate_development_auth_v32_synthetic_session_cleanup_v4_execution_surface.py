#!/usr/bin/env python3
"""Pin and inspect the cleanup-v4 Step 1 implementation surface."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
PLAN = BASE / "development-auth-v32-synthetic-session-cleanup-v4.plan.json"
APPROVAL = BASE / "development-auth-v32-synthetic-session-cleanup-v4.approval.json"
PROGRESS = BASE / "development-auth-v32-synthetic-session-cleanup-v4.progress.json"
EXECUTOR = ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v4.py"
WORKFLOW = ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v4-step1.yml"
LIFECYCLE = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
PLAN_ID = "59bc509b-e2ce-4c27-9245-f9910f77f7c8"
PLAN_DIGEST = "sha256:b0a44c88963f7a1f57cd33eb798e67986dc8aabb82baeef825b2d561cedbc173"
APPROVAL_ID = "60426d08-8e65-4325-8536-b5cd488ad4c7"
APPROVAL_DIGEST = "sha256:9f466b15b64a23914c4474c2af77a139632a30f5644d5bb5079c204797a34ccb"
WINDOW = ("2026-09-27T18:00:00Z", "2026-09-28T00:00:00Z")
CONFIRMATION = "REVOKE_V32_SYNTHETIC_SESSIONS_GLOBAL_V4_STEP1"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
LIFECYCLE_DIGEST = "sha256:bc0d64001ee765c436d09a417668d8e7f2dc2cd405d7384df372b792487315b5"
EXECUTOR_DIGEST = "sha256:928de66010139c1cc072744eb2117cd55eac9ff72d649a6cd7810ee6f368c02f"
WORKFLOW_DIGEST = "sha256:0fa8016a9ffbe509d94be703a4ee0df954df7a8f092cfd3d395c6af583ef3d92"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    approval = json.loads(APPROVAL.read_text(encoding="utf-8"))
    progress = json.loads(PROGRESS.read_text(encoding="utf-8"))
    executor = EXECUTOR.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert digest(EXECUTOR) == EXECUTOR_DIGEST
    assert digest(WORKFLOW) == WORKFLOW_DIGEST
    assert digest(LIFECYCLE) == LIFECYCLE_DIGEST
    assert plan["plan_id"] == PLAN_ID and plan["plan_digest"] == PLAN_DIGEST
    assert approval["approval_id"] == APPROVAL_ID and approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert plan["authorization_window"]["starts_at"] == WINDOW[0]
    assert plan["authorization_window"]["expires_at"] == WINDOW[1]
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(not s["authorization_consumed"] for s in progress["step_states"])
    assert not (BASE / "development-auth-v32-synthetic-session-cleanup-v4.execution-progress.json").exists()
    assert not list(BASE.glob("development-auth-v32-synthetic-session-cleanup-v4-step1-*.evidence.json"))

    assert "cleanup.v4" in executor and PLAN_ID in executor and PLAN_DIGEST in executor
    assert APPROVAL_ID in executor and APPROVAL_DIGEST in executor
    assert ADMIN_ENV in executor and PUBLISHABLE_ENV in executor
    assert "DEVELOPMENT_AUTH_PROJECT_REF" in executor and "pwlhruwutoitnieactol" in executor
    assert LIFECYCLE_DIGEST in executor
    assert "run_recovery_session_lifecycle" not in executor
    assert "_assert_evidence_bindings()" in executor
    assert "_load_and_authorize(_now())" in executor
    assert executor.index("_load_and_authorize(_now())") < executor.index("env.get(ADMIN_ENV)")
    assert executor.index("env.get(ADMIN_ENV)") < executor.index("print(json.dumps(execute_cleanup(")
    for primitive in (
        "request_generate_recovery_credential", "request_direct_recovery_verification",
        "validate_development_synthetic_access_jwt", "request_global_session_logout",
    ):
        assert primitive in executor
    assert executor.index("credential = generate(") < executor.index("session = verify(") < executor.index("validate_jwt(") < executor.index("logout_global(")
    assert '"SESSION_REVOCATION_REQUEST_ACCEPTED"' in executor
    assert '"cleanup_verified": False' in executor
    assert '"step2_readback_required": True' in executor
    assert '"retry_authorized": False' in executor
    assert "auth.sessions" not in executor and "auth.refresh_tokens" not in executor
    assert not re.search(r"(?i)\bdelete\s+from\s+auth\.(sessions|refresh_tokens)", executor)
    assert "service_role" not in executor.lower()

    assert "workflow_dispatch:" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert '[[ "${GITHUB_RUN_NUMBER}" != "1" ]]' in workflow
    assert '[[ "${GITHUB_RUN_ATTEMPT}" != "1" ]]' in workflow
    assert "environment: development" in workflow
    assert CONFIRMATION in workflow and PLAN_ID in workflow and PLAN_DIGEST in workflow
    assert APPROVAL_ID in workflow and APPROVAL_DIGEST in workflow
    assert all(value in workflow for value in WINDOW)
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "persist-credentials: false" in workflow
    assert workflow.count("${{ secrets.") == 2
    assert f"${{{{ secrets.{ADMIN_ENV} }}}}" in workflow
    assert f"${{{{ secrets.{PUBLISHABLE_ENV} }}}}" in workflow
    assert workflow.index("Validate exact approval and Step 1 authority before secret resolution") < workflow.index("Execute exact Step 1 once")
    assert "--preflight-only" in workflow
    print("DEVELOPMENT AUTH cleanup-v4 Step 1 execution surface: PASS (pinned, single-attempt, exact plan/approval/window, fail-closed preflight)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
