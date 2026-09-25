from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/plans/v1/development-auth-v32-session-state-rebaseline-owner-interactive-v1.plan.json"
EXPECTED_QUERY = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""
EXPECTED_FIELDS = ["session_count", "refresh_token_count"]


class SessionStateRebaselineBoundarySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.step = self.plan["steps"][0]

    def test_exact_single_aggregate_query_and_bounded_results(self) -> None:
        self.assertEqual(EXPECTED_QUERY.count(";"), 1)
        self.assertEqual(self.step["resource"]["exact_version"], "owner-interactive.v1")
        self.assertEqual(self.step["execution_class"], "PROVIDER_READ")
        self.assertEqual(
            self.step["credential_policy"]["allowed_classes"],
            ["OWNER_INTERACTIVE_SESSION"],
        )
        self.assertIn("session_count", EXPECTED_FIELDS)
        self.assertIn("refresh_token_count", EXPECTED_FIELDS)
        self.assertNotIn("auth.users", EXPECTED_QUERY)
        for forbidden in ("insert ", "update ", "delete ", "truncate ", "alter ", "create ", "drop "):
            self.assertNotIn(forbidden, EXPECTED_QUERY.lower())

    def test_nonzero_state_cannot_trigger_cleanup_or_followup_sql(self) -> None:
        for action in (
            "provider.mutation", "session.cleanup", "session.delete",
            "additional.sql.execute", "credential.create", "credential.rotate",
        ):
            self.assertIn(action, self.step["prohibited_actions"])
        self.assertIn("SESSION_CLEANUP_REQUIRED", self.step["expected_postcondition"])
        self.assertIn("separate exact plan", self.step["expected_postcondition"])

    def test_no_automation_or_runtime_secret_surface_exists(self) -> None:
        boundary = "development-auth-v32-session-state-rebaseline-owner-interactive-v1"
        self.assertFalse((ROOT / f".github/workflows/{boundary}.yml").exists())
        self.assertFalse((ROOT / "scripts/development_auth_v32_session_state_rebaseline_owner_interactive_v1.py").exists())
        self.assertNotIn("AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL", json.dumps(self.plan))

    def test_boundary_has_one_read_only_step_and_no_cleanup_or_retry_authority(self) -> None:
        serialized = json.dumps(self.plan).lower()
        self.assertEqual(len(self.plan["steps"]), 1)
        self.assertNotIn("logout", serialized)
        self.assertNotIn("token_hash", serialized)
        self.assertNotIn("supabase_auth_admin_ephemeral", serialized)
        self.assertIn("cleanup-v1.retry", self.step["prohibited_actions"])
        self.assertIn("cleanup-v2.retry", self.step["prohibited_actions"])


if __name__ == "__main__":
    unittest.main()
