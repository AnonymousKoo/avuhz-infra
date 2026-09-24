from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v2"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"


class DevelopmentAuthV32SyntheticSessionCleanupV2PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads((BASE / f"{BOUNDARY}.plan.json").read_text())
        self.progress = json.loads((BASE / f"{BOUNDARY}.progress.json").read_text())

    def test_pristine_exact_three_step_boundary_has_only_dormant_step2_surface(self) -> None:
        self.assertEqual(len(self.plan["steps"]), 3)
        self.assertEqual(self.plan["environment"], "DEVELOPMENT")
        self.assertEqual(self.plan["target"]["responsibility"], "AUTH")
        self.assertEqual(self.plan["target"]["project_reference"], PROJECT)
        self.assertNotIn(DATA_PROJECT, json.dumps(self.plan))
        self.assertEqual(
            [step["execution_class"] for step in self.plan["steps"]],
            ["PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_READ"],
        )
        self.assertEqual(self.plan["authority_effect"], "NONE_UNTIL_SEPARATELY_APPROVED")
        self.assertEqual(self.plan["definition_status"], "READY_FOR_APPROVAL")
        self.assertEqual(self.progress["overall_state"], "NOT_STARTED")
        for step in self.progress["step_states"]:
            self.assertEqual(step["authorization_state"], "PENDING")
            self.assertEqual(step["execution_state"], "NOT_STARTED")
            self.assertEqual(step["verification_state"], "NOT_STARTED")
            self.assertFalse(step["authorization_consumed"])
            self.assertEqual(step["evidence"], [])
        self.assertFalse((BASE / f"{BOUNDARY}.approval.json").exists())
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}*.evidence.json")), [])
        self.assertTrue((ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v2.py").is_file())
        self.assertTrue((ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v2.yml").is_file())
        self.assertFalse((ROOT / f"scripts/{BOUNDARY.replace('-', '_')}_v1.py").exists())

    def test_only_the_two_exact_owner_interactive_sql_contracts_are_present(self) -> None:
        step1, step2, step3 = self.plan["steps"]
        self.assertIn("from auth.sessions as s", step1["expected_postcondition"])
        self.assertIn("left join auth.users as u on u.id = s.user_id;", step1["expected_postcondition"])
        self.assertIn("require 1/1 for PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED", step1["expected_postcondition"])
        self.assertNotIn("auth.refresh_tokens", step1["expected_postcondition"])
        self.assertIn("(select count(*) from auth.sessions)", step3["expected_postcondition"])
        self.assertIn("(select count(*) from auth.refresh_tokens)", step3["expected_postcondition"])
        self.assertIn("SESSION_CLEANUP_VERIFIED", step3["expected_postcondition"])
        self.assertIn("SESSION_CLEANUP_NOT_VERIFIED", step3["expected_postcondition"])
        self.assertIn("SESSION_STATE_UNVERIFIED", step3["expected_postcondition"])
        self.assertEqual(step2["execution_class"], "PROVIDER_MUTATION")
        self.assertIn("cleanup-v1.retry", step2["prohibited_actions"])

    def test_step2_names_only_dedicated_credential_and_preserves_retirement(self) -> None:
        step2 = self.plan["steps"][1]
        serialized = json.dumps(step2, sort_keys=True)
        self.assertIn(ADMIN_REFERENCE, serialized)
        self.assertIn("auth.cleanup-admin-retirement.required", serialized)
        self.assertIn("cleanup_verified=false", step2["expected_postcondition"])
        self.assertIn("future fresh approval", step2["expected_postcondition"])
        self.assertIn("service-role.use", self.plan["prohibited_actions"])
        self.assertIn("auth.sessions.delete-sql", self.plan["prohibited_actions"])
        self.assertIn("auth.refresh-tokens.delete-sql", self.plan["prohibited_actions"])
        self.assertIsNone(re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", serialized))
        for forbidden_field in ('"secret_value"', '"credential_value"', '"access_token"', '"refresh_token"'):
            self.assertNotIn(forbidden_field, serialized.lower())


if __name__ == "__main__":
    unittest.main()
