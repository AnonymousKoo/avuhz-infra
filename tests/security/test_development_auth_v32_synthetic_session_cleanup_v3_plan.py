from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v3"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
PLAN = BASE / f"{BOUNDARY}.plan.json"
PROGRESS = BASE / f"{BOUNDARY}.progress.json"
LIFECYCLE = "sha256:bc0d64001ee765c436d09a417668d8e7f2dc2cd405d7384df372b792487315b5"
REBASELINE_EVIDENCE = "sha256:e2955c02b79f245f75a0affefd289376f005cdd165f724c02be88699744a5b43"
RETIREMENT = "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"


class DevelopmentAuthV32SyntheticSessionCleanupV3PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.progress = json.loads(PROGRESS.read_text(encoding="utf-8"))
        self.cleanup, self.verify = self.plan["steps"]

    def test_preparation_is_two_steps_and_grants_no_current_authority(self) -> None:
        self.assertEqual(self.plan["definition_status"], "READY_FOR_APPROVAL")
        self.assertEqual(self.plan["authority_effect"], "NONE_UNTIL_SEPARATELY_APPROVED")
        self.assertEqual(self.plan["environment"], "DEVELOPMENT")
        self.assertEqual(self.plan["target"]["responsibility"], "AUTH")
        self.assertEqual(self.plan["target"]["project_reference"], PROJECT)
        self.assertNotIn(DATA_PROJECT, json.dumps(self.plan))
        self.assertEqual([s["execution_class"] for s in self.plan["steps"]], ["PROVIDER_MUTATION", "PROVIDER_READ"])
        self.assertEqual(self.progress["overall_state"], "NOT_STARTED")
        for state in self.progress["step_states"]:
            self.assertEqual((state["authorization_state"], state["execution_state"], state["verification_state"]), ("PENDING", "NOT_STARTED", "NOT_STARTED"))
            self.assertFalse(state["authorization_consumed"])
        self.assertFalse((BASE / f"{BOUNDARY}.approval.json").exists())
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}*.evidence.json")), [])

    def test_mutation_is_bound_to_rebaseline_corrected_lifecycle_and_retirement(self) -> None:
        serialized = json.dumps(self.cleanup, sort_keys=True)
        self.assertIn(REBASELINE_EVIDENCE, serialized)
        self.assertIn(LIFECYCLE, serialized)
        self.assertIn(RETIREMENT, serialized)
        self.assertIn(ADMIN_REFERENCE, serialized)
        self.assertIn("2 sessions / 2 refresh tokens", self.cleanup["expected_postcondition"])
        self.assertIn("make no total-count-one assumption", self.cleanup["expected_postcondition"])
        self.assertIn("run-recovery-session-lifecycle.use", self.cleanup["prohibited_actions"])
        self.assertIn("cleanup-v2.retry", self.cleanup["prohibited_actions"])
        self.assertIn("service-role.use", self.plan["prohibited_actions"])
        self.assertIn("auth.sessions.delete-sql", self.plan["prohibited_actions"])
        self.assertIn("auth.refresh-tokens.delete-sql", self.plan["prohibited_actions"])
        self.assertIsNone(re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", serialized))
        for field in ('"secret_value"', '"credential_value"', '"access_token"', '"refresh_token"'):
            self.assertNotIn(field, serialized.lower())

    def test_postcleanup_read_is_exact_aggregate_zero_gate(self) -> None:
        post = self.verify["expected_postcondition"]
        self.assertEqual(post.count("select\n"), 1)
        self.assertIn("(select count(*) from auth.sessions)", post)
        self.assertIn("(select count(*) from auth.refresh_tokens)", post)
        self.assertIn("exact 0/0", post)
        self.assertIn("SESSION_CLEANUP_VERIFIED", post)
        self.assertIn("SESSION_CLEANUP_NOT_VERIFIED", post)
        self.assertIn("SESSION_STATE_UNVERIFIED", post)
        self.assertIn("provider.mutation", self.verify["prohibited_actions"])

    def test_bound_lifecycle_file_matches_exact_digest(self) -> None:
        path = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(digest, LIFECYCLE)

    def test_no_execution_surface_exists_yet(self) -> None:
        self.assertFalse((ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v3.py").exists())
        self.assertFalse((ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v3.yml").exists())


if __name__ == "__main__":
    unittest.main()
