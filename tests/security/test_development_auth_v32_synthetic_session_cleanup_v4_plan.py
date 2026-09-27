from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from avuhz_engineering.authorization_plan import approval_digest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v4"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
PLAN = BASE / f"{BOUNDARY}.plan.json"
PROGRESS = BASE / f"{BOUNDARY}.progress.json"
LIFECYCLE = "sha256:bc0d64001ee765c436d09a417668d8e7f2dc2cd405d7384df372b792487315b5"
V3_PLAN = "sha256:7621cb349e26c106fba7941f82088c669ddb0512bfd6a3c6a2bcb16c5fcc04b8"
V3_PROGRESS = "sha256:cf4b76e32638bb92ab188ef511ed48632720fd060073be735797b6852bbba40d"
REBASELINE_EVIDENCE = "sha256:e2955c02b79f245f75a0affefd289376f005cdd165f724c02be88699744a5b43"
RETIREMENT = "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
APPROVAL_ID = "60426d08-8e65-4325-8536-b5cd488ad4c7"
APPROVAL_DIGEST = "sha256:9f466b15b64a23914c4474c2af77a139632a30f5644d5bb5079c204797a34ccb"
APPROVED_AT = "2026-09-27T15:37:24Z"
WINDOW_START = "2026-09-27T18:00:00Z"
WINDOW_END = "2026-09-28T00:00:00Z"


class DevelopmentAuthV32SyntheticSessionCleanupV4PlanTests(unittest.TestCase):
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
        approval = json.loads((BASE / f"{BOUNDARY}.approval.json").read_text())
        self.assertEqual(approval, {
            "approval_id": APPROVAL_ID,
            "plan_id": self.plan["plan_id"],
            "plan_version": 4,
            "plan_digest": self.plan["plan_digest"],
            "owner_identity": "github:AnonymousKoo",
            "decision": "APPROVE",
            "environment": "DEVELOPMENT",
            "effective_at": WINDOW_START,
            "expires_at": WINDOW_END,
            "approved_at": APPROVED_AT,
            "status": "ACTIVE",
            "authority_scope": "EXACT_PLAN_ONLY",
            "approval_digest": APPROVAL_DIGEST,
        })
        self.assertEqual(approval_digest(approval), APPROVAL_DIGEST)
        self.assertLess(APPROVED_AT, WINDOW_START)
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}*.evidence.json")), [])

    def test_mutation_is_bound_to_rebaseline_corrected_lifecycle_and_retirement(self) -> None:
        serialized = json.dumps(self.cleanup, sort_keys=True)
        self.assertIn(REBASELINE_EVIDENCE, serialized)
        self.assertIn(LIFECYCLE, serialized)
        self.assertIn(RETIREMENT, serialized)
        self.assertIn(V3_PLAN, serialized)
        self.assertIn(V3_PROGRESS, serialized)
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

    def test_step1_execution_surface_is_pinned_but_unexecuted(self) -> None:
        self.assertTrue((ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v4.py").is_file())
        self.assertTrue((ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v4-step1.yml").is_file())
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}-step1-*.evidence.json")), [])


if __name__ == "__main__":
    unittest.main()
