from __future__ import annotations

import json
import hashlib
import re
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import approval_digest

BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v2"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
APPROVAL_ID = "431aa7e7-1436-4f26-9330-9688921b5552"
APPROVAL_DIGEST = "sha256:ae964dec7d057008adbf113e217bcfb22741a372d42d13bd1a6202ccd0ed2fed"
PLAN_DIGEST = "sha256:4afea8848bc07967d93be6905b142d6d6c995cd43f204a610c439c0efee50df3"
PROGRESS_DIGEST = "sha256:eba7fe63e59cda2b30d074eedbd2455c69a182d5ee7d1824aa212c9065d57caa"
APPROVED_AT = "2026-09-25T09:27:17Z"
WINDOW_START = "2026-09-25T15:00:00Z"
WINDOW_END = "2026-09-25T21:00:00Z"


class DevelopmentAuthV32SyntheticSessionCleanupV2PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads((BASE / f"{BOUNDARY}.plan.json").read_text())
        self.progress = json.loads((BASE / f"{BOUNDARY}.progress.json").read_text())

    def test_approved_exact_three_step_boundary_remains_unexecuted(self) -> None:
        approval_path = BASE / f"{BOUNDARY}.approval.json"
        approval = json.loads(approval_path.read_text())
        self.assertEqual(approval, {
            "approval_id": APPROVAL_ID,
            "plan_id": self.plan["plan_id"],
            "plan_version": 2,
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
        })
        self.assertEqual(approval_digest(approval), APPROVAL_DIGEST)
        self.assertLess(APPROVED_AT, WINDOW_START)
        self.assertEqual(self.plan["plan_digest"], PLAN_DIGEST)
        self.assertEqual(self.plan["authorization_window"]["starts_at"], WINDOW_START)
        self.assertEqual(self.plan["authorization_window"]["expires_at"], WINDOW_END)
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
        self.assertEqual(self.progress["progress_digest"], PROGRESS_DIGEST)
        self.assertEqual(
            "sha256:" + hashlib.sha256((BASE / f"{BOUNDARY}.progress.json").read_bytes()).hexdigest(),
            "sha256:042221ef8a99e4c654b6f41485b08d5f3ba9ed02a21dbef95b5af261c7310ea3",
        )
        for step in self.progress["step_states"]:
            self.assertEqual(step["authorization_state"], "PENDING")
            self.assertEqual(step["execution_state"], "NOT_STARTED")
            self.assertEqual(step["verification_state"], "NOT_STARTED")
            self.assertFalse(step["authorization_consumed"])
            self.assertEqual(step["evidence"], [])
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}*.evidence.json")), [])
        self.assertTrue((ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v2.py").is_file())
        self.assertTrue((ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v2.yml").is_file())
        self.assertFalse((ROOT / f"scripts/{BOUNDARY.replace('-', '_')}_v1.py").exists())

        cleanup_v1 = json.loads((BASE / "development-auth-v32-synthetic-session-cleanup-v1.execution-progress.json").read_text())
        self.assertEqual(cleanup_v1["overall_state"], "STOPPED")
        self.assertEqual(cleanup_v1["step_states"][1]["safe_error_code"], "SESSION_CLEANUP_ADMIN_CREDENTIAL_UNAVAILABLE")
        repair_progress = json.loads((BASE / "development-auth-v32-synthetic-session-cleanup-credential-repair-v1.execution-progress.json").read_text())
        self.assertEqual(repair_progress["overall_state"], "COMPLETED")
        self.assertEqual(
            json.loads((BASE / "development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step4-success.evidence.json").read_text())["classification"],
            "CLEANUP_CREDENTIAL_RETIREMENT_REQUIRED",
        )
        approval_serialized = json.dumps(approval, sort_keys=True)
        self.assertNotIn("sb_secret_", approval_serialized)
        self.assertNotIn("secret_value", approval_serialized)

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
