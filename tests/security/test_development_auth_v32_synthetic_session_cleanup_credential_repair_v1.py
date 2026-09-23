from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-credential-repair-v1"
PLAN = BASE / f"{BOUNDARY}.plan.json"
PROGRESS = BASE / f"{BOUNDARY}.progress.json"
VALIDATOR = (
    ROOT / "tests/contracts/"
    "validate_development_auth_v32_synthetic_session_cleanup_credential_repair_v1.py"
)
SECRET_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"


class DevelopmentAuthCleanupCredentialRepairV1SecurityTests(unittest.TestCase):
    def test_focused_validator_passes(self) -> None:
        result = subprocess.run(
            ["python", str(VALIDATOR)], cwd=ROOT, check=False,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup credential-repair v1: PASS", result.stdout)

    def test_only_reference_name_and_no_credential_material_is_retained(self) -> None:
        text = PLAN.read_text(encoding="utf-8") + PROGRESS.read_text(encoding="utf-8")
        self.assertIn(SECRET_REFERENCE, text)
        self.assertIsNone(re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", text))
        for field in (
            '"credential_value"', '"secret_value"', '"service_role_key"',
            '"access_token"', '"refresh_token"',
        ):
            self.assertNotIn(field, text.lower())

    def test_steps_are_independent_and_cleanup_v2_is_unreachable(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.assertEqual(len(plan["steps"]), 4)
        self.assertEqual(
            [state for state in json.loads(PROGRESS.read_text(encoding="utf-8"))["step_states"]],
            [
                {
                    "step_id": step["step_id"],
                    "authorization_state": "PENDING",
                    "execution_state": "NOT_STARTED",
                    "verification_state": "NOT_STARTED",
                    "authorization_consumed": False,
                    "evidence": [],
                    "observed_postcondition": None,
                    "safe_error_code": None,
                    "binding_assertions": [],
                }
                for step in plan["steps"]
            ],
        )
        self.assertIn("cleanup-v2.prepare", plan["prohibited_actions"])
        self.assertIn("cleanup.execute", plan["prohibited_actions"])
        self.assertFalse((BASE / f"{BOUNDARY}.approval.json").exists())
        self.assertFalse((BASE / f"{BOUNDARY}.execution-progress.json").exists())


if __name__ == "__main__":
    unittest.main()
