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
APPROVAL = BASE / f"{BOUNDARY}.approval.json"
STEP1_EVIDENCE = BASE / f"{BOUNDARY}-step1-success.evidence.json"
EXECUTION_PROGRESS = BASE / f"{BOUNDARY}.execution-progress.json"


class DevelopmentAuthCleanupCredentialRepairV1SecurityTests(unittest.TestCase):
    def test_focused_validator_passes(self) -> None:
        result = subprocess.run(
            ["python", str(VALIDATOR)], cwd=ROOT, check=False,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cleanup credential-repair v1: PASS", result.stdout)

    def test_step1_is_consumed_and_later_steps_remain_unconsumed(self) -> None:
        approval = json.loads(APPROVAL.read_text(encoding="utf-8"))
        progress = json.loads(EXECUTION_PROGRESS.read_text(encoding="utf-8"))
        self.assertEqual(approval["decision"], "APPROVE")
        self.assertEqual(approval["authority_scope"], "EXACT_PLAN_ONLY")
        self.assertEqual(approval["environment"], "DEVELOPMENT")
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.assertEqual(approval["plan_id"], plan["plan_id"])
        self.assertEqual(progress["overall_state"], "IN_PROGRESS")
        first = progress["step_states"][0]
        self.assertEqual(
            (
                first["authorization_state"], first["execution_state"],
                first["verification_state"], first["authorization_consumed"],
            ),
            ("CONSUMED", "SUCCEEDED", "PASS", True),
        )
        self.assertTrue(
            all(
                state["authorization_state"] == "PENDING"
                and state["execution_state"] == "NOT_STARTED"
                and state["verification_state"] == "NOT_STARTED"
                and not state["authorization_consumed"]
                for state in progress["step_states"][1:]
            )
        )
        self.assertFalse(list(BASE.glob("*synthetic-session-cleanup-v2*.plan.json")))

    def test_only_reference_name_and_no_credential_material_is_retained(self) -> None:
        text = "".join(
            path.read_text(encoding="utf-8")
            for path in (PLAN, PROGRESS, APPROVAL, STEP1_EVIDENCE, EXECUTION_PROGRESS)
        )
        self.assertIn(SECRET_REFERENCE, text)
        self.assertIsNone(re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", text))
        for field in (
            '"credential_value"', '"secret_value"', '"service_role_key"',
            '"access_token"', '"refresh_token"',
        ):
            self.assertNotIn(field, text.lower())

    def test_step1_evidence_records_reference_only_and_no_credential_digest(self) -> None:
        evidence = json.loads(STEP1_EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(
            evidence["classification"], "DEDICATED_CLEANUP_CREDENTIAL_CREATED"
        )
        self.assertEqual(
            evidence["sanitized_result"]["logical_key_name"], "cleanup-v2-ephemeral"
        )
        self.assertFalse(evidence["credential_material_retained"])
        self.assertFalse(evidence["credential_material_digest_recorded"])
        self.assertFalse(evidence["security_state"]["credential_value_provided_to_agent"])
        self.assertFalse(evidence["security_state"]["github_secret_mutated"])

    def test_steps_are_independent_and_cleanup_v2_is_unreachable(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.assertEqual(len(plan["steps"]), 4)
        progress = json.loads(EXECUTION_PROGRESS.read_text(encoding="utf-8"))
        self.assertEqual(len(progress["step_states"][0]["evidence"]), 1)
        self.assertEqual(
            [state["step_id"] for state in progress["step_states"]],
            [step["step_id"] for step in plan["steps"]],
        )
        self.assertIn("cleanup-v2.prepare", plan["prohibited_actions"])
        self.assertIn("cleanup.execute", plan["prohibited_actions"])
        self.assertTrue(EXECUTION_PROGRESS.exists())


if __name__ == "__main__":
    unittest.main()
