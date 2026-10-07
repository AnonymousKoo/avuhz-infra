from __future__ import annotations

import json
import unittest
from pathlib import Path

from avuhz_engineering.authorization_plan import AuthorizationPlanStop, validate_approval


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v13"
PLAN = BASE / (N + ".plan.json")
PROGRESS = BASE / (N + ".progress.json")
APPROVAL = BASE / (N + ".approval.json")
AUDIT = BASE / (N + "-expiry.evidence.json")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DevelopmentProviderAdapterPositiveAuthV13ExpiryTests(unittest.TestCase):
    def test_v13_is_expired_and_unexecuted(self) -> None:
        plan = load(PLAN)
        progress = load(PROGRESS)
        approval = load(APPROVAL)
        audit = load(AUDIT)

        self.assertEqual(audit["outcome"], "EXPIRED_UNEXECUTED")
        self.assertEqual(audit["plan_id"], plan["plan_id"])
        self.assertEqual(audit["plan_version"], plan["plan_version"])
        self.assertEqual(audit["plan_digest"], plan["plan_digest"])
        self.assertEqual(audit["approval_id"], approval["approval_id"])
        self.assertEqual(audit["approval_digest"], approval["approval_digest"])
        self.assertEqual(audit["expires_at"], approval["expires_at"])
        self.assertGreater(audit["observed_at"], audit["expires_at"])

        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_AUTHORIZATION_EXPIRED"):
            validate_approval(plan, approval, SCHEMA_ROOT, audit["observed_at"])

        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertEqual(audit["progress_state"]["step_count"], 10)
        self.assertTrue(audit["progress_state"]["all_steps_pending"])
        self.assertTrue(audit["progress_state"]["all_steps_not_started"])
        self.assertFalse(audit["progress_state"]["authorization_consumed"])
        for state in progress["step_states"]:
            self.assertEqual(state["authorization_state"], "PENDING")
            self.assertEqual(state["execution_state"], "NOT_STARTED")
            self.assertEqual(state["verification_state"], "NOT_STARTED")
            self.assertFalse(state["authorization_consumed"])
            self.assertEqual(state["evidence"], [])
            self.assertEqual(state["binding_assertions"], [])

        self.assertTrue(all(value is False for value in audit["effects"].values()))
        self.assertIn("DO_NOT_REUSE_APPROVAL_OR_WINDOW", audit["continuation_rule"])
        self.assertIn("POSITIVE_AUTH_V14", audit["continuation_rule"])


if __name__ == "__main__":
    unittest.main()
