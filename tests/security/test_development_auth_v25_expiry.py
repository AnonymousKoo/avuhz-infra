from __future__ import annotations

import json
import unittest
from pathlib import Path

from avuhz_engineering.authorization_plan import AuthorizationPlanStop, validate_approval


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN = BASE / "development-auth-integration-v25.plan.json"
PROGRESS = BASE / "development-auth-integration-v25.progress.json"
APPROVAL = BASE / "development-auth-integration-v25.approval.json"
AUDIT = BASE / "development-auth-v25-expiry.evidence.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DevelopmentAuthV25ExpiryTests(unittest.TestCase):
    def test_v25_is_expired_and_unexecuted(self):
        plan = load(PLAN)
        progress = load(PROGRESS)
        approval = load(APPROVAL)
        audit = load(AUDIT)

        self.assertEqual(audit["outcome"], "EXPIRED_UNEXECUTED")
        self.assertEqual(audit["plan_id"], plan["plan_id"])
        self.assertEqual(audit["plan_digest"], plan["plan_digest"])
        self.assertEqual(audit["approval_id"], approval["approval_id"])
        self.assertEqual(audit["approval_digest"], approval["approval_digest"])
        self.assertEqual(audit["expires_at"], approval["expires_at"])

        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_AUTHORIZATION_EXPIRED"):
            validate_approval(plan, approval, SCHEMA_ROOT, audit["observed_at"])

        state = progress["step_states"][0]
        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertEqual(state["authorization_state"], "PENDING")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertEqual(state["binding_assertions"], [])

        self.assertFalse(audit["effects"]["allowlist_bound"])
        self.assertFalse(audit["effects"]["provider_contact_attempted"])
        self.assertFalse(audit["effects"]["provider_mutation_attempted"])
        self.assertFalse(audit["effects"]["credential_used"])
        self.assertIn("CREATE_FRESH_FORWARD_ONLY_PLAN", audit["continuation_rule"])


if __name__ == "__main__":
    unittest.main()
