"""Offline, credential-free safety checks for the separately approved v15 Step 4 correction."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    plan_digest,
    progress_digest,
    validate_plan,
    validate_progress,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "contracts/schemas/v1"
DIR = ROOT / "contracts/plans/v1"
BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v15-step4-corrective-dispatch-v1"
ORIGINAL = "development-implementation-handoff-provider-adapter-positive-auth-v15"
WORKFLOW = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v15-step4-corrective-v1.yml"


def load(name: str) -> dict:
    return json.loads((DIR / name).read_text(encoding="utf-8"))


class CorrectiveV15DispatchContractTests(unittest.TestCase):
    def test_plan_progress_schema_and_source_bound(self):
        plan = load(BOUNDARY + ".plan.json")
        progress = load(BOUNDARY + ".progress.json")
        validate_plan(plan, SCHEMAS)
        validate_progress(plan, progress, SCHEMAS)
        self.assertEqual(plan["plan_digest"], plan_digest(plan))
        self.assertEqual(progress["progress_digest"], progress_digest(progress))
        self.assertEqual(plan["definition_status"], "READY_FOR_APPROVAL")
        self.assertEqual(plan["environment"], "DEVELOPMENT")
        self.assertEqual(plan["target"]["project_reference"], "pwlhruwutoitnieactol")
        self.assertEqual(plan["target"]["responsibility"], "AUTH")
        self.assertEqual(plan["authorization_window"]["starts_at"], "2026-10-08T18:00:00Z")
        self.assertEqual(plan["authorization_window"]["expires_at"], "2026-10-10T16:30:00Z")
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(
            plan["steps"][0]["resource"]["exact_digest"],
            "sha256:" + hashlib.sha256(WORKFLOW.read_bytes()).hexdigest(),
        )
        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertFalse(progress["step_states"][0]["authorization_consumed"])

    def test_original_predecessors_and_fallback_unchanged(self):
        plan = load(BOUNDARY + ".plan.json")
        prior = load(ORIGINAL + ".plan.json")
        progress = load(ORIGINAL + ".progress.json")
        approval = load(ORIGINAL + ".approval.json")
        cleanup = load(ORIGINAL + "-corrective-cleanup-v1.approval.json")
        self.assertEqual(prior["plan_digest"], approval["plan_digest"])
        self.assertEqual(prior["plan_id"], "c91144ec-ca7b-4d3a-a231-128c7ebf0bd5")
        self.assertEqual(progress["overall_state"], "IN_PROGRESS")
        for entry in progress["step_states"][:3]:
            self.assertEqual((entry["authorization_state"], entry["execution_state"], entry["verification_state"]),
                             ("CONSUMED", "SUCCEEDED", "PASS"))
        self.assertTrue(all(entry["execution_state"] == "NOT_STARTED"
                            for entry in progress["step_states"][3:]))
        self.assertEqual(plan["steps"][0]["required_evidence"][0]["exact_digest"],
                         progress["step_states"][2]["evidence"][0]["evidence_digest"])
        self.assertEqual(cleanup["status"], "ACTIVE")
        self.assertEqual(cleanup["expires_at"], "2026-10-10T16:30:00Z")

    def test_exact_corrective_approval_is_time_gated(self):
        from avuhz_engineering.authorization_plan import approval_digest, validate_approval
        plan = load(BOUNDARY + ".plan.json")
        approval = load(BOUNDARY + ".approval.json")
        progress = load(BOUNDARY + ".progress.json")
        self.assertEqual(approval["plan_id"], "4fcaf2f0-53d9-40bb-ac8a-a8cde8869f7c")
        self.assertEqual(approval["plan_digest"], plan["plan_digest"])
        self.assertEqual(approval["owner_identity"], "github:AnonymousKoo")
        self.assertEqual(approval["decision"], "APPROVE")
        self.assertEqual(approval["status"], "ACTIVE")
        self.assertEqual(approval["authority_scope"], "EXACT_PLAN_ONLY")
        self.assertEqual(approval["environment"], "DEVELOPMENT")
        self.assertEqual(approval["effective_at"], "2026-10-08T18:00:00Z")
        self.assertEqual(approval["expires_at"], "2026-10-10T16:30:00Z")
        self.assertEqual(approval["approved_at"], "2026-10-08T17:34:08Z")
        self.assertEqual(approval["approval_digest"], approval_digest(approval))
        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertEqual(progress["step_states"][0]["execution_state"], "NOT_STARTED")
        validate_approval(plan, approval, SCHEMAS, "2026-10-08T18:00:00Z")
        for outside in ("2026-10-08T17:59:59Z", "2026-10-10T16:30:00Z"):
            with self.subTest(outside=outside), self.assertRaises(AuthorizationPlanStop) as stopped:
                validate_approval(plan, approval, SCHEMAS, outside)
            self.assertEqual(str(stopped.exception), "PLAN_AUTHORIZATION_EXPIRED")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.run_number == 1", workflow)
        self.assertIn("github.run_attempt == 1", workflow)
        self.assertIn("type: choice", workflow)
        self.assertIn("CORRECTIVE_CONFIRMATION_INVALID", workflow)
        self.assertIn("validate_approval(item, approval, schema, now)", workflow)
        self.assertIn("authorize_step(p, a, g, request, schema, now)", workflow)
        self.assertIn("development_provider_adapter_positive_auth_v15.py --preflight-only", workflow)
        self.assertIn("development_provider_adapter_positive_auth_v15.py", workflow)
        self.assertLess(workflow.index("Validate separate corrective owner approval"),
                        workflow.index("Execute original v15 one-session lifecycle once"))
        self.assertNotIn("sb_secret_", workflow)
        self.assertNotIn("Bearer eyJ", workflow)
        self.assertNotIn("service_role_key", workflow)


if __name__ == "__main__":
    unittest.main()
