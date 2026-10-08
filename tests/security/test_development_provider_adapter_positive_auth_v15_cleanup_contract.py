"""Offline schema, digest and fail-closed scope tests for v15 cleanup fallback."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
NAME = "development-implementation-handoff-provider-adapter-positive-auth-v15-corrective-cleanup-v1"


def load(kind: str):
    return json.loads((BASE / f"{NAME}.{kind}.json").read_text())


class PositiveAuthV15CleanupFallbackContractTests(unittest.TestCase):
    def test_contract_is_schema_valid_and_digests_are_exact(self) -> None:
        plan, progress, resource = load("plan"), load("progress"), load("resource")
        validate_plan(plan, ROOT / "contracts/schemas/v1")
        validate_progress(plan, progress, ROOT / "contracts/schemas/v1")
        self.assertEqual(plan["plan_digest"], plan_digest(plan))
        self.assertEqual(progress["progress_digest"], progress_digest(progress))
        self.assertEqual(resource["contract_digest"], canonical_digest({
            key: value for key, value in resource.items() if key != "contract_digest"
        }))
        self.assertEqual(
            {step["resource"]["exact_digest"] for step in plan["steps"]},
            {resource["contract_digest"]},
        )

    def test_scope_is_only_unapproved_development_auth_retirement(self) -> None:
        plan, progress, resource = load("plan"), load("progress"), load("resource")
        self.assertEqual(plan["definition_status"], "READY_FOR_APPROVAL")
        self.assertEqual(plan["environment"], "DEVELOPMENT")
        self.assertEqual(plan["target"]["project_reference"], "pwlhruwutoitnieactol")
        self.assertEqual(plan["target"]["responsibility"], "AUTH")
        self.assertEqual(plan["authority_effect"], "NONE_UNTIL_SEPARATELY_APPROVED")
        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertTrue(all(not step["authorization_consumed"] for step in progress["step_states"]))
        self.assertEqual(
            [step["operation"] for step in plan["steps"]],
            [
                "provider.auth-session-state.inspect-read-only-via-supabase-mcp",
                "provider.auth-admin-credential.delete-dedicated-secret-key",
                "provider.auth-secret-binding.delete-github-environment-reference",
                "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
                "provider.auth-secret-binding.verify-github-environment-reference-absent",
            ],
        )
        self.assertEqual(resource["authorized_counts"]["session_issue"], 0)
        self.assertEqual(resource["authorized_counts"]["new_authentication"], 0)
        self.assertEqual(resource["authorized_counts"]["positive_auth_retry"], 0)
        self.assertFalse(resource["security_rules"]["data_project_authorized"])
        self.assertFalse(resource["security_rules"]["production_authorized"])
        self.assertEqual(
            resource["fresh_provider_key_reference"],
            "impl_handoff_provider_adapter_positive_auth_v15_ephemeral",
        )
        self.assertEqual(
            resource["github_secret_binding_name"],
            "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V15_EPHEMERAL",
        )

    def test_no_approval_artifact_and_no_environment_secret(self) -> None:
        self.assertFalse((BASE / f"{NAME}.approval.json").exists())
        for kind in ("plan", "progress", "resource"):
            text = (BASE / f"{NAME}.{kind}.json").read_text()
            self.assertNotIn("sb_secret_", text)
            self.assertNotIn("Bearer eyJ", text)

    def test_derived_steps_depending_on_zero_proof(self) -> None:
        plan = load("plan")
        steps = plan["steps"]
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0]["execution_class"], "PROVIDER_READ")
        self.assertTrue(any(
            "nonzero" in condition for condition in steps[0]["stop_conditions"]
        ))
        self.assertEqual(
            steps[1]["required_evidence"][0]["source_step_id"],
            steps[0]["step_id"],
        )
        self.assertTrue(all(step["resource"]["binding_state"] == "BOUND" for step in steps))


if __name__ == "__main__":
    unittest.main()
