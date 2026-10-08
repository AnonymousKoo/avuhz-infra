"""Offline contract checks for the separately owner-approved DEVELOPMENT v15 auth plan.

This suite does not contact Supabase AUTH/DATA, GitHub secrets or Render.
The owner approval is repository-bound; no execution credential or session is made available.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    approval_digest,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from scripts import development_provider_adapter_positive_auth_v15 as candidate

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
NAME = "development-implementation-handoff-provider-adapter-positive-auth-v15"


def load(kind: str):
    return json.loads((BASE / f"{NAME}.{kind}.json").read_text(encoding="utf-8"))


def source_sha(path: str):
    return "sha256:" + hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


class DevelopmentPositiveAuthV15ContractTests(unittest.TestCase):
    def test_plan_progress_schema_and_all_digests(self):
        plan, progress, resource = load("plan"), load("progress"), load("resource")
        schema_root = ROOT / "contracts/schemas/v1"
        validate_plan(plan, schema_root)
        validate_progress(plan, progress, schema_root)
        self.assertEqual(plan["plan_digest"], plan_digest(plan))
        self.assertEqual(progress["progress_digest"], progress_digest(progress))
        self.assertEqual(resource["contract_digest"], canonical_digest({
            key: value for key, value in resource.items() if key != "contract_digest"
        }))
        self.assertEqual(
            {s["resource"]["exact_digest"] for s in plan["steps"]},
            {resource["contract_digest"]},
        )

    def test_exact_bound_executor_workflow_probe_and_cleanup_plan(self):
        resource = load("resource")
        self.assertEqual(
            resource["step4_executor_digest"],
            source_sha("scripts/development_provider_adapter_positive_auth_v15.py"),
        )
        self.assertEqual(
            resource["step4_workflow_digest"],
            source_sha(".github/workflows/development-provider-adapter-positive-auth-v15-step4.yml"),
        )
        self.assertEqual(
            resource["step4_probe_digest"],
            source_sha("scripts/development_provider_adapter_live_identity_probe_v15.py"),
        )
        fallback = json.loads((
            BASE / (NAME + "-corrective-cleanup-v1.plan.json")
        ).read_text(encoding="utf-8"))
        self.assertEqual(resource["fallback_plan_id"], fallback["plan_id"])
        self.assertEqual(resource["fallback_plan_digest"], fallback["plan_digest"])
        fallback_approval = json.loads((
            BASE / (NAME + "-corrective-cleanup-v1.approval.json")
        ).read_text(encoding="utf-8"))
        self.assertEqual(resource["fallback_approval_digest"], fallback_approval["approval_digest"])
        self.assertFalse(resource["fallback_approval_unresolved"])
        self.assertEqual(fallback_approval["plan_digest"], fallback["plan_digest"])
        validate_approval(
            fallback, fallback_approval, ROOT / "contracts/schemas/v1",
            "2026-10-08T16:30:00Z",
        )

    def test_main_exact_owner_approval_is_time_gated_and_auth_project_is_exact(self):
        plan, progress, resource, approval = (
            load("plan"), load("progress"), load("resource"), load("approval")
        )
        self.assertEqual(plan["definition_status"], "READY_FOR_APPROVAL")
        self.assertEqual(plan["environment"], "DEVELOPMENT")
        self.assertEqual(plan["target"]["project_reference"], "pwlhruwutoitnieactol")
        self.assertEqual(plan["target"]["responsibility"], "AUTH")
        self.assertEqual(plan["authority_effect"], "NONE_UNTIL_SEPARATELY_APPROVED")
        self.assertEqual(plan["authorization_window"]["binding_state"], "BOUND")
        self.assertEqual(plan["authorization_window"]["starts_at"], "2026-10-08T17:00:00Z")
        self.assertEqual(plan["authorization_window"]["expires_at"], "2026-10-10T16:30:00Z")
        self.assertEqual(progress["overall_state"], "IN_PROGRESS")
        self.assertEqual(progress["plan_digest"], plan["plan_digest"])
        self.assertEqual(progress["record_version"], 7)
        self.assertTrue(all(
            state["authorization_state"] == "CONSUMED"
            and state["execution_state"] == "SUCCEEDED"
            and state["verification_state"] == "PASS"
            and state["authorization_consumed"]
            for state in progress["step_states"][:3]
        ))
        self.assertTrue(all(
            state["authorization_state"] == "PENDING"
            and state["execution_state"] == "NOT_STARTED"
            and not state["authorization_consumed"]
            for state in progress["step_states"][3:]
        ))
        self.assertEqual(approval["plan_id"], plan["plan_id"])
        self.assertEqual(approval["plan_version"], plan["plan_version"])
        self.assertEqual(approval["plan_digest"], plan["plan_digest"])
        self.assertEqual(approval["owner_identity"], plan["owner_identity"])
        self.assertEqual(approval["environment"], "DEVELOPMENT")
        self.assertEqual(approval["authority_scope"], "EXACT_PLAN_ONLY")
        self.assertEqual(approval["decision"], "APPROVE")
        self.assertEqual(approval["status"], "ACTIVE")
        self.assertEqual(approval["approved_at"], "2026-10-08T16:28:38Z")
        self.assertEqual(approval["effective_at"], "2026-10-08T17:00:00Z")
        self.assertEqual(approval["expires_at"], "2026-10-10T16:30:00Z")
        self.assertEqual(approval["approval_digest"], approval_digest(approval))
        self.assertFalse(resource["retry_authorized"])
        self.assertFalse(resource["data_operation_authorized"])
        self.assertFalse(resource["production_authorized"])
        self.assertFalse(resource["render_mutation_authorized"])
        self.assertEqual(resource["fallback_approval_unresolved"], False)

        # This validates the proposed exact authorization window offline.
        # It does not execute an operation or grant any production authority.
        validate_approval(plan, approval, ROOT / "contracts/schemas/v1", "2026-10-08T17:00:00Z")
        for outside in ("2026-10-08T16:59:59Z", "2026-10-10T16:30:00Z"):
            with self.subTest(outside=outside), self.assertRaises(AuthorizationPlanStop) as stopped:
                validate_approval(plan, approval, ROOT / "contracts/schemas/v1", outside)
            self.assertEqual(str(stopped.exception), "PLAN_AUTHORIZATION_EXPIRED")

    def test_one_lifecycle_and_no_separate_automation_or_data_path(self):
        plan, resource = load("plan"), load("resource")
        steps = plan["steps"]
        self.assertEqual(len(steps), 9)
        self.assertEqual(
            [step["step_id"] for step in steps], plan["ordered_step_ids"]
        )
        self.assertTrue(all(
            step["resource"]["resource_reference"].startswith(("supabase:pwlhruwutoitnieactol:", "github:AnonymousKoo/avuhz-infra:environment:development:"))
            for step in steps
        ))
        lifecycle = steps[3]
        self.assertEqual(lifecycle["step_id"], candidate.STEP_ID)
        self.assertEqual(lifecycle["operation"], candidate.OPERATION)
        self.assertEqual(lifecycle["credential_policy"]["allowed_classes"], ["SUPABASE_AUTH_ADMIN_EPHEMERAL"])
        self.assertEqual(lifecycle["unresolved_bindings"], [])
        self.assertEqual(lifecycle["resource"]["resource_reference"], "supabase:pwlhruwutoitnieactol:provider-adapter-positive-auth-v15-live-lifecycle")
        self.assertTrue(all(step["execution_class"] in ("PROVIDER_MUTATION", "PROVIDER_READ") for step in steps))
        self.assertFalse(resource["implementation_handoff_execution_authorized"])
        self.assertEqual(resource["planned_counts"]["temporary_session_issue"], 1)
        self.assertEqual(resource["planned_counts"]["live_http_probe"], 1)
        self.assertEqual(resource["planned_counts"]["retry"], 0)

    def test_owner_confirmed_evidence_is_digest_bound_without_secret_values(self):
        plan, progress = load("plan"), load("progress")
        for i in range(3):
            step, state = plan["steps"][i], progress["step_states"][i]
            self.assertEqual(state["observed_postcondition"], step["expected_postcondition"])
            self.assertIsNone(state["safe_error_code"])
            self.assertEqual(len(state["evidence"]), 1)
            record = state["evidence"][0]
            source_file = BASE / record["evidence_reference"]
            full = json.loads(source_file.read_text(encoding="utf-8"))
            self.assertEqual(record["evidence_digest"], canonical_digest(full))
            self.assertEqual(full["evidence_type"], record["evidence_type"])
            self.assertEqual(full["step_id"], state["step_id"])
            self.assertEqual(full["plan_digest"], plan["plan_digest"])
            self.assertEqual(full["record_basis"], "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME")
            self.assertFalse(full["recorded_at_is_execution_timestamp"])
            self.assertFalse(full["not_claimed"]["independent_provider_key_metadata_read"])
            self.assertFalse(full["not_claimed"]["independent_github_secret_metadata_read"])
            self.assertFalse(full["not_claimed"]["new_session_issued"])
            produced = [a for a in state["binding_assertions"]
                        if a["phase"] == "PRODUCED_BY_CURRENT_STEP"]
            self.assertEqual(len(produced), 1)
            self.assertEqual(produced[0]["evidence_digest"], record["evidence_digest"])
            self.assertEqual(
                produced[0]["value_digest"],
                canonical_digest(full["sanitized_result"]),
            )

    def test_fail_closed_before_secret_resolution_when_authority_unavailable(self):
        from unittest.mock import patch
        with patch.object(candidate, "_load", side_effect=AuthorizationPlanStop("PLAN_NOT_READY")):
            with self.assertRaises(AuthorizationPlanStop):
                candidate._load_and_authorize("2026-10-09T13:00:00Z")

    def test_no_live_credentials_committed(self):
        paths = [BASE / f"{NAME}.{kind}.json"
                 for kind in ("plan", "progress", "resource", "approval")]
        paths.extend(BASE / f"{NAME}-step{i}-owner-confirmed.evidence.json"
                     for i in range(1, 4))
        for path in paths:
            txt = path.read_text(encoding="utf-8")
            self.assertNotIn("sb_secret_", txt)
            self.assertNotIn("Bearer eyJ", txt)
            self.assertNotIn('"access_token":', txt)
            self.assertNotIn('"refresh_token":', txt)


if __name__ == "__main__":
    unittest.main()
