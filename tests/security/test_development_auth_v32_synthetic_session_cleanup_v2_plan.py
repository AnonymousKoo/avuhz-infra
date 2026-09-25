from __future__ import annotations

import json
import hashlib
import re
import unittest
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import approval_digest, progress_digest

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
STEP1_EVIDENCE_DIGEST = "sha256:7c8d3d35862eb2762dbab39eac0f2252e501c5115298c4e7202db2ecc3ca2829"
EXECUTION_PROGRESS_DIGEST = "sha256:a942c1fa84f32e96619f916c1686ccb8d8ec1a6f3dd7393a0fa6cc992f167468"
STEP2_FAILURE_EVIDENCE_DIGEST = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
STEP2_SAFE_ERROR = "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID"


class DevelopmentAuthV32SyntheticSessionCleanupV2PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads((BASE / f"{BOUNDARY}.plan.json").read_text())
        self.progress = json.loads((BASE / f"{BOUNDARY}.progress.json").read_text())

    def test_step1_success_step2_consumed_failure_blocks_step3(self) -> None:
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
        self.assertEqual(list(BASE.glob(f"{BOUNDARY}*.evidence.json")), [
            BASE / f"{BOUNDARY}-step1-success.evidence.json",
            BASE / f"{BOUNDARY}-step2-failure.evidence.json",
        ])
        evidence = json.loads((BASE / f"{BOUNDARY}-step1-success.evidence.json").read_text())
        self.assertEqual(evidence["evidence_type"], "auth.synthetic-session.precleanup-attribution.verified")
        self.assertEqual(evidence["step_id"], self.plan["ordered_step_ids"][0])
        self.assertEqual(evidence["classification"], "PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED")
        self.assertEqual(evidence["sanitized_result"], {"session_count": 1, "synthetic_session_count": 1})
        self.assertEqual(evidence["recorded_at"], "2026-09-25T15:37:24Z")
        self.assertFalse(evidence["execution_observation"]["execution_timestamp_retained"])
        self.assertFalse(evidence["execution_observation"]["recorded_at_is_execution_timestamp"])
        self.assertFalse(evidence["execution_observation"]["refresh_token_query_executed"])
        self.assertFalse(evidence["execution_observation"]["additional_sql_executed"])
        self.assertFalse(evidence["provider_mutation_attempted"])
        self.assertFalse(evidence["credential_material_retained"])
        self.assertFalse(evidence["pii_retained"])
        self.assertFalse(evidence["security_state"]["raw_rows_retained"])
        self.assertEqual("sha256:" + hashlib.sha256((BASE / f"{BOUNDARY}-step1-success.evidence.json").read_bytes()).hexdigest(), STEP1_EVIDENCE_DIGEST)
        evidence_text = json.dumps(evidence, sort_keys=True).lower()
        for forbidden in ('"session_id"', '"user_id"', '"email"', '"provider_payload"', '"access_token"', '"refresh_token"', '"secret_value"'):
            self.assertNotIn(forbidden, evidence_text)

        execution = json.loads((BASE / f"{BOUNDARY}.execution-progress.json").read_text())
        self.assertEqual(execution["progress_digest"], EXECUTION_PROGRESS_DIGEST)
        self.assertEqual(progress_digest(execution), EXECUTION_PROGRESS_DIGEST)
        self.assertEqual(execution["overall_state"], "STOPPED")
        first, second, third = execution["step_states"]
        self.assertEqual(
            (first["authorization_state"], first["execution_state"], first["verification_state"], first["authorization_consumed"]),
            ("CONSUMED", "SUCCEEDED", "PASS", True),
        )
        self.assertEqual(
            [assertion["binding_id"] for assertion in first["binding_assertions"]],
            [
                "binding.development.auth.cleanup-v2.dashboard-precleanup-read",
                "binding.development.auth.cleanup-v2.precleanup-state",
            ],
        )
        self.assertEqual(
            (second["authorization_state"], second["execution_state"],
             second["verification_state"], second["authorization_consumed"],
             second["safe_error_code"], len(second["evidence"])),
            ("CONSUMED", "FAILED", "FAIL", True, STEP2_SAFE_ERROR, 1),
        )
        failure = json.loads((BASE / f"{BOUNDARY}-step2-failure.evidence.json").read_text())
        self.assertEqual(failure["evidence_type"], "auth.synthetic-session.global-revocation.accepted")
        self.assertEqual(failure["outcome"], "FAILED_UNVERIFIED")
        self.assertEqual(failure["classification"], "SESSION_STATE_UNVERIFIED")
        self.assertEqual(failure["safe_error_code"], STEP2_SAFE_ERROR)
        self.assertEqual(failure["execution_observation"]["workflow_run_id"], 36157829108)
        self.assertTrue(failure["execution_observation"]["recovery_credential_generation_attempted"])
        self.assertTrue(failure["execution_observation"]["direct_recovery_verification_attempted"])
        self.assertEqual(failure["execution_observation"]["temporary_session_state"], "UNVERIFIED")
        self.assertFalse(failure["execution_observation"]["jwt_validation_reached"])
        self.assertFalse(failure["execution_observation"]["global_logout_attempted"])
        self.assertTrue(failure["execution_observation"]["provider_mutation_attempted"])
        self.assertFalse(failure["failure_observation"]["cleanup_verified"])
        self.assertFalse(failure["failure_observation"]["session_revocation_request_accepted"])
        self.assertFalse(failure["failure_observation"]["retry_authorized"])
        self.assertFalse(failure["credential_material_retained"])
        self.assertFalse(failure["pii_retained"])
        self.assertEqual(
            "sha256:" + hashlib.sha256((BASE / f"{BOUNDARY}-step2-failure.evidence.json").read_bytes()).hexdigest(),
            STEP2_FAILURE_EVIDENCE_DIGEST,
        )
        failure_text = json.dumps(failure, sort_keys=True).lower()
        for forbidden in ('"access_token"', '"refresh_token"', '"token_hash"', '"hashed_token"', '"user_id"', '"email"', '"provider_response"'):
            self.assertNotIn(forbidden, failure_text)
        self.assertEqual(
            (third["authorization_state"], third["execution_state"],
             third["verification_state"], third["authorization_consumed"], third["evidence"]),
            ("BLOCKED", "NOT_STARTED", "NOT_STARTED", False, []),
        )
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
