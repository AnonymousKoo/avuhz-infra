from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    authorize_step,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.approval.json"
INITIAL_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.execution-progress.json"
STEP1_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step1-v3-success.evidence.json"
SEAL_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_identity_seal_v1.sql"

PLAN_ID = "f6ae6374-878e-4a84-9b33-3f5718ed01b9"
PLAN_DIGEST = "sha256:d958bb5cb4d12524ebfb3d748e025af64b8c32da6e77e17ca8559239f18e0eb8"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP1_ID = "development.data.v3.step.01.seal-migration-identity"
STEP2_ID = "development.data.v3.step.02.verify-tenant-isolation"
STEP4_EVIDENCE = "sha256:23f5efaad368cde39ce6d8d4c58e1d3c9912d508ae4c83c994ff12c37463c0a8"
SEAL_BLOB = "65952c5900a6b73f8f413fe21f3c124c2f3e182e"
AUTHORIZED_PROGRESS = "sha256:d0693b0bd0a3973d962e5c387c8cd9830d2405b18b60f34b5430ee952a197a88"
STEP1_SUCCESS = "sha256:ccce61683282152c55225147555d7e6a54ed33218bf02c1a01dc25f06ad5f188"
SEALED_STATE = "sha256:1a1e1ad3aeb6f4a9c92e17b0a4b82b1c150862f3d6360aeeafee87676d94fbfb"
SUCCESS_PROGRESS = "sha256:16dbf6794a6735f243467970baaa1babdc1274ea6cea2d66c246ad2c96d8de5a"
STEP2_AUTHORIZED_PROGRESS = "sha256:179fc8f4f0cfe87b1df83dca643ef4c54bfbe335e0fbf7bc62d689033710a088"
T1A = "2026-09-14T01:43:30Z"
T1O = "2026-09-14T02:11:34Z"
T2A = "2026-09-14T03:13:10Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha(path: Path) -> str:
    body = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def request(plan: dict) -> dict:
    step = plan["steps"][0]
    return {
        "plan_id": PLAN_ID,
        "plan_version": 3,
        "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
        "step_id": STEP1_ID,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [
            {
                "evidence_type": "data.initial-migration.applied",
                "evidence_digest": STEP4_EVIDENCE,
            }
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


class DevelopmentDataV3Step1OutcomeTest(unittest.TestCase):
    def test_exact_step1_authorization_and_success_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial = load(INITIAL_PROGRESS_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)
        evidence = load(STEP1_SUCCESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, T1A)
        validate_approval(plan, approval, SCHEMA_ROOT, T1O)
        validate_approval(plan, approval, SCHEMA_ROOT, T2A)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP1_ID)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(plan["steps"][1]["step_id"], STEP2_ID)
        self.assertEqual(git_blob_sha(SEAL_PATH), SEAL_BLOB)
        self.assertIn("search-path.repair", plan["steps"][0]["prohibited_actions"])
        self.assertIn("search-path.repair", plan["prohibited_actions"])

        authorized = authorize_step(
            plan,
            approval,
            initial,
            request(plan),
            SCHEMA_ROOT,
            T1A,
        )
        self.assertEqual(authorized["record_version"], 2)
        self.assertEqual(authorized["progress_digest"], AUTHORIZED_PROGRESS)
        self.assertEqual(authorized["step_states"][0]["authorization_state"], "AUTHORIZED")
        self.assertFalse(authorized["step_states"][0]["authorization_consumed"])

        self.assertEqual(raw_digest(STEP1_SUCCESS_PATH), STEP1_SUCCESS)
        self.assertEqual(evidence["evidence_type"], "data.migration-identity.sealed")
        self.assertEqual(evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(evidence["recorded_at"], T1O)
        self.assertEqual(evidence["resource_version"], f"gitblob.{SEAL_BLOB}")
        self.assertFalse(evidence["provider_observation"]["migration_role_can_createrole"])
        self.assertFalse(evidence["provider_observation"]["postgres_can_set_migration_role"])
        self.assertFalse(evidence["provider_observation"]["migration_can_set_command_role"])
        self.assertEqual(evidence["provider_observation"]["migration_membership_edge_count"], 2)
        self.assertEqual(evidence["provider_observation"]["migration_direct_public_acl_count"], 0)
        self.assertEqual(evidence["provider_observation"]["migration_delegated_public_acl_count"], 0)
        self.assertEqual(evidence["provider_observation"]["explicit_postgres_set_edge_count"], 0)
        self.assertEqual(evidence["provider_observation"]["table_count"], 16)
        self.assertEqual(evidence["provider_observation"]["rls_enabled_count"], 16)
        self.assertEqual(evidence["provider_observation"]["tenant_policy_count"], 16)
        self.assertEqual(evidence["provider_observation"]["exposed_role_privileged_table_count"], 0)
        self.assertEqual(evidence["provider_observation"]["applied_migration_count"], 1)
        self.assertEqual(
            evidence["verification_observation"]["security_advisor_finding_codes"],
            ["function_search_path_mutable"],
        )
        self.assertFalse(evidence["verification_observation"]["security_advisor_repair_performed"])
        self.assertTrue(
            evidence["verification_observation"]["security_advisor_deferred_to_separate_authorization"]
        )
        self.assertFalse(evidence["security_state"]["credential_retained"])
        self.assertFalse(evidence["security_state"]["raw_provider_payload_retained"])
        self.assertFalse(evidence["security_state"]["pii_retained"])
        self.assertFalse(evidence["security_state"]["row_data_read"])
        self.assertFalse(evidence["security_state"]["row_data_mutated"])
        self.assertFalse(evidence["security_state"]["auth_resource_touched"])
        self.assertFalse(evidence["security_state"]["staging_resource_touched"])
        self.assertFalse(evidence["security_state"]["production_resource_touched"])
        self.assertFalse(evidence["security_state"]["search_path_repair_performed"])

        sealed_state = {
            "project_reference": PROJECT,
            "migration_role": "avuhz_data_migration_service_dev",
            "migration_role_attributes": {
                "can_login": False,
                "is_superuser": False,
                "inherits": False,
                "can_createdb": False,
                "can_createrole": False,
                "can_replicate": False,
                "can_bypassrls": False,
            },
            "postgres_can_set_migration_role": False,
            "migration_can_set_command_role": False,
            "provider_admin_noset_edge_count": 1,
            "command_admin_noset_edge_count": 1,
            "membership_edge_count": 2,
            "direct_public_acl_count": 0,
            "delegated_public_acl_count": 0,
            "explicit_postgres_set_edge_count": 0,
            "command_service_role_valid": True,
            "command_service_public_usage": True,
            "command_service_public_create": False,
            "table_count": 16,
            "rls_enabled_count": 16,
            "migration_owned_table_count": 16,
            "tenant_policy_count": 16,
            "exposed_role_table_grant_count": 0,
            "canonical_migration_history_count": 1,
            "canonical_migration_version": "20260914005437",
            "canonical_migration_name": "rebaseline_provider_neutral_avuhz",
        }
        self.assertEqual(canonical_digest(sealed_state), SEALED_STATE)
        self.assertEqual(
            evidence["verification_observation"]["sealed_migration_identity_state_digest"],
            SEALED_STATE,
        )

        produced_binding = {
            "binding_id": "binding.development.data.v3.migration-identity-sealed",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.migration-identity.sealed",
            "evidence_digest": STEP1_SUCCESS,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": SEALED_STATE,
            "recorded_at": T1O,
        }
        completed = record_step_outcome(
            plan,
            approval,
            authorized,
            STEP1_ID,
            "SUCCEEDED",
            "PASS",
            [
                {
                    "evidence_type": "data.migration-identity.sealed",
                    "evidence_reference": "provider.execution.data-v3.step1.attempt1.verified",
                    "evidence_digest": STEP1_SUCCESS,
                    "recorded_at": T1O,
                }
            ],
            plan["steps"][0]["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            T1O,
            binding_assertions=[produced_binding],
        )

        historical = copy.deepcopy(canonical)
        historical["record_version"] = 3
        historical["updated_at"] = T1O
        historical["progress_digest"] = SUCCESS_PROGRESS
        historical_step2 = historical["step_states"][1]
        historical_step2["authorization_state"] = "PENDING"
        historical_step2["binding_assertions"] = []
        validate_progress(plan, historical, SCHEMA_ROOT)

        self.assertEqual(completed, historical)
        self.assertEqual(historical["record_version"], 3)
        self.assertEqual(historical["overall_state"], "IN_PROGRESS")
        self.assertEqual(historical["progress_digest"], SUCCESS_PROGRESS)

        step1 = canonical["step_states"][0]
        self.assertEqual(step1, historical["step_states"][0])
        self.assertEqual(step1["authorization_state"], "CONSUMED")
        self.assertEqual(step1["execution_state"], "SUCCEEDED")
        self.assertEqual(step1["verification_state"], "PASS")
        self.assertTrue(step1["authorization_consumed"])
        self.assertEqual(step1["evidence"][0]["evidence_digest"], STEP1_SUCCESS)

        self.assertEqual(canonical["record_version"], 4)
        self.assertEqual(canonical["progress_digest"], STEP2_AUTHORIZED_PROGRESS)
        step2 = canonical["step_states"][1]
        self.assertEqual(step2["authorization_state"], "AUTHORIZED")
        self.assertEqual(step2["execution_state"], "NOT_STARTED")
        self.assertEqual(step2["verification_state"], "NOT_STARTED")
        self.assertFalse(step2["authorization_consumed"])
        self.assertEqual(step2["evidence"], [])
        self.assertEqual(step2["binding_assertions"][0]["evidence_digest"], STEP1_SUCCESS)
        self.assertEqual(step2["binding_assertions"][0]["value_digest"], SEALED_STATE)


if __name__ == "__main__":
    unittest.main()
