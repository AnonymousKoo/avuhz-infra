from __future__ import annotations

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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.approval.json"
INITIAL_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.execution-progress.json"
REPAIR_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1-success.evidence.json"
V3_STEP1_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step1-v3-success.evidence.json"
REPAIR_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_outbox_search_path_repair_v1.sql"

PLAN_ID = "02640972-5a93-4286-9ce9-e0ffed45279e"
PLAN_DIGEST = "sha256:23f2ceb93120ab848ba614cf435f1a612913bc3d386eca0af67eb81563f51f47"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP_ID = "development.data.search-path-repair.v1.step.01.repair-outbox-function-search-path"
REPAIR_BLOB = "8afb7df0276e28a681c81dac8c201a5fa5a0f22f"
V3_STEP1_EVIDENCE = "sha256:ccce61683282152c55225147555d7e6a54ed33218bf02c1a01dc25f06ad5f188"
AUTHORIZED_AT = "2026-09-14T02:47:01Z"
AUTHORIZED_PROGRESS = "sha256:69afbed782950d379be57ac1f355480bb676acd4d0e937ddcc363c432b79ac2d"
OUTCOME_AT = "2026-09-14T03:01:04Z"
REPAIR_SUCCESS = "sha256:287b42893e88b0e4402fe031b982e2353d41a15b9b09240904356f26283523ee"
REPAIRED_STATE = "sha256:d51cf99a1bc026c9536cf9018adba3f58fa49ec7cbabde3d38ca26132343affb"
SUCCESS_PROGRESS = "sha256:1c004e001271a770d3f8caca9da33f403837eb17fc1f95eb19e11224a240e30f"


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
        "plan_version": 1,
        "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
        "step_id": STEP_ID,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [
            {
                "evidence_type": "data.migration-identity.sealed",
                "evidence_digest": V3_STEP1_EVIDENCE,
            }
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


class DevelopmentDataSearchPathRepairV1Step1OutcomeTest(unittest.TestCase):
    def test_exact_authorization_and_repair_success_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial = load(INITIAL_PROGRESS_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)
        evidence = load(REPAIR_SUCCESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)
        validate_approval(plan, approval, SCHEMA_ROOT, OUTCOME_AT)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP_ID)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(git_blob_sha(REPAIR_PATH), REPAIR_BLOB)
        self.assertEqual(raw_digest(V3_STEP1_SUCCESS_PATH), V3_STEP1_EVIDENCE)

        authorized = authorize_step(
            plan,
            approval,
            initial,
            request(plan),
            SCHEMA_ROOT,
            AUTHORIZED_AT,
            trusted_preflight_assertions=[],
        )
        self.assertEqual(authorized["record_version"], 2)
        self.assertEqual(authorized["overall_state"], "IN_PROGRESS")
        self.assertEqual(authorized["progress_digest"], AUTHORIZED_PROGRESS)
        self.assertEqual(
            authorized["step_states"][0]["authorization_state"],
            "AUTHORIZED",
        )
        self.assertFalse(authorized["step_states"][0]["authorization_consumed"])

        self.assertEqual(raw_digest(REPAIR_SUCCESS_PATH), REPAIR_SUCCESS)
        self.assertEqual(evidence["evidence_type"], "data.outbox-search-path.repaired")
        self.assertEqual(evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(evidence["recorded_at"], OUTCOME_AT)
        self.assertEqual(evidence["resource_version"], f"gitblob.{REPAIR_BLOB}")
        self.assertEqual(evidence["provider_observation"]["function_search_path"], "")
        self.assertEqual(evidence["provider_observation"]["function_proconfig_count"], 1)
        self.assertFalse(evidence["provider_observation"]["function_security_definer"])
        self.assertEqual(evidence["provider_observation"]["explicit_postgres_set_edge_count"], 0)
        self.assertFalse(evidence["provider_observation"]["postgres_can_set_migration_role"])
        self.assertFalse(evidence["provider_observation"]["migration_can_set_command_role"])
        self.assertEqual(evidence["provider_observation"]["migration_membership_edge_count"], 2)
        self.assertEqual(evidence["provider_observation"]["table_count"], 16)
        self.assertEqual(evidence["provider_observation"]["rls_enabled_count"], 16)
        self.assertEqual(evidence["provider_observation"]["tenant_policy_count"], 16)
        self.assertEqual(evidence["provider_observation"]["exposed_role_table_grant_count"], 0)
        self.assertEqual(evidence["provider_observation"]["canonical_migration_history_count"], 1)
        self.assertEqual(evidence["provider_observation"]["total_migration_history_count"], 1)
        self.assertEqual(
            evidence["verification_observation"]["pre_repair_security_advisor_finding_codes"],
            ["function_search_path_mutable"],
        )
        self.assertEqual(
            evidence["verification_observation"]["post_repair_security_advisor_finding_codes"],
            [],
        )
        self.assertEqual(
            evidence["verification_observation"]["post_repair_security_advisor_finding_count"],
            0,
        )
        self.assertTrue(evidence["verification_observation"]["temporary_set_edge_restored"])
        self.assertTrue(evidence["verification_observation"]["migration_history_unchanged"])
        self.assertTrue(evidence["verification_observation"]["tenant_isolation_preserved"])
        self.assertFalse(evidence["security_state"]["credential_retained"])
        self.assertFalse(evidence["security_state"]["raw_provider_payload_retained"])
        self.assertFalse(evidence["security_state"]["pii_retained"])
        self.assertFalse(evidence["security_state"]["row_data_read"])
        self.assertFalse(evidence["security_state"]["row_data_mutated"])
        self.assertFalse(evidence["security_state"]["auth_resource_touched"])
        self.assertFalse(evidence["security_state"]["staging_resource_touched"])
        self.assertFalse(evidence["security_state"]["production_resource_touched"])
        self.assertFalse(evidence["security_state"]["v3_step2_touched"])
        self.assertFalse(evidence["security_state"]["rls_changed"])
        self.assertFalse(evidence["security_state"]["migration_history_changed"])
        self.assertFalse(evidence["security_state"]["persistent_role_membership_added"])

        repaired_state = {
            "project_reference": PROJECT,
            "function_reference": "public.avuhz_guard_outbox_transition",
            "function_owner": "avuhz_data_migration_service_dev",
            "function_security_definer": False,
            "function_search_path": "",
            "function_proconfig_count": 1,
            "function_semantics_ok": True,
            "function_acl_count": 1,
            "owner_execute_acl_count": 1,
            "trigger_binding_count": 1,
            "provider_admin_noset_edge_count": 1,
            "explicit_postgres_set_edge_count": 0,
            "command_admin_noset_edge_count": 1,
            "membership_edge_count": 2,
            "postgres_can_set_migration_role": False,
            "migration_can_set_command_role": False,
            "table_count": 16,
            "rls_enabled_count": 16,
            "tenant_policy_count": 16,
            "exposed_role_table_grant_count": 0,
            "command_service_public_usage": True,
            "command_service_public_create": False,
            "canonical_migration_history_count": 1,
            "security_advisor_finding_count": 0,
        }
        self.assertEqual(canonical_digest(repaired_state), REPAIRED_STATE)
        self.assertEqual(
            evidence["verification_observation"]["repaired_state_digest"],
            REPAIRED_STATE,
        )

        produced_binding = {
            "binding_id": "binding.development.data.search-path-repair.v1.repaired-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.outbox-search-path.repaired",
            "evidence_digest": REPAIR_SUCCESS,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": REPAIRED_STATE,
            "recorded_at": OUTCOME_AT,
        }
        completed = record_step_outcome(
            plan,
            approval,
            authorized,
            STEP_ID,
            "SUCCEEDED",
            "PASS",
            [
                {
                    "evidence_type": "data.outbox-search-path.repaired",
                    "evidence_reference": "provider.execution.data-search-path-repair-v1.step1.attempt1.verified",
                    "evidence_digest": REPAIR_SUCCESS,
                    "recorded_at": OUTCOME_AT,
                }
            ],
            plan["steps"][0]["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            OUTCOME_AT,
            binding_assertions=[produced_binding],
        )

        self.assertEqual(completed, canonical)
        self.assertEqual(canonical["record_version"], 3)
        self.assertEqual(canonical["overall_state"], "COMPLETED")
        self.assertEqual(canonical["progress_digest"], SUCCESS_PROGRESS)

        state = canonical["step_states"][0]
        self.assertEqual(state["authorization_state"], "CONSUMED")
        self.assertEqual(state["execution_state"], "SUCCEEDED")
        self.assertEqual(state["verification_state"], "PASS")
        self.assertTrue(state["authorization_consumed"])
        self.assertEqual(state["evidence"][0]["evidence_digest"], REPAIR_SUCCESS)
        self.assertEqual(
            [item["binding_id"] for item in state["binding_assertions"]],
            ["binding.development.data.search-path-repair.v1.repaired-state"],
        )


if __name__ == "__main__":
    unittest.main()
