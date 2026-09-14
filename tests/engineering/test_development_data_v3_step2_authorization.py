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
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.execution-progress.json"
STEP2_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step2-v3-success.evidence.json"

PLAN_ID = "f6ae6374-878e-4a84-9b33-3f5718ed01b9"
PLAN_DIGEST = "sha256:d958bb5cb4d12524ebfb3d748e025af64b8c32da6e77e17ca8559239f18e0eb8"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP1_ID = "development.data.v3.step.01.seal-migration-identity"
STEP2_ID = "development.data.v3.step.02.verify-tenant-isolation"
STEP1_EVIDENCE = "sha256:ccce61683282152c55225147555d7e6a54ed33218bf02c1a01dc25f06ad5f188"
SEALED_STATE = "sha256:1a1e1ad3aeb6f4a9c92e17b0a4b82b1c150862f3d6360aeeafee87676d94fbfb"
PRE_STEP2_PROGRESS = "sha256:16dbf6794a6735f243467970baaa1babdc1274ea6cea2d66c246ad2c96d8de5a"
AUTHORIZED_PROGRESS = "sha256:179fc8f4f0cfe87b1df83dca643ef4c54bfbe335e0fbf7bc62d689033710a088"
STEP2_SUCCESS = "sha256:7274e95367bf2c4567e47a7ee48055647aca220bc14ca7a513255be2b09946b3"
TENANT_ISOLATION_STATE = "sha256:ddb68cd3c2f85bc565cf54752290da896e5604feafc5d8056fdbcc58099f389d"
SUCCESS_PROGRESS = "sha256:8564b668da612c02b111c96390e1d7fe66f5f78d88e553bb018edb5d12c23d72"
PRE_STEP2_AT = "2026-09-14T02:11:34Z"
AUTHORIZED_AT = "2026-09-14T03:13:10Z"
OUTCOME_AT = "2026-09-14T03:45:26Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def request(plan: dict) -> dict:
    step = plan["steps"][1]
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
        "step_id": STEP2_ID,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [
            {
                "evidence_type": "data.migration-identity.sealed",
                "evidence_digest": STEP1_EVIDENCE,
            }
        ],
        "prior_evidence_digests": [STEP1_EVIDENCE],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


class DevelopmentDataV3Step2OutcomeTest(unittest.TestCase):
    def test_exact_step2_read_only_authorization_and_success_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)
        evidence = load(STEP2_SUCCESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)
        validate_approval(plan, approval, SCHEMA_ROOT, OUTCOME_AT)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        step2 = plan["steps"][1]
        self.assertEqual(step2["step_id"], STEP2_ID)
        self.assertEqual(step2["execution_class"], "PROVIDER_READ")
        self.assertEqual(
            step2["operation"],
            "provider.resource.verify-tenant-isolation-and-sealed-identity",
        )
        self.assertEqual(
            step2["resource"]["resource_reference"],
            "supabase:gnuqaefotwgkwurjpyik:public:avuhz-shared-core",
        )
        self.assertEqual(step2["resource"]["exact_version"], "tenant-isolation.v2")
        self.assertIn("provider.mutation", step2["prohibited_actions"])
        self.assertIn("resource.repair", step2["prohibited_actions"])
        self.assertIn("search-path.repair", step2["prohibited_actions"])

        authorized = copy.deepcopy(canonical)
        authorized["record_version"] = 4
        authorized["overall_state"] = "IN_PROGRESS"
        authorized["updated_at"] = AUTHORIZED_AT
        authorized["progress_digest"] = AUTHORIZED_PROGRESS
        authorized_step2 = authorized["step_states"][1]
        authorized_step2["authorization_state"] = "AUTHORIZED"
        authorized_step2["execution_state"] = "NOT_STARTED"
        authorized_step2["verification_state"] = "NOT_STARTED"
        authorized_step2["authorization_consumed"] = False
        authorized_step2["evidence"] = []
        authorized_step2["observed_postcondition"] = None
        authorized_step2["safe_error_code"] = None
        authorized_step2["binding_assertions"] = authorized_step2["binding_assertions"][:1]
        validate_progress(plan, authorized, SCHEMA_ROOT)

        pre = copy.deepcopy(authorized)
        pre["record_version"] = 3
        pre["updated_at"] = PRE_STEP2_AT
        pre["progress_digest"] = PRE_STEP2_PROGRESS
        pre_step2 = pre["step_states"][1]
        pre_step2["authorization_state"] = "PENDING"
        pre_step2["binding_assertions"] = []
        validate_progress(plan, pre, SCHEMA_ROOT)

        exact_request = request(plan)
        authorized_from_engine = authorize_step(
            plan,
            approval,
            pre,
            exact_request,
            SCHEMA_ROOT,
            AUTHORIZED_AT,
            trusted_preflight_assertions=[],
        )
        self.assertEqual(authorized_from_engine, authorized)
        self.assertEqual(authorized["progress_digest"], AUTHORIZED_PROGRESS)

        self.assertEqual(raw_digest(STEP2_SUCCESS_PATH), STEP2_SUCCESS)
        self.assertEqual(evidence["evidence_type"], "data.tenant-isolation.verified")
        self.assertEqual(evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(evidence["recorded_at"], OUTCOME_AT)
        self.assertEqual(evidence["resource_version"], "tenant-isolation.v2")
        provider = evidence["provider_observation"]
        self.assertEqual(provider["table_count"], 16)
        self.assertEqual(provider["rls_enabled_count"], 16)
        self.assertEqual(provider["migration_owned_table_count"], 16)
        self.assertEqual(provider["tenant_id_column_count"], 16)
        self.assertEqual(provider["exact_tenant_policy_count"], 16)
        self.assertEqual(provider["tenant_policy_table_count"], 16)
        self.assertEqual(provider["exposed_role_table_acl_count"], 0)
        self.assertEqual(provider["exposed_role_function_execute_acl_count"], 0)
        self.assertEqual(provider["command_select_table_acl_count"], 16)
        self.assertEqual(provider["command_insert_table_acl_count"], 15)
        self.assertEqual(provider["command_update_column_acl_count"], 47)
        self.assertEqual(provider["command_unexpected_table_acl_count"], 0)
        self.assertEqual(provider["command_unexpected_column_acl_count"], 0)
        self.assertTrue(provider["command_service_role_valid"])
        self.assertTrue(provider["command_service_public_usage"])
        self.assertFalse(provider["command_service_public_create"])
        self.assertTrue(provider["migration_role_sealed"])
        self.assertEqual(provider["migration_direct_public_schema_acl_count"], 0)
        self.assertEqual(provider["migration_delegated_public_schema_acl_count"], 0)
        self.assertEqual(provider["provider_admin_noset_edge_count"], 1)
        self.assertEqual(provider["command_admin_noset_edge_count"], 1)
        self.assertEqual(provider["migration_membership_edge_count"], 2)
        self.assertEqual(provider["explicit_postgres_granted_migration_edge_count"], 0)
        self.assertFalse(provider["postgres_can_set_migration_role"])
        self.assertFalse(provider["migration_can_set_command_role"])
        self.assertFalse(provider["outbox_function_security_definer"])
        self.assertTrue(provider["outbox_function_empty_search_path"])
        self.assertEqual(provider["canonical_migration_history_count"], 1)
        self.assertEqual(provider["total_migration_history_count"], 1)

        verification = evidence["verification_observation"]
        self.assertTrue(verification["provider_read_only"])
        self.assertEqual(verification["provider_mutation_attempts"], 0)
        self.assertEqual(verification["row_data_query_attempts"], 0)
        self.assertEqual(verification["security_advisor_finding_count"], 0)
        self.assertEqual(verification["security_advisor_finding_codes"], [])
        self.assertTrue(verification["expected_postcondition_verified"])
        self.assertTrue(verification["catalog_query_error_resolved"])

        security = evidence["security_state"]
        for key in (
            "credential_retained",
            "raw_provider_payload_retained",
            "pii_retained",
            "row_data_read",
            "row_data_mutated",
            "provider_resource_mutated",
            "rls_changed",
            "policy_changed",
            "role_changed",
            "grant_changed",
            "migration_history_changed",
            "auth_resource_touched",
            "staging_resource_touched",
            "production_resource_touched",
            "search_path_repair_performed",
        ):
            self.assertFalse(security[key])

        policy_expression = (
            "(tenant_id = (NULLIF(current_setting('avuhz.tenant_id'::text, true), "
            "''::text))::uuid)"
        )
        tenant_state = {
            "project_reference": PROJECT,
            "resource_reference": "supabase:gnuqaefotwgkwurjpyik:public:avuhz-shared-core",
            "resource_version": "tenant-isolation.v2",
            "table_count": 16,
            "rls_enabled_count": 16,
            "migration_owned_table_count": 16,
            "tenant_id_column_count": 16,
            "tenant_policy_count": 16,
            "tenant_policy_table_count": 16,
            "tenant_policy_using_expression": policy_expression,
            "tenant_policy_check_expression": policy_expression,
            "exposed_role_table_acl_count": 0,
            "exposed_role_function_execute_acl_count": 0,
            "command_select_table_acl_count": 16,
            "command_insert_table_acl_count": 15,
            "command_update_column_acl_count": 47,
            "command_unexpected_table_acl_count": 0,
            "command_unexpected_column_acl_count": 0,
            "command_service_role_valid": True,
            "command_service_public_usage": True,
            "command_service_public_create": False,
            "migration_role_sealed": True,
            "migration_direct_public_schema_acl_count": 0,
            "migration_delegated_public_schema_acl_count": 0,
            "provider_admin_noset_edge_count": 1,
            "command_admin_noset_edge_count": 1,
            "membership_edge_count": 2,
            "explicit_postgres_granted_migration_edge_count": 0,
            "postgres_can_set_migration_role": False,
            "migration_can_set_command_role": False,
            "avuhz_function_count": 10,
            "migration_owned_avuhz_function_count": 10,
            "outbox_function_security_definer": False,
            "outbox_function_empty_search_path": True,
            "outbox_trigger_binding_count": 1,
            "canonical_migration_history_count": 1,
            "total_migration_history_count": 1,
            "security_advisor_finding_count": 0,
        }
        self.assertEqual(canonical_digest(tenant_state), TENANT_ISOLATION_STATE)
        self.assertEqual(
            verification["tenant_isolation_state_digest"],
            TENANT_ISOLATION_STATE,
        )

        produced_binding = {
            "binding_id": "binding.development.data.v3.tenant-isolation-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.tenant-isolation.verified",
            "evidence_digest": STEP2_SUCCESS,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": TENANT_ISOLATION_STATE,
            "recorded_at": OUTCOME_AT,
        }
        completed = record_step_outcome(
            plan,
            approval,
            authorized,
            STEP2_ID,
            "SUCCEEDED",
            "PASS",
            [
                {
                    "evidence_type": "data.tenant-isolation.verified",
                    "evidence_reference": "provider.execution.data-v3.step2.attempt1.verified",
                    "evidence_digest": STEP2_SUCCESS,
                    "recorded_at": OUTCOME_AT,
                }
            ],
            step2["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            OUTCOME_AT,
            binding_assertions=[produced_binding],
        )

        self.assertEqual(completed, canonical)
        self.assertEqual(canonical["record_version"], 5)
        self.assertEqual(canonical["overall_state"], "COMPLETED")
        self.assertEqual(canonical["progress_digest"], SUCCESS_PROGRESS)

        state = canonical["step_states"][1]
        self.assertEqual(state["authorization_state"], "CONSUMED")
        self.assertEqual(state["execution_state"], "SUCCEEDED")
        self.assertEqual(state["verification_state"], "PASS")
        self.assertTrue(state["authorization_consumed"])
        self.assertEqual(state["evidence"][0]["evidence_digest"], STEP2_SUCCESS)
        self.assertEqual(
            [item["binding_id"] for item in state["binding_assertions"]],
            [
                "binding.development.data.v3.migration-identity-sealed",
                "binding.development.data.v3.tenant-isolation-state",
            ],
        )


if __name__ == "__main__":
    unittest.main()
