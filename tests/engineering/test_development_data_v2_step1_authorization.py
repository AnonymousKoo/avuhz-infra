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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.execution-progress.json"
PREFLIGHT_PATH = ROOT / "contracts/plans/v1/development-data-step1-v2-preflight.evidence.json"
STEP1_SUCCESS_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-data-step1-v2-success.evidence.json"
STEP2_SUCCESS_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-data-step2-v2-success.evidence.json"

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
PLAN_DIGEST = "sha256:ed141409e31c0aa70944ca801047f05db574ef3e905dd85dcd2e81c0a393d695"
STEP1_ID = "development.data.v2.step.01.verify-empty-bootstrap-boundary"
STEP2_ID = "development.data.v2.step.02.bootstrap-migration-identity"
PROJECT_REFERENCE = "gnuqaefotwgkwurjpyik"
STEP1_AUTHORIZED_AT = "2026-09-13T22:42:28Z"
STEP1_OUTCOME_AT = "2026-09-13T22:54:53Z"
STEP2_AUTHORIZED_AT = "2026-09-13T23:09:56Z"
STEP2_OUTCOME_AT = "2026-09-13T23:24:38Z"

PACKAGE_IDENTITY_DIGEST = "sha256:ab86caddb7da33e174d14684d00af97941482b35a6cc5fa5cf172865de93bef8"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:83374a5770b00b6a548b72ed627cf493456562a3297678a9ab3455ef2ef94beb"
PREFLIGHT_CONFIGURATION_DIGEST = "sha256:feac73ff90a562d40dbaaacdddca6ac19a21b49ec0be1a760a93fac03d93283a"
STEP1_SUCCESS_EVIDENCE_DIGEST = "sha256:ef26f125d2f2ea47d45e420e9b95c04c50a737c782768b987af694d90829d395"
BASELINE_STATE_VALUE_DIGEST = "sha256:e05c1a9995f1c3383e5237678f766ce9729a1e29756afbee287e882d82284d22"
STEP2_SUCCESS_EVIDENCE_DIGEST = "sha256:9c1e742d1d77d8ac63a2ea201fc39789a54f384f9caa684e24d45112ef27053c"
MIGRATION_IDENTITY_STATE_DIGEST = "sha256:732bf7b9f980dada32ef566dd3b7c9873673086b751e333db4fcdbc4e3ea1898"
MIGRATION_IDENTITY_STATE_VALUE_DIGEST = "sha256:63a91b034cf50e65877b8dae4f7fe2aa86f1355e211c2f006be9268032fcf612"
STEP2_SUCCESS_PROGRESS_DIGEST = "sha256:a3410f72e6ade8bcd7a116412e21b2e6ea6e8f912dead2affd4e9e234e7d7148"
BOOTSTRAP_VERSION = "gitblob.d8a728cbd8e6630ffb39f8489c749cce75aad6f3"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class DevelopmentDataV2ExecutionAuthorizationTest(unittest.TestCase):
    def test_step1_success_then_step2_success_exact_chain(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial_progress = load(PROGRESS_PATH)
        execution_progress = load(EXECUTION_PROGRESS_PATH)
        preflight = load(PREFLIGHT_PATH)
        step1_success_evidence = load(STEP1_SUCCESS_EVIDENCE_PATH)
        step2_success_evidence = load(STEP2_SUCCESS_EVIDENCE_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial_progress, SCHEMA_ROOT)
        validate_progress(plan, execution_progress, SCHEMA_ROOT)
        for timestamp in (
            STEP1_AUTHORIZED_AT,
            STEP1_OUTCOME_AT,
            STEP2_AUTHORIZED_AT,
            STEP2_OUTCOME_AT,
        ):
            validate_approval(plan, approval, SCHEMA_ROOT, timestamp)

        self.assertEqual(plan["plan_id"], PLAN_ID)
        self.assertEqual(plan["plan_digest"], PLAN_DIGEST)
        self.assertEqual(plan["target"]["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP1_ID)
        self.assertEqual(plan["steps"][1]["step_id"], STEP2_ID)
        self.assertEqual(plan["steps"][1]["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(plan["steps"][1]["resource"]["exact_version"], BOOTSTRAP_VERSION)

        preflight_assertion = {
            "binding_id": "binding.development.data.v2.empty-bootstrap-preflight",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "data.empty-bootstrap.preflight.observed",
            "evidence_digest": PREFLIGHT_EVIDENCE_DIGEST,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": PREFLIGHT_CONFIGURATION_DIGEST,
            "recorded_at": STEP1_AUTHORIZED_AT,
        }
        self.assertEqual(preflight["evidence_digest"], PREFLIGHT_EVIDENCE_DIGEST)
        self.assertEqual(preflight["configuration_digest"], PREFLIGHT_CONFIGURATION_DIGEST)

        step1_request = {
            "plan_id": PLAN_ID,
            "plan_version": 2,
            "plan_digest": PLAN_DIGEST,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT_REFERENCE,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
            "step_id": STEP1_ID,
            "resource_reference": plan["steps"][0]["resource"]["resource_reference"],
            "resource_version": plan["steps"][0]["resource"]["exact_version"],
            "resource_digest": plan["steps"][0]["resource"]["exact_digest"],
            "operation": plan["steps"][0]["operation"],
            "execution_class": "PROVIDER_READ",
            "credential_class": "OWNER_INTERACTIVE_SESSION",
            "required_evidence": [
                {
                    "evidence_type": "repository.data-v2.artifact-package.verified",
                    "evidence_digest": PACKAGE_IDENTITY_DIGEST,
                }
            ],
            "prior_evidence_digests": [],
            "unexpected_remote_state": False,
            "extra_privileges": False,
            "unauthorized_migration_surface": False,
            "scope_expansion": False,
        }
        step1_authorized = authorize_step(
            plan,
            approval,
            initial_progress,
            step1_request,
            SCHEMA_ROOT,
            STEP1_AUTHORIZED_AT,
            trusted_preflight_assertions=[preflight_assertion],
        )

        self.assertEqual(raw_digest(STEP1_SUCCESS_EVIDENCE_PATH), STEP1_SUCCESS_EVIDENCE_DIGEST)
        self.assertEqual(step1_success_evidence["outcome"], "SUCCEEDED_VERIFIED")
        step1_outcome_evidence = [
            {
                "evidence_type": "data.empty-baseline.verified",
                "evidence_reference": "provider.execution.data-v2.step1.attempt1.verified",
                "evidence_digest": STEP1_SUCCESS_EVIDENCE_DIGEST,
                "recorded_at": STEP1_OUTCOME_AT,
            }
        ]
        baseline_binding = {
            "binding_id": "binding.development.data.v2.empty-baseline-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.empty-baseline.verified",
            "evidence_digest": STEP1_SUCCESS_EVIDENCE_DIGEST,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": BASELINE_STATE_VALUE_DIGEST,
            "recorded_at": STEP1_OUTCOME_AT,
        }
        step1_success = record_step_outcome(
            plan,
            approval,
            step1_authorized,
            STEP1_ID,
            "SUCCEEDED",
            "PASS",
            step1_outcome_evidence,
            plan["steps"][0]["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            STEP1_OUTCOME_AT,
            binding_assertions=[baseline_binding],
        )

        step2_request = {
            "plan_id": PLAN_ID,
            "plan_version": 2,
            "plan_digest": PLAN_DIGEST,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT_REFERENCE,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
            "step_id": STEP2_ID,
            "resource_reference": plan["steps"][1]["resource"]["resource_reference"],
            "resource_version": plan["steps"][1]["resource"]["exact_version"],
            "resource_digest": plan["steps"][1]["resource"]["exact_digest"],
            "operation": plan["steps"][1]["operation"],
            "execution_class": "PROVIDER_MUTATION",
            "credential_class": "OWNER_INTERACTIVE_SESSION",
            "required_evidence": [
                {
                    "evidence_type": "data.empty-baseline.verified",
                    "evidence_digest": STEP1_SUCCESS_EVIDENCE_DIGEST,
                }
            ],
            "prior_evidence_digests": [STEP1_SUCCESS_EVIDENCE_DIGEST],
            "unexpected_remote_state": False,
            "extra_privileges": False,
            "unauthorized_migration_surface": False,
            "scope_expansion": False,
        }
        step2_authorized = authorize_step(
            plan,
            approval,
            step1_success,
            step2_request,
            SCHEMA_ROOT,
            STEP2_AUTHORIZED_AT,
        )

        self.assertEqual(raw_digest(STEP2_SUCCESS_EVIDENCE_PATH), STEP2_SUCCESS_EVIDENCE_DIGEST)
        self.assertEqual(step2_success_evidence["evidence_type"], "data.migration-identity.bootstrapped")
        self.assertEqual(step2_success_evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(step2_success_evidence["resource_version"], BOOTSTRAP_VERSION)
        self.assertEqual(step2_success_evidence["recorded_at"], STEP2_OUTCOME_AT)

        provider = step2_success_evidence["provider_observation"]
        migration_state = {
            "project_reference": provider["project_reference"],
            "role_name": provider["role_name"],
            "can_login": provider["can_login"],
            "is_superuser": provider["is_superuser"],
            "inherits": provider["inherits"],
            "can_createdb": provider["can_createdb"],
            "can_createrole": provider["can_createrole"],
            "can_replicate": provider["can_replicate"],
            "can_bypassrls": provider["can_bypassrls"],
            "public_usage": provider["public_usage"],
            "public_create": provider["public_create"],
            "public_usage_grantable_count": provider["public_usage_grantable_count"],
            "public_create_nongrantable_count": provider["public_create_nongrantable_count"],
            "explicit_postgres_set_edge_count": provider["explicit_postgres_set_edge_count"],
            "provider_admin_noset_edge_count": provider["provider_admin_noset_edge_count"],
            "total_membership_edges": provider["total_membership_edges"],
            "direct_database_acl_count": provider["direct_database_acl_count"],
            "provider_schema_privilege_count": provider["provider_schema_privilege_count"],
            "table_privilege_count": provider["table_privilege_count"],
            "sequence_privilege_count": provider["sequence_privilege_count"],
            "direct_function_execute_count": provider["direct_function_execute_count"],
            "command_service_role_exists": provider["command_service_role_exists"],
            "avuhz_schema_count": provider["avuhz_schema_count"],
            "avuhz_relation_count": provider["avuhz_relation_count"],
            "avuhz_routine_count": provider["avuhz_routine_count"],
            "avuhz_type_count": provider["avuhz_type_count"],
            "avuhz_trigger_count": provider["avuhz_trigger_count"],
            "avuhz_policy_count": provider["avuhz_policy_count"],
            "applied_migration_count": provider["applied_migration_count"],
        }
        self.assertEqual(canonical_digest(migration_state), MIGRATION_IDENTITY_STATE_DIGEST)
        self.assertEqual(
            step2_success_evidence["verification_observation"]["migration_identity_state_digest"],
            MIGRATION_IDENTITY_STATE_DIGEST,
        )
        self.assertEqual(
            canonical_digest(MIGRATION_IDENTITY_STATE_DIGEST),
            MIGRATION_IDENTITY_STATE_VALUE_DIGEST,
        )

        self.assertFalse(provider["can_login"])
        self.assertFalse(provider["is_superuser"])
        self.assertFalse(provider["inherits"])
        self.assertFalse(provider["can_createdb"])
        self.assertTrue(provider["can_createrole"])
        self.assertFalse(provider["can_replicate"])
        self.assertFalse(provider["can_bypassrls"])
        self.assertTrue(provider["public_usage"])
        self.assertTrue(provider["public_create"])
        self.assertEqual(provider["public_usage_grantable_count"], 1)
        self.assertEqual(provider["public_create_nongrantable_count"], 1)
        self.assertEqual(provider["explicit_postgres_set_edge_count"], 1)
        self.assertIn(provider["provider_admin_noset_edge_count"], (0, 1))
        self.assertEqual(
            provider["total_membership_edges"],
            provider["explicit_postgres_set_edge_count"]
            + provider["provider_admin_noset_edge_count"],
        )
        for field in (
            "direct_database_acl_count",
            "provider_schema_privilege_count",
            "table_privilege_count",
            "sequence_privilege_count",
            "direct_function_execute_count",
            "avuhz_schema_count",
            "avuhz_relation_count",
            "avuhz_routine_count",
            "avuhz_type_count",
            "avuhz_trigger_count",
            "avuhz_policy_count",
            "applied_migration_count",
        ):
            self.assertEqual(provider[field], 0)
        self.assertFalse(provider["command_service_role_exists"])

        verification = step2_success_evidence["verification_observation"]
        self.assertEqual(verification["provider_mutation_attempts"], 1)
        self.assertTrue(verification["provider_mutation_committed"])
        self.assertTrue(verification["bound_artifact_executed"])
        self.assertTrue(verification["artifact_transaction_committed"])
        self.assertTrue(verification["postcondition_verified"])
        self.assertTrue(verification["migration_history_verified_empty"])

        security = step2_success_evidence["security_state"]
        for field in (
            "credential_retained",
            "raw_provider_payload_retained",
            "pii_retained",
            "row_data_read",
            "auth_resource_touched",
            "staging_resource_touched",
            "production_resource_touched",
            "application_schema_created",
            "command_service_role_created",
        ):
            self.assertFalse(security[field])

        step2_outcome_evidence = [
            {
                "evidence_type": "data.migration-identity.bootstrapped",
                "evidence_reference": "provider.execution.data-v2.step2.attempt1.verified",
                "evidence_digest": STEP2_SUCCESS_EVIDENCE_DIGEST,
                "recorded_at": STEP2_OUTCOME_AT,
            }
        ]
        migration_identity_binding = {
            "binding_id": "binding.development.data.v2.migration-identity-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.migration-identity.bootstrapped",
            "evidence_digest": STEP2_SUCCESS_EVIDENCE_DIGEST,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": MIGRATION_IDENTITY_STATE_VALUE_DIGEST,
            "recorded_at": STEP2_OUTCOME_AT,
        }
        step2_success = record_step_outcome(
            plan,
            approval,
            step2_authorized,
            STEP2_ID,
            "SUCCEEDED",
            "PASS",
            step2_outcome_evidence,
            plan["steps"][1]["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            STEP2_OUTCOME_AT,
            binding_assertions=[migration_identity_binding],
        )

        self.assertEqual(execution_progress, step2_success)
        self.assertEqual(execution_progress["record_version"], 5)
        self.assertEqual(execution_progress["overall_state"], "IN_PROGRESS")
        self.assertEqual(execution_progress["progress_digest"], STEP2_SUCCESS_PROGRESS_DIGEST)

        step2_state = execution_progress["step_states"][1]
        self.assertEqual(step2_state["authorization_state"], "CONSUMED")
        self.assertEqual(step2_state["execution_state"], "SUCCEEDED")
        self.assertEqual(step2_state["verification_state"], "PASS")
        self.assertTrue(step2_state["authorization_consumed"])
        self.assertEqual(step2_state["evidence"], step2_outcome_evidence)

        for pending in execution_progress["step_states"][2:]:
            self.assertEqual(pending["authorization_state"], "PENDING")
            self.assertEqual(pending["execution_state"], "NOT_STARTED")
            self.assertEqual(pending["verification_state"], "NOT_STARTED")
            self.assertFalse(pending["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
