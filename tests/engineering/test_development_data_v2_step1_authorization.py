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
SUCCESS_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-data-step1-v2-success.evidence.json"

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
PLAN_DIGEST = "sha256:ed141409e31c0aa70944ca801047f05db574ef3e905dd85dcd2e81c0a393d695"
STEP1_ID = "development.data.v2.step.01.verify-empty-bootstrap-boundary"
STEP2_ID = "development.data.v2.step.02.bootstrap-migration-identity"
PROJECT_REFERENCE = "gnuqaefotwgkwurjpyik"
STEP1_AUTHORIZED_AT = "2026-09-13T22:42:28Z"
STEP1_OUTCOME_AT = "2026-09-13T22:54:53Z"
STEP2_AUTHORIZED_AT = "2026-09-13T23:09:56Z"
PACKAGE_IDENTITY_DIGEST = "sha256:ab86caddb7da33e174d14684d00af97941482b35a6cc5fa5cf172865de93bef8"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:83374a5770b00b6a548b72ed627cf493456562a3297678a9ab3455ef2ef94beb"
PREFLIGHT_CONFIGURATION_DIGEST = "sha256:feac73ff90a562d40dbaaacdddca6ac19a21b49ec0be1a760a93fac03d93283a"
STEP1_AUTHORIZED_PROGRESS_DIGEST = "sha256:522948b97e7a6720561a186b5f350fba584fab0e32587d0176eb75f3b54cb8a7"
SUCCESS_EVIDENCE_DIGEST = "sha256:ef26f125d2f2ea47d45e420e9b95c04c50a737c782768b987af694d90829d395"
BASELINE_STATE_DIGEST = "sha256:cfe2d6236a20ee4858cc655b2684131819d9459e3a92f95e8a755de0abbfe886"
BASELINE_STATE_VALUE_DIGEST = "sha256:e05c1a9995f1c3383e5237678f766ce9729a1e29756afbee287e882d82284d22"
STEP1_SUCCESS_PROGRESS_DIGEST = "sha256:7283a6e467f8267692d1833515954dce016a75b5fb48925aeaa79c074a55a616"
STEP2_AUTHORIZED_PROGRESS_DIGEST = "sha256:66435959842f541ad30e983c0f3c357562979dd037787c40d40a3e4db9c91b33"
BOOTSTRAP_VERSION = "gitblob.d8a728cbd8e6630ffb39f8489c749cce75aad6f3"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class DevelopmentDataV2ExecutionAuthorizationTest(unittest.TestCase):
    def test_step1_success_then_exact_step2_authorization(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial_progress = load(PROGRESS_PATH)
        execution_progress = load(EXECUTION_PROGRESS_PATH)
        preflight = load(PREFLIGHT_PATH)
        success_evidence = load(SUCCESS_EVIDENCE_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial_progress, SCHEMA_ROOT)
        validate_progress(plan, execution_progress, SCHEMA_ROOT)
        for timestamp in (STEP1_AUTHORIZED_AT, STEP1_OUTCOME_AT, STEP2_AUTHORIZED_AT):
            validate_approval(plan, approval, SCHEMA_ROOT, timestamp)

        self.assertEqual(plan["plan_id"], PLAN_ID)
        self.assertEqual(plan["plan_digest"], PLAN_DIGEST)
        self.assertEqual(plan["target"]["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP1_ID)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_READ")
        self.assertEqual(plan["steps"][1]["step_id"], STEP2_ID)
        self.assertEqual(plan["steps"][1]["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(plan["steps"][1]["resource"]["exact_version"], BOOTSTRAP_VERSION)

        self.assertEqual(preflight["evidence_type"], "data.empty-bootstrap.preflight.observed")
        self.assertEqual(preflight["preflight_result"], "PASS")
        self.assertEqual(preflight["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(preflight["observed_at"], STEP1_AUTHORIZED_AT)
        self.assertTrue(preflight["observation_only"])
        self.assertFalse(preflight["source"]["raw_provider_payload_retained"])
        self.assertFalse(preflight["source"]["credentials_retained"])
        self.assertFalse(preflight["source"]["provider_mutation_attempted"])
        self.assertFalse(preflight["source"]["row_data_read"])

        observed = preflight["database_observation"]
        for count_name in (
            "avuhz_schema_count",
            "avuhz_relation_count",
            "avuhz_routine_count",
            "avuhz_type_count",
            "avuhz_trigger_count",
            "avuhz_policy_count",
            "applied_migration_count",
        ):
            self.assertEqual(observed[count_name], 0)
        self.assertFalse(observed["command_service_role_exists"])
        self.assertFalse(observed["migration_role_exists"])
        self.assertFalse(observed["postgres_superuser"])
        self.assertTrue(observed["postgres_createrole"])
        self.assertTrue(observed["postgres_public_usage"])
        self.assertTrue(observed["postgres_public_create"])

        evidence_body = {
            key: value
            for key, value in preflight.items()
            if key not in {"evidence_digest", "configuration_digest"}
        }
        self.assertEqual(canonical_digest(evidence_body), PREFLIGHT_EVIDENCE_DIGEST)
        configuration = {
            "project_reference": preflight["project_reference"],
            "project_status": preflight["project_status"],
            "project_region": preflight["project_region"],
            "postgres_engine": preflight["postgres_engine"],
            "database_version": preflight["database_version"],
            "database_observation": observed,
            "preflight_result": preflight["preflight_result"],
        }
        self.assertEqual(canonical_digest(configuration), PREFLIGHT_CONFIGURATION_DIGEST)

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
        self.assertEqual(step1_authorized["record_version"], 2)
        self.assertEqual(step1_authorized["progress_digest"], STEP1_AUTHORIZED_PROGRESS_DIGEST)

        self.assertEqual(raw_digest(SUCCESS_EVIDENCE_PATH), SUCCESS_EVIDENCE_DIGEST)
        self.assertEqual(success_evidence["evidence_type"], "data.empty-baseline.verified")
        self.assertEqual(success_evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(success_evidence["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(success_evidence["recorded_at"], STEP1_OUTCOME_AT)
        verification = success_evidence["verification_observation"]
        self.assertTrue(verification["provider_read_only"])
        self.assertEqual(verification["provider_mutation_attempts"], 0)
        self.assertFalse(verification["provider_mutation_committed"])
        self.assertTrue(verification["postcondition_verified"])
        security = success_evidence["security_state"]
        for field in (
            "credential_retained",
            "raw_provider_payload_retained",
            "pii_retained",
            "row_data_read",
            "auth_resource_touched",
            "staging_resource_touched",
            "production_resource_touched",
        ):
            self.assertFalse(security[field])

        outcome_evidence = [
            {
                "evidence_type": "data.empty-baseline.verified",
                "evidence_reference": "provider.execution.data-v2.step1.attempt1.verified",
                "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
                "recorded_at": STEP1_OUTCOME_AT,
            }
        ]
        baseline_binding = {
            "binding_id": "binding.development.data.v2.empty-baseline-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.empty-baseline.verified",
            "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
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
            outcome_evidence,
            plan["steps"][0]["expected_postcondition"],
            None,
            SCHEMA_ROOT,
            STEP1_OUTCOME_AT,
            binding_assertions=[baseline_binding],
        )
        self.assertEqual(step1_success["record_version"], 3)
        self.assertEqual(step1_success["progress_digest"], STEP1_SUCCESS_PROGRESS_DIGEST)

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
                    "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
                }
            ],
            "prior_evidence_digests": [SUCCESS_EVIDENCE_DIGEST],
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
        self.assertEqual(execution_progress, step2_authorized)
        self.assertEqual(execution_progress["record_version"], 4)
        self.assertEqual(execution_progress["progress_digest"], STEP2_AUTHORIZED_PROGRESS_DIGEST)

        step1_state = execution_progress["step_states"][0]
        self.assertEqual(step1_state["authorization_state"], "CONSUMED")
        self.assertEqual(step1_state["execution_state"], "SUCCEEDED")
        self.assertEqual(step1_state["verification_state"], "PASS")
        self.assertTrue(step1_state["authorization_consumed"])

        step2_state = execution_progress["step_states"][1]
        self.assertEqual(step2_state["authorization_state"], "AUTHORIZED")
        self.assertEqual(step2_state["execution_state"], "NOT_STARTED")
        self.assertEqual(step2_state["verification_state"], "NOT_STARTED")
        self.assertFalse(step2_state["authorization_consumed"])
        self.assertEqual(step2_state["evidence"], [])
        self.assertEqual(
            step2_state["binding_assertions"],
            [
                {
                    "binding_id": "binding.development.data.v2.empty-baseline-state",
                    "phase": "DERIVED_FROM_SOURCE_STEP",
                    "value_class": "CONTENT_DIGEST",
                    "source_step_id": STEP1_ID,
                    "evidence_type": "data.empty-baseline.verified",
                    "evidence_digest": SUCCESS_EVIDENCE_DIGEST,
                    "digest_policy": "REQUIRED",
                    "persistence_policy": "DIGEST_ONLY",
                    "sanitized_value": None,
                    "value_digest": BASELINE_STATE_VALUE_DIGEST,
                    "recorded_at": STEP2_AUTHORIZED_AT,
                }
            ],
        )
        for pending in execution_progress["step_states"][2:]:
            self.assertEqual(pending["authorization_state"], "PENDING")
            self.assertEqual(pending["execution_state"], "NOT_STARTED")
            self.assertEqual(pending["verification_state"], "NOT_STARTED")
            self.assertFalse(pending["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
