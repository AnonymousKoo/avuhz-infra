from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    authorize_step,
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

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
PLAN_DIGEST = "sha256:ed141409e31c0aa70944ca801047f05db574ef3e905dd85dcd2e81c0a393d695"
STEP_ID = "development.data.v2.step.01.verify-empty-bootstrap-boundary"
PROJECT_REFERENCE = "gnuqaefotwgkwurjpyik"
AUTHORIZED_AT = "2026-09-13T22:42:28Z"
PACKAGE_IDENTITY_DIGEST = "sha256:ab86caddb7da33e174d14684d00af97941482b35a6cc5fa5cf172865de93bef8"
PREFLIGHT_EVIDENCE_DIGEST = "sha256:83374a5770b00b6a548b72ed627cf493456562a3297678a9ab3455ef2ef94beb"
PREFLIGHT_CONFIGURATION_DIGEST = "sha256:feac73ff90a562d40dbaaacdddca6ac19a21b49ec0be1a760a93fac03d93283a"
AUTHORIZED_PROGRESS_DIGEST = "sha256:522948b97e7a6720561a186b5f350fba584fab0e32587d0176eb75f3b54cb8a7"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class DevelopmentDataV2Step1AuthorizationTest(unittest.TestCase):
    def test_exact_authorization_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        progress = load(PROGRESS_PATH)
        execution_progress = load(EXECUTION_PROGRESS_PATH)
        preflight = load(PREFLIGHT_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_progress(plan, execution_progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)

        self.assertEqual(plan["plan_id"], PLAN_ID)
        self.assertEqual(plan["plan_digest"], PLAN_DIGEST)
        self.assertEqual(plan["target"]["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP_ID)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_READ")

        self.assertEqual(preflight["evidence_type"], "data.empty-bootstrap.preflight.observed")
        self.assertEqual(preflight["preflight_result"], "PASS")
        self.assertEqual(preflight["project_reference"], PROJECT_REFERENCE)
        self.assertEqual(preflight["observed_at"], AUTHORIZED_AT)
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
        self.assertEqual(preflight["evidence_digest"], PREFLIGHT_EVIDENCE_DIGEST)

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
        self.assertEqual(preflight["configuration_digest"], PREFLIGHT_CONFIGURATION_DIGEST)

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
            "recorded_at": AUTHORIZED_AT,
        }
        authorization_request = {
            "plan_id": PLAN_ID,
            "plan_version": 2,
            "plan_digest": PLAN_DIGEST,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT_REFERENCE,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
            "step_id": STEP_ID,
            "resource_reference": "supabase:gnuqaefotwgkwurjpyik:public:avuhz-empty-bootstrap-boundary",
            "resource_version": "empty-bootstrap-boundary.v2",
            "resource_digest": None,
            "operation": "provider.resource.verify-empty-avuhz-bootstrap-boundary",
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
        expected = authorize_step(
            plan,
            approval,
            progress,
            authorization_request,
            SCHEMA_ROOT,
            AUTHORIZED_AT,
            trusted_preflight_assertions=[preflight_assertion],
        )
        self.assertEqual(execution_progress, expected)
        self.assertEqual(execution_progress["record_version"], 2)
        self.assertEqual(execution_progress["overall_state"], "IN_PROGRESS")
        self.assertEqual(execution_progress["progress_digest"], AUTHORIZED_PROGRESS_DIGEST)

        state = execution_progress["step_states"][0]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertEqual(state["binding_assertions"], [preflight_assertion])
        for pending in execution_progress["step_states"][1:]:
            self.assertEqual(pending["authorization_state"], "PENDING")
            self.assertEqual(pending["execution_state"], "NOT_STARTED")
            self.assertFalse(pending["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
