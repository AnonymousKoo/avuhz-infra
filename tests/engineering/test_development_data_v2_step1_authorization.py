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
INITIAL_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.execution-progress.json"
STEP1_PREFLIGHT_PATH = ROOT / "contracts/plans/v1/development-data-step1-v2-preflight.evidence.json"
STEP1_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step1-v2-success.evidence.json"
STEP2_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step2-v2-success.evidence.json"
STEP3_PREFLIGHT_PATH = ROOT / "contracts/plans/v1/development-data-step3-v2-preflight.evidence.json"

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
PLAN_DIGEST = "sha256:ed141409e31c0aa70944ca801047f05db574ef3e905dd85dcd2e81c0a393d695"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP1_ID = "development.data.v2.step.01.verify-empty-bootstrap-boundary"
STEP2_ID = "development.data.v2.step.02.bootstrap-migration-identity"
STEP3_ID = "development.data.v2.step.03.verify-migration-identity"

T1A = "2026-09-13T22:42:28Z"
T1O = "2026-09-13T22:54:53Z"
T2A = "2026-09-13T23:09:56Z"
T2O = "2026-09-13T23:24:38Z"
T3A = "2026-09-13T23:47:26Z"

PACKAGE = "sha256:ab86caddb7da33e174d14684d00af97941482b35a6cc5fa5cf172865de93bef8"
PREFLIGHT1 = "sha256:83374a5770b00b6a548b72ed627cf493456562a3297678a9ab3455ef2ef94beb"
PREFLIGHT1_CFG = "sha256:feac73ff90a562d40dbaaacdddca6ac19a21b49ec0be1a760a93fac03d93283a"
SUCCESS1 = "sha256:ef26f125d2f2ea47d45e420e9b95c04c50a737c782768b987af694d90829d395"
BASELINE_VALUE = "sha256:e05c1a9995f1c3383e5237678f766ce9729a1e29756afbee287e882d82284d22"
SUCCESS2 = "sha256:9c1e742d1d77d8ac63a2ea201fc39789a54f384f9caa684e24d45112ef27053c"
IDENTITY_STATE = "sha256:732bf7b9f980dada32ef566dd3b7c9873673086b751e333db4fcdbc4e3ea1898"
IDENTITY_VALUE = "sha256:63a91b034cf50e65877b8dae4f7fe2aa86f1355e211c2f006be9268032fcf612"
STEP2_PROGRESS = "sha256:a3410f72e6ade8bcd7a116412e21b2e6ea6e8f912dead2affd4e9e234e7d7148"
PREFLIGHT3 = "sha256:c780ec5939cde52cbc7b7da7b7836f11b0f56cb8f77959d44d8cb275eef48266"
PREFLIGHT3_CFG = "sha256:e38a67a1463b7a67ec341d6de6a55bb42ab44bb93e4c18cfaff39490a7702a7f"
STEP3_PROGRESS = "sha256:54cf5afc8d4a64dafa253ff1269b0fa542def95e367530d4660309526314a815"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def request(plan: dict, index: int, required: list[dict], prior: list[str]) -> dict:
    step = plan["steps"][index]
    return {
        "plan_id": PLAN_ID,
        "plan_version": 2,
        "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": required,
        "prior_evidence_digests": prior,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


class DevelopmentDataV2ExecutionAuthorizationTest(unittest.TestCase):
    def test_exact_chain_through_step3_authorization(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial = load(INITIAL_PROGRESS_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)
        p1 = load(STEP1_PREFLIGHT_PATH)
        e2 = load(STEP2_SUCCESS_PATH)
        p3 = load(STEP3_PREFLIGHT_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        for timestamp in (T1A, T1O, T2A, T2O, T3A):
            validate_approval(plan, approval, SCHEMA_ROOT, timestamp)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["steps"][2]["step_id"], STEP3_ID)
        self.assertEqual(plan["steps"][2]["execution_class"], "PROVIDER_READ")

        a1 = {
            "binding_id": "binding.development.data.v2.empty-bootstrap-preflight",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "data.empty-bootstrap.preflight.observed",
            "evidence_digest": PREFLIGHT1,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": PREFLIGHT1_CFG,
            "recorded_at": T1A,
        }
        s1a = authorize_step(
            plan, approval, initial,
            request(plan, 0, [{"evidence_type": "repository.data-v2.artifact-package.verified",
                               "evidence_digest": PACKAGE}], []),
            SCHEMA_ROOT, T1A, trusted_preflight_assertions=[a1],
        )
        self.assertEqual(p1["evidence_digest"], PREFLIGHT1)

        self.assertEqual(raw_digest(STEP1_SUCCESS_PATH), SUCCESS1)
        b1 = {
            "binding_id": "binding.development.data.v2.empty-baseline-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.empty-baseline.verified",
            "evidence_digest": SUCCESS1,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": BASELINE_VALUE,
            "recorded_at": T1O,
        }
        s1 = record_step_outcome(
            plan, approval, s1a, STEP1_ID, "SUCCEEDED", "PASS",
            [{"evidence_type": "data.empty-baseline.verified",
              "evidence_reference": "provider.execution.data-v2.step1.attempt1.verified",
              "evidence_digest": SUCCESS1, "recorded_at": T1O}],
            plan["steps"][0]["expected_postcondition"], None, SCHEMA_ROOT, T1O,
            binding_assertions=[b1],
        )

        s2a = authorize_step(
            plan, approval, s1,
            request(plan, 1, [{"evidence_type": "data.empty-baseline.verified",
                               "evidence_digest": SUCCESS1}], [SUCCESS1]),
            SCHEMA_ROOT, T2A,
        )
        self.assertEqual(raw_digest(STEP2_SUCCESS_PATH), SUCCESS2)
        self.assertEqual(e2["verification_observation"]["migration_identity_state_digest"], IDENTITY_STATE)

        b2 = {
            "binding_id": "binding.development.data.v2.migration-identity-state",
            "phase": "PRODUCED_BY_CURRENT_STEP",
            "value_class": "CONTENT_DIGEST",
            "source_step_id": None,
            "evidence_type": "data.migration-identity.bootstrapped",
            "evidence_digest": SUCCESS2,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": IDENTITY_VALUE,
            "recorded_at": T2O,
        }
        s2 = record_step_outcome(
            plan, approval, s2a, STEP2_ID, "SUCCEEDED", "PASS",
            [{"evidence_type": "data.migration-identity.bootstrapped",
              "evidence_reference": "provider.execution.data-v2.step2.attempt1.verified",
              "evidence_digest": SUCCESS2, "recorded_at": T2O}],
            plan["steps"][1]["expected_postcondition"], None, SCHEMA_ROOT, T2O,
            binding_assertions=[b2],
        )
        self.assertEqual(s2["record_version"], 5)
        self.assertEqual(s2["progress_digest"], STEP2_PROGRESS)

        self.assertEqual(p3["evidence_type"], "data.migration-identity.preflight.observed")
        self.assertEqual(p3["observed_at"], T3A)
        self.assertEqual(p3["preflight_result"], "PASS")
        self.assertEqual(p3["migration_identity_state_digest"], IDENTITY_STATE)
        p3_body = {k: v for k, v in p3.items() if k not in {"evidence_digest", "configuration_digest"}}
        self.assertEqual(canonical_digest(p3_body), PREFLIGHT3)

        obs = p3["database_observation"]
        cfg = {
            "project_reference": p3["project_reference"],
            "project_status": p3["project_status"],
            "project_region": p3["project_region"],
            "postgres_engine": p3["postgres_engine"],
            "database_version": p3["database_version"],
            "database_observation": obs,
            "migration_identity_state_digest": p3["migration_identity_state_digest"],
            "preflight_result": p3["preflight_result"],
        }
        self.assertEqual(canonical_digest(cfg), PREFLIGHT3_CFG)
        self.assertFalse(obs["can_login"])
        self.assertFalse(obs["is_superuser"])
        self.assertTrue(obs["can_createrole"])
        self.assertFalse(obs["can_bypassrls"])
        self.assertEqual(obs["public_usage_grantable_count"], 1)
        self.assertEqual(obs["public_create_nongrantable_count"], 1)
        self.assertEqual(obs["explicit_postgres_set_edge_count"], 1)
        self.assertEqual(obs["provider_admin_noset_edge_count"], 1)
        self.assertEqual(obs["total_membership_edges"], 2)
        for field in (
            "direct_database_acl_count", "provider_schema_privilege_count",
            "table_privilege_count", "sequence_privilege_count",
            "direct_function_execute_count", "avuhz_schema_count",
            "avuhz_relation_count", "avuhz_routine_count", "avuhz_type_count",
            "avuhz_trigger_count", "avuhz_policy_count", "applied_migration_count",
        ):
            self.assertEqual(obs[field], 0)
        self.assertFalse(obs["command_service_role_exists"])
        self.assertFalse(p3["source"]["provider_mutation_attempted"])
        self.assertFalse(p3["source"]["row_data_read"])

        a3 = {
            "binding_id": "binding.development.data.v2.migration-identity-preflight",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "data.migration-identity.preflight.observed",
            "evidence_digest": PREFLIGHT3,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": PREFLIGHT3_CFG,
            "recorded_at": T3A,
        }
        s3a = authorize_step(
            plan, approval, s2,
            request(plan, 2, [{"evidence_type": "data.migration-identity.bootstrapped",
                               "evidence_digest": SUCCESS2}], [SUCCESS1, SUCCESS2]),
            SCHEMA_ROOT, T3A, trusted_preflight_assertions=[a3],
        )

        self.assertEqual(canonical, s3a)
        self.assertEqual(canonical["record_version"], 6)
        self.assertEqual(canonical["progress_digest"], STEP3_PROGRESS)
        state = canonical["step_states"][2]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(
            [item["binding_id"] for item in state["binding_assertions"]],
            ["binding.development.data.v2.migration-identity-state",
             "binding.development.data.v2.migration-identity-preflight"],
        )
        for pending in canonical["step_states"][3:]:
            self.assertEqual(pending["authorization_state"], "PENDING")
            self.assertEqual(pending["execution_state"], "NOT_STARTED")
            self.assertFalse(pending["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
