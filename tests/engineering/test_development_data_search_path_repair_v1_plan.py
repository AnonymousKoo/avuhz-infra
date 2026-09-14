from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    initial_progress,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.progress.json"
V3_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.execution-progress.json"
V3_STEP1_SUCCESS_PATH = ROOT / "contracts/plans/v1/development-data-step1-v3-success.evidence.json"
REPAIR_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_outbox_search_path_repair_v1.sql"

PLAN_ID = "02640972-5a93-4286-9ce9-e0ffed45279e"
PROGRESS_ID = "64d11eaf-f8d5-4c52-b0e3-7c0a3bcd594f"
PLAN_DIGEST = "sha256:23f2ceb93120ab848ba614cf435f1a612913bc3d386eca0af67eb81563f51f47"
APPROVAL_DIGEST = "sha256:ec2f4ab63066c5cdaffffa2dab49ed4ca2ef2cf778b2672c01157027260ab703"
APPROVAL_FILE_DIGEST = "sha256:bad4b3bccb211b386d4d7f064672ab08649635de6c2a4fa2e13284594f112643"
INITIAL_PROGRESS_DIGEST = "sha256:e782d26d5d7cdc40035f336904a49d0a505f045696ccce1c4dc189e00cd11639"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP_ID = "development.data.search-path-repair.v1.step.01.repair-outbox-function-search-path"
REPAIR_BLOB = "8afb7df0276e28a681c81dac8c201a5fa5a0f22f"
REPAIR_REFERENCE = f"gitblob.{REPAIR_BLOB}"
REPAIR_REFERENCE_DIGEST = "sha256:26550364f532b1eeb8017bd0d5b937bb1db2c86a74b44d2d4cdfdc47c27d5e95"
V3_STEP1_EVIDENCE = "sha256:ccce61683282152c55225147555d7e6a54ed33218bf02c1a01dc25f06ad5f188"
SEALED_STATE = "sha256:1a1e1ad3aeb6f4a9c92e17b0a4b82b1c150862f3d6360aeeafee87676d94fbfb"
SEALED_STATE_REFERENCE_DIGEST = "sha256:fd93676cac2752a7b116547e69bac109b5a75b19717af73b62033803b3861cc4"
CREATED_AT = "2026-09-14T02:35:38Z"
WINDOW_START = "2026-09-14T02:40:00Z"
WINDOW_END = "2026-09-14T06:40:00Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha(path: Path) -> str:
    body = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


class DevelopmentDataSearchPathRepairV1PlanTest(unittest.TestCase):
    def test_exact_repair_plan_is_bound_but_not_authorized_for_execution(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        progress = load(PROGRESS_PATH)
        v3_execution = load(V3_EXECUTION_PATH)
        v3_evidence = load(V3_STEP1_SUCCESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

        self.assertEqual(plan["plan_id"], PLAN_ID)
        self.assertEqual(plan["plan_version"], 1)
        self.assertEqual(plan["plan_digest"], PLAN_DIGEST)
        self.assertEqual(plan["environment"], "DEVELOPMENT")
        self.assertEqual(plan["target"]["provider_reference"], "supabase")
        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["authorization_window"]["starts_at"], WINDOW_START)
        self.assertEqual(plan["authorization_window"]["expires_at"], WINDOW_END)
        self.assertEqual(plan["authority_effect"], "NONE_UNTIL_SEPARATELY_APPROVED")
        self.assertEqual(plan["ordered_step_ids"], [STEP_ID])

        step = plan["steps"][0]
        self.assertEqual(step["step_id"], STEP_ID)
        self.assertEqual(step["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(
            step["operation"],
            "provider.resource.repair-function-search-path",
        )
        self.assertEqual(step["dependency_step_ids"], [])
        self.assertEqual(step["resource"]["exact_version"], REPAIR_REFERENCE)
        self.assertIsNone(step["resource"]["exact_digest"])
        self.assertEqual(git_blob_sha(REPAIR_PATH), REPAIR_BLOB)
        self.assertEqual(
            step["required_evidence"],
            [
                {
                    "evidence_type": "data.migration-identity.sealed",
                    "source_step_id": None,
                    "binding_state": "BOUND",
                    "exact_digest": V3_STEP1_EVIDENCE,
                }
            ],
        )

        self.assertIn("persistent-role-membership", step["prohibited_actions"])
        self.assertIn("v3.step2.execute", step["prohibited_actions"])
        self.assertIn("security-advisor.finding-persists", step["stop_conditions"])
        self.assertIn("temporary-set-edge.not-restored", step["stop_conditions"])
        self.assertIn("v3.step2.execute", plan["prohibited_actions"])

        artifact_binding = next(
            item
            for item in step["binding_declarations"]
            if item["binding_id"]
            == "binding.development.data.search-path-repair.v1.artifact-git-blob"
        )
        self.assertEqual(
            artifact_binding["preapproval_value"],
            {
                "value": REPAIR_REFERENCE,
                "exact_digest": REPAIR_REFERENCE_DIGEST,
            },
        )
        self.assertEqual(canonical_digest(REPAIR_REFERENCE), REPAIR_REFERENCE_DIGEST)

        sealed_binding = next(
            item
            for item in step["binding_declarations"]
            if item["binding_id"]
            == "binding.development.data.search-path-repair.v1.sealed-identity-state"
        )
        self.assertEqual(
            sealed_binding["preapproval_value"],
            {
                "value": SEALED_STATE,
                "exact_digest": SEALED_STATE_REFERENCE_DIGEST,
            },
        )
        self.assertEqual(canonical_digest(SEALED_STATE), SEALED_STATE_REFERENCE_DIGEST)

        self.assertEqual(raw_digest(V3_STEP1_SUCCESS_PATH), V3_STEP1_EVIDENCE)
        self.assertEqual(v3_evidence["outcome"], "SUCCEEDED_VERIFIED")
        self.assertEqual(v3_evidence["project_reference"], PROJECT)
        self.assertEqual(
            v3_evidence["verification_observation"]["sealed_migration_identity_state_digest"],
            SEALED_STATE,
        )
        self.assertEqual(
            v3_evidence["verification_observation"]["security_advisor_finding_codes"],
            ["function_search_path_mutable"],
        )
        self.assertFalse(
            v3_evidence["verification_observation"]["security_advisor_repair_performed"]
        )

        self.assertEqual(v3_execution["step_states"][0]["authorization_state"], "CONSUMED")
        self.assertEqual(v3_execution["step_states"][0]["verification_state"], "PASS")
        self.assertEqual(v3_execution["step_states"][1]["authorization_state"], "PENDING")
        self.assertEqual(v3_execution["step_states"][1]["execution_state"], "NOT_STARTED")
        self.assertEqual(v3_execution["step_states"][1]["verification_state"], "NOT_STARTED")

        sql = REPAIR_PATH.read_text(encoding="utf-8").lower()
        self.assertEqual(
            sql.count("alter function public.avuhz_guard_outbox_transition() set search_path to '';"),
            1,
        )
        self.assertEqual(sql.count("grant avuhz_data_migration_service_dev to postgres"), 1)
        self.assertEqual(sql.count("set local role avuhz_data_migration_service_dev;"), 1)
        self.assertEqual(sql.count("reset role;"), 1)
        self.assertEqual(
            sql.count("revoke avuhz_data_migration_service_dev from postgres granted by postgres;"),
            1,
        )

        self.assertEqual(approval["approval_digest"], APPROVAL_DIGEST)
        self.assertEqual(raw_digest(APPROVAL_PATH), APPROVAL_FILE_DIGEST)
        self.assertEqual(approval["authority_scope"], "EXACT_PLAN_ONLY")
        self.assertEqual(approval["effective_at"], WINDOW_START)
        self.assertEqual(approval["expires_at"], WINDOW_END)

        expected_progress = initial_progress(
            plan,
            SCHEMA_ROOT,
            PROGRESS_ID,
            CREATED_AT,
        )
        self.assertEqual(progress, expected_progress)
        self.assertEqual(progress["progress_digest"], INITIAL_PROGRESS_DIGEST)
        self.assertEqual(progress["record_version"], 1)
        self.assertEqual(progress["overall_state"], "NOT_STARTED")

        state = progress["step_states"][0]
        self.assertEqual(state["authorization_state"], "PENDING")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertEqual(state["binding_assertions"], [])


if __name__ == "__main__":
    unittest.main()
