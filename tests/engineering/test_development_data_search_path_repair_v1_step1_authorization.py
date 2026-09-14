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
    validate_approval,
    validate_plan,
    validate_progress,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.approval.json"
INITIAL_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-search-path-repair-v1.execution-progress.json"
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


class DevelopmentDataSearchPathRepairV1Step1AuthorizationTest(unittest.TestCase):
    def test_exact_step1_authorization_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial = load(INITIAL_PROGRESS_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP_ID)
        self.assertEqual(plan["steps"][0]["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(
            plan["steps"][0]["operation"],
            "provider.resource.repair-function-search-path",
        )
        self.assertEqual(git_blob_sha(REPAIR_PATH), REPAIR_BLOB)
        self.assertEqual(raw_digest(V3_STEP1_SUCCESS_PATH), V3_STEP1_EVIDENCE)
        self.assertIn("persistent-role-membership", plan["steps"][0]["prohibited_actions"])
        self.assertIn("v3.step2.execute", plan["steps"][0]["prohibited_actions"])
        self.assertIn("security-advisor.finding-persists", plan["steps"][0]["stop_conditions"])
        self.assertIn("temporary-set-edge.not-restored", plan["steps"][0]["stop_conditions"])

        exact_request = request(plan)
        self.assertFalse(exact_request["unexpected_remote_state"])
        self.assertFalse(exact_request["extra_privileges"])
        self.assertFalse(exact_request["unauthorized_migration_surface"])
        self.assertFalse(exact_request["scope_expansion"])

        authorized = authorize_step(
            plan,
            approval,
            initial,
            exact_request,
            SCHEMA_ROOT,
            AUTHORIZED_AT,
            trusted_preflight_assertions=[],
        )
        self.assertEqual(authorized, canonical)
        self.assertEqual(canonical["record_version"], 2)
        self.assertEqual(canonical["overall_state"], "IN_PROGRESS")
        self.assertEqual(canonical["updated_at"], AUTHORIZED_AT)
        self.assertEqual(canonical["progress_digest"], AUTHORIZED_PROGRESS)

        state = canonical["step_states"][0]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertEqual(state["binding_assertions"], [])
        self.assertIsNone(state["observed_postcondition"])
        self.assertIsNone(state["safe_error_code"])

        initial_state = initial["step_states"][0]
        self.assertEqual(initial_state["authorization_state"], "PENDING")
        self.assertEqual(initial_state["execution_state"], "NOT_STARTED")
        self.assertFalse(initial_state["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
