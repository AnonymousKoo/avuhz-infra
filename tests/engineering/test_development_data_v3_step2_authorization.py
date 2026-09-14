from __future__ import annotations

import copy
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.approval.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.execution-progress.json"

PLAN_ID = "f6ae6374-878e-4a84-9b33-3f5718ed01b9"
PLAN_DIGEST = "sha256:d958bb5cb4d12524ebfb3d748e025af64b8c32da6e77e17ca8559239f18e0eb8"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP1_ID = "development.data.v3.step.01.seal-migration-identity"
STEP2_ID = "development.data.v3.step.02.verify-tenant-isolation"
STEP1_EVIDENCE = "sha256:ccce61683282152c55225147555d7e6a54ed33218bf02c1a01dc25f06ad5f188"
SEALED_STATE = "sha256:1a1e1ad3aeb6f4a9c92e17b0a4b82b1c150862f3d6360aeeafee87676d94fbfb"
PRE_STEP2_PROGRESS = "sha256:16dbf6794a6735f243467970baaa1babdc1274ea6cea2d66c246ad2c96d8de5a"
AUTHORIZED_PROGRESS = "sha256:179fc8f4f0cfe87b1df83dca643ef4c54bfbe335e0fbf7bc62d689033710a088"
PRE_STEP2_AT = "2026-09-14T02:11:34Z"
AUTHORIZED_AT = "2026-09-14T03:13:10Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


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


class DevelopmentDataV3Step2AuthorizationTest(unittest.TestCase):
    def test_exact_step2_read_only_authorization_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, AUTHORIZED_AT)

        self.assertEqual(plan["target"]["project_reference"], PROJECT)
        self.assertEqual(plan["target"]["responsibility"], "DATA")
        self.assertEqual(plan["steps"][0]["step_id"], STEP1_ID)
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

        pre = copy.deepcopy(canonical)
        pre["record_version"] = 3
        pre["updated_at"] = PRE_STEP2_AT
        pre["progress_digest"] = PRE_STEP2_PROGRESS
        pre_step2 = pre["step_states"][1]
        pre_step2["authorization_state"] = "PENDING"
        pre_step2["binding_assertions"] = []
        validate_progress(plan, pre, SCHEMA_ROOT)

        step1 = pre["step_states"][0]
        self.assertEqual(step1["authorization_state"], "CONSUMED")
        self.assertEqual(step1["execution_state"], "SUCCEEDED")
        self.assertEqual(step1["verification_state"], "PASS")
        self.assertTrue(step1["authorization_consumed"])
        self.assertEqual(step1["evidence"][0]["evidence_digest"], STEP1_EVIDENCE)
        self.assertEqual(step1["binding_assertions"][0]["value_digest"], SEALED_STATE)

        exact_request = request(plan)
        self.assertFalse(exact_request["unexpected_remote_state"])
        self.assertFalse(exact_request["extra_privileges"])
        self.assertFalse(exact_request["unauthorized_migration_surface"])
        self.assertFalse(exact_request["scope_expansion"])

        authorized = authorize_step(
            plan,
            approval,
            pre,
            exact_request,
            SCHEMA_ROOT,
            AUTHORIZED_AT,
            trusted_preflight_assertions=[],
        )
        self.assertEqual(authorized, canonical)
        self.assertEqual(canonical["record_version"], 4)
        self.assertEqual(canonical["overall_state"], "IN_PROGRESS")
        self.assertEqual(canonical["updated_at"], AUTHORIZED_AT)
        self.assertEqual(canonical["progress_digest"], AUTHORIZED_PROGRESS)

        state = canonical["step_states"][1]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertIsNone(state["observed_postcondition"])
        self.assertIsNone(state["safe_error_code"])
        self.assertEqual(
            state["binding_assertions"],
            [
                {
                    "binding_id": "binding.development.data.v3.migration-identity-sealed",
                    "phase": "DERIVED_FROM_SOURCE_STEP",
                    "value_class": "CONTENT_DIGEST",
                    "source_step_id": STEP1_ID,
                    "evidence_type": "data.migration-identity.sealed",
                    "evidence_digest": STEP1_EVIDENCE,
                    "digest_policy": "REQUIRED",
                    "persistence_policy": "DIGEST_ONLY",
                    "sanitized_value": None,
                    "value_digest": SEALED_STATE,
                    "recorded_at": AUTHORIZED_AT,
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
