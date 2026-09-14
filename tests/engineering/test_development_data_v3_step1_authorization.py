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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.approval.json"
INITIAL_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.progress.json"
EXECUTION_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.execution-progress.json"
SEAL_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_identity_seal_v1.sql"

PLAN_ID = "f6ae6374-878e-4a84-9b33-3f5718ed01b9"
PLAN_DIGEST = "sha256:d958bb5cb4d12524ebfb3d748e025af64b8c32da6e77e17ca8559239f18e0eb8"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP1_ID = "development.data.v3.step.01.seal-migration-identity"
STEP2_ID = "development.data.v3.step.02.verify-tenant-isolation"
STEP4_EVIDENCE = "sha256:23f5efaad368cde39ce6d8d4c58e1d3c9912d508ae4c83c994ff12c37463c0a8"
SEAL_BLOB = "65952c5900a6b73f8f413fe21f3c124c2f3e182e"
AUTHORIZED_PROGRESS = "sha256:d0693b0bd0a3973d962e5c387c8cd9830d2405b18b60f34b5430ee952a197a88"
T1A = "2026-09-14T01:43:30Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


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


class DevelopmentDataV3Step1AuthorizationTest(unittest.TestCase):
    def test_exact_step1_authorization_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        initial = load(INITIAL_PROGRESS_PATH)
        canonical = load(EXECUTION_PROGRESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, initial, SCHEMA_ROOT)
        validate_progress(plan, canonical, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, T1A)

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

        self.assertEqual(authorized, canonical)
        self.assertEqual(canonical["record_version"], 2)
        self.assertEqual(canonical["overall_state"], "IN_PROGRESS")
        self.assertEqual(canonical["progress_digest"], AUTHORIZED_PROGRESS)

        step1 = canonical["step_states"][0]
        self.assertEqual(step1["authorization_state"], "AUTHORIZED")
        self.assertEqual(step1["execution_state"], "NOT_STARTED")
        self.assertEqual(step1["verification_state"], "NOT_STARTED")
        self.assertFalse(step1["authorization_consumed"])
        self.assertEqual(step1["evidence"], [])
        self.assertEqual(step1["binding_assertions"], [])

        step2 = canonical["step_states"][1]
        self.assertEqual(step2["authorization_state"], "PENDING")
        self.assertEqual(step2["execution_state"], "NOT_STARTED")
        self.assertEqual(step2["verification_state"], "NOT_STARTED")
        self.assertFalse(step2["authorization_consumed"])


if __name__ == "__main__":
    unittest.main()
