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
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.execution-progress.json"
MIGRATION_PATH = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
ROLE_BINDING_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_role_binding_v1.sql"

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
PLAN_DIGEST = "sha256:ed141409e31c0aa70944ca801047f05db574ef3e905dd85dcd2e81c0a393d695"
PROJECT = "gnuqaefotwgkwurjpyik"
STEP4_ID = "development.data.v2.step.04.apply-initial-migration"

T3O = "2026-09-14T00:00:44Z"
T4A = "2026-09-14T00:19:21Z"

SUCCESS1 = "sha256:ef26f125d2f2ea47d45e420e9b95c04c50a737c782768b987af694d90829d395"
SUCCESS2 = "sha256:9c1e742d1d77d8ac63a2ea201fc39789a54f384f9caa684e24d45112ef27053c"
SUCCESS3 = "sha256:4c01cf41fd7dd5cac07576cba6bddea2644f30250788ae58299e6def626e486c"
IDENTITY_VALUE = "sha256:63a91b034cf50e65877b8dae4f7fe2aa86f1355e211c2f006be9268032fcf612"
STEP3_PROGRESS = "sha256:70d9f86df61e58268bd60c1297cd83b04a18adc4c5044ed3723361697442afbb"
STEP4_AUTH_PROGRESS = "sha256:d9c25d8d7ec112831395481672b32782e9a1537a0e983d44fc4785f078095755"
MIGRATION_BLOB = "ff2fa6ce4e2b788a9eada5379f85593e96d82424"
ROLE_BINDING_BLOB = "978fafb64a21b8acb3572c237e08d739afd473f0"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def git_blob_sha(path: Path) -> str:
    body = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


class DevelopmentDataV2Step4AuthorizationTest(unittest.TestCase):
    def test_exact_step4_authorization_transition(self) -> None:
        plan = load(PLAN_PATH)
        approval = load(APPROVAL_PATH)
        canonical = load(PROGRESS_PATH)

        validate_plan(plan, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, T4A)
        validate_progress(plan, canonical, SCHEMA_ROOT)

        step4 = plan["steps"][3]
        self.assertEqual(step4["step_id"], STEP4_ID)
        self.assertEqual(step4["execution_class"], "PROVIDER_MUTATION")
        self.assertEqual(
            step4["operation"],
            "provider.resource.apply-bound-role-scoped-initial-migration",
        )
        self.assertEqual(
            step4["resource"]["exact_version"],
            f"gitblob.{MIGRATION_BLOB}",
        )
        self.assertEqual(git_blob_sha(MIGRATION_PATH), MIGRATION_BLOB)
        self.assertEqual(git_blob_sha(ROLE_BINDING_PATH), ROLE_BINDING_BLOB)
        self.assertEqual(
            ROLE_BINDING_PATH.read_text(encoding="utf-8").splitlines()[-1],
            "set local role avuhz_data_migration_service_dev;",
        )

        prior = copy.deepcopy(canonical)
        prior_state = prior["step_states"][3]
        prior_state["authorization_state"] = "PENDING"
        prior_state["execution_state"] = "NOT_STARTED"
        prior_state["verification_state"] = "NOT_STARTED"
        prior_state["authorization_consumed"] = False
        prior_state["evidence"] = []
        prior_state["observed_postcondition"] = None
        prior_state["safe_error_code"] = None
        prior_state["binding_assertions"] = []
        prior["record_version"] = 7
        prior["updated_at"] = T3O
        prior["progress_digest"] = progress_digest(prior)
        self.assertEqual(prior["progress_digest"], STEP3_PROGRESS)
        validate_progress(plan, prior, SCHEMA_ROOT)

        request = {
            "plan_id": PLAN_ID,
            "plan_version": 2,
            "plan_digest": PLAN_DIGEST,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
            "step_id": STEP4_ID,
            "resource_reference": step4["resource"]["resource_reference"],
            "resource_version": step4["resource"]["exact_version"],
            "resource_digest": step4["resource"]["exact_digest"],
            "operation": step4["operation"],
            "execution_class": step4["execution_class"],
            "credential_class": "OWNER_INTERACTIVE_SESSION",
            "required_evidence": [
                {
                    "evidence_type": "data.migration-identity.verified",
                    "evidence_digest": SUCCESS3,
                }
            ],
            "prior_evidence_digests": [SUCCESS1, SUCCESS2, SUCCESS3],
            "unexpected_remote_state": False,
            "extra_privileges": False,
            "unauthorized_migration_surface": False,
            "scope_expansion": False,
        }
        authorized = authorize_step(
            plan,
            approval,
            prior,
            request,
            SCHEMA_ROOT,
            T4A,
        )

        self.assertEqual(authorized, canonical)
        self.assertEqual(canonical["record_version"], 8)
        self.assertEqual(canonical["progress_digest"], STEP4_AUTH_PROGRESS)

        state = canonical["step_states"][3]
        self.assertEqual(state["authorization_state"], "AUTHORIZED")
        self.assertEqual(state["execution_state"], "NOT_STARTED")
        self.assertEqual(state["verification_state"], "NOT_STARTED")
        self.assertFalse(state["authorization_consumed"])
        self.assertEqual(state["evidence"], [])
        self.assertEqual(len(state["binding_assertions"]), 1)

        assertion = state["binding_assertions"][0]
        self.assertEqual(
            assertion["binding_id"],
            "binding.development.data.v2.migration-identity-verified",
        )
        self.assertEqual(assertion["phase"], "DERIVED_FROM_SOURCE_STEP")
        self.assertEqual(assertion["evidence_digest"], SUCCESS3)
        self.assertEqual(assertion["value_digest"], IDENTITY_VALUE)
        self.assertEqual(assertion["recorded_at"], T4A)

        for pending in canonical["step_states"][4:]:
            self.assertEqual(pending["authorization_state"], "PENDING")
            self.assertEqual(pending["execution_state"], "NOT_STARTED")
            self.assertEqual(pending["verification_state"], "NOT_STARTED")
            self.assertFalse(pending["authorization_consumed"])
            self.assertEqual(pending["evidence"], [])
            self.assertEqual(pending["binding_assertions"], [])


if __name__ == "__main__":
    unittest.main()
