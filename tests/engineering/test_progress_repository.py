"""Persistence tests for bounded authorization-plan execution progress."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    record_step_outcome,
)
from avuhz_engineering.progress_repository import FileAuthorizationProgressStore


SCHEMAS = ROOT / "contracts/schemas/v1"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
PROGRESS_ID = "a7100000-0000-4000-8000-000000000203"


def local_plan() -> dict:
    step = {
        "step_id": "plan.step.01",
        "ordinal": 1,
        "resource": {
            "resource_type": "migration.artifact",
            "resource_reference": "resource.local.artifact",
            "binding_state": "BOUND",
            "exact_version": "version.1",
            "exact_digest": DIGEST_B,
        },
        "operation": "local.artifact.validate",
        "dependency_step_ids": [],
        "required_evidence": [
            {
                "evidence_type": "baseline.green",
                "source_step_id": None,
                "binding_state": "BOUND",
                "exact_digest": DIGEST_A,
            }
        ],
        "expected_postcondition": "local artifact validated",
        "prohibited_actions": ["provider.contact", "remote.mutation"],
        "stop_conditions": ["evidence.mismatch", "scope.drift"],
        "correction_reference": "correction.stop-for-review",
        "execution_class": "LOCAL_ONLY",
        "credential_policy": {
            "permitted": False,
            "allowed_classes": ["NONE"],
            "values_stored": False,
        },
        "unresolved_bindings": [],
    }
    value = {
        "plan_id": "a7100000-0000-4000-8000-000000000201",
        "plan_version": 1,
        "plan_digest": DIGEST_C,
        "definition_status": "READY_FOR_APPROVAL",
        "environment": "DEVELOPMENT",
        "target": {
            "provider_class": "provider.fictional",
            "provider_reference": "provider.fictional",
            "project_reference": "project.fictional.development",
            "responsibility": "AUTH",
            "issuer_reference": "https://auth.example.invalid/issuer",
            "audience_reference": "audience.fictional.service",
        },
        "owner_identity": "owner.fictional",
        "created_at": "2030-01-15T14:00:00Z",
        "authorization_window": {
            "binding_state": "BOUND",
            "starts_at": "2030-01-15T15:00:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
        },
        "ordered_step_ids": [step["step_id"]],
        "steps": [step],
        "prohibited_actions": [
            "batch.mutation",
            "production.target",
            "staging.target",
            "self.repair",
        ],
        "stop_conditions": [
            "scope.drift",
            "target.drift",
            "evidence.missing",
            "outcome.ambiguous",
            "authorization.expired",
        ],
        "authority_effect": "NONE_UNTIL_SEPARATELY_APPROVED",
    }
    value["plan_digest"] = plan_digest(value)
    return value


def owner_approval(value: dict) -> dict:
    approval = {
        "approval_id": "a7100000-0000-4000-8000-000000000202",
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "approval_digest": DIGEST_C,
        "owner_identity": value["owner_identity"],
        "decision": "APPROVE",
        "environment": value["environment"],
        "effective_at": value["authorization_window"]["starts_at"],
        "expires_at": value["authorization_window"]["expires_at"],
        "approved_at": "2030-01-15T14:59:00Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
    }
    approval["approval_digest"] = approval_digest(approval)
    return approval


def step_request(value: dict) -> dict:
    step = value["steps"][0]
    return {
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "environment": value["environment"],
        "provider_reference": value["target"]["provider_reference"],
        "project_reference": value["target"]["project_reference"],
        "responsibility": value["target"]["responsibility"],
        "issuer_reference": value["target"]["issuer_reference"],
        "audience_reference": value["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "NONE",
        "required_evidence": [
            {"evidence_type": "baseline.green", "evidence_digest": DIGEST_A}
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def outcome_evidence() -> list[dict]:
    return [
        {
            "evidence_type": "local.artifact.validated",
            "evidence_reference": "evidence.local.step-01",
            "evidence_digest": DIGEST_C,
            "recorded_at": "2030-01-15T15:02:00Z",
        }
    ]


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class ProgressRepositoryTests(unittest.TestCase):
    def test_v8_execution_progress_is_separate_valid_lineage(self):
        plan_path = ROOT / "contracts/plans/v1/development-auth-integration-v8.plan.json"
        initial_path = ROOT / "contracts/plans/v1/development-auth-integration-v8.progress.json"
        execution_path = (
            ROOT
            / "contracts/plans/v1/development-auth-integration-v8.execution-progress.json"
        )
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        initial = json.loads(initial_path.read_text(encoding="utf-8"))
        store = FileAuthorizationProgressStore(
            plan=plan,
            schema_root=SCHEMAS,
            initial_progress_path=initial_path,
            execution_progress_path=execution_path,
        )

        current = store.load_current()

        self.assertEqual(initial["record_version"], 1)
        self.assertEqual(initial["overall_state"], "NOT_STARTED")
        self.assertEqual(current["progress_id"], initial["progress_id"])
        self.assertGreaterEqual(current["record_version"], initial["record_version"])

    def test_persists_authorize_and_outcome_as_separate_versions(self):
        value = local_plan()
        approval = owner_approval(value)
        initial = initial_progress(
            value, SCHEMAS, PROGRESS_ID, "2030-01-15T15:00:30Z"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial_path = root / "initial.json"
            execution_path = root / "execution.json"
            write_json(initial_path, initial)
            store = FileAuthorizationProgressStore(
                plan=value,
                schema_root=SCHEMAS,
                initial_progress_path=initial_path,
                execution_progress_path=execution_path,
            )

            bootstrapped = store.bootstrap_execution_progress()
            self.assertEqual(bootstrapped, initial)

            authorized = store.persist_transition(
                expected_progress_digest=initial["progress_digest"],
                transition=lambda current: authorize_step(
                    value,
                    approval,
                    current,
                    step_request(value),
                    SCHEMAS,
                    "2030-01-15T15:01:00Z",
                ),
            )
            self.assertEqual(authorized["record_version"], 2)
            self.assertEqual(
                authorized["step_states"][0]["authorization_state"], "AUTHORIZED"
            )

            completed = store.persist_transition(
                expected_progress_digest=authorized["progress_digest"],
                transition=lambda current: record_step_outcome(
                    value,
                    approval,
                    current,
                    "plan.step.01",
                    "SUCCEEDED",
                    "PASS",
                    outcome_evidence(),
                    value["steps"][0]["expected_postcondition"],
                    None,
                    SCHEMAS,
                    "2030-01-15T15:02:00Z",
                ),
            )
            self.assertEqual(completed["record_version"], 3)
            self.assertEqual(completed["overall_state"], "COMPLETED")
            self.assertTrue(completed["step_states"][0]["authorization_consumed"])
            self.assertEqual(
                json.loads(initial_path.read_text(encoding="utf-8")), initial
            )

    def test_rejects_stale_write(self):
        value = local_plan()
        approval = owner_approval(value)
        initial = initial_progress(
            value, SCHEMAS, PROGRESS_ID, "2030-01-15T15:00:30Z"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial_path = root / "initial.json"
            execution_path = root / "execution.json"
            write_json(initial_path, initial)
            store = FileAuthorizationProgressStore(
                plan=value,
                schema_root=SCHEMAS,
                initial_progress_path=initial_path,
                execution_progress_path=execution_path,
            )
            store.bootstrap_execution_progress()
            authorized = store.persist_transition(
                expected_progress_digest=initial["progress_digest"],
                transition=lambda current: authorize_step(
                    value,
                    approval,
                    current,
                    step_request(value),
                    SCHEMAS,
                    "2030-01-15T15:01:00Z",
                ),
            )

            with self.assertRaisesRegex(AuthorizationPlanStop, "PROGRESS_STALE_WRITE"):
                store.persist_transition(
                    expected_progress_digest=initial["progress_digest"],
                    transition=lambda current: copy.deepcopy(current),
                )
            self.assertEqual(store.load_current(), authorized)

    def test_rejects_collapsed_authorize_and_outcome_transition(self):
        value = local_plan()
        approval = owner_approval(value)
        initial = initial_progress(
            value, SCHEMAS, PROGRESS_ID, "2030-01-15T15:00:30Z"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial_path = root / "initial.json"
            execution_path = root / "execution.json"
            write_json(initial_path, initial)
            store = FileAuthorizationProgressStore(
                plan=value,
                schema_root=SCHEMAS,
                initial_progress_path=initial_path,
                execution_progress_path=execution_path,
            )
            store.bootstrap_execution_progress()

            def collapsed(current: dict) -> dict:
                authorized = authorize_step(
                    value,
                    approval,
                    current,
                    step_request(value),
                    SCHEMAS,
                    "2030-01-15T15:01:00Z",
                )
                return record_step_outcome(
                    value,
                    approval,
                    authorized,
                    "plan.step.01",
                    "SUCCEEDED",
                    "PASS",
                    outcome_evidence(),
                    value["steps"][0]["expected_postcondition"],
                    None,
                    SCHEMAS,
                    "2030-01-15T15:02:00Z",
                )

            with self.assertRaisesRegex(
                AuthorizationPlanStop, "PROGRESS_VERSION_NOT_MONOTONIC"
            ):
                store.persist_transition(
                    expected_progress_digest=initial["progress_digest"],
                    transition=collapsed,
                )
            self.assertEqual(store.load_current(), initial)


if __name__ == "__main__":
    unittest.main()
