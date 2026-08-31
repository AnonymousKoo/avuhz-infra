"""Focused Phase 5D-D5b DeploymentVerification runtime/security/history tests."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.phase5d_brief import reference
from avuhz_runtime.phase5d_deployment_execution import DeploymentExecutionReadService
from avuhz_runtime.phase5d_deployment_verification import (
    DEPLOYMENT_VERIFICATION_CAPABILITIES,
    DeploymentVerificationReadService,
    derive_verification_status,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_deployment_execution_runtime as execution_runtime


VERIFICATION_ID = "d5d60000-0000-4000-8000-000000000001"


class DeploymentVerificationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.e = execution_runtime.DeploymentExecutionRuntimeTests()
        self.e.setUp()
        start, context = self.e.raw("StartDeploymentExecution", self.e.start_payload())
        self.assertEqual(self.e.execute(start, context)["result"], "ACCEPTED")
        complete, context = self.e.raw("CompleteDeploymentExecution", self.e.completion_payload(), expected=1)
        self.assertEqual(self.e.execute(complete, context)["result"], "ACCEPTED")
        self.store = self.e.store
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self._number = 1900
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now, ids=self.next_id,
        )

    @property
    def tenant(self): return self.e.tenant
    @property
    def engagement_id(self): return self.e.engagement_id
    @property
    def now(self): return self.e.now

    def next_id(self):
        self._number += 1
        return f"d5d69000-0000-4000-8000-{self._number:012d}"

    def execution(self):
        if hasattr(self, "source_execution"):
            return copy.deepcopy(self.source_execution)
        return UnitOfWork(self.store).deployment_executions.get(
            self.tenant, execution_runtime.EXECUTION_ID
        )

    def context(self, *, tenant=None, caller_type="INTERNAL_SERVICE"):
        principal = "service.phase5d-deployment-verification" if caller_type == "INTERNAL_SERVICE" else "human.deployment-verifier"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({DEPLOYMENT_VERIFICATION_CAPABILITIES["RecordDeploymentVerification"]}),
            frozenset(), "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if caller_type == "HUMAN" else None,
        )

    def payload(self, *, attempt=1, result="MATCHED"):
        execution = self.execution()
        artifact_digest = execution["authority_binding"]["artifact_reference"]["artifact_digest"]
        verification = {
            "target_resource": copy.deepcopy(execution["authority_binding"]["target_resources"][0]),
            "result": result,
            "expected_artifact_digest": artifact_digest,
            "evidence_references": [{
                "evidence_reference_id": f"evidence.deployment.verification.{attempt}",
                "evidence_class": "TARGET_STATE",
                "evidence_digest": "sha256:" + "c" * 64,
                "provenance_reference": "service.phase5d-deployment-verification",
            }],
            "detail": "Bounded target-state evidence was recorded by the trusted verifier.",
            "verified_at": self.now,
        }
        if result in {"MATCHED", "MISMATCHED"}:
            verification["observed_artifact_digest"] = (
                artifact_digest if result == "MATCHED" else "sha256:" + "d" * 64
            )
            verification["observed_state_fingerprint"] = f"fpv1:observed-target-state-fictional-{attempt:04d}"
        return {
            "verification_attempt": attempt,
            "deployment_execution_reference": reference(
                "DEPLOYMENT_EXECUTION", execution["deployment_execution_id"], execution["record_version"]
            ),
            "deployment_execution_digest": execution["execution_digest"],
            "authority_binding": copy.deepcopy(execution["authority_binding"]),
            "target_verifications": [verification],
        }

    def raw(self, payload, *, verification_id=VERIFICATION_ID, key=None, tenant=None, caller_type="INTERNAL_SERVICE"):
        context = self.context(tenant=tenant, caller_type=caller_type)
        raw = {
            "command_id": self.next_id(), "command_type": "RecordDeploymentVerification",
            "command_schema_version": 1, "tenant_id": tenant or self.tenant,
            "engagement_id": self.engagement_id, "subject_type": "DEPLOYMENT_VERIFICATION",
            "subject_id": verification_id, "requested_by": "trusted.phase5d",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d", "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant or self.tenant], "capabilities": ["deployment_verification:record"],
                "environment": "TEST", "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5d60000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"d5b-record-verification-{self._number}",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:record-deployment-verification-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }
        return raw, context

    def execute(self, raw, context): return self.executor.execute(raw, context)

    def test_execution_success_is_not_verification_then_exact_verified_record(self):
        execution_view = DeploymentExecutionReadService(UnitOfWork(self.store)).status(
            self.tenant, execution_runtime.EXECUTION_ID, self.now
        )
        self.assertFalse(execution_view["deployment_verified"])
        self.assertEqual(len(self.store.deployment_verifications), 0)
        raw, context = self.raw(self.payload())
        self.assertEqual(self.execute(raw, context)["result"], "ACCEPTED")
        uow = UnitOfWork(self.store)
        record = uow.deployment_verifications.get(self.tenant, VERIFICATION_ID)
        view = DeploymentVerificationReadService(uow).status(self.tenant, VERIFICATION_ID, self.now)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        for schema_id, value in (
            ("urn:avuhz:schema:contracts:domain:deployment-verification:v1", record),
            ("urn:avuhz:schema:contracts:read-models:deployment-verification-status-view:v1", view),
        ):
            validator = Draft202012Validator(registry.expanded(schema_id), format_checker=FormatChecker())
            self.assertEqual(list(validator.iter_errors(value)), [])
        event_validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(event_validator.iter_errors(self.store.events[0])), [])
        self.assertEqual((record["overall_status"], view["deployment_verified"], record["rollback_required"]), ("VERIFIED", True, False))
        self.assertEqual(self.store.events[0]["event_type"], "deployment_verification.recorded")
        self.assertEqual(self.store.outbox[0]["status"], "PENDING")

    def test_all_frozen_dispositions_are_deterministically_derived(self):
        self.assertEqual(derive_verification_status([{"result": "MATCHED"}]), "VERIFIED")
        self.assertEqual(derive_verification_status([{"result": "MISMATCHED"}]), "FAILED")
        self.assertEqual(derive_verification_status([{"result": "MATCHED"}, {"result": "BLOCKED"}]), "PARTIAL")
        self.assertEqual(derive_verification_status([{"result": "BLOCKED"}]), "BLOCKED")
        raw, context = self.raw(self.payload(result="BLOCKED"))
        self.assertEqual(self.execute(raw, context)["result"], "ACCEPTED")
        record = UnitOfWork(self.store).deployment_verifications.get(self.tenant, VERIFICATION_ID)
        self.assertEqual((record["overall_status"], record["rollback_required"]), ("BLOCKED", True))

    def test_wrong_binding_invented_match_and_spoofed_provenance_have_no_side_effects(self):
        mutations = (
            lambda p: p.__setitem__("deployment_execution_digest", "sha256:" + "f" * 64),
            lambda p: p["authority_binding"].__setitem__("qa_result_digest", "sha256:" + "f" * 64),
            lambda p: p["target_verifications"][0].__setitem__("expected_artifact_digest", "sha256:" + "f" * 64),
            lambda p: p["target_verifications"][0].__setitem__("observed_artifact_digest", "sha256:" + "f" * 64),
            lambda p: p["target_verifications"][0]["evidence_references"][0].__setitem__("provenance_reference", "workload.spoofed"),
            lambda p: p.__setitem__("verification_passed", True),
        )
        for index, mutate in enumerate(mutations):
            payload = self.payload(); mutate(payload)
            raw, context = self.raw(payload, verification_id=f"d5d60000-0000-4000-8000-{index + 100:012d}", key=f"d5b-negative-{index:04d}")
            self.assertNotEqual(self.execute(raw, context)["result"], "ACCEPTED")
        self.assertEqual((len(self.store.deployment_verifications), len(self.store.events), len(self.store.outbox)), (0, 0, 0))

    def test_failure_history_retest_idempotency_conflict_and_atomicity(self):
        first_raw, context = self.raw(self.payload(result="BLOCKED"), key="d5b-initial-blocked-verification")
        self.assertEqual(self.execute(first_raw, context)["result"], "ACCEPTED")
        self.assertEqual(self.execute(first_raw, context)["result"], "DUPLICATE")
        changed = copy.deepcopy(first_raw)
        changed["payload"]["target_verifications"][0]["detail"] = "Changed semantic evidence summary."
        self.assertEqual(self.execute(changed, context)["result"], "CONFLICT")
        first = UnitOfWork(self.store).deployment_verifications.get(self.tenant, VERIFICATION_ID)
        second_id = "d5d60000-0000-4000-8000-000000000002"
        retry = self.payload(attempt=2)
        retry["supersedes_deployment_verification_reference"] = reference(
            "DEPLOYMENT_VERIFICATION", VERIFICATION_ID, first["record_version"]
        )
        retry_raw, retry_context = self.raw(retry, verification_id=second_id, key="d5b-retest-verification")
        self.assertEqual(self.execute(retry_raw, retry_context)["result"], "ACCEPTED")
        uow = UnitOfWork(self.store)
        self.assertEqual(uow.deployment_verifications.get(self.tenant, VERIFICATION_ID), first)
        self.assertEqual(len(uow.deployment_verifications.list_by_execution(
            self.tenant, execution_runtime.EXECUTION_ID, 2
        )), 2)
        third = self.payload(attempt=3)
        third["supersedes_deployment_verification_reference"] = reference(
            "DEPLOYMENT_VERIFICATION", second_id, 2
        )
        raw, context = self.raw(third, verification_id="d5d60000-0000-4000-8000-000000000003", key="d5b-stale-supersedes")
        self.assertEqual(self.execute(raw, context)["result"], "REJECTED")
        self.store.fail_stage = "OUTBOX_APPEND"
        atomic = self.payload(attempt=3)
        atomic["supersedes_deployment_verification_reference"] = reference(
            "DEPLOYMENT_VERIFICATION", second_id, 1
        )
        raw, context = self.raw(atomic, verification_id="d5d60000-0000-4000-8000-000000000004", key="d5b-atomic-rollback")
        self.assertEqual(self.execute(raw, context)["result"], "REJECTED")
        self.store.fail_stage = None
        self.assertIsNone(UnitOfWork(self.store).deployment_verifications.get(
            self.tenant, "d5d60000-0000-4000-8000-000000000004"
        ))
        self.assertEqual((len(self.store.events), len(self.store.outbox)), (2, 2))


if __name__ == "__main__": unittest.main()
