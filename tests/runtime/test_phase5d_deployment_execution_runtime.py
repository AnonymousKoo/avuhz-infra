"""Focused Phase 5D-D5a DeploymentExecution runtime/security/history tests."""
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
from avuhz_runtime.phase5d_deployment_execution import (
    DEPLOYMENT_EXECUTION_CAPABILITIES,
    DeploymentExecutionReadService,
    _terminal_truth,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_deployment_authorization_runtime as authorization_runtime


EXECUTION_ID = "d5d50000-0000-4000-8000-000000000001"


class DeploymentExecutionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.d = authorization_runtime.DeploymentAuthorizationRuntimeTests()
        self.d.setUp()
        self.d.make_active()
        self.store = self.d.store
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self._number = 1700
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now, ids=self.next_id,
        )

    @property
    def tenant(self): return self.d.tenant
    @property
    def engagement_id(self): return self.d.engagement_id
    @property
    def now(self): return self.d.now

    def next_id(self):
        self._number += 1
        return f"d5d59000-0000-4000-8000-{self._number:012d}"

    def context(self, command, *, tenant=None, caller_type=None):
        caller_type = caller_type or "INTERNAL_SERVICE"
        principal = "service.phase5d-deployment-execution" if caller_type == "INTERNAL_SERVICE" else "human.deployment-operator"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({DEPLOYMENT_EXECUTION_CAPABILITIES[command]}), frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if caller_type == "HUMAN" else None,
        )

    def authority(self):
        if hasattr(self, "source_authority"):
            return copy.deepcopy(self.source_authority)
        return UnitOfWork(self.store).deployment_authorizations.get_version(
            self.tenant, authorization_runtime.AUTHORIZATION_ID, 1
        )

    def binding(self):
        authority = self.authority()
        return {
            "deployment_authorization_reference": reference("DEPLOYMENT_AUTHORIZATION", authority["deployment_authorization_id"], authority["authorization_version"]),
            "deployment_authority_digest": authority["deployment_authority_digest"],
            "implementation_authorization_reference": copy.deepcopy(authority["implementation_authorization_reference"]),
            "implementation_authority_digest": authority["implementation_authority_digest"],
            "codex_build_package_reference": copy.deepcopy(authority["codex_build_package_reference"]),
            "package_digest": authority["package_digest"],
            "build_execution_reference": copy.deepcopy(authority["build_execution_reference"]),
            "build_execution_digest": authority["build_execution_digest"],
            "qa_result_reference": copy.deepcopy(authority["qa_result_reference"]),
            "qa_result_digest": authority["qa_result_digest"],
            "client_acceptance_reference": copy.deepcopy(authority["client_acceptance_reference"]),
            "client_acceptance_digest": authority["client_acceptance_digest"],
            "artifact_reference": copy.deepcopy(authority["artifact_reference"]),
            "target_environment": authority["target_environment"],
            "target_resources": copy.deepcopy(authority["target_resources"]),
        }

    def raw(self, command, payload, *, execution_id=EXECUTION_ID, expected=None, key=None, tenant=None, caller_type=None):
        context = self.context(command, tenant=tenant, caller_type=caller_type)
        slug = "start-deployment-execution" if command == "StartDeploymentExecution" else "complete-deployment-execution"
        raw = {
            "command_id": self.next_id(), "command_type": command, "command_schema_version": 1,
            "tenant_id": tenant or self.tenant, "engagement_id": self.engagement_id,
            "subject_type": "DEPLOYMENT_EXECUTION", "subject_id": execution_id,
            "requested_by": "trusted.phase5d", "caller_type": context.caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d", "audience": "avuhz-command-api", "caller_type": context.caller_type,
                "tenant_ids": [tenant or self.tenant], "capabilities": [DEPLOYMENT_EXECUTION_CAPABILITIES[command]],
                "environment": "TEST", "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5d50000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"d5a-{command.lower()}-{self._number}",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{slug}-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }
        if expected is not None: raw["expected_record_version"] = expected
        return raw, context

    def start_payload(self):
        return {
            "execution_attempt": 1, "authority_binding": self.binding(),
            "execution_action": "DEPLOY_EXACT_ARTIFACT",
            "execution_fingerprint": "fpv1:deployment-attempt-fictional-0001",
        }

    def completion_payload(self, outcome="APPLIED"):
        return {
            "execution_attempt": 1,
            "target_outcomes": [{
                "target_resource": copy.deepcopy(self.binding()["target_resources"][0]),
                "outcome": outcome,
                "evidence_references": [{
                    "evidence_reference_id": "evidence.deployment.operation.001",
                    "evidence_class": "DEPLOYMENT_OPERATION",
                    "evidence_digest": "sha256:" + "a" * 64,
                    "provenance_reference": "service.phase5d-deployment-execution",
                }],
                "detail": "Bounded operation evidence was recorded by the trusted executor.",
            }],
            "completion_summary": "The bounded target operation outcome was recorded.",
        }

    def execute(self, raw, context): return self.executor.execute(raw, context)

    def test_exact_authority_start_completion_event_outbox_and_read_view(self):
        start, context = self.raw("StartDeploymentExecution", self.start_payload())
        self.assertEqual(self.execute(start, context)["result"], "ACCEPTED")
        in_progress = UnitOfWork(self.store).deployment_executions.get(self.tenant, EXECUTION_ID)
        self.assertEqual(in_progress["status"], "IN_PROGRESS")
        complete, context = self.raw("CompleteDeploymentExecution", self.completion_payload(), expected=1)
        self.assertEqual(self.execute(complete, context)["result"], "ACCEPTED")
        uow = UnitOfWork(self.store); record = uow.deployment_executions.get(self.tenant, EXECUTION_ID)
        view = DeploymentExecutionReadService(uow).status(self.tenant, EXECUTION_ID, self.now)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        for schema_id, value in (
            ("urn:avuhz:schema:contracts:domain:deployment-execution:v1", record),
            ("urn:avuhz:schema:contracts:read-models:deployment-execution-status-view:v1", view),
        ):
            self.assertEqual(list(Draft202012Validator(registry.expanded(schema_id), format_checker=FormatChecker()).iter_errors(value)), [])
        self.assertEqual((record["status"], record["rollback_disposition"], view["deployment_verified"]), ("SUCCEEDED", "PENDING_VERIFICATION", False))
        self.assertEqual([e["event_type"] for e in self.store.events], ["deployment_execution.started", "deployment_execution.completed"])
        event_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=FormatChecker())
        self.assertTrue(all(not list(event_validator.iter_errors(event)) for event in self.store.events))
        self.assertEqual([o["status"] for o in self.store.outbox], ["PENDING", "PENDING"])

    def test_states_are_derived_and_attempt_never_implies_verification(self):
        self.assertEqual(_terminal_truth([{"outcome": "APPLIED"}]), ("SUCCEEDED", "PENDING_VERIFICATION"))
        self.assertEqual(_terminal_truth([{"outcome": "APPLIED"}, {"outcome": "FAILED"}]), ("PARTIAL", "REQUIRED"))
        self.assertEqual(_terminal_truth([{"outcome": "FAILED"}]), ("FAILED", "NOT_REQUIRED"))
        self.assertEqual(_terminal_truth([{"outcome": "BLOCKED"}]), ("BLOCKED", "NOT_REQUIRED"))
        start, context = self.raw("StartDeploymentExecution", self.start_payload())
        self.assertEqual(self.execute(start, context)["result"], "ACCEPTED")
        view = DeploymentExecutionReadService(UnitOfWork(self.store)).status(self.tenant, EXECUTION_ID, self.now)
        self.assertFalse(view["operation_completed"]); self.assertFalse(view["deployment_verified"])

    def test_wrong_authority_spoofed_truth_and_provenance_have_no_side_effects(self):
        for mutate in (
            lambda p: p["authority_binding"].__setitem__("deployment_authority_digest", "sha256:" + "f" * 64),
            lambda p: p.__setitem__("deployment_succeeded", True),
        ):
            payload = self.start_payload(); mutate(payload)
            raw, context = self.raw("StartDeploymentExecution", payload, key=self.next_id())
            self.assertNotEqual(self.execute(raw, context)["result"], "ACCEPTED")
        self.assertEqual((len(self.store.deployment_executions), len(self.store.events), len(self.store.outbox)), (0, 0, 0))
        start, context = self.raw("StartDeploymentExecution", self.start_payload())
        self.assertEqual(self.execute(start, context)["result"], "ACCEPTED")
        completion = self.completion_payload(); completion["target_outcomes"][0]["evidence_references"][0]["provenance_reference"] = "workload.spoofed"
        raw, context = self.raw("CompleteDeploymentExecution", completion, expected=1)
        self.assertEqual(self.execute(raw, context)["result"], "REJECTED")
        self.assertEqual(UnitOfWork(self.store).deployment_executions.get(self.tenant, EXECUTION_ID)["status"], "IN_PROGRESS")

    def test_idempotency_stale_version_and_atomic_rollback(self):
        raw, context = self.raw("StartDeploymentExecution", self.start_payload(), key="d5a-execution-replay")
        self.assertEqual(self.execute(raw, context)["result"], "ACCEPTED")
        self.assertEqual(self.execute(raw, context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw); changed["payload"]["execution_fingerprint"] = "fpv1:deployment-attempt-fictional-0002"
        self.assertEqual(self.execute(changed, context)["result"], "CONFLICT")
        complete, complete_context = self.raw("CompleteDeploymentExecution", self.completion_payload(), expected=2)
        self.assertEqual(self.execute(complete, complete_context)["reason_code"], "VERSION_STALE")
        self.store.fail_stage = "OUTBOX_APPEND"
        complete, complete_context = self.raw("CompleteDeploymentExecution", self.completion_payload(), expected=1, key="d5a-atomic-rollback")
        self.assertEqual(self.execute(complete, complete_context)["result"], "REJECTED")
        self.store.fail_stage = None
        self.assertEqual(UnitOfWork(self.store).deployment_executions.get(self.tenant, EXECUTION_ID)["status"], "IN_PROGRESS")
        self.assertEqual(len(self.store.events), 1); self.assertEqual(len(self.store.outbox), 1)


    def test_failed_attempt_is_immutable_and_retry_creates_exact_new_history(self):
        start, context = self.raw("StartDeploymentExecution", self.start_payload())
        self.assertEqual(self.execute(start, context)["result"], "ACCEPTED")
        complete, context = self.raw("CompleteDeploymentExecution", self.completion_payload("FAILED"), expected=1)
        self.assertEqual(self.execute(complete, context)["result"], "ACCEPTED")
        first = UnitOfWork(self.store).deployment_executions.get(self.tenant, EXECUTION_ID)
        retry_id = "d5d50000-0000-4000-8000-000000000002"
        payload = self.start_payload()
        payload.update(
            execution_attempt=2,
            execution_fingerprint="fpv1:deployment-attempt-fictional-0002",
            supersedes_deployment_execution_reference=reference(
                "DEPLOYMENT_EXECUTION", EXECUTION_ID, first["record_version"]
            ),
        )
        retry, context = self.raw("StartDeploymentExecution", payload, execution_id=retry_id)
        self.assertEqual(self.execute(retry, context)["result"], "ACCEPTED")
        uow = UnitOfWork(self.store)
        self.assertEqual(uow.deployment_executions.get(self.tenant, EXECUTION_ID), first)
        second = uow.deployment_executions.get(self.tenant, retry_id)
        self.assertEqual((second["execution_attempt"], second["status"]), (2, "IN_PROGRESS"))
        self.assertEqual(len(uow.deployment_executions.list_by_authorization(
            self.tenant, authorization_runtime.AUTHORIZATION_ID, 1
        )), 2)


if __name__ == "__main__": unittest.main()
