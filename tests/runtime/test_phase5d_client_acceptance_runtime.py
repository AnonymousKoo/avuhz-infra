"""Phase 5D-D3 ClientAcceptance runtime, authority, history, and atomicity coverage."""
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
from avuhz_runtime.phase5d_client_acceptance import (
    CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
    CLIENT_ACCEPTANCE_CAPABILITIES,
    ClientAcceptanceReadService,
    client_acceptance_digest,
)
from avuhz_runtime.phase5d_qa_result import QAResultReadService
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_qa_result_runtime as qa_runtime


ACCEPTANCE_ID = "d5d30000-0000-4000-8000-000000000001"
FOREIGN_TENANT = "d5d30000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
    return Draft202012Validator(
        registry.expanded(schema_id), format_checker=FormatChecker()
    )


class ClientAcceptanceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.q = qa_runtime.QAResultRuntimeTests()
        self.q.setUp()
        self.q.record()
        self.store = self.q.store
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self._number = 1280
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"),
            GuardPipeline(),
            self.store,
            clock=lambda: self.now,
            ids=self.next_id,
        )

    @property
    def tenant(self):
        return self.q.tenant

    @property
    def engagement_id(self):
        return self.q.engagement_id

    @property
    def now(self):
        return self.q.now

    @property
    def package_payload(self):
        return self.q.package_payload

    def next_id(self):
        self._number += 1
        return f"d5d39000-0000-4000-8000-{self._number:012d}"

    def context(
        self, *, caller_type="HUMAN", tenant=None, principal=None,
        authority_role=CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
    ):
        principal = principal or (
            "human.client-acceptance" if caller_type == "HUMAN" else "service.phase5d"
        )
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({CLIENT_ACCEPTANCE_CAPABILITIES["RecordClientAcceptance"]}),
            frozenset({authority_role}) if authority_role else frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if human else None,
            "organization.client" if human else None,
            authority_role if human else None,
        )

    def raw(
        self, payload, *, key=None, command_id=None, tenant=None,
        engagement=None, caller_type="HUMAN", expected=None,
    ):
        value = {
            "command_id": command_id or self.next_id(),
            "command_type": "RecordClientAcceptance",
            "command_schema_version": 1,
            "tenant_id": tenant or self.tenant,
            "engagement_id": engagement or self.engagement_id,
            "subject_type": "CLIENT_ACCEPTANCE",
            "subject_id": payload["client_acceptance_id"],
            "requested_by": "trusted.phase5d",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d",
                "audience": "avuhz-command-api",
                "caller_type": caller_type,
                "tenant_ids": [tenant or self.tenant],
                "capabilities": [
                    CLIENT_ACCEPTANCE_CAPABILITIES["RecordClientAcceptance"]
                ],
                "environment": "TEST",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5d30000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5d-client-acceptance-{self._number}",
            "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:record-client-acceptance-payload:v1",
            "payload_version": 1,
            "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def payload(self, *, version=1, decision="ACCEPTED"):
        qa = getattr(self, "source_qa", None)
        if qa is None:
            qa = UnitOfWork(self.store).qa_results.get(self.tenant, qa_runtime.QA_ID)
        build = getattr(self, "source_builds", {}).get(
            qa["build_execution_reference"]["reference_id"]
        )
        if build is None:
            build = UnitOfWork(self.store).build_execution_results.get(
                self.tenant, qa["build_execution_reference"]["reference_id"]
            )
        value = {
            "client_acceptance_id": ACCEPTANCE_ID,
            "acceptance_version": version,
            "codex_build_package_reference": copy.deepcopy(
                qa["codex_build_package_reference"]
            ),
            "package_digest": qa["package_digest"],
            "build_execution_reference": copy.deepcopy(qa["build_execution_reference"]),
            "build_execution_digest": qa["build_execution_digest"],
            "qa_result_reference": {
                "reference_type": "QA_RESULT",
                "reference_id": qa["qa_result_id"],
                "reference_version": qa["record_version"],
            },
            "qa_result_digest": qa["qa_digest"],
            "artifact_reference": copy.deepcopy(build["artifact_references"][0]),
            "decision": decision,
            "decision_rationale": (
                "The exact tested artifact is accepted by the client."
                if decision == "ACCEPTED"
                else "The client rejects the exact tested artifact."
            ),
            "client_acceptance_digest": "sha256:" + "0" * 64,
        }
        if version > 1:
            value["supersedes_client_acceptance_reference"] = {
                "reference_type": "CLIENT_ACCEPTANCE",
                "reference_id": ACCEPTANCE_ID,
                "reference_version": version - 1,
            }
        value["client_acceptance_digest"] = client_acceptance_digest(
            self.tenant,
            self.engagement_id,
            value,
            {
                "principal_reference": "human.client-acceptance",
                "organization_reference": "organization.client",
                "authority_role": CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
            },
        )
        return value

    def execute(self, raw, *, context=None):
        return self.executor.execute(raw, context or self.context(caller_type=raw["caller_type"]))

    def record(self, payload=None, **kwargs):
        payload = payload or self.payload()
        raw = self.raw(payload, **kwargs)
        result = self.execute(raw)
        self.assertEqual(result["result"], "ACCEPTED", result)
        return raw

    def test_explicit_acceptance_event_outbox_read_model_and_non_authority(self):
        qa_view = QAResultReadService(UnitOfWork(self.store)).status(
            self.tenant, qa_runtime.QA_ID, self.now
        )
        self.assertTrue(qa_view["qa_passed"])
        self.assertFalse(qa_view["client_accepted"])
        self.assertEqual(len(self.store.client_acceptances), 0)

        self.record()
        uow = UnitOfWork(self.store)
        record = uow.client_acceptances.get_version(self.tenant, ACCEPTANCE_ID, 1)
        view = ClientAcceptanceReadService(uow).status(
            self.tenant, ACCEPTANCE_ID, 1, self.now
        )
        self.assertEqual(record["decision"], "ACCEPTED")
        self.assertEqual(record["attribution"]["authority_role"], CLIENT_ACCEPTANCE_AUTHORITY_ROLE)
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:domain:client-acceptance:v1"
            ).iter_errors(record)),
            [],
        )
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:read-models:client-acceptance-status-view:v1"
            ).iter_errors(view)),
            [],
        )
        self.assertEqual(
            (view["sources_exact"], view["stale"], view["client_accepted"],
             view["deployment_authorized"]),
            (True, False, True, False),
        )
        self.assertEqual([event["event_type"] for event in self.store.events], [
            "client_acceptance.recorded"
        ])
        self.assertEqual([item["status"] for item in self.store.outbox], ["PENDING"])
        self.assertTrue(schema_validator(
            "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
        ).is_valid(self.store.events[0]))

    def test_human_authority_workload_role_and_claim_spoofing_are_rejected(self):
        workload = self.raw(self.payload(), caller_type="INTERNAL_SERVICE")
        before = copy.deepcopy(self.store)
        self.assertEqual(self.execute(workload)["result"], "REJECTED")
        self.assertEqual(self.store.client_acceptances, before.client_acceptances)

        wrong_role = self.context(authority_role="CLIENT_IMPLEMENTATION_AUTHORITY")
        self.assertEqual(
            self.execute(
                self.raw(self.payload(), key="phase5d-client-wrong-role"), context=wrong_role
            )["result"],
            "REJECTED",
        )
        for field, value in (
            ("client_accepted", True),
            ("approved", True),
            ("qa_passed", True),
            ("deployment_allowed", True),
            ("production_authorized", True),
            ("role", CLIENT_ACCEPTANCE_AUTHORITY_ROLE),
        ):
            payload = self.payload()
            payload[field] = value
            self.assertEqual(
                self.execute(self.raw(payload, key=f"phase5d-client-spoof-{field}"))["result"],
                "VALIDATION_FAILED",
                field,
            )
        authority_text = self.payload()
        authority_text["decision_rationale"] = "Deployment authorized for production."
        authority_text["client_acceptance_digest"] = client_acceptance_digest(
            self.tenant, self.engagement_id, authority_text,
            {
                "principal_reference": "human.client-acceptance",
                "organization_reference": "organization.client",
                "authority_role": CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
            },
        )
        self.assertEqual(
            self.execute(self.raw(authority_text, key="phase5d-client-authority-text"))["result"],
            "REJECTED",
        )
        self.assertEqual(len(self.store.client_acceptances), 0)

    def test_exact_source_artifact_tenant_and_qa_negatives_have_no_side_effects(self):
        for label, mutation in (
            ("package digest", lambda p: p.update(package_digest="sha256:" + "9" * 64)),
            ("build digest", lambda p: p.update(build_execution_digest="sha256:" + "9" * 64)),
            ("qa digest", lambda p: p.update(qa_result_digest="sha256:" + "9" * 64)),
            ("package version", lambda p: p["codex_build_package_reference"].update(reference_version=2)),
            ("build version", lambda p: p["build_execution_reference"].update(reference_version=1)),
            ("qa version", lambda p: p["qa_result_reference"].update(reference_version=2)),
            ("artifact", lambda p: p["artifact_reference"].update(artifact_digest="sha256:" + "9" * 64)),
        ):
            payload = self.payload()
            mutation(payload)
            payload["client_acceptance_digest"] = client_acceptance_digest(
                self.tenant, self.engagement_id, payload,
                {
                    "principal_reference": "human.client-acceptance",
                    "organization_reference": "organization.client",
                    "authority_role": CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
                },
            )
            before = (
                len(self.store.client_acceptances), len(self.store.events),
                len(self.store.outbox), len(self.store.idempotency),
            )
            result = self.execute(
                self.raw(payload, key=f"phase5d-client-wrong-{label.replace(' ', '-')}")
            )
            self.assertEqual(result["result"], "REJECTED", label)
            self.assertEqual(
                (
                    len(self.store.client_acceptances), len(self.store.events),
                    len(self.store.outbox), len(self.store.idempotency),
                ),
                before,
                label,
            )

        qa_key = (self.tenant, qa_runtime.QA_ID)
        self.store.qa_results[qa_key]["overall_status"] = "FAILED"
        self.assertEqual(
            self.execute(self.raw(self.payload(), key="phase5d-client-failed-qa"))["result"],
            "REJECTED",
        )
        self.store.qa_results[qa_key]["overall_status"] = "PASSED"

        foreign = self.raw(
            self.payload(), tenant=FOREIGN_TENANT, key="phase5d-client-cross-tenant"
        )
        self.assertEqual(
            self.execute(foreign, context=self.context(tenant=FOREIGN_TENANT))["result"],
            "REJECTED",
        )

        stale_payload = self.payload()
        retest = self.q.payload(qa_id=qa_runtime.RETEST_ID, attempt=2)
        self.q.executor = self.executor
        self.q.record(retest, qa_id=qa_runtime.RETEST_ID)
        self.assertEqual(
            self.execute(
                self.raw(stale_payload, key="phase5d-client-stale-qa")
            )["result"],
            "REJECTED",
        )

    def test_versioned_immutable_decision_history_and_staleness(self):
        self.record()
        replacement = self.payload(version=2, decision="REJECTED")
        self.record(replacement, key="phase5d-client-reject-v2")
        uow = UnitOfWork(self.store)
        history = uow.client_acceptances.list_by_package(
            self.tenant, self.package_payload["codex_build_package_id"], 1
        )
        self.assertEqual(
            [(item["acceptance_version"], item["decision"]) for item in history],
            [(1, "ACCEPTED"), (2, "REJECTED")],
        )
        self.assertEqual(
            history[1]["supersedes_client_acceptance_reference"]["reference_version"], 1
        )
        old_view = ClientAcceptanceReadService(uow).status(
            self.tenant, ACCEPTANCE_ID, 1, self.now
        )
        new_view = ClientAcceptanceReadService(uow).status(
            self.tenant, ACCEPTANCE_ID, 2, self.now
        )
        self.assertIn("ACCEPTANCE_SUPERSEDED", old_view["reasons"])
        self.assertFalse(old_view["client_accepted"])
        self.assertEqual((new_view["decision"], new_view["client_accepted"]), ("REJECTED", False))

        stale = self.payload(version=3)
        stale["supersedes_client_acceptance_reference"]["reference_version"] = 1
        stale["client_acceptance_digest"] = client_acceptance_digest(
            self.tenant, self.engagement_id, stale,
            {
                "principal_reference": "human.client-acceptance",
                "organization_reference": "organization.client",
                "authority_role": CLIENT_ACCEPTANCE_AUTHORITY_ROLE,
            },
        )
        self.assertEqual(
            self.execute(self.raw(stale, key="phase5d-client-stale-predecessor"))["result"],
            "REJECTED",
        )

    def test_idempotency_duplicate_version_and_atomic_rollback(self):
        raw = self.record()
        self.assertEqual(self.execute(copy.deepcopy(raw))["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["decision_rationale"] = "Changed exact client rationale."
        self.assertEqual(self.execute(changed)["result"], "CONFLICT")
        duplicate = self.payload()
        self.assertEqual(
            self.execute(self.raw(duplicate, key="phase5d-client-duplicate-version"))["result"],
            "REJECTED",
        )
        for stage in (
            "AUTHORITATIVE_WRITE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND",
            "IDEMPOTENCY_COMPLETE", "COMMIT",
        ):
            fresh = ClientAcceptanceRuntimeTests()
            fresh.setUp()
            fresh.store.fail_stage = stage
            before = copy.deepcopy(fresh.store)
            result = fresh.execute(
                fresh.raw(fresh.payload(), key=f"phase5d-client-fail-{stage.lower()}")
            )
            self.assertEqual(result["result"], "REJECTED", stage)
            fresh.store.fail_stage = None
            self.assertEqual(fresh.store.client_acceptances, before.client_acceptances, stage)
            self.assertEqual(fresh.store.events, before.events, stage)
            self.assertEqual(fresh.store.outbox, before.outbox, stage)
            self.assertEqual(fresh.store.idempotency, before.idempotency, stage)


if __name__ == "__main__":
    unittest.main()
