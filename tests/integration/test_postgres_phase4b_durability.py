"""Phase 4B local-only durability, contention, and tenant-boundary proof."""
from __future__ import annotations

import copy
import json
import os
import queue
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "contracts")]

import psycopg

from avuhz_runtime.guards import COMMAND_CAPABILITIES, GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import (
    IdempotencyPostgresRepository,
    PostgresStore,
    PostgresUnitOfWork,
    connection_factory_from_environment,
)
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope, handoff, payloads

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
TENANT_A = "a3000000-0000-4000-8000-000000000002"
TENANT_B = "b3000000-0000-4000-8000-000000000002"
HANDOFF = "a3000000-0000-4000-8000-000000000001"
ENGAGEMENT = "a3000000-0000-4000-8000-000000000004"
SCOPE = "a3000000-0000-4000-8000-000000000005"


def context(command, tenant=TENANT_A, principal="phase4b-service", role=None):
    return TrustedExecutionContext(
        True, principal, "HUMAN" if role else "INTERNAL_SERVICE", tenant, None,
        frozenset({COMMAND_CAPABILITIES[command]}), frozenset(), "TEST",
        "avuhz-command-api", "STRONG", False, "2030-01-15T15:00:00Z",
        "2030-01-15T16:00:00Z", principal if role else None,
        f"org:{principal}" if role else None, role,
    )


class _ContendedIdempotency(IdempotencyPostgresRepository):
    """Hold the first unique-index owner until the other connection is waiting."""
    def reserve(self, key, fingerprint, prepared=None):
        ordinal = self.uow.coordinator.next_ordinal()
        if ordinal == 2:
            self.uow.coordinator.second_about_to_reserve.set()
            self.uow.coordinator.backend_pids.put(self.uow.connection.info.backend_pid)
        result = super().reserve(key, fingerprint, prepared)
        if ordinal == 1:
            self.uow.coordinator.first_reserved.set()
            if not self.uow.coordinator.release_first.wait(10):
                raise RuntimeError("concurrent contender did not reach idempotency reservation")
        return result


class _Coordinator:
    def __init__(self):
        self.lock = threading.Lock(); self.ordinal = 0
        self.first_reserved = threading.Event(); self.second_about_to_reserve = threading.Event()
        self.release_first = threading.Event(); self.backend_pids = queue.Queue()
    def next_ordinal(self):
        with self.lock:
            self.ordinal += 1
            return self.ordinal


class _ContendedUnitOfWork(PostgresUnitOfWork):
    coordinator = None
    def __init__(self, store):
        super().__init__(store)
        self.coordinator = type(self).coordinator
        self.idempotency = _ContendedIdempotency(self)


@unittest.skipUnless(DSN, "AVUHZ_POSTGRES_DSN is required for local integration tests")
class Phase4BDurabilityTests(unittest.TestCase):
    tables = (
        "avuhz_outbox_deliveries", "avuhz_lifecycle_events", "avuhz_idempotency_records",
        "avuhz_human_approvals", "avuhz_diagnostic_scopes", "avuhz_engagements",
        "avuhz_acquisition_handoffs",
    )

    def setUp(self):
        with psycopg.connect(DSN) as connection:
            for table in self.tables:
                connection.execute(f"delete from public.{table}")
            record = handoff()
            connection.execute(
                "insert into public.avuhz_acquisition_handoffs "
                "(tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) "
                "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,null)",
                (record["tenant_id"], record["handoff_id"], record["handoff_version"],
                 json.dumps(record["canonical_account_reference"]), json.dumps(record["acquisition_opportunity_reference"]),
                 record["qualification_status"], record["target_outcome"], "[]", "[]", "[]", "[]",
                 record["requested_engagement_type"], record["source_system"], record["source_record_version"],
                 record["producer_identity"], record["produced_at"], record["correlation_id"], record["idempotency_key"]),
            )
        self.store = PostgresStore(connection_factory_from_environment())
        self.ids = iter(f"c4000000-0000-4000-8000-{number:012d}" for number in range(1, 300))
        self.executor = self.make_executor()

    def make_executor(self, uow_factory=PostgresUnitOfWork):
        return Executor(CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
                        ids=lambda: next(self.ids), uow_factory=uow_factory)

    def raw(self, command, key, command_id, version=1):
        value = envelope(command, copy.deepcopy(payloads()[command]))
        value["idempotency_key"] = key; value["command_id"] = command_id
        if command in ("SubmitDiagnosticScope", "CanonicalizeDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope"):
            value["expected_record_version"] = version
        if command == "RecordHumanApproval":
            value["caller_type"] = "HUMAN"; value["caller_identity"]["caller_type"] = "HUMAN"
            value["caller_identity"]["capabilities"] = ["scope:approve"]
        return value

    def execute(self, command, key, command_id, *, role=None, version=1, executor=None):
        raw = self.raw(command, key, command_id, version)
        if role:
            raw["payload"]["authority_role"] = role
        return (executor or self.executor).execute(raw,
                                                   context(command, role=role, principal=f"human:{role}" if role else "phase4b-service"))

    def scope(self, tenant=TENANT_A):
        unit = PostgresUnitOfWork(self.store)
        try:
            return unit.diagnostic_scopes.get(tenant, SCOPE)
        finally:
            unit.close()

    def count(self, table, tenant=TENANT_A):
        with psycopg.connect(DSN) as connection:
            return connection.execute(f"select count(*) from public.{table} where tenant_id=%s", (tenant,)).fetchone()[0]

    def establish(self):
        commands = (
            ("AcceptAcquisitionHandoff", "p4b-handoff-0001", "c4000000-0000-4000-8000-000000000101", None, 1),
            ("OpenEngagement", "p4b-engagement-0001", "c4000000-0000-4000-8000-000000000102", None, 1),
            ("SubmitDiagnosticScope", "p4b-diagnostic-scope-0001", "c4000000-0000-4000-8000-000000000103", None, 1),
            ("CanonicalizeDiagnosticScope", "p4b-canonical-0001", "c4000000-0000-4000-8000-000000000104", None, 1),
        )
        for command, key, command_id, role, version in commands:
            self.assertEqual(self.execute(command, key, command_id, role=role, version=version)["result"], "ACCEPTED")

    def approve(self):
        self.assertEqual(self.execute("RecordHumanApproval", "p4b-client-approval-0001", "c4000000-0000-4000-8000-000000000105", role="CLIENT_DECISION_AUTHORITY", version=2)["result"], "ACCEPTED")
        self.assertEqual(self.execute("RecordHumanApproval", "p4b-sekinfra-approval-0001", "c4000000-0000-4000-8000-000000000106", role="SEKINFRA_ENGAGEMENT_AUTHORITY", version=2)["result"], "ACCEPTED")
        raw = self.raw("ApproveDiagnosticScope", "p4b-final-approval-0001", "c4000000-0000-4000-8000-000000000107", 2)
        raw["payload"].update(scope_content_digest=self.scope()["canonical_scope_digest"],
            client_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"c4000000-0000-4000-8000-000000000105","reference_version":1},
            sekinfra_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"c4000000-0000-4000-8000-000000000106","reference_version":1})
        self.assertEqual(self.executor.execute(raw, context("ApproveDiagnosticScope"))["result"], "ACCEPTED")
        return raw

    def test_full_restart_all_seven_durable_resources_and_replay(self):
        self.establish(); final = self.approve()
        self.assertEqual(self.scope()["status"], "APPROVED")
        self.assertEqual(tuple(self.count(table) for table in self.tables), (7, 7, 7, 2, 1, 1, 1))
        # Fresh objects and fresh connections must see the same authority projection.
        self.executor = self.make_executor()
        self.assertEqual(self.scope()["status"], "APPROVED")
        self.assertEqual(self.executor.execute(self.raw("CanonicalizeDiagnosticScope", "p4b-canonical-0001", "c4000000-0000-4000-8000-000000000104", 1), context("CanonicalizeDiagnosticScope"))["result"], "DUPLICATE")
        replay = self.raw("RecordHumanApproval", "p4b-client-approval-0001", "c4000000-0000-4000-8000-000000000105", 2)
        replay["payload"]["authority_role"] = "CLIENT_DECISION_AUTHORITY"
        self.assertEqual(self.executor.execute(replay, context("RecordHumanApproval", role="CLIENT_DECISION_AUTHORITY", principal="human:CLIENT_DECISION_AUTHORITY"))["result"], "DUPLICATE")
        self.assertEqual(self.executor.execute(final, context("ApproveDiagnosticScope"))["result"], "DUPLICATE")
        self.assertEqual(tuple(self.count(table) for table in self.tables), (7, 7, 7, 2, 1, 1, 1))

    def test_real_postgres_concurrent_same_fingerprint_and_semantic_conflict(self):
        for changed, expected in ((False, "DUPLICATE"), (True, "CONFLICT")):
            self.setUp()
            coordinator = _Coordinator(); _ContendedUnitOfWork.coordinator = coordinator
            race_executor = self.make_executor(_ContendedUnitOfWork)
            raw = self.raw("AcceptAcquisitionHandoff", "p4b-concurrent-key-0001", "c4000000-0000-4000-8000-000000000120")
            other = copy.deepcopy(raw)
            if changed:
                other["payload"]["acquisition_handoff"]["target_outcome"] = "A different fictional outcome."
            results = []
            def run(value): results.append(race_executor.execute(value, context("AcceptAcquisitionHandoff")))
            first = threading.Thread(target=run, args=(raw,)); second = threading.Thread(target=run, args=(other,))
            first.start(); self.assertTrue(coordinator.first_reserved.wait(10))
            second.start(); self.assertTrue(coordinator.second_about_to_reserve.wait(10))
            second_pid = coordinator.backend_pids.get(timeout=10)
            # This checks the actual PostgreSQL lock wait; no sleep-based race assumption.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with psycopg.connect(DSN) as connection:
                    waiting = connection.execute("select wait_event_type from pg_stat_activity where pid=%s", (second_pid,)).fetchone()
                if waiting and waiting[0] == "Lock": break
                time.sleep(.02)
            else:
                self.fail("second independent PostgreSQL transaction never contended on the reservation")
            coordinator.release_first.set(); first.join(10); second.join(10)
            self.assertFalse(first.is_alive() or second.is_alive())
            self.assertEqual(sorted(result["result"] for result in results), ["ACCEPTED", expected])
            self.assertEqual((self.count("avuhz_acquisition_handoffs"), self.count("avuhz_idempotency_records"), self.count("avuhz_lifecycle_events"), self.count("avuhz_outbox_deliveries")), (1, 1, 1, 1))

    def test_tenant_boundaries_and_cross_tenant_same_idempotency_key(self):
        # Handoffs intentionally share identifier and textual idempotency key: tenant is the boundary.
        with psycopg.connect(DSN) as connection:
            connection.execute(
                "insert into public.avuhz_acquisition_handoffs "
                "(tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) "
                "select %s,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,null from public.avuhz_acquisition_handoffs where tenant_id=%s",
                (TENANT_B, TENANT_A),
            )
        a = self.raw("AcceptAcquisitionHandoff", "p4b-cross-tenant-key-0001", "c4000000-0000-4000-8000-000000000130")
        b = copy.deepcopy(a); b["tenant_id"] = TENANT_B; b["payload"]["acquisition_handoff"]["tenant_id"] = TENANT_B; b["caller_identity"]["tenant_ids"] = [TENANT_B]
        self.assertEqual(self.executor.execute(a, context("AcceptAcquisitionHandoff"))["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(b, context("AcceptAcquisitionHandoff", TENANT_B))["result"], "ACCEPTED")
        self.assertEqual((self.count("avuhz_acquisition_handoffs"), self.count("avuhz_acquisition_handoffs", TENANT_B)), (1, 1))
        unit = PostgresUnitOfWork(self.store)
        try:
            self.assertIsNotNone(unit.handoffs.get(TENANT_B, HANDOFF))
            key = (TENANT_B, "phase4b-service", "AcceptAcquisitionHandoff", "ACQUISITION_HANDOFF", HANDOFF, "p4b-cross-tenant-key-0001")
            self.assertIsNotNone(unit.idempotency.get(key))
        finally:
            unit.close()
        # The normal repository lookup never crosses the boundary.
        unit = PostgresUnitOfWork(self.store)
        try:
            self.assertIsNone(unit.handoffs.get("c3000000-0000-4000-8000-000000000002", HANDOFF))
            self.assertIsNone(unit.engagements.get(TENANT_B, ENGAGEMENT))
            self.assertIsNone(unit.diagnostic_scopes.get(TENANT_B, SCOPE))
            self.assertIsNone(unit.human_approvals.get(TENANT_B, "c4000000-0000-4000-8000-000000000105"))
        finally:
            unit.close()

    def test_representative_failpoints_are_atomic_for_canonicalization_and_approval(self):
        for command, role, version in (("CanonicalizeDiagnosticScope", None, 1), ("RecordHumanApproval", "CLIENT_DECISION_AUTHORITY", 2)):
            for point in ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT"):
                self.setUp()
                if command == "CanonicalizeDiagnosticScope":
                    for setup_command, key, command_id in (
                        ("AcceptAcquisitionHandoff", "p4b-handoff-0001", "c4000000-0000-4000-8000-000000000101"),
                        ("OpenEngagement", "p4b-engagement-0001", "c4000000-0000-4000-8000-000000000102"),
                        ("SubmitDiagnosticScope", "p4b-diagnostic-scope-0001", "c4000000-0000-4000-8000-000000000103"),
                    ):
                        self.assertEqual(self.execute(setup_command, key, command_id)["result"], "ACCEPTED")
                    expected_artifacts = 3
                else:
                    self.establish(); expected_artifacts = 4
                self.store.fail_stage = point
                result = self.execute(command, f"p4b-{command}-{point}", "c4000000-0000-4000-8000-000000000150", role=role, version=version)
                self.assertEqual(result["result"], "REJECTED")
                if command == "CanonicalizeDiagnosticScope": self.assertIsNone(self.scope()["canonical_scope_digest"])
                else: self.assertEqual(self.count("avuhz_human_approvals"), 0)
                self.assertEqual(self.count("avuhz_idempotency_records"), expected_artifacts)
                self.assertEqual(self.count("avuhz_lifecycle_events"), expected_artifacts)
                self.assertEqual(self.count("avuhz_outbox_deliveries"), expected_artifacts)

    def test_all_repository_tenant_boundaries_and_composite_relationship_constraints(self):
        self.establish(); self.approve()
        unit = PostgresUnitOfWork(self.store)
        try:
            # Every repository with a supported read surface requires its tenant argument.
            self.assertIsNone(unit.handoffs.get(TENANT_B, HANDOFF))
            self.assertIsNone(unit.engagements.get(TENANT_B, ENGAGEMENT))
            self.assertIsNone(unit.diagnostic_scopes.get(TENANT_B, SCOPE))
            self.assertIsNone(unit.human_approvals.get(TENANT_B, "c4000000-0000-4000-8000-000000000105"))
            self.assertIsNone(unit.idempotency.get((TENANT_B, "phase4b-service", "CanonicalizeDiagnosticScope", "DIAGNOSTIC_SCOPE", SCOPE, "p4b-canonical-0001")))
        finally:
            unit.close()
        # Lifecycle-event and outbox repositories intentionally expose append only; durable
        # reads below verify their tenant columns and their composite FK boundaries.
        with psycopg.connect(DSN) as connection:
            for table in ("avuhz_lifecycle_events", "avuhz_outbox_deliveries"):
                self.assertEqual(connection.execute(f"select count(*) from public.{table} where tenant_id=%s", (TENANT_B,)).fetchone()[0], 0)
        cross = PostgresUnitOfWork(self.store)
        try:
            engagement = {"engagement_id":"d4000000-0000-4000-8000-000000000001", "tenant_id":TENANT_B,
                "engagement_state":"OPEN", "record_version":1, "engagement_version":1, "opened_at":"2030-01-15T15:00:00Z",
                "accepted_handoff_reference":{"reference_id":HANDOFF,"reference_version":1},
                "canonical_account_reference":payloads()["OpenEngagement"]["canonical_account_reference"],
                "acquisition_opportunity_reference":payloads()["OpenEngagement"]["acquisition_opportunity_reference"], "engagement_type":"DIAGNOSTIC_OIA"}
            with self.assertRaises(psycopg.errors.ForeignKeyViolation): cross.engagements.save(engagement)
            cross.rollback()
            scope = {"diagnostic_scope_id":"d4000000-0000-4000-8000-000000000002", "tenant_id":TENANT_B, "engagement_id":ENGAGEMENT,
                "scope_version":1, "record_version":1, "status":"REVIEW_PENDING", "action_set_version":1, "canonical_scope_digest":None,
                **payloads()["SubmitDiagnosticScope"]}
            with self.assertRaises(psycopg.errors.ForeignKeyViolation): cross.diagnostic_scopes.save(scope)
            cross.rollback()
            approval = {"approval_id":"d4000000-0000-4000-8000-000000000003", "tenant_id":TENANT_B, "engagement_id":ENGAGEMENT,
                "subject_id":SCOPE, "subject_version":1, "authority_role":"CLIENT_DECISION_AUTHORITY", "authority_category":"CLIENT_AUTHORITY",
                "approving_principal_reference":"human:test", "approving_organization_reference":"org:test", "canonical_scope_digest":self.scope()["canonical_scope_digest"],
                "action_set_version":1, "decision":"APPROVE", "status":"ACTIVE", "conditions":[], "effective_at":"2030-01-15T15:00:00Z", "correlation_id":"d4000000-0000-4000-8000-000000000004", "idempotency_key":"p4b-cross-approval-0001"}
            with self.assertRaises(psycopg.errors.ForeignKeyViolation): cross.human_approvals.save(approval)
            cross.rollback()
        finally:
            cross.close()
        with psycopg.connect(DSN) as connection:
            event_id = connection.execute("select lifecycle_event_id from public.avuhz_lifecycle_events where tenant_id=%s limit 1", (TENANT_A,)).fetchone()[0]
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                connection.execute("insert into public.avuhz_outbox_deliveries (tenant_id,lifecycle_event_id,status) values (%s,%s,'PENDING')", (TENANT_B, event_id))
        self.assertEqual((self.count("avuhz_engagements"), self.count("avuhz_diagnostic_scopes"), self.count("avuhz_human_approvals")), (1, 1, 2))

    def test_approval_binding_version_digest_action_set_and_success_atomicity(self):
        self.establish()
        self.assertEqual((self.count("avuhz_diagnostic_scopes"), self.count("avuhz_idempotency_records"), self.count("avuhz_lifecycle_events"), self.count("avuhz_outbox_deliveries")), (1, 4, 4, 4))
        with psycopg.connect(DSN) as connection:
            self.assertEqual(connection.execute("select processing_status from public.avuhz_idempotency_records where tenant_id=%s and command_type='CanonicalizeDiagnosticScope'", (TENANT_A,)).fetchone()[0], "COMPLETED")
            self.assertEqual(connection.execute("select status from public.avuhz_outbox_deliveries where tenant_id=%s order by created_at desc limit 1", (TENANT_A,)).fetchone()[0], "PENDING")
        self.approve()
        self.assertEqual((self.count("avuhz_human_approvals"), self.count("avuhz_idempotency_records"), self.count("avuhz_lifecycle_events"), self.count("avuhz_outbox_deliveries")), (2, 7, 7, 7))
        with psycopg.connect(DSN) as connection:
            self.assertEqual(connection.execute("select count(*) from public.avuhz_idempotency_records where tenant_id=%s and processing_status='COMPLETED'", (TENANT_A,)).fetchone()[0], 7)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_outbox_deliveries where tenant_id=%s and status='PENDING'", (TENANT_A,)).fetchone()[0], 7)
        # A durable approval pins scope version through the composite FK; a version N -> N+1
        # rewrite is rejected, rather than allowing N's approval to be repurposed.
        with psycopg.connect(DSN) as connection:
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                connection.execute("update public.avuhz_diagnostic_scopes set scope_version=2 where tenant_id=%s and diagnostic_scope_id=%s", (TENANT_A, SCOPE))
        # The finalizer independently rejects changed digest/action-set bindings (including
        # defensive database states that normal commands never fabricate).
        for field, value in (("canonical_scope_digest", "sha256:" + "b" * 64), ("action_set_version", 2)):
            self.setUp(); self.establish()
            self.assertEqual(self.execute("RecordHumanApproval", "p4b-binding-client-0001", "d4000000-0000-4000-8000-000000000010", role="CLIENT_DECISION_AUTHORITY", version=2)["result"], "ACCEPTED")
            self.assertEqual(self.execute("RecordHumanApproval", "p4b-binding-sekinfra-0001", "d4000000-0000-4000-8000-000000000011", role="SEKINFRA_ENGAGEMENT_AUTHORITY", version=2)["result"], "ACCEPTED")
            with psycopg.connect(DSN) as connection:
                connection.execute(f"update public.avuhz_diagnostic_scopes set {field}=%s where tenant_id=%s and diagnostic_scope_id=%s", (value, TENANT_A, SCOPE))
            final = self.raw("ApproveDiagnosticScope", "p4b-binding-final-0001", "d4000000-0000-4000-8000-000000000012", 2)
            final["payload"].update(scope_content_digest=self.scope()["canonical_scope_digest"],
                client_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"d4000000-0000-4000-8000-000000000010","reference_version":1},
                sekinfra_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"d4000000-0000-4000-8000-000000000011","reference_version":1})
            self.assertEqual(self.executor.execute(final, context("ApproveDiagnosticScope"))["result"], "REJECTED")
            self.assertEqual(self.scope()["status"], "REVIEW_PENDING")


if __name__ == "__main__":
    unittest.main()
