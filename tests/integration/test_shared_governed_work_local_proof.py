"""Focused client-neutral LOCAL/TEST governed Work Item proof.

The PostgreSQL cases are opt-in and use only the existing disposable PG17
fixture.  The injected n8n transport uses the canonical LOCAL/TEST receipt
store; it is not a running n8n workflow and does not certify hosted n8n,
AUTH/DATA providers, PostgreSQL when skipped, or a real owner/tenant.
"""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from unittest.mock import patch

from avuhz_service.shared_acquisition_work_handoff import (
    SharedAcquisitionWorkHandoff,
)
from avuhz_service.shared_governed_work_local_proof import (
    SharedGovernedWorkLocalProof,
    SharedGovernedWorkLocalProofUnavailable,
)
from avuhz_service.shared_work_intake_postgres_candidate import DurableWorkReceipt
from avuhz_worker.local_unattended_n8n_dispatch import (
    LocalN8nDispatchConfig,
    LocalN8nDispatchSummary,
    LocalN8nOutboxDispatcher,
)
from avuhz_worker.local_n8n_receipt_store import (
    ConflictingReceipt,
    InvalidReceipt,
    LocalN8nReceiptStore,
    ReceiptStoreUnavailable,
    UnauthorizedReceipt,
)


class SharedGovernedWorkCoordinatorTests(unittest.TestCase):
    """Always-run ordering checks without claiming database integration."""

    def setUp(self):
        self.handoff = object.__new__(SharedAcquisitionWorkHandoff)
        self.dispatcher = object.__new__(LocalN8nOutboxDispatcher)
        self.receipt_checks = []
        self.proof = SharedGovernedWorkLocalProof(
            self.handoff, self.dispatcher,
            receipt_committed=lambda receipt: self.receipt_checks.append(receipt) or True,
        )

    def test_authoritative_return_precedes_dispatch_and_replay_can_drain(self):
        order = []
        receipt = DurableWorkReceipt("a4730000-0000-4000-8000-000000000021", 1, False,
                                     "a4730000-0000-4000-8000-000000000051")
        summary = LocalN8nDispatchSummary(1, 1, 1, 0, 0, "CYCLE_LIMIT")
        with (
            patch.object(SharedAcquisitionWorkHandoff, "open",
                         side_effect=lambda *_: order.append("committed") or receipt),
            patch.object(LocalN8nOutboxDispatcher, "run_until_stopped",
                         side_effect=lambda *_: order.append("dispatched") or summary),
        ):
            outcome = self.proof.run("fictional-evidence", receipt.work_item_id, stop=Event())
        self.assertEqual(order, ["committed", "dispatched"])
        self.assertEqual(outcome.work, receipt)
        self.assertEqual(outcome.dispatch, summary)
        self.assertEqual(self.receipt_checks, [receipt])

        replay = dataclasses.replace(receipt, replayed=True, event_id=None)
        with (
            patch.object(SharedAcquisitionWorkHandoff, "open", return_value=replay),
            patch.object(LocalN8nOutboxDispatcher, "run_until_stopped",
                         return_value=LocalN8nDispatchSummary(1, 0, 0, 0, 0, "CYCLE_LIMIT")) as run,
        ):
            self.assertTrue(self.proof.run(
                "fictional-evidence", receipt.work_item_id, stop=Event()).work.replayed)
        run.assert_called_once()

    def test_missing_target_receipt_or_unpublished_new_event_fails_closed(self):
        receipt = DurableWorkReceipt("a4730000-0000-4000-8000-000000000021", 1, False,
                                     "a4730000-0000-4000-8000-000000000051")
        for summary, committed in (
            (LocalN8nDispatchSummary(1, 1, 0, 1, 0, "CYCLE_LIMIT"), True),
            (LocalN8nDispatchSummary(1, 1, 1, 0, 0, "CYCLE_LIMIT"), False),
        ):
            with self.subTest(summary=summary, committed=committed):
                proof = SharedGovernedWorkLocalProof(
                    self.handoff, self.dispatcher,
                    receipt_committed=lambda _receipt, value=committed: value,
                )
                with (
                    patch.object(SharedAcquisitionWorkHandoff, "open", return_value=receipt),
                    patch.object(LocalN8nOutboxDispatcher, "run_until_stopped",
                                 return_value=summary),
                    self.assertRaises(SharedGovernedWorkLocalProofUnavailable),
                ):
                    proof.run("fictional-evidence", receipt.work_item_id, stop=Event())

    def test_denial_or_transaction_failure_never_starts_dispatch(self):
        with (
            patch.object(SharedAcquisitionWorkHandoff, "open",
                         side_effect=RuntimeError("raw database detail")),
            patch.object(LocalN8nOutboxDispatcher, "run_until_stopped") as run,
            self.assertRaisesRegex(
                SharedGovernedWorkLocalProofUnavailable,
                "^governed work local proof unavailable$",
            ),
        ):
            self.proof.run("forged", "a4730000-0000-4000-8000-000000000021", stop=Event())
        run.assert_not_called()

    def test_pre_stopped_dispatch_is_rejected_before_business_mutation(self):
        stopped = Event()
        stopped.set()
        with patch.object(SharedAcquisitionWorkHandoff, "open") as opened:
            with self.assertRaises(SharedGovernedWorkLocalProofUnavailable):
                self.proof.run("fictional-evidence", "a4730000-0000-4000-8000-000000000021",
                               stop=stopped)
        opened.assert_not_called()


from tests.integration import test_shared_acquisition_work_handoff_postgres as acquisition

if acquisition.fixture.DRIVER:
    from avuhz_runtime.guards import TrustedExecutionContext
    from avuhz_runtime.postgres import PostgresUnitOfWork
    from avuhz_worker.n8n_event_sink import N8nOutboxSink
    from avuhz_worker.outbox import DeliveryRejected, OutboxWorker, WorkerSettings


class _CanonicalDurableWorkReceiver:
    """Synthetic transport around the canonical LOCAL/TEST receipt store."""

    def __init__(self, path: Path, case) -> None:
        self.path = path
        self.case = case
        self.calls = 0
        self.status = 202
        self.envelopes = {}
        self.store = LocalN8nReceiptStore(
            path,
            trusted_tenant_id=acquisition.TENANT,
            allowed_event_types=frozenset({"work_intake.opened"}),
        )

    def post(self, _url, headers, raw) -> int:
        envelope = json.loads(raw)
        # The transport cannot be reached until all four transaction records
        # are externally visible, proving dispatch is post-commit.
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records",
            "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
        ):
            if len(self.case.table(table)) != 1:
                raise AssertionError("pre-commit dispatch")
        if self.status != 202:
            return self.status
        try:
            receipt = self.store.receive(
                envelope, delivery_header=headers.get("X-Avuhz-Delivery-Key")
            )
        except UnauthorizedReceipt:
            return 403
        except ConflictingReceipt:
            return 409
        except InvalidReceipt:
            return 400
        except ReceiptStoreUnavailable:
            return 503
        reference_id = envelope["authoritative_subject_reference"]["reference_id"]
        self.envelopes[(envelope["event_id"], reference_id)] = envelope
        self.calls += 1
        return receipt.status

    def count(self) -> int:
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT count(*) FROM local_n8n_receipts"
            ).fetchone()[0]

    def committed(self, work: DurableWorkReceipt) -> bool:
        candidates = [
            envelope for (event_id, subject_id), envelope in self.envelopes.items()
            if subject_id == work.work_item_id
            and (work.event_id is None or event_id == work.event_id)
        ]
        return len(candidates) == 1 and self.store.committed(
            candidates[0], delivery_header=candidates[0]["delivery_idempotency_key"]
        )


@unittest.skipUnless(
    acquisition.fixture.DRIVER and acquisition.fixture.DSN and acquisition.fixture.CONTAINER,
    "disposable PG17, pinned psycopg and local DSN required",
)
class SharedGovernedWorkRealLocalPostgresTests(unittest.TestCase):
    """Real canonical transaction/outbox and canonical LOCAL receipt store."""

    def setUp(self):
        # Manual nested TestCase composition must not bypass the canonical
        # localhost/disposable-DSN/container safety preflight.
        acquisition.fixture.SharedDurableWorkIntakePostgresTests.setUpClass()
        self.addCleanup(
            acquisition.fixture.SharedDurableWorkIntakePostgresTests.tearDownClass
        )
        self.journey = acquisition.SharedAcquisitionFullLocalPostgresJourney(
            methodName="test_complete_shared_acquisition_to_due_replay_and_handoff"
        )
        self.addCleanup(self.journey.doCleanups)
        self.journey.setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-governed-work-proof-")
        self.addCleanup(self.temp.cleanup)
        self.receiver = _CanonicalDurableWorkReceiver(
            Path(self.temp.name) / "receipts.sqlite", self.journey.case,
        )
        self.sink = N8nOutboxSink(
            environment="TEST", tenant_id=acquisition.TENANT,
            endpoint="https://n8n.example.invalid/webhook/avuhz-events",
            expected_host="n8n.example.invalid",
            credential_provider=lambda: "fictional-local-credential",
            post=self.receiver.post,
        )
        context = TrustedExecutionContext(
            True, "service.outbox-worker-local", "INTERNAL_SERVICE", acquisition.TENANT,
            None, frozenset({"event:publish_internal"}), frozenset(), "TEST",
            "avuhz-command-api", "STRONG", False, "2026-10-18T00:00:00Z",
            "2099-01-01T00:00:00Z",
        )
        worker = OutboxWorker(
            self.journey.case.store, PostgresUnitOfWork, self.sink, context,
            WorkerSettings(tenant_id=acquisition.TENANT),
            clock=lambda: datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc),
        )
        self.dispatcher = LocalN8nOutboxDispatcher(
            worker, LocalN8nDispatchConfig(acquisition.TENANT, 1, 1),
        )
        self.proof = SharedGovernedWorkLocalProof(
            self.journey.handoff, self.dispatcher,
            receipt_committed=self.receiver.committed,
        )

    def _run(self, evidence="sender", intake=acquisition.INTAKE):
        signal = Event()
        with patch.object(signal, "wait", return_value=False):
            return self.proof.run(evidence, intake, stop=signal)

    def _assert_zero_authoritative_effects(self):
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records",
            "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
        ):
            self.assertEqual(self.journey.case.table(table), [], table)
        self.assertEqual(self.receiver.count(), 0)

    def test_one_atomic_work_and_durable_post_commit_receipt_with_exact_replay(self):
        created = self._run()
        self.assertEqual((created.work.replayed, created.dispatch.published), (False, 1))
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records",
            "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
        ):
            self.assertEqual(len(self.journey.case.table(table)), 1, table)
        self.assertEqual(self.receiver.count(), 1)
        before_replay = {
            table: self.journey.case.table(table)
            for table in (
                "avuhz_work_items", "avuhz_idempotency_records",
                "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
            )
        }
        replay = self._run()
        self.assertEqual((replay.work.replayed, replay.dispatch.claimed), (True, 0))
        for table, rows in before_replay.items():
            self.assertEqual(self.journey.case.table(table), rows, table)
        self.assertEqual(self.receiver.count(), 1)
        self.assertEqual(self.receiver.calls, 1)
        event = self.journey.case.table("avuhz_lifecycle_events")[0]
        self.assertEqual(set(event["sanitized_metadata"]), {"work_item_id", "state"})

    def test_all_authority_denials_and_stale_intake_have_zero_side_effects(self):
        original = self.journey.case.evidence["sender"]
        attempts = [
            lambda: self._run("outside"),
            lambda: self._run(original),
        ]
        self.journey.case.members[acquisition.TENANT].remove("worker.sender")
        attempts.append(lambda: self._run("sender"))
        for attempt in attempts:
            with self.assertRaises(SharedGovernedWorkLocalProofUnavailable):
                attempt()
            self._assert_zero_authoritative_effects()
        self.journey.case.members[acquisition.TENANT].add("worker.sender")
        for changed in (
            dataclasses.replace(original, organization_id=acquisition.OTHER_ORG),
            dataclasses.replace(original, capabilities=frozenset()),
        ):
            self.journey.case.evidence["sender"] = changed
            with self.assertRaises(SharedGovernedWorkLocalProofUnavailable):
                self._run()
            self._assert_zero_authoritative_effects()
        self.journey.case.evidence["sender"] = original
        with self.journey.case.owner() as con:
            con.execute(
                "UPDATE public.avuhz_acquisition_intake_requests "
                "SET record_version=2 WHERE intake_id=%s", (acquisition.INTAKE,),
            )
        with self.assertRaises(SharedGovernedWorkLocalProofUnavailable):
            self._run()
        self._assert_zero_authoritative_effects()

    def test_transaction_failure_rolls_back_and_prevents_receipt(self):
        self.journey.case.store.fail_stage = "OUTBOX_APPEND"
        with self.assertRaisesRegex(
            SharedGovernedWorkLocalProofUnavailable,
            "^governed work local proof unavailable$",
        ):
            self._run()
        self._assert_zero_authoritative_effects()

    def test_dispatch_failure_is_post_commit_and_persists_only_safe_code(self):
        self.receiver.status = 503
        with self.assertRaisesRegex(
            SharedGovernedWorkLocalProofUnavailable,
            "^governed work local proof unavailable$",
        ):
            self._run()
        for table in (
            "avuhz_work_items", "avuhz_idempotency_records", "avuhz_lifecycle_events",
        ):
            self.assertEqual(len(self.journey.case.table(table)), 1, table)
        delivery = self.journey.case.table("avuhz_outbox_deliveries")[0]
        self.assertEqual(
            (delivery["status"], delivery["last_safe_error_code"], delivery["attempt_count"]),
            ("FAILED_RETRYABLE", "DELIVERY_UNAVAILABLE", 1),
        )
        self.assertEqual(self.receiver.count(), 0)

    def test_forged_event_or_receipt_cannot_mutate_authoritative_tables(self):
        self._run()
        before = {
            table: len(self.journey.case.table(table))
            for table in ("avuhz_work_items", "avuhz_idempotency_records",
                          "avuhz_lifecycle_events", "avuhz_outbox_deliveries")
        }
        event = dict(self.journey.case.table("avuhz_lifecycle_events")[0])
        event["event_id"] = str(event.pop("lifecycle_event_id"))
        event["authoritative_subject_reference"] = {
            "reference_type": event.pop("authoritative_subject_type"),
            "reference_id": str(event.pop("authoritative_subject_id")),
        }
        event["tenant_id"] = acquisition.OUTSIDE_TENANT
        with self.assertRaises(DeliveryRejected):
            self.sink.deliver("outbox-delivery:forged-work-event", event,
                              "2030-01-15T15:00:00Z")
        forged = {
            "event_id": "a4730000-0000-4000-8000-000000000099",
            "event_type": "work_intake.opened", "tenant_id": acquisition.OUTSIDE_TENANT,
            "correlation_id": "a4730000-0000-4000-8000-000000000098",
            "occurred_at": "2030-01-15T15:00:00Z",
            "authoritative_subject_reference": {
                "reference_type": "WORK_ITEM", "reference_id": acquisition.INTAKE,
            },
            "authoritative_subject_version": 1,
            "delivery_idempotency_key": "outbox-delivery:forged-work-event",
        }
        self.assertEqual(self.receiver.post("", {"X-Avuhz-Delivery-Key":
                         forged["delivery_idempotency_key"]}, json.dumps(forged).encode()), 403)
        self.assertEqual(before, {table: len(self.journey.case.table(table)) for table in before})
        self.assertEqual(self.receiver.count(), 1)


if __name__ == "__main__":
    unittest.main()
