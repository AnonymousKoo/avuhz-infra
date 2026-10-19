"""Focused certification for the deterministic shared communications fake.

The fake is LOCAL/TEST-only and assumes trusted in-process OutboxWorker
composition.  Its sink protocol has no caller or committed-claim attestation;
direct calls below exercise sink validation but do not model authorization.
"""
from __future__ import annotations

import copy
import dataclasses
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore
from avuhz_worker.outbox import (
    DeliveryRejected,
    MemoryOutboxUnitOfWork,
    OutboxWorker,
    WorkerSettings,
)
from avuhz_worker.shared_communications_local import (
    DeterministicLocalCommunicationsFake,
    SharedCommunicationsAdapter,
)


TENANT = "f1000000-0000-4000-8000-000000000001"
OTHER_TENANT = "f1000000-0000-4000-8000-000000000002"
EVENT_ID = "f2000000-0000-4000-8000-000000000001"
CORRELATION_ID = "f2000000-0000-4000-8000-000000000002"
ENGAGEMENT_ID = "f2000000-0000-4000-8000-000000000003"
COMMAND_ID = "f2000000-0000-4000-8000-000000000004"
T0 = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self): self.value = T0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += timedelta(seconds=seconds)


def timestamp(value=T0):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def context(*, tenant=TENANT, caller_type="INTERNAL_SERVICE", capabilities=None):
    capabilities = frozenset({"event:publish_internal"}) if capabilities is None else capabilities
    return TrustedExecutionContext(
        True, "service.outbox-worker-local", caller_type, tenant, None,
        frozenset(capabilities), frozenset(), "TEST", "avuhz-command-api",
        "STRONG", False, timestamp(), "2031-01-15T15:00:00Z",
        human_authority_role=None,
    )


def event(**changes):
    value = {
        "event_id": EVENT_ID, "event_type": "engagement.opened", "event_schema_version": 1,
        "tenant_id": TENANT,
        "authoritative_subject_reference": {
            "reference_type": "ENGAGEMENT", "reference_id": ENGAGEMENT_ID,
        },
        "engagement_id": ENGAGEMENT_ID,
        "authoritative_subject_version": 1, "occurred_at": timestamp(),
        "producer_reference": "command.service-01", "correlation_id": CORRELATION_ID,
        "command_id": COMMAND_ID, "subject_id": ENGAGEMENT_ID,
        "idempotency_key": "communications-fixture-idempotency-0001",
        "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {"engagement_id": ENGAGEMENT_ID},
    }
    value.update(changes)
    return value


def fake(*, trusted=None, outcomes=()):
    return DeterministicLocalCommunicationsFake(
        tenant_id=TENANT, environment="TEST", trusted_context=trusted or context(), outcomes=outcomes,
    )


def worker(source, sink, clock=None, trusted=None):
    store = MemoryStore(
        events=[copy.deepcopy(source)], outbox=[{"event_id": source["event_id"], "status": "PENDING"}],
    )
    active_clock = clock or MutableClock()
    return store, OutboxWorker(
        store, MemoryOutboxUnitOfWork, sink, trusted or context(),
        WorkerSettings(tenant_id=TENANT, destination_reference="internal.lifecycle-events"),
        clock=active_clock,
    )


class SharedCommunicationsLocalTests(unittest.TestCase):
    def test_canonical_worker_delivers_one_immutable_internal_receipt(self):
        trusted = context()
        sink = fake(trusted=trusted)
        source = event()
        store, active = worker(source, sink, trusted=trusted)
        self.assertIsInstance(sink, SharedCommunicationsAdapter)
        self.assertEqual(active.run_once(), {
            "claimed": 1, "published": 1, "retry_scheduled": 0, "dead_lettered": 0,
        })
        receipt = sink.receipts[0]
        self.assertEqual((receipt.channel, receipt.tenant_id, store.outbox[0]["status"]),
                         ("INTERNAL_NOTIFICATION", TENANT, "PUBLISHED"))
        self.assertEqual(store.events, [source])
        self.assertFalse(hasattr(receipt, "address"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.channel = "EMAIL"

    def test_replay_returns_same_receipt_without_second_effect(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        first = sink.deliver(key, event(), timestamp())
        replay = sink.deliver(key, copy.deepcopy(event()), timestamp(T0 + timedelta(seconds=1)))
        self.assertEqual((first.disposition, replay.disposition), ("PUBLISHED", "DUPLICATE"))
        self.assertIs(first.receipt, replay.receipt)
        self.assertEqual(len(sink.receipts), 1)

    def test_same_identity_with_changed_semantics_is_terminal(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        sink.deliver(key, event(), timestamp())
        changed = event(authoritative_subject_version=2)
        with self.assertRaisesRegex(DeliveryRejected, "^COMMUNICATION_IDENTITY_COLLISION$"):
            sink.deliver(key, changed, timestamp())
        self.assertEqual(len(sink.receipts), 1)

    def test_cross_tenant_replay_is_denied(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        sink.deliver(key, event(), timestamp())
        foreign = event(tenant_id=OTHER_TENANT)
        with self.assertRaisesRegex(DeliveryRejected, "^COMMUNICATION_EVENT_REJECTED$"):
            sink.deliver(key, foreign, timestamp())
        self.assertEqual(len(sink.receipts), 1)

    def test_exact_schema_version_and_engagement_identity_are_required(self):
        for changes in (
            {"event_schema_version": 2},
            {"engagement_id": EVENT_ID},
            {"subject_id": EVENT_ID},
            {"authoritative_subject_reference": {
                "reference_type": "WORK_ITEM", "reference_id": ENGAGEMENT_ID,
            }},
            {"authoritative_subject_reference": {
                "reference_type": "ENGAGEMENT", "reference_id": EVENT_ID,
            }},
        ):
            with self.subTest(changes=changes), self.assertRaises(DeliveryRejected):
                fake().deliver("outbox-delivery:" + EVENT_ID,
                               event(**changes), timestamp())

    def test_unsafe_text_and_oversize_metadata_are_denied(self):
        for metadata in (
            {"engagement_id": ENGAGEMENT_ID, "name": "Fictional Person"},
            {"engagement_id": ENGAGEMENT_ID, "message": "x" * 17_000},
        ):
            with self.subTest(keys=tuple(metadata)), self.assertRaises(DeliveryRejected):
                fake().deliver("outbox-delivery:" + EVENT_ID,
                               event(sanitized_metadata=metadata), timestamp())

    def test_unknown_event_and_channel_are_denied(self):
        with self.assertRaises(DeliveryRejected):
            fake().deliver("outbox-delivery:" + EVENT_ID,
                           event(event_type="work_intake.opened"), timestamp())
        with self.assertRaises(ValueError):
            DeterministicLocalCommunicationsFake(
                tenant_id=TENANT, environment="TEST", trusted_context=context(), channel="EMAIL",
            )

    def test_direct_user_or_unprivileged_context_fails_closed(self):
        for trusted in (context(caller_type="HUMAN"), context(capabilities=frozenset())):
            with self.subTest(caller=trusted.caller_type), self.assertRaises(ValueError):
                fake(trusted=trusted)

    def test_concurrent_duplicates_create_exactly_one_effect(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        barrier = threading.Barrier(9); results = []; errors = []
        def deliver():
            try:
                barrier.wait(); results.append(sink.deliver(key, event(), timestamp()).disposition)
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=deliver) for _ in range(8)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(timeout=3)
        self.assertFalse(errors)
        self.assertEqual((results.count("PUBLISHED"), results.count("DUPLICATE")), (1, 7))
        self.assertEqual(len(sink.receipts), 1)

    def test_retryable_failure_then_worker_retry_creates_only_one_receipt(self):
        clock = MutableClock(); sink = fake(outcomes=("DELIVERY_UNAVAILABLE", "PUBLISHED"))
        store, active = worker(event(), sink, clock)
        self.assertEqual(active.run_once()["retry_scheduled"], 1)
        self.assertEqual((store.outbox[0]["last_safe_error_code"], len(sink.receipts)),
                         ("DELIVERY_UNAVAILABLE", 0))
        clock.advance(5)
        self.assertEqual(active.run_once()["published"], 1)
        self.assertEqual(len(sink.receipts), 1)
        self.assertEqual([attempt["outcome"] for attempt in store.outbox[0]["attempt_history"]],
                         ["FAILED_RETRYABLE", "PUBLISHED"])

    def test_invalid_event_is_terminal_with_only_safe_worker_error(self):
        source = event(sanitized_metadata={
            "engagement_id": ENGAGEMENT_ID, "contact_email": "person@example.invalid",
        })
        sink = fake()
        store, active = worker(source, sink)
        self.assertEqual(active.run_once(), {
            "claimed": 1, "published": 0, "retry_scheduled": 0, "dead_lettered": 1,
        })
        self.assertEqual(store.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_REJECTED")
        self.assertNotIn("contact_email", str(store.outbox[0]))
        self.assertEqual(sink.receipts, ())
        self.assertEqual(store.events, [source])

    def test_retry_after_post_effect_worker_commit_failure_has_no_second_receipt(self):
        clock = MutableClock(); sink = fake(); source = event()
        store = MemoryStore(events=[copy.deepcopy(source)], outbox=[{"event_id": EVENT_ID, "status": "PENDING"}])
        class FailSecondCommit(MemoryOutboxUnitOfWork):
            count = 0
            def commit(self):
                type(self).count += 1
                if type(self).count == 2:
                    raise RuntimeError("injected worker commit failure")
                return super().commit()
        active = OutboxWorker(
            store, FailSecondCommit, sink, context(),
            WorkerSettings(tenant_id=TENANT, lease_seconds=5), clock=clock,
        )
        with self.assertRaises(RuntimeError): active.run_once()
        self.assertEqual(len(sink.receipts), 1)
        clock.advance(6)
        restarted = OutboxWorker(
            store, MemoryOutboxUnitOfWork, sink, context(),
            WorkerSettings(tenant_id=TENANT, lease_seconds=5), clock=clock,
        )
        self.assertEqual(restarted.run_once()["published"], 1)
        self.assertEqual(len(sink.receipts), 1)


if __name__ == "__main__":
    unittest.main()
