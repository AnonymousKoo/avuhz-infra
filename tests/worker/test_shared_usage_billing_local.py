"""Focused certification for the shared LOCAL/TEST usage and billing fake.

Direct sink calls exercise validation only.  The sink cannot attest caller or
committed-event authority; supported composition is behind OutboxWorker.
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
from avuhz_worker.shared_usage_billing_local import (
    DeterministicLocalUsageBillingFake,
    SharedUsageMeteringAdapter,
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
        "idempotency_key": "usage-fixture-idempotency-0001",
        "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {"engagement_id": ENGAGEMENT_ID},
    }
    value.update(changes)
    return value


def fake(*, trusted=None, outcomes=()):
    return DeterministicLocalUsageBillingFake(
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


class SharedUsageBillingLocalTests(unittest.TestCase):
    def test_worker_records_one_immutable_unpriced_measurement(self):
        trusted = context(); sink = fake(trusted=trusted); source = event()
        store, active = worker(source, sink, trusted=trusted)
        self.assertIsInstance(sink, SharedUsageMeteringAdapter)
        self.assertEqual(active.run_once(), {
            "claimed": 1, "published": 1, "retry_scheduled": 0, "dead_lettered": 0,
        })
        record = sink.records[0]
        self.assertEqual(
            (record.tenant_id, record.metric, record.unit, record.measured_quantity,
             record.billing_effect, store.outbox[0]["status"]),
            (TENANT, "engagement_opened", "governed_event", 1, "NONE", "PUBLISHED"),
        )
        self.assertEqual(store.events, [source])
        for prohibited in ("price", "amount", "currency", "invoice", "payment", "address"):
            self.assertFalse(hasattr(record, prohibited))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.measured_quantity = 2

    def test_exact_replay_returns_same_stable_record(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        first = sink.deliver(key, event(), timestamp())
        replay = sink.deliver(key, copy.deepcopy(event()), timestamp(T0 + timedelta(seconds=1)))
        self.assertEqual((first.disposition, replay.disposition), ("RECORDED", "DUPLICATE"))
        self.assertIs(first.record, replay.record)
        self.assertEqual(len(sink.records), 1)
        self.assertEqual(
            first.record.usage_record_id,
            "eaa769ba-bfb3-5127-9a64-93213e3b0094",
        )

    def test_changed_semantics_collide_terminally(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        sink.deliver(key, event(), timestamp())
        with self.assertRaisesRegex(DeliveryRejected, "^USAGE_IDENTITY_COLLISION$"):
            sink.deliver(key, event(authoritative_subject_version=2), timestamp())
        self.assertEqual(len(sink.records), 1)

    def test_foreign_tenant_and_cross_tenant_replay_are_denied(self):
        sink = fake(); key = "outbox-delivery:" + EVENT_ID
        sink.deliver(key, event(), timestamp())
        with self.assertRaisesRegex(DeliveryRejected, "^USAGE_EVENT_REJECTED$"):
            sink.deliver(key, event(tenant_id=OTHER_TENANT), timestamp())
        with self.assertRaises(ValueError):
            fake(trusted=context(tenant=OTHER_TENANT))
        self.assertEqual(len(sink.records), 1)

    def test_identity_reference_and_worker_key_must_match(self):
        cases = (
            ({"engagement_id": EVENT_ID}, "outbox-delivery:" + EVENT_ID),
            ({"subject_id": EVENT_ID}, "outbox-delivery:" + EVENT_ID),
            ({"authoritative_subject_reference": {
                "reference_type": "WORK_ITEM", "reference_id": ENGAGEMENT_ID,
            }}, "outbox-delivery:" + EVENT_ID),
            ({"authoritative_subject_reference": {
                "reference_type": "ENGAGEMENT", "reference_id": EVENT_ID,
            }}, "outbox-delivery:" + EVENT_ID),
            ({}, "outbox-delivery:" + CORRELATION_ID),
        )
        for changes, key in cases:
            with self.subTest(changes=changes, key=key), self.assertRaises(DeliveryRejected):
                fake().deliver(key, event(**changes), timestamp())

    def test_only_narrow_event_and_metadata_without_client_quantity_are_allowed(self):
        for changes in (
            {"event_type": "work_intake.opened"},
            {"event_schema_version": 2},
            {"visibility": "INTEGRATION_INTERNAL"},
            {"sanitized_metadata": {"engagement_id": ENGAGEMENT_ID, "usage_quantity": 50}},
            {"sanitized_metadata": {"engagement_id": ENGAGEMENT_ID, "contact_email": "x@example.invalid"}},
            {"sanitized_metadata": {"engagement_id": ENGAGEMENT_ID, "note": "x" * 17_000}},
        ):
            with self.subTest(changes=changes), self.assertRaises(DeliveryRejected):
                fake().deliver("outbox-delivery:" + EVENT_ID, event(**changes), timestamp())

        deeply_nested = {}
        cursor = deeply_nested
        for _ in range(2_000):
            cursor["nested"] = {}
            cursor = cursor["nested"]
        with self.assertRaisesRegex(DeliveryRejected, "^USAGE_EVENT_REJECTED$"):
            fake().deliver(
                "outbox-delivery:" + EVENT_ID,
                event(sanitized_metadata=deeply_nested),
                timestamp(),
            )

    def test_untrusted_direct_composition_and_unknown_outcome_fail_closed(self):
        for trusted in (context(caller_type="HUMAN"), context(capabilities=frozenset())):
            with self.subTest(caller=trusted.caller_type), self.assertRaises(ValueError):
                fake(trusted=trusted)
        with self.assertRaises(ValueError):
            fake(outcomes=("CHARGED",))

    def test_concurrent_duplicates_create_exactly_one_record(self):
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
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual((results.count("RECORDED"), results.count("DUPLICATE")), (1, 7))
        self.assertEqual(len(sink.records), 1)

    def test_transient_failure_uses_canonical_worker_retry(self):
        clock = MutableClock(); sink = fake(outcomes=("DELIVERY_UNAVAILABLE", "RECORDED"))
        store, active = worker(event(), sink, clock)
        self.assertEqual(active.run_once()["retry_scheduled"], 1)
        self.assertEqual((store.outbox[0]["last_safe_error_code"], len(sink.records)),
                         ("DELIVERY_UNAVAILABLE", 0))
        clock.advance(5)
        self.assertEqual(active.run_once()["published"], 1)
        self.assertEqual(len(sink.records), 1)
        self.assertEqual([attempt["outcome"] for attempt in store.outbox[0]["attempt_history"]],
                         ["FAILED_RETRYABLE", "PUBLISHED"])

    def test_invalid_event_is_terminal_with_safe_worker_error_only(self):
        source = event(sanitized_metadata={
            "engagement_id": ENGAGEMENT_ID, "contact_email": "x@example.invalid",
        })
        sink = fake(); store, active = worker(source, sink)
        self.assertEqual(active.run_once(), {
            "claimed": 1, "published": 0, "retry_scheduled": 0, "dead_lettered": 1,
        })
        self.assertEqual(store.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_REJECTED")
        self.assertNotIn("contact_email", str(store.outbox[0]))
        self.assertEqual(sink.records, ())
        self.assertEqual(store.events, [source])

    def test_retry_after_post_effect_commit_interruption_does_not_duplicate(self):
        clock = MutableClock(); sink = fake(); source = event()
        store = MemoryStore(
            events=[copy.deepcopy(source)],
            outbox=[{"event_id": EVENT_ID, "status": "PENDING"}],
        )
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
        self.assertEqual(len(sink.records), 1)
        clock.advance(6)
        restarted = OutboxWorker(
            store, MemoryOutboxUnitOfWork, sink, context(),
            WorkerSettings(tenant_id=TENANT, lease_seconds=5), clock=clock,
        )
        self.assertEqual(restarted.run_once()["published"], 1)
        self.assertEqual(len(sink.records), 1)


if __name__ == "__main__":
    unittest.main()
