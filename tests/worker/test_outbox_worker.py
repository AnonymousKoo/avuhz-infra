"""Focused transactional outbox worker recovery certification."""
from __future__ import annotations

import copy
import json
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore
from avuhz_runtime.outbox_delivery import fail_delivery
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_worker import (
    DeliveryRejected,
    FakeLocalSink,
    MemoryOutboxUnitOfWork,
    OutboxWorker,
    WorkerSettings,
)

TENANT = "f1000000-0000-4000-8000-000000000001"
OTHER_TENANT = "f1000000-0000-4000-8000-000000000002"
EVENT_ID = "f2000000-0000-4000-8000-000000000001"
CORRELATION_ID = "f2000000-0000-4000-8000-000000000002"
SUBJECT_ID = "f2000000-0000-4000-8000-000000000003"
COMMAND_ID = "f2000000-0000-4000-8000-000000000004"
T0 = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value=T0): self.value = value
    def __call__(self): return self.value
    def advance(self, seconds): self.value += timedelta(seconds=seconds)


def timestamp(value=T0):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def event(*, tenant=TENANT, event_id=EVENT_ID):
    return {
        "event_id": event_id, "event_type": "engagement.opened", "event_schema_version": 1,
        "tenant_id": tenant,
        "authoritative_subject_reference": {"reference_type": "ENGAGEMENT", "reference_id": SUBJECT_ID},
        "authoritative_subject_version": 1, "occurred_at": timestamp(),
        "producer_reference": "command.service-01", "correlation_id": CORRELATION_ID,
        "command_id": COMMAND_ID, "subject_id": SUBJECT_ID,
        "idempotency_key": "worker-fixture-idempotency-0001", "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {"engagement_id": SUBJECT_ID},
    }


def context(*, tenant=TENANT, capabilities=frozenset({"event:publish_internal"}),
            authority_roles=frozenset(), caller_type="INTERNAL_SERVICE", expires_at="2031-01-15T15:00:00Z"):
    return TrustedExecutionContext(
        True, "service.outbox-worker-local", caller_type, tenant, None,
        frozenset(capabilities), frozenset(authority_roles), "TEST", "avuhz-command-api",
        "STRONG", False, timestamp(), expires_at,
        human_authority_role=next(iter(authority_roles), None),
    )


def store_for(source_event=None):
    source_event = event() if source_event is None else source_event
    return MemoryStore(events=[copy.deepcopy(source_event)], outbox=[{"event_id": source_event["event_id"], "status": "PENDING"}])


def make_worker(store, sink, clock, *, worker_reference="outbox.worker-01", trusted=None, **overrides):
    settings = WorkerSettings(
        tenant_id=TENANT, worker_reference=worker_reference,
        **overrides,
    )
    return OutboxWorker(
        store, MemoryOutboxUnitOfWork, sink, trusted or context(), settings, clock=clock,
    )


class OutboxWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        cls.delivery_validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:outbox-delivery:v1"),
            format_checker=FormatChecker(),
        )

    def assert_delivery_valid(self, value):
        errors = sorted(self.delivery_validator.iter_errors(value), key=lambda error: list(error.path))
        self.assertEqual([error.message for error in errors], [])

    def test_successful_fake_sink_delivery_is_canonical_and_does_not_mutate_domain_truth(self):
        store = store_for(); store.engagements[SUBJECT_ID] = {"tenant_id": TENANT, "truth": "unchanged"}
        before_domain = copy.deepcopy(store.engagements)
        sink = FakeLocalSink(); result = make_worker(store, sink, MutableClock()).run_once()
        self.assertEqual(result, {"claimed": 1, "published": 1, "retry_scheduled": 0, "dead_lettered": 0})
        delivery = store.outbox[0]
        self.assertEqual((delivery["status"], delivery["attempt_count"]), ("PUBLISHED", 1))
        self.assertEqual(delivery["attempt_history"][0]["outcome"], "PUBLISHED")
        self.assertEqual(sink.receipts[0]["correlation_id"], CORRELATION_ID)
        self.assertEqual(store.engagements, before_domain)
        self.assert_delivery_valid(delivery)

    def test_concurrent_workers_exclude_duplicate_claim_and_delivery(self):
        store = store_for(); sink = FakeLocalSink(); clock = MutableClock()
        workers = [make_worker(store, sink, clock, worker_reference=f"outbox.worker-0{index}") for index in (1, 2)]
        barrier = threading.Barrier(3); results = []; errors = []
        def run(worker):
            try:
                barrier.wait(); results.append(worker.run_once())
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=run, args=(worker,)) for worker in workers]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(timeout=3)
        self.assertFalse(errors)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(result["published"] for result in results), 1)
        self.assertEqual(len(sink.receipts), 1)
        self.assertEqual(store.outbox[0]["attempt_count"], 1)

    def test_expired_lease_is_recovered_as_traceable_new_attempt(self):
        store = store_for(); clock = MutableClock(); trusted = context()
        first = MemoryOutboxUnitOfWork(store); first.bind_trusted_context(trusted)
        claim = first.outbox.claim_next(
            TENANT, "outbox.worker-crashed", "internal.lifecycle-events",
            timestamp(clock()), timestamp(clock() + timedelta(seconds=5)), 3,
        )
        first.commit(); first.close()
        self.assertEqual(claim["delivery"]["status"], "PUBLISHING")
        clock.advance(6); sink = FakeLocalSink()
        result = make_worker(store, sink, clock, worker_reference="outbox.worker-recovery", max_attempts=3).run_once()
        self.assertEqual(result["published"], 1)
        delivery = store.outbox[0]
        self.assertEqual(delivery["attempt_count"], 2)
        self.assertEqual([item["outcome"] for item in delivery["attempt_history"]], ["LEASE_EXPIRED", "PUBLISHED"])
        self.assert_delivery_valid(delivery)

    def test_retry_uses_bounded_exponential_backoff_then_publishes(self):
        store = store_for(); clock = MutableClock(); sink = FakeLocalSink(["DELIVERY_UNAVAILABLE", "PUBLISHED"])
        worker = make_worker(store, sink, clock, base_backoff_seconds=5, max_backoff_seconds=20)
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        self.assertEqual(store.outbox[0]["next_attempt_at"], timestamp(T0 + timedelta(seconds=5)))
        clock.advance(4); self.assertEqual(worker.run_once()["claimed"], 0)
        clock.advance(1); self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual([item["outcome"] for item in store.outbox[0]["attempt_history"]], ["FAILED_RETRYABLE", "PUBLISHED"])
        self.assert_delivery_valid(store.outbox[0])

    def test_max_attempts_transitions_to_explicit_dead_letter(self):
        store = store_for(); clock = MutableClock(); sink = FakeLocalSink(["DELIVERY_UNAVAILABLE", "DELIVERY_UNAVAILABLE"])
        worker = make_worker(store, sink, clock, max_attempts=2, base_backoff_seconds=5)
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        clock.advance(5); self.assertEqual(worker.run_once()["dead_lettered"], 1)
        delivery = store.outbox[0]
        self.assertEqual((delivery["status"], delivery["attempt_count"], delivery["last_safe_error_code"]), ("FAILED_TERMINAL", 2, "DELIVERY_UNAVAILABLE"))
        self.assertEqual(len(delivery["attempt_history"]), 2)
        self.assertNotIn("next_attempt_at", delivery)
        self.assertEqual(store.events[0]["event_id"], EVENT_ID)
        self.assert_delivery_valid(delivery)

    def test_terminal_sink_rejection_does_not_retry(self):
        store = store_for(); sink = FakeLocalSink(["DELIVERY_REJECTED"])
        result = make_worker(store, sink, MutableClock()).run_once()
        self.assertEqual(result["dead_lettered"], 1)
        self.assertEqual(store.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_REJECTED")
        self.assertNotIn("fictional local sink", json.dumps(store.outbox[0]))
        self.assert_delivery_valid(store.outbox[0])

    def test_restart_after_post_sink_commit_interruption_is_idempotent(self):
        store = store_for(); clock = MutableClock(); sink = FakeLocalSink()
        class FailSecondCommit(MemoryOutboxUnitOfWork):
            count = 0
            def commit(self):
                type(self).count += 1
                if type(self).count == 2:
                    raise RuntimeError("injected post-sink commit interruption")
                return super().commit()
        worker = OutboxWorker(
            store, FailSecondCommit, sink, context(),
            WorkerSettings(tenant_id=TENANT, worker_reference="outbox.worker-crash", lease_seconds=5),
            clock=clock,
        )
        with self.assertRaises(RuntimeError): worker.run_once()
        self.assertEqual((store.outbox[0]["status"], len(sink.receipts)), ("PUBLISHING", 1))
        clock.advance(6)
        restarted = make_worker(store, sink, clock, worker_reference="outbox.worker-restarted", lease_seconds=5)
        self.assertEqual(restarted.run_once()["published"], 1)
        self.assertEqual(len(sink.receipts), 1)
        self.assertEqual(store.outbox[0]["status"], "PUBLISHED")
        self.assertEqual([item["outcome"] for item in store.outbox[0]["attempt_history"]], ["LEASE_EXPIRED", "PUBLISHED"])

    def test_fake_sink_replay_is_duplicate_and_semantic_mismatch_is_terminal(self):
        sink = FakeLocalSink(); source = event(); key = "outbox-delivery:" + EVENT_ID
        first = sink.deliver(key, source, timestamp())
        second = sink.deliver(key, copy.deepcopy(source), timestamp(T0 + timedelta(seconds=1)))
        self.assertEqual((first["result"], second["result"], len(sink.receipts)), ("PUBLISHED", "DUPLICATE", 1))
        changed = event(event_id="f2000000-0000-4000-8000-000000000099")
        with self.assertRaises(DeliveryRejected): sink.deliver(key, changed, timestamp())

    def test_missing_event_claim_is_terminal_and_records_only_safe_code(self):
        lease = "f3000000-0000-4000-8000-000000000001"
        delivery = {
            "outbox_delivery_id": "f3000000-0000-4000-8000-000000000002",
            "event_reference": {"reference_type": "LIFECYCLE_EVENT", "reference_id": EVENT_ID},
            "destination_reference": "internal.lifecycle-events", "status": "PUBLISHING",
            "attempt_count": 1, "attempt_history": [], "last_attempt_at": timestamp(),
            "lease_owner_reference": "outbox.worker-stub", "lease_token": lease,
            "lease_expires_at": timestamp(T0 + timedelta(seconds=30)), "last_safe_error_code": None,
            "delivery_idempotency_key": "outbox-delivery:" + EVENT_ID, "record_version": 2,
            "created_at": timestamp(), "updated_at": timestamp(),
        }
        class Repository:
            def __init__(self): self.claimed = False; self.record = copy.deepcopy(delivery)
            def claim_next(self, *args):
                if self.claimed: return None
                self.claimed = True
                return {"disposition": "CLAIMED", "delivery": copy.deepcopy(self.record), "event": None}
            def mark_failed(self, tenant_id, delivery_id, lease_token, failed_at, safe_error_code, next_attempt_at):
                self.record = fail_delivery(self.record, lease_token, failed_at, safe_error_code, next_attempt_at)
                return copy.deepcopy(self.record)
        repository = Repository()
        class Uow:
            def __init__(self, store): self.outbox = repository
            def bind_trusted_context(self, trusted): pass
            def commit(self): pass
            def rollback(self): pass
            def close(self): pass
        result = OutboxWorker(
            object(), Uow, FakeLocalSink(), context(), WorkerSettings(tenant_id=TENANT), clock=MutableClock(),
        ).run_once()
        self.assertEqual(result["dead_lettered"], 1)
        self.assertEqual((repository.record["status"], repository.record["last_safe_error_code"]), ("FAILED_TERMINAL", "EVENT_UNAVAILABLE"))
        self.assert_delivery_valid(repository.record)

    def test_tenant_and_trusted_worker_isolation_fail_closed(self):
        foreign = event(tenant=OTHER_TENANT)
        store = store_for(foreign); sink = FakeLocalSink(); clock = MutableClock()
        self.assertEqual(make_worker(store, sink, clock).run_once()["claimed"], 0)
        self.assertEqual(store.outbox, [{"event_id": EVENT_ID, "status": "PENDING"}])
        for trusted in (
            context(tenant=OTHER_TENANT), context(capabilities=frozenset()),
            context(authority_roles=frozenset({"CLIENT_DEPLOYMENT_AUTHORITY"})),
            context(caller_type="HUMAN"), context(expires_at=timestamp()),
        ):
            with self.assertRaises(ValueError):
                make_worker(MemoryStore(), FakeLocalSink(), clock, trusted=trusted)


if __name__ == "__main__":
    unittest.main()
