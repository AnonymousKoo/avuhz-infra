"""Synthetic Avuhz outbox -> authenticated n8n receiver round-trip tests.

No hosted n8n, Supabase, credentials, customer data, or network access.
The receiver here is a test double, not a deployed n8n workflow.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import DeliveryRejected
from tests.worker.test_outbox_worker import (
    TENANT, OTHER_TENANT, MutableClock, event, make_worker, store_for,
)

_ENDPOINT = "https://n8n.example.invalid/webhook/avuhz-events"
_TEST_TOKEN = "synthetic-not-a-real-credential"
_FIELDS = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})


class FakeAuthenticatedN8nReceiver:
    """In-memory stand-in for native n8n header auth + durable idempotent receipt.

    Receipts are simulated in memory ONLY to test the sender contract. A
    separately approved real consumer MUST provide persistent deduplication
    and acknowledge only after durable receipt before any side effects.
    """

    def __init__(self, *, expected_token=_TEST_TOKEN, tenant_id=TENANT, lose_first_ack=False):
        self.expected_token = expected_token
        self.tenant_id = tenant_id
        self.lose_first_ack = lose_first_ack
        self.receipts = {}
        self.accepted_attempts = 0

    def post(self, url, headers, raw_body):
        if url != _ENDPOINT:
            return 404
        if headers.get("X-Avuhz-Webhook-Token") != self.expected_token:
            return 401
        if headers.get("Content-Type") != "application/json":
            return 415
        try:
            body = json.loads(raw_body)
        except (TypeError, ValueError):
            return 400
        if type(body) is not dict or set(body) != _FIELDS:
            return 400
        if body["tenant_id"] != self.tenant_id:
            return 403
        if body["event_type"] != "engagement.opened":
            return 403
        delivery_key = body["delivery_idempotency_key"]
        if headers.get("X-Avuhz-Delivery-Key") != delivery_key:
            return 400
        if type(delivery_key) is not str or len(delivery_key) < 8:
            return 400
        prior = self.receipts.get(delivery_key)
        if prior is not None and prior != body:
            return 409
        if prior is None:
            self.receipts[delivery_key] = copy.deepcopy(body)
        self.accepted_attempts += 1
        if self.lose_first_ack:
            self.lose_first_ack = False
            # Models an already-persisted receipt followed by a lost response.
            raise TimeoutError("synthetic acknowledgment loss")
        return 202


def sink(receiver, *, token=_TEST_TOKEN, tenant=TENANT):
    return N8nOutboxSink(
        environment="TEST", tenant_id=tenant, endpoint=_ENDPOINT,
        expected_host="n8n.example.invalid",
        credential_provider=lambda: token,
        post=receiver.post,
    )


class AuthenticatedN8nRoundTripTests(unittest.TestCase):
    def test_committed_outbox_delivers_only_minimal_event_and_marks_published(self):
        store = store_for()
        original_domain_event = copy.deepcopy(store.events)
        receiver = FakeAuthenticatedN8nReceiver()
        result = make_worker(store, sink(receiver), MutableClock()).run_once()
        self.assertEqual(result, {
            "claimed": 1, "published": 1, "retry_scheduled": 0, "dead_lettered": 0
        })
        self.assertEqual(store.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(store.events, original_domain_event)
        self.assertEqual(len(receiver.receipts), 1)
        delivered = next(iter(receiver.receipts.values()))
        self.assertEqual(set(delivered), _FIELDS)
        self.assertEqual(delivered["tenant_id"], TENANT)
        self.assertEqual(delivered["event_type"], "engagement.opened")
        self.assertNotIn("sanitized_metadata", delivered)
        self.assertNotIn("name", delivered)
        self.assertNotIn("email", delivered)
        self.assertNotIn("token", json.dumps(delivered).lower())
        self.assertEqual(make_worker(store, sink(receiver), MutableClock()).run_once()["claimed"], 0)
        self.assertEqual(receiver.accepted_attempts, 1)

    def test_lost_ack_retries_without_duplicate_receipt(self):
        store = store_for()
        clock = MutableClock()
        receiver = FakeAuthenticatedN8nReceiver(lose_first_ack=True)
        worker = make_worker(store, sink(receiver), clock, max_attempts=3)
        first = worker.run_once()
        self.assertEqual(first["retry_scheduled"], 1)
        self.assertEqual(store.outbox[0]["status"], "FAILED_RETRYABLE")
        self.assertEqual(len(receiver.receipts), 1)
        clock.advance(5)
        second = worker.run_once()
        self.assertEqual(second["published"], 1)
        self.assertEqual(store.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(store.outbox[0]["attempt_count"], 2)
        self.assertEqual(receiver.accepted_attempts, 2)
        self.assertEqual(len(receiver.receipts), 1)

    def test_wrong_credential_blocks_before_receipt_and_dead_letters(self):
        store = store_for()
        receiver = FakeAuthenticatedN8nReceiver()
        result = make_worker(
            store, sink(receiver, token="different-synthetic-credential"),
            MutableClock(),
        ).run_once()
        self.assertEqual(result["dead_lettered"], 1)
        self.assertEqual(store.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_REJECTED")
        self.assertEqual(receiver.receipts, {})

    def test_cross_tenant_delivery_is_rejected_both_directions(self):
        receiver = FakeAuthenticatedN8nReceiver()
        foreign_event = event(tenant=OTHER_TENANT)
        with self.assertRaises(DeliveryRejected):
            sink(receiver).deliver(
                "synthetic-delivery-foreign", foreign_event, "2030-01-15T15:01:00Z"
            )
        with self.assertRaises(DeliveryRejected):
            sink(receiver, tenant=OTHER_TENANT).deliver(
                "synthetic-delivery-foreign", foreign_event, "2030-01-15T15:01:00Z"
            )
        self.assertEqual(receiver.receipts, {})

    def test_delivery_key_collision_is_not_accepted(self):
        receiver = FakeAuthenticatedN8nReceiver()
        local_sink = sink(receiver)
        original = event()
        self.assertEqual(
            local_sink.deliver("synthetic-delivery-key01", original, "2030-01-15T15:01:00Z")["result"],
            "PUBLISHED",
        )
        changed = event(event_id="f2000000-0000-4000-8000-000000000009")
        with self.assertRaises(DeliveryRejected):
            local_sink.deliver("synthetic-delivery-key01", changed, "2030-01-15T15:01:00Z")
        self.assertEqual(len(receiver.receipts), 1)


if __name__ == "__main__":
    unittest.main()
