"""Local-only tests for the shared Avuhz -> n8n outbox notification adapter.

All transport and credentials are synthetic in memory. No provider calls.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import DeliveryRejected, DeliveryUnavailable


TENANT = "f1000000-0000-4000-8000-000000000001"
OTHER_TENANT = "f1000000-0000-4000-8000-000000000002"
EVENT_ID = "f2000000-0000-4000-8000-000000000001"
SUBJECT_ID = "f2000000-0000-4000-8000-000000000003"
CORRELATION_ID = "f2000000-0000-4000-8000-000000000002"
URL = "https://n8n.example.invalid/webhook/avuhz-events"
KEY = "test-notification-delivery-01"


def fixture_event(*, tenant=TENANT):
    return {
        "event_id": EVENT_ID,
        "event_type": "engagement.opened",
        "event_schema_version": 1,
        "tenant_id": tenant,
        "authoritative_subject_reference": {
            "reference_type": "ENGAGEMENT", "reference_id": SUBJECT_ID,
        },
        "authoritative_subject_version": 1,
        "engagement_id": SUBJECT_ID,
        "occurred_at": "2030-01-15T15:00:00Z",
        "producer_reference": "command.service-01",
        "correlation_id": CORRELATION_ID,
        "idempotency_key": "worker-fixture-idempotency-0001",
        "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {"engagement_id": SUBJECT_ID},
    }


class N8nOutboxSinkTests(unittest.TestCase):
    def build_sink(self, *, status=202, environment="TEST", endpoint=URL,
                   credential_provider=None, post=None):
        self.calls = []
        def fake_post(url, headers, body):
            self.calls.append((url, dict(headers), bytes(body)))
            return status
        return N8nOutboxSink(
            environment=environment, tenant_id=TENANT,
            endpoint=endpoint, expected_host="n8n.example.invalid",
            credential_provider=credential_provider or (lambda: "x" * 24),
            post=post or fake_post,
        )

    def test_minimal_notification_excludes_payload_and_metadata(self):
        sink = self.build_sink()
        data = fixture_event()
        data["sanitized_metadata"]["client_email"] = "nobody@example.invalid"
        # Schema allows only the actual event-specific sanitized metadata.
        data["sanitized_metadata"].pop("client_email")
        result = sink.deliver(KEY, data, "2030-01-15T15:01:00Z")
        self.assertEqual(result["result"], "PUBLISHED")
        self.assertEqual(len(self.calls), 1)
        url, headers, body = self.calls[0]
        self.assertEqual(url, URL)
        self.assertEqual(headers["X-Avuhz-Delivery-Key"], KEY)
        self.assertEqual(headers["X-Avuhz-Webhook-Token"], "x" * 24)
        event = json.loads(body)
        self.assertEqual(event["tenant_id"], TENANT)
        self.assertEqual(event["event_id"], EVENT_ID)
        self.assertEqual(event["event_type"], "engagement.opened")
        self.assertEqual(event["delivery_idempotency_key"], KEY)
        self.assertNotIn("sanitized_metadata", event)
        self.assertNotIn("contact_email", event)
        self.assertNotIn("credential", event)
        self.assertNotIn("Authorization", headers)

    def test_cross_tenant_event_is_rejected_before_credentials_and_transport(self):
        reads = []
        sink = self.build_sink(credential_provider=lambda: reads.append("read") or "x" * 24)
        with self.assertRaises(DeliveryRejected):
            sink.deliver(KEY, fixture_event(tenant=OTHER_TENANT), "2030-01-15T15:01:00Z")
        self.assertEqual(reads, [])
        self.assertEqual(self.calls, [])

    def test_invalid_contract_rejected_before_transport(self):
        sink = self.build_sink()
        for change in (
            {"event_type": "payment.confirmed"},
            {"correlation_id": "not-a-uuid"},
            {"sanitized_metadata": {"unexpected": "PII"}},
            {"event_id": "invalid"},
            {"tenant_id": None},
        ):
            with self.subTest(change=change), self.assertRaises(DeliveryRejected):
                sink.deliver(KEY, {**fixture_event(), **change}, "2030-01-15T15:01:00Z")
        self.assertEqual(self.calls, [])

    def test_invalid_delivery_key_rejected(self):
        sink = self.build_sink()
        for key in ("", "bad key", "x" * 129, "/invalid/key"):
            with self.subTest(key=key), self.assertRaises(DeliveryRejected):
                sink.deliver(key, fixture_event(), "2030-01-15T15:01:00Z")
        self.assertEqual(self.calls, [])

    def test_no_hosted_execution_or_unapproved_destination(self):
        for environment in ("DEVELOPMENT", "PRODUCTION", "STAGING"):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.build_sink(environment=environment)
        for endpoint in (
            "http://n8n.example.invalid/webhook/avuhz-events",
            "https://untrusted.example.invalid/webhook/avuhz-events",
            "https://n8n.example.invalid/private/path",
            "https://n8n.example.invalid/webhook/avuhz-events?token=unsafe",
            "https://secret@n8n.example.invalid/webhook/avuhz-events",
            "https://n8n.example.invalid:444/webhook/avuhz-events",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.build_sink(endpoint=endpoint)

    def test_missing_or_invalid_credential_fails_closed(self):
        for value in ("", "short", None, "x" * 513, "bad\nvalue"):
            with self.subTest(kind=type(value).__name__), self.assertRaises(DeliveryRejected):
                self.build_sink(credential_provider=lambda: value).deliver(
                    KEY, fixture_event(), "2030-01-15T15:01:00Z"
                )
            self.assertEqual(self.calls, [])
        def unavailable():
            raise RuntimeError("sensitive provider diagnostics")
        sink = self.build_sink(credential_provider=unavailable)
        with self.assertRaisesRegex(DeliveryUnavailable, "^n8n credential temporarily unavailable$"):
            sink.deliver(KEY, fixture_event(), "2030-01-15T15:01:00Z")
        self.assertEqual(self.calls, [])

    def test_response_status_failure_classification(self):
        self.assertEqual(self.build_sink(status=202).deliver(
            KEY, fixture_event(), "2030-01-15T15:01:00Z"
        )["result"], "PUBLISHED")
        # Other 2xx values can originate from proxy or default n8n webhook
        # responses without an actual private durable receipt; retry rather
        # than silently treating them as acknowledged work.
        for status in (200, 201, 204, 206, 207):
            with self.subTest(status=status), self.assertRaisesRegex(
                DeliveryUnavailable, "^n8n durable acknowledgment not confirmed$"
            ):
                self.build_sink(status=status).deliver(
                    KEY, fixture_event(), "2030-01-15T15:01:00Z"
                )
        for status in (429, 500, 502, 503):
            with self.subTest(status=status), self.assertRaises(DeliveryUnavailable):
                self.build_sink(status=status).deliver(
                    KEY, fixture_event(), "2030-01-15T15:01:00Z"
                )
        for status in (400, 401, 403, 404, 409):
            with self.subTest(status=status), self.assertRaises(DeliveryRejected):
                self.build_sink(status=status).deliver(
                    KEY, fixture_event(), "2030-01-15T15:01:00Z"
                )

    def test_false_success_200_persists_retry_and_only_202_publishes(self):
        from tests.worker.test_outbox_worker import (
            MutableClock, make_worker, store_for,
        )
        store = store_for(fixture_event())
        clock = MutableClock()
        responses = [200, 202]
        calls = []
        def post(url, headers, body):
            calls.append((url, json.loads(body)["event_id"]))
            return responses.pop(0)
        worker = make_worker(
            store, self.build_sink(post=post), clock,
            max_attempts=2,base_backoff_seconds=5,
        )
        first = worker.run_once()
        self.assertEqual(first, {
            "claimed": 1, "published": 0, "retry_scheduled": 1,
            "dead_lettered": 0,
        })
        self.assertEqual(store.outbox[0]["status"], "FAILED_RETRYABLE")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_UNAVAILABLE")
        clock.advance(4)
        self.assertEqual(worker.run_once()["claimed"], 0)
        clock.advance(1)
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(store.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(store.outbox[0]["attempt_count"], 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual([item[1] for item in calls], [EVENT_ID, EVENT_ID])
        self.assertEqual(worker.run_once()["claimed"], 0)

    def test_persistent_false_success_cannot_publish_or_retry_forever(self):
        from tests.worker.test_outbox_worker import (
            MutableClock, make_worker, store_for,
        )
        store = store_for(fixture_event())
        clock = MutableClock()
        worker = make_worker(
            store,self.build_sink(status=204),clock,
            max_attempts=2,base_backoff_seconds=5,
        )
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        clock.advance(5)
        self.assertEqual(worker.run_once()["dead_lettered"], 1)
        self.assertEqual(store.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(store.outbox[0]["last_safe_error_code"], "DELIVERY_UNAVAILABLE")
        self.assertEqual(store.outbox[0]["attempt_count"], 2)
        self.assertEqual(worker.run_once()["claimed"], 0)

    def test_transport_exception_is_sanitized(self):
        def broken_post(url, headers, body):
            raise RuntimeError("unexpected private response payload")
        sink = self.build_sink(post=broken_post)
        with self.assertRaisesRegex(DeliveryUnavailable, "^n8n transport unavailable$"):
            sink.deliver(KEY, fixture_event(), "2030-01-15T15:01:00Z")


if __name__ == "__main__":
    unittest.main()
