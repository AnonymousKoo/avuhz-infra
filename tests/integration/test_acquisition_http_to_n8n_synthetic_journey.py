"""LOCAL/TEST-only first-client journey: authenticated HTTP -> intake -> outbox -> n8n.

This is an offline, synthetic contract test. The DB connections are in-memory
test doubles, not Supabase. The n8n receiver is a fake, not an installed flow.
No real prospect, credential, AUTH capability, role grant, or hosted activation.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "src"),
    str(ROOT / "tests/service"),
    str(ROOT / "tests/worker"),
]
from avuhz_runtime.in_memory import MemoryStore
from avuhz_worker import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from test_development_acquisition_http import application, request, TOKEN
from test_development_acquisition_ingress import TENANT_A, TENANT_B, sample
from test_outbox_worker import MutableClock, context

ENDPOINT = "https://n8n.example.invalid/webhook/avuhz-events"
CREDENTIAL = "synthetic-not-a-provider-credential-123"
FIELDS = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})


class SyntheticAuthenticatedN8nReceiver:
    """Mimics header auth and idempotent durable receipt, only in local memory."""

    def __init__(self, *, lose_first_ack=False):
        self.receipts = {}
        self.attempt_count = 0
        self.lose_first_ack = lose_first_ack

    def post(self, url, headers, raw):
        if url != ENDPOINT:
            return 404
        if headers.get("X-Avuhz-Webhook-Token") != CREDENTIAL:
            return 401
        if headers.get("Content-Type") != "application/json":
            return 415
        try:
            message = json.loads(raw)
        except (TypeError, ValueError):
            return 400
        if (
            type(message) is not dict
            or frozenset(message) != FIELDS
            or message.get("event_type") != "acquisition.intake.received"
            or message.get("tenant_id") != TENANT_A
            or message.get("authoritative_subject_reference", {}).get("reference_type")
               != "ACQUISITION_INTAKE"
            or message.get("delivery_idempotency_key")
               != headers.get("X-Avuhz-Delivery-Key")
        ):
            return 403
        key = message["delivery_idempotency_key"]
        if key in self.receipts and self.receipts[key] != message:
            return 409
        self.receipts.setdefault(key, message)
        self.attempt_count += 1
        if self.lose_first_ack:
            self.lose_first_ack = False
            # Receipt committed, but the acknowledgment never reached Avuhz.
            raise TimeoutError("synthetic ack loss")
        return 202


def event_and_outbox_from_committed_intake(store):
    """Translate DB-double INSERT parameters into the canonical worker store.

    This helper intentionally does not certify actual PostgreSQL transactions.
    Existing independent writer tests cover atomic rollback and replay.
    """
    self_check = store.connections[1]
    if self_check.commits != 1 or self_check.rollbacks:
        raise AssertionError("intake transaction did not commit")
    inserts = self_check.calls
    if len(inserts) != 5:
        raise AssertionError("unexpected shared intake write sequence")
    event_sql, p = inserts[3]
    outbox_sql, delivery = inserts[4]
    if (
        "insert into public.avuhz_lifecycle_events" not in event_sql
        or "insert into public.avuhz_outbox_deliveries" not in outbox_sql
        or delivery != (p[0], "PENDING", "outbox-delivery:" + p[0], p[0])
    ):
        raise AssertionError("event and outbox contract mismatch")
    source_event = {
        "event_id": p[0],
        "tenant_id": p[1],
        "engagement_id": p[2],
        "event_type": p[3],
        "event_schema_version": p[4],
        "authoritative_subject_reference": {
            "reference_type": p[5], "reference_id": p[6],
        },
        "authoritative_subject_version": p[7],
        "occurred_at": p[8],
        "producer_reference": p[9],
        "correlation_id": p[10],
        "idempotency_key": p[12],
        "visibility": p[13],
        "sanitized_metadata": json.loads(p[14]),
    }
    # The canonical schema disallows null engagement_id on intake receipt.
    if source_event["engagement_id"] is None:
        del source_event["engagement_id"]
    if p[11] is not None:
        source_event["command_id"] = p[11]
    return MemoryStore(
        events=[source_event],
        outbox=[{"event_id": p[0], "status": "PENDING"}],
    )


def worker_for(memory, receiver, *, supplied_token=CREDENTIAL, max_attempts=3):
    sink = N8nOutboxSink(
        environment="TEST", tenant_id=TENANT_A, endpoint=ENDPOINT,
        expected_host="n8n.example.invalid",
        credential_provider=lambda: supplied_token,
        post=receiver.post,
    )
    clock = MutableClock()
    worker = OutboxWorker(
        memory, MemoryOutboxUnitOfWork, sink, context(tenant=TENANT_A),
        WorkerSettings(
            tenant_id=TENANT_A,
            worker_reference="outbox.worker-acquisition-synthetic",
            base_backoff_seconds=5,
            max_attempts=max_attempts,
        ),
        clock=clock,
    )
    return worker, clock


class SyntheticClientJourneyTests(unittest.TestCase):
    def test_fictional_request_reaches_authenticated_n8n_once_without_pii(self):
        app, store = application()
        status, result, headers = request(app)
        self.assertEqual(status, 202)
        self.assertEqual(result["duplicate"], False)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(sample()["contact_email"], json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))
        memory = event_and_outbox_from_committed_intake(store)
        original_event = memory.events[0]
        self.assertEqual(original_event["event_type"], "acquisition.intake.received")
        self.assertEqual(original_event["tenant_id"], TENANT_A)
        self.assertEqual(original_event["authoritative_subject_reference"]["reference_id"],
                         result["intake_id"])
        receiver = SyntheticAuthenticatedN8nReceiver()
        worker, _ = worker_for(memory, receiver)
        outcome = worker.run_once()
        self.assertEqual(outcome, {
            "claimed": 1, "published": 1, "retry_scheduled": 0, "dead_lettered": 0,
        })
        self.assertEqual(memory.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(len(receiver.receipts), 1)
        message = next(iter(receiver.receipts.values()))
        self.assertEqual(frozenset(message), FIELDS)
        self.assertEqual(message["event_type"], "acquisition.intake.received")
        self.assertEqual(message["tenant_id"], TENANT_A)
        self.assertNotIn("sanitized_metadata", message)
        for pii in (
            sample()["contact_email"], sample()["contact_name"],
            sample()["business_name"], sample()["diagnostic_summary"], TOKEN, CREDENTIAL,
        ):
            self.assertNotIn(pii, json.dumps(message))
        self.assertEqual(worker.run_once()["claimed"], 0)
        self.assertEqual(receiver.attempt_count, 1)

    def test_lost_ack_is_retried_without_second_receiver_receipt(self):
        app, store = application()
        self.assertEqual(request(app)[0], 202)
        memory = event_and_outbox_from_committed_intake(store)
        receiver = SyntheticAuthenticatedN8nReceiver(lose_first_ack=True)
        worker, clock = worker_for(memory, receiver)
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        self.assertEqual(memory.outbox[0]["status"], "FAILED_RETRYABLE")
        self.assertEqual(len(receiver.receipts), 1)
        clock.advance(5)
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(memory.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(len(receiver.receipts), 1)
        self.assertEqual(receiver.attempt_count, 2)

    def test_bad_n8n_auth_dead_letters_without_receipt(self):
        app, store = application()
        self.assertEqual(request(app)[0], 202)
        memory = event_and_outbox_from_committed_intake(store)
        receiver = SyntheticAuthenticatedN8nReceiver()
        worker, _ = worker_for(memory, receiver,
                               supplied_token="synthetic-incorrect-credential")
        self.assertEqual(worker.run_once()["dead_lettered"], 1)
        self.assertEqual(receiver.receipts, {})
        self.assertEqual(memory.outbox[0]["last_safe_error_code"], "DELIVERY_REJECTED")

    def test_untrusted_tenant_and_absent_owner_block_before_event_delivery(self):
        receiver = SyntheticAuthenticatedN8nReceiver()
        for payload, kwargs in (
            ({**sample(), "tenant_id": TENANT_B}, {}),
            (sample(), {"headers": {"HTTP_AUTHORIZATION": "Bearer invalid.invalid.invalid.invalid.invalid"}}),
        ):
            with self.subTest(payload=payload.get("tenant_id", "unauthorized")):
                app, store = application()
                status, _, _ = request(app, obj=payload, **kwargs)
                self.assertEqual(status, 403)
                self.assertEqual(store.connections, [])
                self.assertEqual(receiver.receipts, {})


if __name__ == "__main__":
    unittest.main()
