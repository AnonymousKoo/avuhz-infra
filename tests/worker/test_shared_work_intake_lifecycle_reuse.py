"""LOCAL/TEST end-to-end System #001 -> existing Avuhz outbox -> n8n adapter.

The in-memory MemoryStore fixture is synthetic, NOT evidence of a durable
atomic work-item/event/outbox commit or an activated hosted workflow.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_service.shared_work_intake_candidate import (
    SharedWorkIntakeCandidate, WorkIntakeCommand,
)
from avuhz_service.shared_work_intake_lifecycle_projection import (
    project_test_work_intake_lifecycle_event,
)
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings

TENANT = "a4730000-0000-4000-8000-000000000001"
OTHER = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"
EVENT_PREFIX = "f8000000-0000-4000-8000-0000000000"
CORRELATION = "a4730000-0000-4000-8000-000000000044"
STAMP = "2030-01-15T15:00:00Z"
CLOCK = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
CAPS = frozenset({
    "work_intake:create", "work_intake:manage", "work_intake:accept",
    "work_intake:read",
})


def human(name):
    return TrustedExecutionContext(
        True, name, "HUMAN", TENANT, None, CAPS, frozenset(),
        "DEVELOPMENT", "avuhz-command-api", "STRONG", False, STAMP,
        "2099-01-01T00:00:00Z",
    )


def worker(tenant=TENANT):
    return TrustedExecutionContext(
        True, "service.outbox-worker-local", "INTERNAL_SERVICE", tenant,
        None, frozenset({"event:publish_internal"}), frozenset(), "TEST",
        "avuhz-command-api", "STRONG", False, STAMP,
        "2031-01-01T15:00:00Z",
    )


def synthetic_domain():
    identities = {"sender": human("worker.sender"), "receiver": human("worker.receiver")}
    directory = frozenset({"worker.sender", "worker.receiver"})
    return SharedWorkIntakeCandidate(
        lambda bearer: identities[bearer],
        resolve_tenant_member=lambda tenant, subject: (
            subject if tenant == TENANT and subject in directory else None
        ),
    )


def action(kind, version=None, *, key, recipient=None):
    return WorkIntakeCommand(
        kind, ITEM, key, expected_record_version=version,
        source="web" if kind == "OPEN" else None,
        classification="service_request" if kind == "OPEN" else None,
        recipient=recipient,
    )


def render(outcome, index):
    return project_test_work_intake_lifecycle_event(
        outcome, environment="TEST",
        event_id=EVENT_PREFIX + f"{index:02d}",
        correlation_id=CORRELATION,
        idempotency_key=f"work-intake-demo-{index:02d}",
        occurred_at=STAMP,
    )


class ReusedAvuhzWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        registry = SchemaRegistry(ROOT / "contracts" / "schemas" / "v1")
        cls.validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"),
            format_checker=FormatChecker(),
        )

    def setUp(self):
        self.engine = synthetic_domain()
        self.deliveries = []
        self.credential_reads = []
        self.sink = N8nOutboxSink(
            environment="TEST", tenant_id=TENANT,
            endpoint="https://n8n.example.invalid/webhook/avuhz-events",
            expected_host="n8n.example.invalid",
            credential_provider=lambda: self.credential_reads.append("used") or "x" * 24,
            post=lambda url, headers, body: (
                self.deliveries.append((url, dict(headers), bytes(body))) or 202
            ),
        )

    def transitions(self):
        steps = [
            ("sender", action("OPEN", key="opened0001")),
            ("sender", action("OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver")),
            ("receiver", action("ACCEPT_HANDOFF", 2, key="accepted001")),
            ("receiver", action("BLOCK", 3, key="blocked001")),
            ("receiver", action("RESUME", 4, key="resumed001")),
            ("receiver", action("RESOLVE", 5, key="resolved001")),
        ]
        return [self.engine.apply(actor, command) for actor, command in steps]

    def test_full_system_001_events_flow_through_existing_worker_and_n8n_sink(self):
        transitions = self.transitions()
        events = [render(item, i) for i, item in enumerate(transitions, 1)]
        for event in events:
            self.assertTrue(self.validator.is_valid(event), event["event_type"])
        self.assertEqual([x["authoritative_subject_version"] for x in events], list(range(1, 7)))
        self.assertEqual(events[-1]["sanitized_metadata"]["state"], "RESOLVED")

        # A local fixture simulates a previously committed shared outbox.
        # No hosted app commits or publishes these events.
        store = MemoryStore(
            events=copy.deepcopy(events),
            outbox=[{"event_id": event["event_id"], "status": "PENDING"} for event in events],
        )
        engine_before = self.engine.get("receiver", ITEM)
        outbox_worker = OutboxWorker(
            store, MemoryOutboxUnitOfWork, self.sink, worker(),
            WorkerSettings(tenant_id=TENANT, batch_size=10),
            clock=lambda: CLOCK,
        )
        delivery = outbox_worker.run_once()
        self.assertEqual(delivery, {
            "claimed": 6, "published": 6, "retry_scheduled": 0, "dead_lettered": 0,
        })
        self.assertEqual(len(self.deliveries), 6)
        self.assertEqual(len(self.credential_reads), 6)
        self.assertTrue(all(row["status"] == "PUBLISHED" for row in store.outbox))
        self.assertEqual(engine_before, self.engine.get("receiver", ITEM))
        self.assertEqual([row["event_type"] for row in store.events],
                         [row["event_type"] for row in events])

        for i, (url, headers, raw_body) in enumerate(self.deliveries, 1):
            body = json.loads(raw_body)
            self.assertEqual(body["event_type"], events[i - 1]["event_type"])
            self.assertEqual(body["tenant_id"], TENANT)
            self.assertEqual(body["authoritative_subject_reference"], {
                "reference_type": "WORK_ITEM", "reference_id": ITEM,
            })
            self.assertEqual(body["authoritative_subject_version"], i)
            self.assertEqual(
                set(body),
                {"event_id", "event_type", "tenant_id", "correlation_id",
                 "occurred_at", "authoritative_subject_reference",
                 "authoritative_subject_version", "delivery_idempotency_key"},
            )
            self.assertTrue(url.startswith("https://"))
            self.assertNotIn("worker.receiver", json.dumps(body))
            self.assertNotIn("worker.sender", json.dumps(body))
            self.assertNotIn("@", json.dumps(body))
            self.assertNotIn("sanitized_metadata", body)
            self.assertNotIn("X-Avuhz-Webhook-Token", body)
            self.assertIn("X-Avuhz-Webhook-Token", headers)

        self.assertEqual(outbox_worker.run_once()["published"], 0)
        self.assertEqual(len(self.deliveries), 6)

    def test_old_duplicate_work_command_cannot_project_another_event(self):
        first = self.engine.apply("sender", action("OPEN", key="opened0001"))
        self.assertEqual(render(first, 1)["event_type"], "work_intake.opened")
        retry = self.engine.apply("sender", action("OPEN", key="opened0001"))
        self.assertTrue(retry.replayed)
        self.assertIsNone(retry.intent)
        with self.assertRaisesRegex(ValueError, "projection unavailable"):
            render(retry, 2)

    def test_bad_event_contract_is_rejected_without_credential_access(self):
        valid = render(self.engine.apply("sender", action("OPEN", key="opened0001")), 1)
        for corrupt in (
            {"event_type": "work_intake.fake_transition"},
            {"sanitized_metadata": {"work_item_id": ITEM, "state": "OPEN", "contact_email": "a@b.co"}},
            {"sanitized_metadata": {"work_item_id": ITEM, "state": "RESOLVED"}},
            {"authoritative_subject_reference": {"reference_type": "ENGAGEMENT", "reference_id": ITEM}},
            {"visibility": "INTEGRATION_INTERNAL"},
            {"engagement_id": ITEM},
            {"tenant_id": OTHER},
        ):
            with self.subTest(corrupt=corrupt):
                bad = {**valid, **corrupt}
                if corrupt.get("tenant_id") == OTHER:
                    self.assertTrue(self.validator.is_valid(bad))
                else:
                    self.assertFalse(self.validator.is_valid(bad))
                from avuhz_worker.outbox import DeliveryRejected
                with self.assertRaises(DeliveryRejected):
                    self.sink.deliver("work-intake-demo-01", bad, STAMP)
        self.assertEqual(self.credential_reads, [])
        self.assertEqual(self.deliveries, [])

    def test_projection_requires_verified_matching_synthetic_intent_and_local_environment(self):
        first = self.engine.apply("sender", action("OPEN", key="opened0001"))
        for bad in (
            dataclasses.replace(first, item=dataclasses.replace(first.item, tenant_id=OTHER)),
            dataclasses.replace(first, item=dataclasses.replace(first.item, record_version=2)),
            dataclasses.replace(first, item=dataclasses.replace(first.item, state="BLOCKED")),
            dataclasses.replace(first, replayed=True),
            dataclasses.replace(first, intent=None),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    render(bad, 1)
        for env in ("DEVELOPMENT", "PRODUCTION", "", "production"):
            with self.subTest(env=env):
                with self.assertRaises(ValueError):
                    project_test_work_intake_lifecycle_event(
                        first, environment=env, event_id=EVENT_PREFIX + "01",
                        correlation_id=CORRELATION,
                        idempotency_key="work-intake-demo-01",
                        occurred_at=STAMP,
                    )


if __name__ == "__main__":
    unittest.main()
