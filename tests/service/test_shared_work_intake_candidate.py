"""Synthetic, no-network end-to-end tests for reusable Avuhz System #001."""
from __future__ import annotations

import dataclasses
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.shared_work_intake_candidate import (
    BLOCKED, OPEN, RESOLVED, SharedWorkIntakeCandidate, WorkIntakeCommand,
    WorkIntakeConflict, WorkIntakeDenied,
)

A = "a4730000-0000-4000-8000-000000000001"
B = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"
ITEM2 = "a4730000-0000-4000-8000-000000000032"
ALL = frozenset({
    "work_intake:create", "work_intake:manage",
    "work_intake:accept", "work_intake:read",
})


def trusted(name, tenant=A, caps=ALL, *, authenticated=True, expiry="2099-01-01T00:00:00Z"):
    return TrustedExecutionContext(
        authenticated=authenticated,
        principal_id=name, caller_type="HUMAN",
        tenant_id=tenant, organization_id=None, capabilities=caps,
        authority_roles=frozenset(), environment="DEVELOPMENT",
        audience="avuhz-command-api", authentication_strength="STRONG",
        step_up_satisfied=False, authenticated_at="2026-10-13T00:00:00Z",
        expires_at=expiry,
    )


class FakeOfflineResolver:
    def __init__(self):
        self.evidence = {
            "sender": trusted("worker.sender"),
            "receiver": trusted("worker.receiver"),
            "other": trusted("worker.other"),
            "outsider": trusted("worker.outsider", B),
            "no_create": trusted("worker.limited", caps=frozenset({"work_intake:read"})),
            "expired": trusted("worker.expired", expiry="2020-01-01T00:00:00Z"),
            "unauthenticated": trusted("worker.unknown", authenticated=False),
        }

    def __call__(self, token):
        if type(token) is not str or token not in self.evidence:
            raise RuntimeError("PRIVATE raw token diagnostic: should never leak")
        return self.evidence[token]


def command(kind, version=None, *, key="idempotency01", item=ITEM, source=None,
            classification=None, recipient=None):
    return WorkIntakeCommand(
        kind=kind, work_item_id=item, idempotency_key=key,
        expected_record_version=version, source=source,
        classification=classification, recipient=recipient,
    )


class WorkIntakeSystemTests(unittest.TestCase):
    def setUp(self):
        self.store = SharedWorkIntakeCandidate(FakeOfflineResolver())

    def open(self, *, actor="sender", key="opened0001", item=ITEM):
        return self.store.apply(actor, command(
            "OPEN", key=key, item=item, source="web",
            classification="service_request",
        ))

    def test_complete_multi_step_workflow_and_sanitized_transition_intents(self):
        results = [self.open()]
        self.assertEqual(
            (results[0].item.owner_reference, results[0].item.state),
            ("worker.sender", OPEN),
        )
        results.append(self.store.apply("sender", command(
            "OFFER_HANDOFF", 1, key="handoff0001", recipient="worker.receiver",
        )))
        self.assertEqual(results[-1].item.owner_reference, "worker.sender")
        self.assertEqual(results[-1].item.pending_recipient, "worker.receiver")
        results.append(self.store.apply("receiver", command(
            "ACCEPT_HANDOFF", 2, key="accepted001",
        )))
        self.assertEqual(results[-1].item.owner_reference, "worker.receiver")
        self.assertIsNone(results[-1].item.pending_recipient)
        results.append(self.store.apply("receiver", command(
            "BLOCK", 3, key="blocked0001",
        )))
        self.assertEqual(results[-1].item.state, BLOCKED)
        results.append(self.store.apply("receiver", command(
            "RESUME", 4, key="resumed0001",
        )))
        self.assertEqual(results[-1].item.state, OPEN)
        results.append(self.store.apply("receiver", command(
            "RESOLVE", 5, key="resolved0001",
        )))
        self.assertEqual(results[-1].item.state, RESOLVED)
        self.assertEqual([r.item.record_version for r in results], [1, 2, 3, 4, 5, 6])
        self.assertEqual(
            [r.intent.event_type for r in results],
            ["work_intake.opened", "work_intake.handoff_offered",
             "work_intake.handoff_accepted", "work_intake.blocked",
             "work_intake.resumed", "work_intake.resolved"],
        )
        snapshot = self.store.get("receiver", ITEM)
        self.assertEqual(snapshot, results[-1].item)
        self.assertEqual(snapshot.tenant_id, A)
        for result in results:
            payload = dataclasses.asdict(result.intent)
            self.assertEqual(set(payload), {
                "tenant_id", "work_item_id", "record_version", "state", "event_type",
            })
            serialized = json.dumps(payload).lower()
            self.assertNotIn("@", serialized)
            self.assertNotIn("phone", serialized)
            self.assertNotIn("worker.sender", serialized)
            self.assertNotIn("worker.receiver", serialized)

    def test_cancel_handoff_is_owner_only_and_restores_assignment(self):
        self.open()
        self.store.apply("sender", command(
            "OFFER_HANDOFF", 1, key="offer00001", recipient="worker.receiver",
        ))
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("receiver", command(
                "CANCEL_HANDOFF", 2, key="badcancel1",
            ))
        cancelled = self.store.apply("sender", command(
            "CANCEL_HANDOFF", 2, key="cancel0001",
        ))
        self.assertEqual(cancelled.item.owner_reference, "worker.sender")
        self.assertIsNone(cancelled.item.pending_recipient)
        self.assertEqual(cancelled.intent.event_type, "work_intake.handoff_cancelled")
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("receiver", command(
                "ACCEPT_HANDOFF", 3, key="badaccept1",
            ))

    def test_wrong_tenant_can_neither_read_nor_modify_work(self):
        self.open()
        with self.assertRaisesRegex(WorkIntakeDenied, "unavailable"):
            self.store.get("outsider", ITEM)
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("outsider", command(
                "BLOCK", 1, key="cross00001",
            ))
        self.assertEqual(self.store.get("sender", ITEM).record_version, 1)

    def test_only_trusted_pending_recipient_can_accept(self):
        self.open()
        self.store.apply("sender", command(
            "OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver",
        ))
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("other", command("ACCEPT_HANDOFF", 2, key="wrong00001"))
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("sender", command("ACCEPT_HANDOFF", 2, key="wrong00002"))
        self.assertEqual(self.store.get("sender", ITEM).owner_reference, "worker.sender")
        self.assertEqual(self.store.get("sender", ITEM).record_version, 2)

    def test_previous_owner_loses_access_after_accepted_handoff(self):
        self.open()
        self.store.apply("sender", command(
            "OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver",
        ))
        self.store.apply("receiver", command("ACCEPT_HANDOFF", 2, key="accepted001"))
        with self.assertRaises(WorkIntakeDenied):
            self.store.apply("sender", command("BLOCK", 3, key="badowner01"))
        with self.assertRaises(WorkIntakeDenied):
            self.store.get("sender", ITEM)
        self.assertEqual(self.store.get("receiver", ITEM).record_version, 3)

    def test_same_command_retry_returns_previous_result_without_new_intent(self):
        opened = command("OPEN", key="retry00001", source="web",
                         classification="service_request")
        first = self.store.apply("sender", opened)
        second = self.store.apply("sender", opened)
        self.assertEqual(first.item, second.item)
        self.assertIsNone(second.intent)
        self.assertTrue(second.replayed)
        self.assertEqual(self.store.get("sender", ITEM).record_version, 1)
        with self.assertRaisesRegex(WorkIntakeConflict, "idempotency"):
            self.store.apply("sender", command("OPEN", key="retry00001",
                source="web", classification="work_order", item=ITEM2))
        self.assertEqual(self.store.get("sender", ITEM).record_version, 1)

    def test_retry_after_owner_transfer_does_not_authorize_new_transition(self):
        self.open()
        original_offer = command(
            "OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver",
        )
        self.store.apply("sender", original_offer)
        self.store.apply("receiver", command(
            "ACCEPT_HANDOFF", 2, key="accepted001",
        ))
        duplicate = self.store.apply("sender", original_offer)
        self.assertTrue(duplicate.replayed)
        self.assertIsNone(duplicate.intent)
        self.assertEqual(duplicate.item.record_version, 2)
        self.assertEqual(self.store.get("receiver", ITEM).record_version, 3)

    def test_optimistic_version_and_idempotency_collisions_fail_closed(self):
        self.open()
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("sender", command(
                "BLOCK", 2, key="stale00001",
            ))
        self.assertEqual(self.store.get("sender", ITEM).record_version, 1)
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("sender", command(
                "OPEN", key="opened0002", source="web",
                classification="service_request",
            ))
        self.assertEqual(self.store.get("sender", ITEM).record_version, 1)

    def test_invalid_transition_and_pending_handoff_blocked(self):
        self.open()
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("sender", command("RESUME", 1, key="resume0001"))
        self.store.apply("sender", command(
            "OFFER_HANDOFF", 1, key="offer00001", recipient="worker.receiver",
        ))
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("sender", command("RESOLVE", 2, key="resolv0001"))
        self.store.apply("receiver", command("ACCEPT_HANDOFF", 2, key="accept0001"))
        self.store.apply("receiver", command("RESOLVE", 3, key="resolved001"))
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("receiver", command("BLOCK", 4, key="blocked0001"))
        with self.assertRaises(WorkIntakeConflict):
            self.store.apply("receiver", command(
                "OFFER_HANDOFF", 4, key="offer00002", recipient="worker.sender",
            ))

    def test_missing_capability_expired_and_untrusted_identity_denied(self):
        request = command("OPEN", key="request0001", source="web",
                          classification="service_request")
        for actor in ("no_create", "expired", "unauthenticated",
                      "unrecognized", None, {"principal_id": "worker.sender"}):
            with self.subTest(actor=type(actor).__name__):
                with self.assertRaisesRegex(WorkIntakeDenied, "authority denied"):
                    self.store.apply(actor, request)
        self.assertEqual(len(self.store._items), 0)

    def test_untrusted_payload_cannot_assign_owner_tenant_or_contact_pii(self):
        for bad in (
            {"tenant_id": A, "work_item_id": ITEM},
            command("OPEN", key="badone000", source="person@example.com",
                    classification="service_request"),
            command("OPEN", key="badtwo000", source="web",
                    classification="John Smith"),
            command("OPEN", key="badthr000", source="web",
                    classification="service_request", recipient="worker.other"),
            WorkIntakeCommand("OPEN", ITEM, "badfou000", expected_record_version=1,
                source="web", classification="service_request"),
            command("OPEN", key="badfiv000", source="web",
                    classification="service_request", item="tenant-bypass"),
            WorkIntakeCommand("OPEN", ITEM, "badkey!", source="web",
                classification="service_request"),
            WorkIntakeCommand("OPEN", ITEM, "badkey000", source=[],
                classification="service_request"),
        ):
            with self.subTest(value=type(bad).__name__):
                with self.assertRaises(WorkIntakeDenied):
                    self.store.apply("sender", bad)
        self.assertEqual(len(self.store._items), 0)

    def test_snapshots_immutable_results_copy_safe_and_separate_tenants(self):
        first = self.open()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.item.owner_reference = "worker.other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.intent.event_type = "custom.spoofed"
        other = self.store.apply("outsider", command(
            "OPEN", key="other0001", item=ITEM, source="api",
            classification="internal_task",
        ))
        self.assertEqual(other.item.tenant_id, B)
        self.assertEqual(self.store.get("sender", ITEM).tenant_id, A)
        self.assertNotEqual(other.item.owner_reference, first.item.owner_reference)

    def test_source_contains_no_hosted_identity_bypass_or_new_event_publisher(self):
        source = (ROOT / "src" / "avuhz_service" /
                  "shared_work_intake_candidate.py").read_text()
        for forbidden in (
            "supabase", "stripe", "twilio", "import requests", "import psycopg",
            "n8n_event_sink", "requests.post", "urllib.request",
        ):
            self.assertNotIn(forbidden, source.lower().replace("no supabase", ""))
        for path in ("src/avuhz_service/application.py",
                     "src/avuhz_service/development.py",
                     "src/avuhz_runtime/command_registry.py"):
            self.assertNotIn(
                "shared_work_intake_candidate",
                (ROOT / path).read_text(),
            )


if __name__ == "__main__":
    unittest.main()
