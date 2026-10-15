"""Negative and replay tests for LOCAL Avuhz receipt-to-work authority gate.

No hosted AUTH, Supabase DATA, n8n execution, secrets, or network effects.
"""
from __future__ import annotations

import dataclasses
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.shared_work_intake_candidate import WorkIntakeDenied
from avuhz_worker.local_n8n_receipt_store import LocalN8nReceiptStore
from avuhz_worker.local_system001_governed_handoff import (
    AuthorizedAcquisitionSnapshot, LocalSystem001GovernedHandoff,
    LocalSystem001HandoffDenied,
)
from tests.worker.test_local_n8n_receipt_store import TENANT, OTHER, INTAKE, KEY, envelope
from tests.service.test_shared_work_intake_candidate import trusted, ALL

WORK = "a4770000-0000-4000-8000-000000000082"
DUE = "2030-01-15T16:05:00Z"


class SyntheticBoundedWriter:
    def __init__(self, *, reject=False):
        self.calls = []
        self.reject = reject

    def execute(self, evidence, command):
        if self.reject or evidence != "server.resolved.owner":
            raise WorkIntakeDenied("work intake authority denied")
        self.calls.append((evidence, command))
        return {"accepted_version": 1, "replayed": len(self.calls) > 1}


def valid_source(**changes):
    return dataclasses.replace(AuthorizedAcquisitionSnapshot(
        tenant_id=TENANT, intake_id=INTAKE, work_item_id=WORK,
        state="RECEIVED", source="web", classification="service_request",
        next_action_due_at=DUE, owner_identity_evidence="server.resolved.owner",
    ), **changes)


class LocalGovernedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-local-handoff-test-")
        self.addCleanup(self.temp.cleanup)
        self.store = LocalN8nReceiptStore(
            Path(self.temp.name) / "receipt.sqlite", trusted_tenant_id=TENANT,
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )
        self.lookups = []
        self.writer = SyntheticBoundedWriter()
        self.source = valid_source()
        self.bridge = LocalSystem001GovernedHandoff(
            receipt_store=self.store, work_writer=self.writer,
            resolve_acquisition=self.lookup,
            resolve_owner_identity=self.resolve_owner,
        )

    def lookup(self, id):
        self.lookups.append(id)
        return self.source

    def resolve_owner(self, evidence):
        if evidence == "server.resolved.owner":
            return trusted("server.resolved.owner", tenant=TENANT, caps=ALL)
        if evidence == "other.tenant":
            return trusted("other.tenant", tenant=OTHER, caps=ALL)
        raise PermissionError("no synthetic identity")

    def test_read_only_receipt_check_never_creates_missing_row(self):
        self.assertFalse(self.store.committed(envelope(), delivery_header=KEY))
        with self.assertRaises(LocalSystem001HandoffDenied):
            self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.writer.calls, [])
        with sqlite3.connect(self.store._path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM local_n8n_receipts").fetchone()[0], 0)

    def test_exact_committed_receipt_requires_independent_source_and_shared_writer(self):
        self.store.receive(envelope(), delivery_header=KEY)
        self.assertTrue(self.store.committed(envelope(), delivery_header=KEY))
        accepted = self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        replayed = self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertEqual(accepted["accepted_version"], 1)
        self.assertTrue(replayed["replayed"])
        self.assertEqual(self.lookups, [INTAKE, INTAKE])
        self.assertEqual(self.writer.calls[0][0], "server.resolved.owner")
        self.assertEqual(self.writer.calls[0][1].work_item_id, WORK)
        self.assertEqual(self.writer.calls[0][1].next_action_due_at, DUE)
        self.assertEqual(self.writer.calls[0][1].source, "web")
        self.assertEqual(self.writer.calls[0][1].classification, "service_request")
        self.assertEqual(self.writer.calls[0][1].idempotency_key, self.writer.calls[1][1].idempotency_key)
        self.assertNotIn(KEY, self.writer.calls[0][1].idempotency_key)
        with sqlite3.connect(self.store._path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM local_n8n_receipts").fetchone()[0], 1)

    def test_tamper_wrong_tenant_changed_id_or_delivery_key_fails_before_lookup(self):
        self.store.receive(envelope(), delivery_header=KEY)
        for x,header in (
            (envelope(tenant_id=OTHER), KEY),
            (envelope(event_id="a4770000-0000-4000-8000-000000000099"), KEY),
            (envelope(delivery_idempotency_key="different-delivery-key"), "different-delivery-key"),
            (envelope(), "incorrect-key"),
            (envelope(contact_email="private@example.invalid"), KEY),
            (envelope(event_type="billing.charge.approved"), KEY),
        ):
            with self.subTest(value=x), self.assertRaises(LocalSystem001HandoffDenied):
                self.bridge.open_receipted_intake(x, delivery_header=header)
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.writer.calls, [])

    def test_source_authority_mismatch_denied_without_shared_writer(self):
        self.store.receive(envelope(), delivery_header=KEY)
        for source in (
            valid_source(tenant_id=OTHER),
            valid_source(intake_id="a4770000-0000-4000-8000-000000000089"),
            valid_source(work_item_id=INTAKE),
            valid_source(state="PENDING_VERIFICATION"),
            valid_source(source="forged"),
            valid_source(classification="unknown"),
            valid_source(next_action_due_at=None),
            object(),
        ):
            with self.subTest(source=type(source).__name__):
                self.source = source
                with self.assertRaises(LocalSystem001HandoffDenied):
                    self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertEqual(self.writer.calls, [])

    def test_missing_owner_writer_rejects_even_after_durable_receipt(self):
        self.store.receive(envelope(), delivery_header=KEY)
        self.writer.reject=True
        with self.assertRaises(WorkIntakeDenied):
            self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(len(self.lookups), 1)

    def test_cross_tenant_owner_evidence_denied_before_shared_writer(self):
        self.store.receive(envelope(), delivery_header=KEY)
        self.source = valid_source(owner_identity_evidence="other.tenant")
        with self.assertRaisesRegex(LocalSystem001HandoffDenied, "^local handoff denied$"):
            self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.lookups, [INTAKE])

    def test_unauthorized_lookup_exception_is_sanitized(self):
        self.store.receive(envelope(), delivery_header=KEY)
        self.bridge = LocalSystem001GovernedHandoff(
            receipt_store=self.store, work_writer=self.writer,
            resolve_acquisition=lambda _: (_ for _ in ()).throw(
                RuntimeError("raw-owner-contact-sensitive@example.invalid")),
            resolve_owner_identity=self.resolve_owner,
        )
        with self.assertRaisesRegex(LocalSystem001HandoffDenied, "^local handoff denied$") as caught:
            self.bridge.open_receipted_intake(envelope(), delivery_header=KEY)
        self.assertNotIn("sensitive@example.invalid", str(caught.exception))
        self.assertEqual(self.writer.calls, [])


if __name__ == "__main__":
    unittest.main()
