"""Disposable LOCAL/TEST receipt storage tests. No n8n, hosted provider, or PII."""
from __future__ import annotations

import concurrent.futures
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_worker.local_n8n_receipt_store import (
    ConflictingReceipt,
    InvalidReceipt,
    LocalN8nReceiptStore,
    ReceiptStoreUnavailable,
    UnauthorizedReceipt,
)

TENANT = "a4770000-0000-4000-8000-000000000011"
OTHER = "a4770000-0000-4000-8000-000000000012"
EVENT = "a4770000-0000-4000-8000-000000000021"
CORRELATION = "a4770000-0000-4000-8000-000000000031"
INTAKE = "a4770000-0000-4000-8000-000000000041"
WORK_ITEM = "a4770000-0000-4000-8000-000000000042"
KEY = "localtest-delivery-key-001"


def envelope(**changes):
    original = {
        "event_id": EVENT,
        "event_type": "acquisition.intake.received",
        "tenant_id": TENANT,
        "correlation_id": CORRELATION,
        "occurred_at": "2026-10-13T12:00:00Z",
        "authoritative_subject_reference": {
            "reference_type": "ACQUISITION_INTAKE", "reference_id": INTAKE,
        },
        "authoritative_subject_version": 1,
        "delivery_idempotency_key": KEY,
    }
    original.update(changes)
    return original


class LocalN8nReceiptStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-local-receipts-")
        self.path = Path(self.temp.name) / "receipts.sqlite"
        self.store = self.open_store()

    def tearDown(self):
        self.temp.cleanup()

    def open_store(self):
        return LocalN8nReceiptStore(
            self.path,
            trusted_tenant_id=TENANT,
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )

    def test_first_receipt_and_persisted_replay_accept_once(self):
        first = self.store.receive(envelope(), delivery_header=KEY)
        self.assertEqual((first.status, first.duplicate), (202, False))
        # A new instance simulates n8n process restart and a lost prior ACK.
        reopened = self.open_store()
        second = reopened.receive(envelope(), delivery_header=KEY)
        self.assertEqual((second.status, second.duplicate), (202, True))
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                "SELECT trusted_tenant_id,delivery_key,event_id,envelope_digest "
                "FROM local_n8n_receipts"
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][:3], (TENANT, KEY, EVENT))
        self.assertEqual(len(rows[0][3]), 64)
        # No raw JSON, business name, email, or message is stored.
        self.assertNotIn("contact_email", str(rows))

    def test_semantic_collision_cannot_overwrite_committed_receipt(self):
        self.assertFalse(self.store.receive(envelope(), delivery_header=KEY).duplicate)
        with self.assertRaisesRegex(ConflictingReceipt, "^delivery_key_conflict$"):
            self.store.receive(
                envelope(event_id="a4770000-0000-4000-8000-000000000099"),
                delivery_header=KEY,
            )
        self.assertTrue(self.open_store().receive(envelope(), delivery_header=KEY).duplicate)

    def test_concurrent_duplicate_receipts_have_one_insert(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda _: self.open_store().receive(envelope(), delivery_header=KEY),
                range(8),
            ))
        self.assertEqual(sum(not result.duplicate for result in results), 1)
        self.assertEqual(sum(result.duplicate for result in results), 7)
        self.assertTrue(all(result.status == 202 for result in results))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM local_n8n_receipts"
            ).fetchone()[0], 1)

    def test_cross_tenant_and_unlisted_event_fail_before_write(self):
        for payload, err in (
            (envelope(tenant_id=OTHER), UnauthorizedReceipt),
            (envelope(event_type="billing.charge.approved"), UnauthorizedReceipt),
            (envelope(contact_email="private@example.invalid"), InvalidReceipt),
            (envelope(authoritative_subject_reference={
                "reference_type": "OTHER", "reference_id": INTAKE,
            }), InvalidReceipt),
            (envelope(authoritative_subject_version=2), InvalidReceipt),
            (envelope(delivery_idempotency_key="bad key"), InvalidReceipt),
        ):
            with self.subTest(reason=err.__name__), self.assertRaises(err):
                self.store.receive(payload, delivery_header=KEY)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM local_n8n_receipts"
            ).fetchone()[0], 0)

    def test_work_item_contract_is_explicit_and_idempotent(self):
        store = LocalN8nReceiptStore(
            self.path,
            trusted_tenant_id=TENANT,
            allowed_event_types=frozenset({"work_intake.opened"}),
        )
        payload = envelope(
            event_type="work_intake.opened",
            authoritative_subject_reference={
                "reference_type": "WORK_ITEM", "reference_id": WORK_ITEM,
            },
        )
        self.assertFalse(store.receive(payload, delivery_header=KEY).duplicate)
        self.assertTrue(store.committed(payload, delivery_header=KEY))
        self.assertTrue(store.receive(payload, delivery_header=KEY).duplicate)
        for changed in (
            {"authoritative_subject_reference": {
                "reference_type": "ACQUISITION_INTAKE", "reference_id": WORK_ITEM,
            }},
            {"authoritative_subject_version": 2},
        ):
            with self.subTest(changed=changed), self.assertRaises(InvalidReceipt):
                store.receive(envelope(
                    event_type="work_intake.opened", **changed
                ), delivery_header=KEY)

    def test_configuration_rejects_unknown_contract(self):
        with self.assertRaises(ValueError):
            LocalN8nReceiptStore(
                self.path,
                trusted_tenant_id=TENANT,
                allowed_event_types=frozenset({"unreviewed.event"}),
            )

    def test_header_mismatch_and_oversize_fail_closed(self):
        with self.assertRaises(InvalidReceipt):
            self.store.receive(envelope(), delivery_header="incorrect-key")
        with self.assertRaises(InvalidReceipt):
            self.store.receive(envelope(
                delivery_idempotency_key="A" * 129
            ), delivery_header="A" * 129)
        with self.assertRaises(InvalidReceipt):
            self.store.receive(envelope(
                authoritative_subject_reference={
                    "reference_type": "ACQUISITION_INTAKE",
                    "reference_id": INTAKE,
                    "extra": "untrusted",
                }
            ), delivery_header=KEY)

    def test_storage_failure_does_not_ack_event(self):
        self.path.unlink()
        with self.assertRaisesRegex(ReceiptStoreUnavailable, "^receipt_store_unavailable$"):
            self.store.receive(envelope(), delivery_header=KEY)

    def test_database_private_permissions(self):
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)
        self.assertEqual((Path(self.temp.name).stat().st_mode & 0o077), 0)

    def test_actual_avuhz_outbox_sink_retries_one_persisted_receipt(self):
        # This exercises the REAL LOCAL/TEST Avuhz outbox and sender, but the
        # authenticated n8n HTTP callback is still a synthetic test double.
        from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
            CREDENTIAL, ENDPOINT, application, request,
            event_and_outbox_from_committed_intake, worker_for,
        )

        app, fake_db = application()
        self.assertEqual(request(app)[0], 202)
        outbox = event_and_outbox_from_committed_intake(fake_db)
        tenant = outbox.events[0]["tenant_id"]
        receipt_store = LocalN8nReceiptStore(
            self.path,
            trusted_tenant_id=tenant,
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )

        class SyntheticNativeN8nAuth:
            lose_ack = True

            def post(self, endpoint, headers, raw):
                if endpoint != ENDPOINT:
                    return 404
                if headers.get("X-Avuhz-Webhook-Token") != CREDENTIAL:
                    return 401
                try:
                    entry = json.loads(raw)
                    result = receipt_store.receive(
                        entry, delivery_header=headers.get("X-Avuhz-Delivery-Key")
                    )
                except ConflictingReceipt:
                    return 409
                except (TypeError, ValueError):
                    return 400
                except UnauthorizedReceipt:
                    return 403
                except ReceiptStoreUnavailable:
                    return 503
                if self.lose_ack:
                    self.lose_ack = False
                    raise TimeoutError("fictional-lost-ack")
                return result.status

        receiver = SyntheticNativeN8nAuth()
        worker, clock = worker_for(outbox, receiver)
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM local_n8n_receipts").fetchone()[0], 1
            )
        clock.advance(5)
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(outbox.outbox[0]["status"], "PUBLISHED")
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT count(*) FROM local_n8n_receipts").fetchone()
        self.assertEqual(rows[0], 1)

    def test_invalid_directory_and_symlink_not_accepted(self):
        with self.assertRaises(ValueError):
            LocalN8nReceiptStore(
                Path("/tmp/avuhz-not-private/receipts.sqlite"),
                trusted_tenant_id=TENANT,
                allowed_event_types=frozenset({"acquisition.intake.received"}),
            )
        link = Path(self.temp.name) / "link.sqlite"
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            LocalN8nReceiptStore(
                link,
                trusted_tenant_id=TENANT,
                allowed_event_types=frozenset({"acquisition.intake.received"}),
            )


if __name__ == "__main__":
    unittest.main()
