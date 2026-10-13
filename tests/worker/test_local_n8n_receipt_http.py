"""Actual loopback HTTP + durable LOCAL receipt tests, all fictional."""
from __future__ import annotations

import json
import secrets
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_worker.local_n8n_receipt_store import LocalN8nReceiptStore
from avuhz_worker.local_n8n_receipt_http import (
    AUTH_HEADER, DELIVERY_HEADER, PATH, LocalN8nReceiptHTTPServer,
)
from tests.worker.test_local_n8n_receipt_store import KEY, TENANT, envelope


class LoopbackReceiptHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="avuhz-loopback-http-")
        self.token = secrets.token_urlsafe(48)
        self.store = LocalN8nReceiptStore(
            Path(self.tmp.name) / "receipts.sqlite",
            trusted_tenant_id=TENANT,
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )
        self.server = LocalN8nReceiptHTTPServer(
            receipt_store=self.store, token_provider=lambda: self.token
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.03},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def post(self, value=None, *, token=None, key=KEY, content_type="application/json", path=PATH, raw=None):
        data = raw if raw is not None else json.dumps(
            envelope() if value is None else value, separators=(",", ":")
        ).encode()
        headers = {
            "Content-Type": content_type,
            AUTH_HEADER: self.token if token is None else token,
            DELIVERY_HEADER: key,
        }
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.server.server_port}{path}",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def rows(self):
        with sqlite3.connect(self.store._path) as db:
            return db.execute("SELECT COUNT(*) FROM local_n8n_receipts").fetchone()[0]

    def test_first_http_receipt_and_replay_have_single_durable_row(self):
        self.assertEqual(self.post(), (202, {"accepted": True, "duplicate": False}))
        self.assertEqual(self.post(), (202, {"accepted": True, "duplicate": True}))
        self.assertEqual(self.rows(), 1)

    def test_wrong_secret_rejected_before_receipt(self):
        status, body = self.post(token=secrets.token_urlsafe(48))
        self.assertEqual((status, body), (401, {"error": "unauthorized"}))
        self.assertEqual(self.rows(), 0)

    def test_untrusted_tenant_and_event_rejected(self):
        self.assertEqual(self.post(envelope(tenant_id="a4770000-0000-4000-8000-000000000099"))[0], 403)
        self.assertEqual(self.post(envelope(event_type="billing.charge.approved"))[0], 403)
        self.assertEqual(self.rows(), 0)

    def test_bounded_data_and_no_pii(self):
        self.assertEqual(self.post(envelope(contact_name="Sensitive Person"))[0], 400)
        self.assertEqual(self.post(content_type="text/plain")[0], 415)
        self.assertEqual(self.post(raw=b"[" + b"0" * 5000 + b"]")[0], 413)
        self.assertEqual(self.post(raw=b"not JSON")[0], 400)
        raw = json.dumps(envelope(), separators=(",", ":"))
        duplicate_tenant = raw.replace('"tenant_id":', '"tenant_id":"forged", "tenant_id":')
        self.assertEqual(self.post(raw=duplicate_tenant.encode())[0], 400)
        self.assertEqual(self.post(path="/webhook/unapproved")[0], 404)
        self.assertEqual(self.rows(), 0)

    def test_semantic_collision_is_http_409(self):
        self.assertEqual(self.post()[0], 202)
        changed = envelope(event_id="a4770000-0000-4000-8000-000000000099")
        self.assertEqual(self.post(changed), (409, {"error": "delivery_key_conflict"}))
        self.assertEqual(self.rows(), 1)

    def test_storage_failure_is_503_never_202(self):
        self.store._path.unlink()
        self.assertEqual(self.post(), (503, {"error": "receipt_store_unavailable"}))

    def test_server_binds_exact_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertGreater(self.server.server_address[1], 0)

    def test_actual_outbox_sink_through_real_http_receipt_adapter(self):
        from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
            CREDENTIAL, ENDPOINT, application, request,
            event_and_outbox_from_committed_intake, worker_for,
        )
        app, fake_db = application()
        self.assertEqual(request(app)[0], 202)
        outbox = event_and_outbox_from_committed_intake(fake_db)
        # The acquisition test has a distinct fictional trusted tenant.
        self.server.receipt_store = LocalN8nReceiptStore(
            self.store._path,
            trusted_tenant_id=outbox.events[0]["tenant_id"],
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )
        # Only test-double event/HTTP n8n relay; not an active n8n workflow.
        class SyntheticNativeN8nRelay:
            first_ack_lost = True
            def post(self, url, headers, raw):
                if url != ENDPOINT or headers.get("X-Avuhz-Webhook-Token") != CREDENTIAL:
                    return 401
                status, _ = self_http.post(
                    token=self_token, key=headers["X-Avuhz-Delivery-Key"], raw=raw
                )
                if self.first_ack_lost:
                    self.first_ack_lost = False
                    raise TimeoutError("synthetic-lost-ack-after-commit")
                return status
        self_http = self
        self_token = self.token
        worker, clock = worker_for(outbox, SyntheticNativeN8nRelay())
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        self.assertEqual(self.rows(), 1)
        clock.advance(5)
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(self.rows(), 1)
        self.assertEqual(outbox.outbox[0]["status"], "PUBLISHED")


if __name__ == "__main__":
    unittest.main()
