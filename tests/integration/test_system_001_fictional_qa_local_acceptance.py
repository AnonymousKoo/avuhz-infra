"""One LOCAL synthetic System #001 journey without SekInfra as a client.

This is a composite acceptance test, NOT deployed AUTH, hosted DATA, running
n8n, persisted Work Item authority, communication delivery, or client billing.
It uses the REAL Avuhz intake/worker/HTTP-receipt/work-intake/followup modules
with explicit TEST-only authentication and lookup doubles.
"""
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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/service"), str(ROOT / "tests/worker")]
from avuhz_worker.local_n8n_receipt_http import (
    AUTH_HEADER, DELIVERY_HEADER, PATH, LocalN8nReceiptHTTPServer,
)
from avuhz_worker.local_n8n_receipt_store import LocalN8nReceiptStore
from avuhz_service.shared_work_intake_candidate import SharedWorkIntakeCandidate, WorkIntakeCommand, WorkIntakeDenied
from avuhz_service.shared_revenue_followup_review import (
    FollowupObservation, FollowupReviewPolicy, review_followup_due,
)
from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
    CREDENTIAL, ENDPOINT, application, request, worker_for,
    event_and_outbox_from_committed_intake,
)
from test_shared_work_intake_candidate import FakeOfflineResolver, FakeTenantMembershipDirectory

FIXTURE_PATH = ROOT / "tests/fixtures/system001_qa_tenant_local_v1.json"


def fixture() -> dict:
    payload = json.loads(FIXTURE_PATH.read_text())
    if (
        payload.get("fixture_type") != "LOCAL_TEST_ONLY_FICTIONAL_CLIENT"
        or payload.get("fixture_name") != "Avuhz QA Tenant 001"
        or payload.get("owner_is_real_or_verified") is not False
        or payload.get("hosted_data_insert_authorized") is not False
        or payload.get("production_allowed") is not False
        or "tenant_id" in payload.get("request", {})
        or "organization_id" in payload.get("request", {})
        or not payload["request"]["contact_email"].endswith(".invalid")
        or "sekinfra" in json.dumps(payload).lower()
    ):
        raise ValueError("fictional local client evidence required")
    return payload


class SyntheticLocalRelay:
    """n8n wire SIMULATION. Authenticated hop is a disposable loopback server.

    A real locally installed n8n workflow is NOT invoked by this class.
    """
    def __init__(self, receipt_port: int, token: str, *, lose_ack=False):
        self.port = receipt_port
        self.token = token
        self.lose_ack = lose_ack
        self.calls = 0

    def post(self, endpoint, headers, body):
        if endpoint != ENDPOINT or headers.get("X-Avuhz-Webhook-Token") != CREDENTIAL:
            return 401
        self.calls += 1
        if type(body) is not bytes or not 1 <= len(body) <= 4096:
            return 400
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{PATH}", data=body,
            headers={
                "Content-Type": "application/json",
                AUTH_HEADER: self.token,
                DELIVERY_HEADER: headers["X-Avuhz-Delivery-Key"],
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                status = response.status
                reply = json.load(response)
        except urllib.error.HTTPError as error:
            return error.code
        if status != 202 or reply.get("accepted") is not True:
            return 503
        if self.lose_ack:
            self.lose_ack = False
            raise TimeoutError("synthetic lost acknowledgment after durable receipt")
        return status


class FictionalSystem001LocalAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.qa = fixture()
        self.tmp = tempfile.TemporaryDirectory(prefix="avuhz-system001-qa-")
        self.addCleanup(self.tmp.cleanup)
        self.token = secrets.token_urlsafe(48)
        self.receipts = LocalN8nReceiptStore(
            Path(self.tmp.name) / "receipts.sqlite",
            trusted_tenant_id=self.qa["tenant_id"],
            allowed_event_types=frozenset({"acquisition.intake.received"}),
        )
        self.server = LocalN8nReceiptHTTPServer(
            receipt_store=self.receipts,
            token_provider=lambda: self.token,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def receipt_rows(self):
        with sqlite3.connect(self.receipts._path) as conn:
            return conn.execute(
                "select trusted_tenant_id, delivery_key, event_id, envelope_digest from local_n8n_receipts"
            ).fetchall()

    def test_fictional_qa_intake_receipt_owner_due_handoff_and_resolution(self):
        app, fake_acquisition_db = application()
        status, result, _headers = request(app, obj=self.qa["request"])
        self.assertEqual((status, result["duplicate"]), (202, False))
        self.assertNotIn(self.qa["request"]["contact_email"], json.dumps(result))
        outbox = event_and_outbox_from_committed_intake(fake_acquisition_db)
        self.assertEqual(outbox.events[0]["tenant_id"], self.qa["tenant_id"])
        self.assertEqual(outbox.events[0]["event_type"], "acquisition.intake.received")

        relay = SyntheticLocalRelay(self.server.server_port, self.token, lose_ack=True)
        worker, clock = worker_for(outbox, relay)
        self.assertEqual(worker.run_once()["retry_scheduled"], 1)
        self.assertEqual(len(self.receipt_rows()), 1)
        clock.advance(5)
        self.assertEqual(worker.run_once()["published"], 1)
        self.assertEqual(outbox.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(len(self.receipt_rows()), 1)
        self.assertEqual(relay.calls, 2)
        self.assertEqual(worker.run_once()["claimed"], 0)
        row = self.receipt_rows()[0]
        self.assertEqual(row[0], self.qa["tenant_id"])
        self.assertEqual(len(row[3]), 64)
        # The durable receipt is a PII-free digest+key, NOT a Work Item.
        self.assertNotIn(self.qa["request"]["contact_email"], json.dumps(row))
        self.assertNotIn(self.qa["request"]["contact_name"], json.dumps(row))
        self.assertNotIn(self.token, json.dumps(row))

        # MANUAL synthetic shared-core owner authorization boundary.
        # This is NOT an n8n command, automated lookup, or real AUTH proof.
        work = SharedWorkIntakeCandidate(
            FakeOfflineResolver(),
            resolve_tenant_member=FakeTenantMembershipDirectory(),
        )
        open_command = WorkIntakeCommand(
            "OPEN", self.qa["work_item_id"], "qa-work-open-0001",
            source="web", classification="service_request",
            next_action_due_at=self.qa["next_action_due_at"],
        )
        opened = work.apply("sender", open_command)
        self.assertEqual(opened.item.owner_reference, self.qa["work_owner_reference"])
        self.assertEqual(opened.item.tenant_id, self.qa["tenant_id"])
        self.assertEqual(opened.item.state, "OPEN")
        self.assertEqual(opened.item.next_action_due_at, self.qa["next_action_due_at"])
        self.assertEqual(opened.intent.event_type, "work_intake.opened")
        self.assertTrue(work.apply("sender", open_command).replayed)
        self.assertEqual(work.get("sender", self.qa["work_item_id"]).record_version, 1)

        policy = FollowupReviewPolicy(escalation_after_minutes=15)
        def review(item, now):
            return review_followup_due(
                (FollowupObservation(item, self.qa["next_action_due_at"]),),
                trusted_tenant_id=self.qa["tenant_id"], policy=policy, now=now,
            )
        self.assertEqual(review(opened.item, datetime(2030, 1, 15, 16, 4, tzinfo=timezone.utc)), ())
        due = review(opened.item, datetime(2030, 1, 15, 16, 5, tzinfo=timezone.utc))
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].kind, "FOLLOWUP_DUE")
        escalated = review(opened.item, datetime(2030, 1, 15, 16, 21, tzinfo=timezone.utc))
        self.assertEqual(escalated[0].kind, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED")

        offered = work.apply("sender", WorkIntakeCommand(
            "OFFER_HANDOFF", self.qa["work_item_id"], "qa-handoff-offer-0001",
            expected_record_version=1, recipient="worker.receiver",
        ))
        accepted = work.apply("receiver", WorkIntakeCommand(
            "ACCEPT_HANDOFF", self.qa["work_item_id"], "qa-handoff-accept-0001",
            expected_record_version=2,
        ))
        self.assertEqual((offered.item.record_version, accepted.item.record_version), (2, 3))
        self.assertEqual(accepted.item.owner_reference, "worker.receiver")
        with self.assertRaises(WorkIntakeDenied):
            work.get("sender", self.qa["work_item_id"])

        resolved = work.apply("receiver", WorkIntakeCommand(
            "RESOLVE", self.qa["work_item_id"], "qa-work-resolve-0001",
            expected_record_version=3,
        ))
        self.assertEqual(resolved.item.state, "RESOLVED")
        self.assertEqual(review(resolved.item, datetime(2030, 1, 15, 17, 0, tzinfo=timezone.utc)), ())
        self.assertEqual(len(self.receipt_rows()), 1)

    def test_untrusted_tenant_or_secret_never_reaches_committed_qa_receipt(self):
        app, store = application()
        malicious = {**self.qa["request"], "tenant_id": self.qa["tenant_id"]}
        self.assertEqual(request(app, obj=malicious)[0], 403)
        self.assertEqual(store.connections, [])
        self.assertEqual(self.receipt_rows(), [])
        relay = SyntheticLocalRelay(self.server.server_port, self.token)
        self.assertEqual(relay.post(ENDPOINT, {"X-Avuhz-Webhook-Token":"wrong"}, "{}"), 401)
        self.assertEqual(self.receipt_rows(), [])


if __name__ == "__main__":
    unittest.main()
