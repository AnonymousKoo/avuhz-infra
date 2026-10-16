"""Opt-in real disposable PG17 proof: unattended outbox polls using shared sink.

No installed n8n HTTP request. A strict in-memory receiver implements only
the n8n transport acknowledgment contract. The real tenant-RLS-scoped
PostgresStore, OutboxWorker and N8nOutboxSink are exercised together.
"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from threading import Event
from unittest.mock import patch

from tests.integration import test_postgres_outbox_worker_persistence as fixture
from avuhz_worker.local_unattended_n8n_dispatch import (
    LocalN8nOutboxDispatcher,LocalN8nDispatchConfig,
)
from avuhz_worker.n8n_event_sink import N8nOutboxSink

if fixture.DRIVER:
    from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork
    from avuhz_worker.outbox import OutboxWorker,WorkerSettings


@unittest.skipUnless(fixture.DRIVER and fixture.DSN, "approved disposable PG17 and DSN required")
class RealLocalPostgresUnattendedOutboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.PostgresOutboxWorkerTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixture.PostgresOutboxWorkerTests.tearDownClass()

    def setUp(self):
        self.fixtures=fixture.PostgresOutboxWorkerTests(
            methodName="test_publish_round_trip_restart_state_and_rls"
        )
        # The old outbox persistence fixture emits engagement.opened without
        # its required engagement_id. That historical fixture is legal SQL
        # but is intentionally rejected by the strict N8nOutboxSink schema.
        # Use a correctly shaped shared engagement.handoff.accepted event:
        # it needs no parent engagement row, and preserves same tenant RLS.
        with self.fixtures.owner() as db:
            db.execute(
                "truncate public.avuhz_outbox_deliveries,"
                "public.avuhz_lifecycle_events cascade"
            )
            db.execute(
                "insert into public.avuhz_lifecycle_events "
                "(lifecycle_event_id,tenant_id,event_type,event_schema_version,"
                "authoritative_subject_type,authoritative_subject_id,"
                "authoritative_subject_version,occurred_at,producer_reference,"
                "correlation_id,idempotency_key,visibility,sanitized_metadata) "
                "values (%s,%s,'engagement.handoff.accepted',1,"
                "'ACQUISITION_HANDOFF',%s,1,%s,'command.service-01',%s,"
                "'postgres-worker-idempotency-0001','TENANT_OPERATIONAL',%s::jsonb)",
                (
                    fixture.EVENT_ID,fixture.TENANT,fixture.SUBJECT_ID,
                    fixture.NOW,fixture.CORRELATION_ID,
                    json.dumps({"handoff_id":fixture.SUBJECT_ID}),
                ),
            )
            db.execute(
                "insert into public.avuhz_outbox_deliveries "
                "(tenant_id,lifecycle_event_id,destination_reference,status,"
                "delivery_idempotency_key) "
                "values (%s,%s,'internal.lifecycle-events','PENDING',%s)",
                (fixture.TENANT,fixture.EVENT_ID,"outbox-delivery:"+fixture.EVENT_ID),
            )

    def test_unattended_polls_persist_one_receipt_without_leaking_source_metadata(self):
        receipts={}
        def fake_n8n_https(url,headers,raw):
            assert url=="https://n8n.example.invalid/webhook/avuhz-events"
            assert headers["Content-Type"]=="application/json"
            assert headers["X-Avuhz-Webhook-Token"]=="synthetic-only-no-real-secret"
            env=json.loads(raw)
            assert set(env)=={
                "event_id","event_type","tenant_id","correlation_id",
                "occurred_at","authoritative_subject_reference",
                "authoritative_subject_version","delivery_idempotency_key",
            }
            assert env["tenant_id"]==fixture.TENANT
            assert "sanitized_metadata" not in env
            assert "engagement_id" not in env
            key=headers["X-Avuhz-Delivery-Key"]
            assert key==env["delivery_idempotency_key"]
            receipts.setdefault(key,env)
            return 202
        sink=N8nOutboxSink(
            environment="TEST",tenant_id=fixture.TENANT,
            endpoint="https://n8n.example.invalid/webhook/avuhz-events",
            expected_host="n8n.example.invalid",
            credential_provider=lambda:"synthetic-only-no-real-secret",
            post=fake_n8n_https,
        )
        worker=OutboxWorker(
            PostgresStore(self.fixtures.service_factory),
            PostgresUnitOfWork,sink,self.fixtures.context(),
            WorkerSettings(tenant_id=fixture.TENANT),
            clock=lambda:datetime(2030,1,15,15,0,tzinfo=timezone.utc),
        )
        runner=LocalN8nOutboxDispatcher(
            worker, LocalN8nDispatchConfig(fixture.TENANT,1,3)
        )
        signal=Event()
        with patch.object(signal,"wait",return_value=False) as wait:
            summary=runner.run_until_stopped(signal)
        self.assertEqual((summary.cycles,summary.claimed,summary.published),(3,1,1))
        self.assertEqual(summary.termination,"CYCLE_LIMIT")
        self.assertEqual(wait.call_count,3)
        self.assertEqual(len(receipts),1)
        with self.fixtures.owner() as db:
            rows=db.execute("SELECT status,attempt_count FROM public.avuhz_outbox_deliveries").fetchall()
            self.assertEqual(
                [(row["status"],row["attempt_count"]) for row in rows],
                [("PUBLISHED",1)],
            )
        self.assertEqual(next(iter(receipts.values()))["event_id"],fixture.EVENT_ID)
        self.assertNotIn("synthetic-only-no-real-secret",repr(summary))
        self.assertNotIn(fixture.EVENT_ID,repr(summary))


if __name__=="__main__":
    unittest.main()
