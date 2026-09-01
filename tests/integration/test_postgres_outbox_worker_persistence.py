"""Opt-in local PostgreSQL persistence certification for outbox delivery."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
DRIVER = importlib.util.find_spec("psycopg") is not None

if DRIVER:
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    from avuhz_runtime.guards import TrustedExecutionContext
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    from avuhz_worker import FakeLocalSink, OutboxWorker, WorkerSettings
else:
    psycopg = None

TENANT = "f4000000-0000-4000-8000-000000000001"
EVENT_ID = "f4000000-0000-4000-8000-000000000002"
SUBJECT_ID = "f4000000-0000-4000-8000-000000000003"
CORRELATION_ID = "f4000000-0000-4000-8000-000000000004"
NOW = "2030-01-15T15:00:00Z"


@unittest.skipUnless(DRIVER and DSN, "explicit disposable local PostgreSQL DSN and psycopg are required")
class PostgresOutboxWorkerTests(unittest.TestCase):
    @classmethod
    def owner(cls, *, autocommit=False):
        return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)

    @classmethod
    def service_factory(cls):
        connection = cls.owner(autocommit=True)
        connection.execute("set role avuhz_command_service")
        return connection

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if DRIVER and DSN:
            with cls.owner(autocommit=True) as connection:
                owner = connection.execute("select current_user").fetchone()["current_user"]
                connection.execute(sql.SQL("grant avuhz_command_service to {}").format(sql.Identifier(owner)))

    @classmethod
    def tearDownClass(cls):
        if DRIVER and DSN:
            with cls.owner(autocommit=True) as connection:
                owner = connection.execute("select current_user").fetchone()["current_user"]
                connection.execute(sql.SQL("revoke avuhz_command_service from {}").format(sql.Identifier(owner)))
        super().tearDownClass()

    def setUp(self):
        with self.owner() as connection:
            connection.execute("truncate public.avuhz_outbox_deliveries,public.avuhz_lifecycle_events cascade")
            connection.execute(
                "insert into public.avuhz_lifecycle_events "
                "(lifecycle_event_id,tenant_id,event_type,event_schema_version,authoritative_subject_type,"
                "authoritative_subject_id,authoritative_subject_version,occurred_at,producer_reference,"
                "correlation_id,idempotency_key,visibility,sanitized_metadata) values "
                "(%s,%s,'engagement.opened',1,'ENGAGEMENT',%s,1,%s,'command.service-01',%s,"
                "'postgres-worker-idempotency-0001','TENANT_OPERATIONAL',%s::jsonb)",
                (EVENT_ID,TENANT,SUBJECT_ID,NOW,CORRELATION_ID,'{"engagement_id":"'+SUBJECT_ID+'"}'),
            )
            connection.execute(
                "insert into public.avuhz_outbox_deliveries "
                "(tenant_id,lifecycle_event_id,destination_reference,status,delivery_idempotency_key) "
                "values (%s,%s,'internal.lifecycle-events','PENDING',%s)",
                (TENANT,EVENT_ID,"outbox-delivery:"+EVENT_ID),
            )

    @staticmethod
    def context():
        return TrustedExecutionContext(
            True,"service.outbox-worker-local","INTERNAL_SERVICE",TENANT,None,
            frozenset({"event:publish_internal"}),frozenset(),"TEST","avuhz-command-api",
            "STRONG",False,NOW,"2031-01-15T15:00:00Z",
        )

    def test_publish_round_trip_restart_state_and_rls(self):
        sink = FakeLocalSink()
        worker = OutboxWorker(
            PostgresStore(self.service_factory),PostgresUnitOfWork,sink,self.context(),
            WorkerSettings(tenant_id=TENANT),clock=lambda: datetime(2030,1,15,15,0,tzinfo=timezone.utc),
        )
        self.assertEqual(worker.run_once()["published"],1)
        with self.owner() as connection:
            row=connection.execute("select status,attempt_count,jsonb_array_length(attempt_history) history_count from public.avuhz_outbox_deliveries").fetchone()
            self.assertEqual((row["status"],row["attempt_count"],row["history_count"]),("PUBLISHED",1,1))
        self.assertEqual(OutboxWorker(
            PostgresStore(self.service_factory),PostgresUnitOfWork,sink,self.context(),
            WorkerSettings(tenant_id=TENANT),clock=lambda: datetime(2030,1,15,15,1,tzinfo=timezone.utc),
        ).run_once()["claimed"],0)
        self.assertEqual(len(sink.receipts),1)


if __name__ == "__main__":
    unittest.main()
