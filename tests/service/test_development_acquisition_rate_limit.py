"""TEST-only shared DEVELOPMENT PostgreSQL acquisition limiter contract.

Synthetic tenant/service references only. The fake atomic executor models
a durable table across separate application instances and tests boundaries;
it is not proof of hosted DATA RLS, grants, or real database concurrency.
"""
from __future__ import annotations

import hashlib
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development_acquisition_rate_limit import (
    DevelopmentPostgresAcquisitionRateLimiter,
    _ATOMIC_ADMISSION_SQL,
    _MAX_REQUESTS,
    _WINDOW_SECONDS,
)

TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
PRINCIPAL = "service.shared-acquisition-test"


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class SharedCounterDatabase:
    def __init__(self):
        self.counters = {}
        self.clock_seconds = 1000
        self.lock = threading.Lock()
        self.fail_step = None
        self.execute_history = []

    def advance(self, seconds):
        self.clock_seconds += seconds

    def connect(self):
        return SimulatedConnection(self)


class SimulatedConnection:
    autocommit = False

    def __init__(self, database):
        self.database = database
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.tenant = None
        self.admission_key = None
        self.next_row = None
        self.is_denied = False

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if self.database.fail_step == "setting":
            raise RuntimeError("private database setting diagnostics")
        if "set_config('avuhz.tenant_id'" in sql:
            self.tenant = params[0]
            return Cursor(None)
        if self.database.fail_step == "upsert":
            raise RuntimeError("private database upsert diagnostics")
        assert sql == _ATOMIC_ADMISSION_SQL
        assert "on conflict (tenant_id, principal_digest)" in sql
        assert "returning request_count" in sql
        assert "interval '300 seconds'" in sql
        tenant, digest = params
        assert tenant == self.tenant
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
        with self.database.lock:
            existing = self.database.counters.get((tenant, digest))
            if existing is None or self.database.clock_seconds - existing[0] >= _WINDOW_SECONDS:
                self.next_row = (self.database.clock_seconds, 1)
                self.admission_key = (tenant, digest)
            elif existing[1] < _MAX_REQUESTS:
                self.next_row = (existing[0], existing[1] + 1)
                self.admission_key = (tenant, digest)
            else:
                self.is_denied = True
        return Cursor(None if self.is_denied else {"request_count": self.next_row[1]})

    def commit(self):
        if self.database.fail_step == "commit":
            raise RuntimeError("private transaction error")
        with self.database.lock:
            if self.admission_key is not None:
                self.database.counters[self.admission_key] = self.next_row
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class Store:
    def __init__(self, db):
        self.db = db
        self.connections = []

    def connection_factory(self):
        conn = self.db.connect()
        self.connections.append(conn)
        return conn


class PersistentAcquisitionRateLimiterTests(unittest.TestCase):
    def test_atomic_sql_and_fixed_database_policy_not_client_request_uuid(self):
        sql = _ATOMIC_ADMISSION_SQL.lower()
        self.assertIn("clock_timestamp()", sql)
        self.assertIn("on conflict (tenant_id, principal_digest)", sql)
        self.assertIn("returning request_count", sql)
        self.assertIn("where public.avuhz_acquisition_rate_limit_counters.window_started_at", sql)
        self.assertIn("request_count < 10", sql)
        self.assertIn("interval '300 seconds'", sql)
        self.assertNotIn("external_request_id", sql)
        self.assertNotIn("request_uuid", sql)
        self.assertNotIn("service_role", sql)
        self.assertNotIn("bypassrls", sql)
        self.assertNotIn("grant ", sql)
        self.assertNotIn("create table", sql)

    def test_tenth_accepted_eleventh_denied_and_window_resets(self):
        db = SharedCounterDatabase()
        first_store = Store(db)
        first = DevelopmentPostgresAcquisitionRateLimiter(first_store)
        for index in range(10):
            with self.subTest(index=index):
                self.assertIs(first(TENANT_A, PRINCIPAL), True)
        self.assertIs(first(TENANT_A, PRINCIPAL), False)
        self.assertEqual(len(db.counters), 1)
        self.assertEqual(next(iter(db.counters.values()))[1], 10)
        rejected = first_store.connections[-1]
        self.assertEqual(rejected.commits, 0)
        self.assertEqual(rejected.rollbacks, 1)
        self.assertTrue(rejected.closed)
        db.advance(299)
        second_store = Store(db)
        second = DevelopmentPostgresAcquisitionRateLimiter(second_store)
        self.assertIs(second(TENANT_A, PRINCIPAL), False)
        db.advance(1)
        self.assertIs(second(TENANT_A, PRINCIPAL), True)
        self.assertEqual(next(iter(db.counters.values()))[1], 1)

    def test_same_counter_across_hosts_but_tenants_and_services_isolated(self):
        db = SharedCounterDatabase()
        left = DevelopmentPostgresAcquisitionRateLimiter(Store(db))
        right = DevelopmentPostgresAcquisitionRateLimiter(Store(db))
        self.assertTrue(left(TENANT_A, PRINCIPAL))
        self.assertTrue(right(TENANT_A, PRINCIPAL))
        self.assertTrue(left(TENANT_B, PRINCIPAL))
        self.assertTrue(right(TENANT_A, "service.different"))
        self.assertEqual(len(db.counters), 3)
        digest_a = hashlib.sha256((TENANT_A + "\x00" + PRINCIPAL).encode()).hexdigest()
        digest_b = hashlib.sha256((TENANT_B + "\x00" + PRINCIPAL).encode()).hexdigest()
        self.assertNotEqual(digest_a, digest_b)
        self.assertEqual(db.counters[(TENANT_A, digest_a)][1], 2)
        self.assertEqual(db.counters[(TENANT_B, digest_b)][1], 1)
        self.assertNotIn(PRINCIPAL, repr(db.counters))

    def test_untrusted_tenant_and_invalid_principal_rejected_without_connection(self):
        db = SharedCounterDatabase()
        store = Store(db)
        limit = DevelopmentPostgresAcquisitionRateLimiter(store)
        for tenant, principal in (
            (None, PRINCIPAL),
            ("not-a-tenant", PRINCIPAL),
            (TENANT_A.upper(), PRINCIPAL),
            (TENANT_A, None),
            (TENANT_A, ""),
            (TENANT_A, "Public Name With Spaces"),
            (TENANT_A, "a" * 129),
            (TENANT_A, "service.password\nvalue"),
            (TENANT_A, "service.💥"),
        ):
            with self.subTest(tenant=tenant, principal=principal):
                self.assertIs(limit(tenant, principal), False)
        self.assertEqual(store.connections, [])

    def test_missing_table_or_database_error_fails_closed_and_rolls_back(self):
        for step in ("setting", "upsert", "commit"):
            with self.subTest(step=step):
                db = SharedCounterDatabase()
                db.fail_step = step
                store = Store(db)
                result = DevelopmentPostgresAcquisitionRateLimiter(store)(
                    TENANT_A, PRINCIPAL,
                )
                self.assertIs(result, False)
                self.assertEqual(len(store.connections), 1)
                connection = store.connections[0]
                self.assertEqual(connection.commits, 0)
                self.assertEqual(connection.rollbacks, 1)
                self.assertTrue(connection.closed)
                self.assertEqual(db.counters, {})

    def test_missing_connection_or_bad_row_denies(self):
        with self.assertRaises(ValueError):
            DevelopmentPostgresAcquisitionRateLimiter(None)

        class BrokenStore:
            def connection_factory(self):
                raise RuntimeError("private missing DATA connection")

        self.assertIs(
            DevelopmentPostgresAcquisitionRateLimiter(BrokenStore())(
                TENANT_A, PRINCIPAL,
            ),
            False,
        )

    def test_existing_writer_can_use_limiter_without_new_auth_or_intake_path(self):
        from test_acquisition_intake_command import (
            Connection as WriterConnection,
            Store as WriterStore,
            NOW, payload, service_context,
        )
        from avuhz_service.acquisition_intake_command import ReceiveAcquisitionIntakeCandidate

        db = SharedCounterDatabase()
        limiter = DevelopmentPostgresAcquisitionRateLimiter(Store(db))
        writer_connection = WriterConnection()
        writer = ReceiveAcquisitionIntakeCandidate(
            WriterStore(writer_connection), limiter,
        )
        request = payload()
        for index in range(_MAX_REQUESTS):
            request = {**request, "external_request_id": f"a4730000-0000-4000-8000-{index + 100:012d}"}
            writer.receive(request, service_context(), evaluated_at=NOW)
        with self.assertRaisesRegex(PermissionError, "^acquisition_intake_not_authorized$"):
            writer.receive(
                {**request, "external_request_id": "a4730000-0000-4000-8000-000000999999"},
                service_context(),
                evaluated_at=NOW,
            )
        self.assertEqual(writer_connection.commits, 10)
        self.assertEqual(len(db.counters), 1)

    def test_source_remains_unmounted_and_hosted_grants_unavailable(self):
        root = ROOT / "src" / "avuhz_service"
        source = (root / "development.py").read_text()
        self.assertNotIn("DevelopmentPostgresAcquisitionRateLimiter", source)
        self.assertNotIn("DevelopmentAuthenticatedAcquisitionIngress(", source)
        from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
        self.assertTrue(all("acquisition_intake:receive" not in x.capabilities
                            for x in DEVELOPMENT_IDENTITY_ALLOWLIST))


if __name__ == "__main__":
    unittest.main()
