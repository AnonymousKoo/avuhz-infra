"""Offline, synthetic Stage 3 acquisition DATA connection guards.

No Supabase/Render/n8n calls, credentials, login-role creation or live traffic.
The installed non-login role alone must NOT satisfy this connection boundary.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.postgres import PostgresStore
from avuhz_service.development_acquisition_data import (
    ACQUISITION_DATABASE_ROLE,
    ACQUISITION_POSTGRES_DSN_ENV,
    ACQUISITION_RUNTIME_LOGIN,
    HostedDevelopmentAcquisitionConnectionFactory,
    create_hosted_development_acquisition_store,
)
from avuhz_service.development_data import (
    DEVELOPMENT_DATA_ENDPOINT_HOST,
    DEVELOPMENT_DATA_ENDPOINT_PORT,
    DEVELOPMENT_DATA_REQUIRED_SSLMODE,
    DEVELOPMENT_DATA_SESSION_POOLER_HOST,
    DEVELOPMENT_MIGRATION_IDENTITY,
)


class Cursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class ConnectionInfo:
    def __init__(self, host=DEVELOPMENT_DATA_ENDPOINT_HOST, port=5432, sslmode="require"):
        self.host = host
        self.port = port
        self.sslmode = sslmode

    def get_parameters(self):
        return {"sslmode": self.sslmode}


class Connection:
    def __init__(self, *, host=DEVELOPMENT_DATA_ENDPOINT_HOST, port=5432,
                 sslmode="require", preflight=True, effective=True, autocommit=True):
        self.info = ConnectionInfo(host, port, sslmode)
        self.preflight = preflight
        self.effective = effective
        self.autocommit = autocommit
        self.calls = []
        self.rollback_count = 0
        self.close_count = 0

    def execute(self, statement, params=()):
        self.calls.append((statement, params))
        if statement.startswith("select session_user"):
            return Cursor({"ready": self.preflight})
        if statement == "set role avuhz_acquisition_service_dev":
            return Cursor()
        if statement.startswith("select current_user"):
            return Cursor({"ready": self.effective})
        raise AssertionError("unexpected database query")

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.close_count += 1


class ConnectionFactory:
    def __init__(self, **options):
        self.options = options
        self.connections = []

    def __call__(self):
        connection = Connection(**self.options)
        self.connections.append(connection)
        return connection


class AcquisitionDevelopmentConnectionTests(unittest.TestCase):
    def test_acquisition_factory_is_distinct_and_stays_dormant(self):
        self.assertEqual(ACQUISITION_DATABASE_ROLE, "avuhz_acquisition_service_dev")
        self.assertEqual(ACQUISITION_RUNTIME_LOGIN, "avuhz_acquisition_runtime_service_dev")
        self.assertEqual(ACQUISITION_POSTGRES_DSN_ENV, "AVUHZ_ACQUISITION_POSTGRES_DSN")
        self.assertNotEqual(ACQUISITION_RUNTIME_LOGIN, "avuhz_data_runtime_service_dev")
        self.assertNotEqual(ACQUISITION_DATABASE_ROLE, "avuhz_command_service")
        raw = ConnectionFactory()
        store = create_hosted_development_acquisition_store(raw)
        self.assertIsInstance(store, PostgresStore)
        self.assertEqual(raw.connections, [])  # no connection before explicit use
        app = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("create_hosted_development_acquisition_store(", app)
        self.assertNotIn("/v1/acquisition/intakes", app)

    def test_success_validates_only_acquisition_login_membership_and_rls(self):
        raw = ConnectionFactory()
        conn = HostedDevelopmentAcquisitionConnectionFactory(raw)()
        self.assertIs(conn, raw.connections[0])
        self.assertFalse(conn.autocommit)
        self.assertEqual(conn.close_count, 0)
        self.assertEqual(len(conn.calls), 3)
        preflight, params = conn.calls[0]
        self.assertTrue(preflight.startswith("select session_user"))
        self.assertEqual(params, (
            ACQUISITION_RUNTIME_LOGIN,
            ACQUISITION_DATABASE_ROLE,
            ACQUISITION_DATABASE_ROLE,
            DEVELOPMENT_MIGRATION_IDENTITY,
            "avuhz_command_service",
            DEVELOPMENT_MIGRATION_IDENTITY,
        ))
        self.assertIn("not role.rolbypassrls", preflight)
        self.assertIn("not role.rolinherit", preflight)
        self.assertIn("not m.admin_option and not m.inherit_option and m.set_option", preflight)
        self.assertIn("where r.rolname=session_user)=1", preflight)
        self.assertIn("not pg_has_role(session_user,%s,'MEMBER')", preflight)
        self.assertIn("where grantee=session_user)=0", preflight)
        self.assertEqual(conn.calls[1], ("set role avuhz_acquisition_service_dev", ()))
        effective, role_params = conn.calls[2]
        self.assertEqual(
            role_params,
            (ACQUISITION_DATABASE_ROLE, ACQUISITION_RUNTIME_LOGIN, ACQUISITION_DATABASE_ROLE),
        )
        self.assertTrue(effective.startswith("select current_user"))
        self.assertIn("relforcerowsecurity)=3", effective)
        self.assertIn("and c.relrowsecurity)=2", effective)
        self.assertIn("avuhz_acquisition_event_insert", effective)
        self.assertIn("avuhz_acquisition_outbox_insert", effective)
        self.assertIn("p.roles=ARRAY[%s]::name[])=4", effective)
        self.assertIn("'avuhz_engagements','SELECT'", effective)
        self.assertIn("'principal_subject_digest','SELECT'", effective)
        self.assertIn("'intake_state','SELECT'", effective)
        self.assertIn("'avuhz_outbox_deliveries','UPDATE'", effective)
        self.assertNotIn("set_config('avuhz.tenant_id'", effective)
        conn.rollback()
        conn.close()

    def test_exact_session_pooler_accepted(self):
        raw = ConnectionFactory(
            host=DEVELOPMENT_DATA_SESSION_POOLER_HOST,
            port=DEVELOPMENT_DATA_ENDPOINT_PORT,
            sslmode=DEVELOPMENT_DATA_REQUIRED_SSLMODE,
        )
        conn = HostedDevelopmentAcquisitionConnectionFactory(raw)()
        self.assertEqual(conn.info.host, DEVELOPMENT_DATA_SESSION_POOLER_HOST)
        self.assertEqual(conn.close_count, 0)
        conn.close()

    def test_endpoint_role_and_rls_fail_closed_without_leaking_diagnostics(self):
        for options in (
            {"host": "db.example.invalid"},
            {"host": "db.pwlhruwutoitnieactol.supabase.co"},  # AUTH is never DATA
            {"host": "aws-0-us-west-2.pooler.supabase.com"},
            {"port": 6543},
            {"sslmode": "disable"},
            {"sslmode": "prefer"},
            {"preflight": False},   # missing login, SET role or extra membership
            {"effective": False},   # missing Stage 1/2 grants, policies or RLS
        ):
            with self.subTest(options=options):
                raw = ConnectionFactory(**options)
                with self.assertRaisesRegex(
                    RuntimeError, "^DEVELOPMENT acquisition DATA connection is invalid$"
                ):
                    HostedDevelopmentAcquisitionConnectionFactory(raw)()
                conn = raw.connections[0]
                self.assertEqual((conn.rollback_count, conn.close_count), (1, 1))
                self.assertFalse(any("avuhz_command_service" in sql and sql.startswith("set role")
                                     for sql, _ in conn.calls))

    def test_factory_is_not_a_fallback_to_command_role_or_credentials(self):
        with self.assertRaises(ValueError):
            HostedDevelopmentAcquisitionConnectionFactory(None)
        source = (ROOT / "src/avuhz_service/development_acquisition_data.py").read_text()
        self.assertNotIn("AVUHZ_POSTGRES_DSN", source)
        self.assertNotIn("create_development_application(", source)
        self.assertNotIn("GRANT ", source)


if __name__ == "__main__":
    unittest.main()
