"""Focused local-only DEVELOPMENT DATA composition tests."""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
from avuhz_service.development import DevelopmentServiceSettings, create_development_application
from avuhz_service.development_data import (
    CANONICAL_APPLICATION_DATABASE_ROLE,
    DEVELOPMENT_DATA_ENDPOINT_HOST,
    DEVELOPMENT_DATA_ENDPOINT_PORT,
    DEVELOPMENT_DATA_REQUIRED_SSLMODE,
    DEVELOPMENT_DATA_SESSION_POOLER_HOST,
    DEVELOPMENT_MIGRATION_IDENTITY,
    DEVELOPMENT_RUNTIME_LOGIN_IDENTITY,
    DevelopmentDataSettings,
    DisposableLocalPostgresEndpoint,
    create_hosted_development_data_composition,
    create_local_development_data_composition,
)


TENANT = "00000000-0000-4000-8000-000000000031"


class FakeCursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, ready=True):
        self.autocommit = True
        self.ready = ready
        self.executions = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, statement, parameters=()):
        self.executions.append((statement, parameters))
        row = {"ready": self.ready} if statement.startswith("select current_user") else None
        return FakeCursor(row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class FakeLocalConnector:
    def __init__(self, ready=True):
        self.ready = ready
        self.calls = []
        self.connections = []

    def connect(self, endpoint, database_role):
        self.calls.append((endpoint, database_role))
        connection = FakeConnection(self.ready)
        self.connections.append(connection)
        return connection


class FakeConnectionInfo:
    def __init__(
        self,
        host=DEVELOPMENT_DATA_ENDPOINT_HOST,
        port=DEVELOPMENT_DATA_ENDPOINT_PORT,
        sslmode=DEVELOPMENT_DATA_REQUIRED_SSLMODE,
    ):
        self.host = host
        self.port = port
        self.sslmode = sslmode

    def get_parameters(self):
        return {"sslmode": self.sslmode}


class FakeHostedConnection(FakeConnection):
    def __init__(
        self,
        *,
        host=DEVELOPMENT_DATA_ENDPOINT_HOST,
        port=DEVELOPMENT_DATA_ENDPOINT_PORT,
        sslmode=DEVELOPMENT_DATA_REQUIRED_SSLMODE,
        runtime_ready=True,
        effective_ready=True,
        readiness_ready=True,
    ):
        super().__init__(readiness_ready)
        self.info = FakeConnectionInfo(host, port, sslmode)
        self.runtime_ready = runtime_ready
        self.effective_ready = effective_ready

    def execute(self, statement, parameters=()):
        self.executions.append((statement, parameters))
        if statement.startswith("select session_user"):
            return FakeCursor({"ready": self.runtime_ready})
        if statement == "set role avuhz_command_service":
            return FakeCursor()
        if statement.startswith("select current_user"):
            return FakeCursor({"ready": self.effective_ready and self.ready})
        return FakeCursor()


class FakeHostedFactory:
    def __init__(self, **connection_options):
        self.connection_options = connection_options
        self.connections = []

    def __call__(self):
        connection = FakeHostedConnection(**self.connection_options)
        self.connections.append(connection)
        return connection


def context(**changes):
    values = dict(
        authenticated=True,
        principal_id="subject.development-workload-1",
        caller_type="WORKLOAD",
        tenant_id=TENANT,
        organization_id=None,
        capabilities=frozenset({"engagement:read"}),
        authority_roles=frozenset(),
        environment="DEVELOPMENT",
        audience="avuhz-command-api",
        authentication_strength="STRONG",
        step_up_satisfied=False,
        authenticated_at="2030-01-15T14:00:00Z",
        expires_at="2030-01-15T16:00:00Z",
    )
    values.update(changes)
    return TrustedExecutionContext(**values)


def endpoint():
    return DisposableLocalPostgresEndpoint(
        host="127.0.0.1",
        port=54322,
        database="avuhz_development_disposable_composition",
    )


class DevelopmentDataCompositionTests(unittest.TestCase):
    def test_exact_approved_settings_and_loopback_endpoint_are_required(self):
        settings = DevelopmentDataSettings()
        self.assertEqual(settings.data_project_ref, "gnuqaefotwgkwurjpyik")
        self.assertEqual(
            settings.tenant_bridge,
            "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
        )
        self.assertNotEqual(settings.application_identity, settings.migration_identity)
        self.assertEqual(settings.migration_identity, DEVELOPMENT_MIGRATION_IDENTITY)
        for changes in (
            {"environment": "STAGING"},
            {"data_project_ref": "unapproved-project"},
            {"tenant_bridge": "payload.tenant -> database.tenant"},
            {"migration_identity": settings.application_identity},
        ):
            with self.assertRaises(ValueError):
                replace(settings, **changes)
        for values in (
            {"host": "db.example.invalid", "port": 5432, "database": "avuhz_development_disposable_test"},
            {"host": "127.0.0.1", "port": 0, "database": "avuhz_development_disposable_test"},
            {"host": "127.0.0.1", "port": 5432, "database": "gnuqaefotwgkwurjpyik"},
        ):
            with self.assertRaises(ValueError):
                DisposableLocalPostgresEndpoint(**values)

    def test_composition_reuses_postgres_store_uow_ports_and_tenant_binding(self):
        connector = FakeLocalConnector()
        composition = create_local_development_data_composition(
            DevelopmentDataSettings(), endpoint(), connector,
        )
        self.assertIsInstance(composition.store, PostgresStore)
        self.assertIs(composition.uow_factory, PostgresUnitOfWork)
        uow = composition.unit_of_work(context())
        connection = connector.connections[-1]
        self.assertFalse(connection.autocommit)
        self.assertEqual(uow.trusted_tenant_id, TENANT)
        self.assertEqual(
            connection.executions[0],
            ("select set_config('avuhz.tenant_id',%s,true)", (TENANT,)),
        )
        for repository in (
            "handoffs", "engagements", "implementation_handoffs", "implementation_briefs",
            "idempotency", "lifecycle_events", "outbox", "deployment_verifications",
        ):
            self.assertTrue(hasattr(uow, repository), repository)
        uow.commit()
        self.assertEqual(connection.commits, 1)
        uow.rollback()
        self.assertEqual(connection.rollbacks, 1)
        uow.close()
        self.assertTrue(connection.closed)
        self.assertEqual(connector.calls[0][1], CANONICAL_APPLICATION_DATABASE_ROLE)

    def test_missing_trusted_tenant_fails_and_rolls_connection_closed(self):
        connector = FakeLocalConnector()
        composition = create_local_development_data_composition(
            DevelopmentDataSettings(), endpoint(), connector,
        )
        for invalid in (
            context(authenticated=False),
            context(tenant_id=None),
            context(environment="STAGING"),
            context(audience="avuhz-worker"),
        ):
            with self.assertRaises(ValueError):
                composition.unit_of_work(invalid)
        self.assertEqual(len(connector.connections), 2)
        self.assertTrue(all(connection.closed for connection in connector.connections))

    def test_local_readiness_is_bounded_and_never_uses_provider_project(self):
        connector = FakeLocalConnector(ready=True)
        composition = create_local_development_data_composition(
            DevelopmentDataSettings(), endpoint(), connector,
        )
        self.assertTrue(composition.readiness_probe.ready())
        connection = connector.connections[-1]
        statement, parameters = connection.executions[0]
        self.assertIn("rolbypassrls", statement)
        self.assertIn("relrowsecurity", statement)
        self.assertEqual(parameters, (CANONICAL_APPLICATION_DATABASE_ROLE,))
        self.assertNotIn("gnuqaefotwgkwurjpyik", statement)
        self.assertEqual((connection.rollbacks, connection.closed), (1, True))
        self.assertFalse(create_local_development_data_composition(
            DevelopmentDataSettings(), endpoint(), FakeLocalConnector(ready=False),
        ).readiness_probe.ready())

    def test_hosted_connection_validates_runtime_identity_then_sets_command_role(self):
        raw_factory = FakeHostedFactory()
        composition = create_hosted_development_data_composition(
            DevelopmentDataSettings(),
            raw_factory,
        )
        self.assertIsInstance(composition.store, PostgresStore)
        self.assertIs(composition.uow_factory, PostgresUnitOfWork)
        self.assertTrue(composition.readiness_probe.ready())

        connection = raw_factory.connections[-1]
        self.assertEqual(connection.info.host, DEVELOPMENT_DATA_ENDPOINT_HOST)
        self.assertEqual(connection.info.port, DEVELOPMENT_DATA_ENDPOINT_PORT)
        self.assertEqual(connection.info.get_parameters(), {"sslmode": "require"})
        runtime_sql, runtime_parameters = connection.executions[0]
        self.assertTrue(runtime_sql.startswith("select session_user"))
        self.assertNotIn("pg_stat_ssl", runtime_sql)
        self.assertEqual(
            runtime_parameters,
            (
                DEVELOPMENT_RUNTIME_LOGIN_IDENTITY,
                CANONICAL_APPLICATION_DATABASE_ROLE,
                DEVELOPMENT_MIGRATION_IDENTITY,
                DEVELOPMENT_MIGRATION_IDENTITY,
            ),
        )
        self.assertEqual(
            connection.executions[1],
            ("set role avuhz_command_service", ()),
        )
        effective_sql, effective_parameters = connection.executions[2]
        self.assertTrue(effective_sql.startswith("select current_user"))
        self.assertEqual(
            effective_parameters,
            (
                CANONICAL_APPLICATION_DATABASE_ROLE,
                DEVELOPMENT_RUNTIME_LOGIN_IDENTITY,
            ),
        )
        readiness_sql, readiness_parameters = connection.executions[3]
        self.assertIn("avuhz_command_service_tenant_isolation", readiness_sql)
        self.assertIn("has_table_privilege", readiness_sql)
        self.assertIn("'DELETE'", readiness_sql)
        self.assertEqual(
            readiness_parameters,
            (CANONICAL_APPLICATION_DATABASE_ROLE,),
        )
        self.assertEqual((connection.rollbacks, connection.closed), (1, True))

    def test_hosted_connection_accepts_exact_supavisor_session_endpoint(self):
        raw_factory = FakeHostedFactory(
            host=DEVELOPMENT_DATA_SESSION_POOLER_HOST,
            port=DEVELOPMENT_DATA_ENDPOINT_PORT,
        )
        composition = create_hosted_development_data_composition(
            DevelopmentDataSettings(),
            raw_factory,
        )
        self.assertTrue(composition.readiness_probe.ready())
        connection = raw_factory.connections[-1]
        self.assertEqual(connection.info.host, DEVELOPMENT_DATA_SESSION_POOLER_HOST)
        self.assertEqual(connection.info.port, 5432)
        self.assertEqual(
            connection.executions[1],
            ("set role avuhz_command_service", ()),
        )
        self.assertEqual((connection.rollbacks, connection.closed), (1, True))

    def test_hosted_connection_fails_closed_on_endpoint_or_role_drift(self):
        for options in (
            {"host": "db.example.invalid"},
            {"host": "aws-0-us-west-2.pooler.supabase.com"},
            {"host": DEVELOPMENT_DATA_SESSION_POOLER_HOST, "port": 6543},
            {"host": DEVELOPMENT_DATA_SESSION_POOLER_HOST, "sslmode": "disable"},
            {"host": DEVELOPMENT_DATA_SESSION_POOLER_HOST, "sslmode": "prefer"},
            {"runtime_ready": False},
            {"effective_ready": False},
            {"readiness_ready": False},
        ):
            with self.subTest(options=options):
                raw_factory = FakeHostedFactory(**options)
                composition = create_hosted_development_data_composition(
                    DevelopmentDataSettings(),
                    raw_factory,
                )
                self.assertFalse(composition.readiness_probe.ready())
                connection = raw_factory.connections[-1]
                self.assertTrue(connection.closed)
                self.assertGreaterEqual(connection.rollbacks, 1)

    def test_hosted_uow_keeps_existing_tenant_binding_and_never_uses_migration_identity(self):
        raw_factory = FakeHostedFactory()
        composition = create_hosted_development_data_composition(
            DevelopmentDataSettings(),
            raw_factory,
        )
        uow = composition.uow_factory(composition.store)
        connection = raw_factory.connections[-1]
        uow.bind_trusted_context(context())
        self.assertEqual(
            connection.executions[-1],
            ("select set_config('avuhz.tenant_id',%s,true)", (TENANT,)),
        )
        runtime_sql = connection.executions[0][0]
        self.assertIn("not pg_has_role(session_user,%s,'SET')", runtime_sql)
        self.assertNotIn("set role avuhz_data_migration_service_dev", "\n".join(
            statement for statement, _ in connection.executions
        ))
        uow.rollback()
        uow.close()
        self.assertTrue(connection.closed)

    def test_hosted_development_composition_remains_fail_closed_without_dsn(self):
        source = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("create_local_development_data_composition", source)
        self.assertIn("create_hosted_development_data_composition", source)
        self.assertNotIn("_UnavailableUnitOfWork", source)
        settings = DevelopmentServiceSettings.from_environment({
            "AVUHZ_SERVICE_ENVIRONMENT": "DEVELOPMENT",
            "AVUHZ_DATA_PROJECT_REF": "gnuqaefotwgkwurjpyik",
            "AVUHZ_DATA_PROJECT_URL": "https://gnuqaefotwgkwurjpyik.supabase.co",
            "AVUHZ_AUTH_PROJECT_REF": "pwlhruwutoitnieactol",
            "AVUHZ_AUTH_ISSUER": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
            "AVUHZ_SERVICE_AUDIENCE": "audience.avuhz.command-service.development",
            "AVUHZ_TENANT_BRIDGE": "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
            "AVUHZ_RLS_POLICY_REFERENCE": "policy.avuhz.tenant-rls.development.v1",
            "AVUHZ_COMMAND_SERVICE_IDENTITY": "avuhz_command_service_dev",
            "PORT": "10000",
        })
        application = create_development_application(settings)
        self.assertFalse(application.readiness_probes["data"].ready())
        self.assertTrue(application.readiness_probes["identity"].ready())

    def test_hosted_development_application_becomes_data_ready_only_after_validated_connection(self):
        settings = DevelopmentServiceSettings.from_environment({
            "AVUHZ_SERVICE_ENVIRONMENT": "DEVELOPMENT",
            "AVUHZ_DATA_PROJECT_REF": "gnuqaefotwgkwurjpyik",
            "AVUHZ_DATA_PROJECT_URL": "https://gnuqaefotwgkwurjpyik.supabase.co",
            "AVUHZ_AUTH_PROJECT_REF": "pwlhruwutoitnieactol",
            "AVUHZ_AUTH_ISSUER": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
            "AVUHZ_SERVICE_AUDIENCE": "audience.avuhz.command-service.development",
            "AVUHZ_TENANT_BRIDGE": "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
            "AVUHZ_RLS_POLICY_REFERENCE": "policy.avuhz.tenant-rls.development.v1",
            "AVUHZ_COMMAND_SERVICE_IDENTITY": "avuhz_command_service_dev",
            "PORT": "10000",
        })
        raw_factory = FakeHostedFactory()
        application = create_development_application(
            settings,
            data_connection_factory=raw_factory,
        )
        self.assertTrue(application.readiness_probes["identity"].ready())
        self.assertTrue(application.readiness_probes["data"].ready())
        self.assertEqual(
            raw_factory.connections[-1].executions[1],
            ("set role avuhz_command_service", ()),
        )


if __name__ == "__main__":
    unittest.main()
