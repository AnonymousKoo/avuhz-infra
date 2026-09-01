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
    DEVELOPMENT_MIGRATION_IDENTITY,
    DevelopmentDataSettings,
    DisposableLocalPostgresEndpoint,
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
        row = {"?column?": self.ready} if statement.startswith("select current_user") else None
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
        self.assertEqual(settings.data_project_ref, "pwlhruwutoitnieactol")
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
            {"host": "127.0.0.1", "port": 5432, "database": "pwlhruwutoitnieactol"},
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
        self.assertNotIn("pwlhruwutoitnieactol", statement)
        self.assertEqual((connection.rollbacks, connection.closed), (1, True))
        self.assertFalse(create_local_development_data_composition(
            DevelopmentDataSettings(), endpoint(), FakeLocalConnector(ready=False),
        ).readiness_probe.ready())

    def test_hosted_development_composition_remains_fail_closed(self):
        source = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("create_local_development_data_composition", source)
        settings = DevelopmentServiceSettings.from_environment({
            "AVUHZ_SERVICE_ENVIRONMENT": "DEVELOPMENT",
            "AVUHZ_DATA_PROJECT_REF": "pwlhruwutoitnieactol",
            "AVUHZ_DATA_PROJECT_URL": "https://pwlhruwutoitnieactol.supabase.co",
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
        self.assertFalse(application.readiness_probes["identity"].ready())


if __name__ == "__main__":
    unittest.main()
