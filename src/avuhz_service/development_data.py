"""Disposable-local PostgreSQL composition for DEVELOPMENT DATA certification."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Protocol

from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork

from .development import (
    DEVELOPMENT_COMMAND_SERVICE_IDENTITY,
    DEVELOPMENT_DATA_PROJECT_REF,
    DEVELOPMENT_ENVIRONMENT,
    DEVELOPMENT_RLS_POLICY_REFERENCE,
    DEVELOPMENT_TENANT_BRIDGE,
)


DEVELOPMENT_MIGRATION_IDENTITY = "avuhz_migration_service_dev"
CANONICAL_APPLICATION_DATABASE_ROLE = "avuhz_command_service"
_INTERNAL_RUNTIME_AUDIENCE = "avuhz-command-api"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_DATABASE_NAME = re.compile(r"^avuhz_development_disposable_[a-z0-9_]{1,48}$")


@dataclass(frozen=True)
class DevelopmentDataSettings:
    environment: str = DEVELOPMENT_ENVIRONMENT
    data_project_ref: str = DEVELOPMENT_DATA_PROJECT_REF
    tenant_bridge: str = DEVELOPMENT_TENANT_BRIDGE
    rls_policy_reference: str = DEVELOPMENT_RLS_POLICY_REFERENCE
    application_identity: str = DEVELOPMENT_COMMAND_SERVICE_IDENTITY
    migration_identity: str = DEVELOPMENT_MIGRATION_IDENTITY

    def __post_init__(self):
        expected = (
            self.environment == DEVELOPMENT_ENVIRONMENT,
            self.data_project_ref == DEVELOPMENT_DATA_PROJECT_REF,
            self.tenant_bridge == DEVELOPMENT_TENANT_BRIDGE,
            self.rls_policy_reference == DEVELOPMENT_RLS_POLICY_REFERENCE,
            self.application_identity == DEVELOPMENT_COMMAND_SERVICE_IDENTITY,
            self.migration_identity == DEVELOPMENT_MIGRATION_IDENTITY,
            self.application_identity != self.migration_identity,
        )
        if not all(expected):
            raise ValueError("approved DEVELOPMENT DATA boundary is required")


@dataclass(frozen=True)
class DisposableLocalPostgresEndpoint:
    host: str
    port: int
    database: str

    def __post_init__(self):
        if self.host not in _LOOPBACK_HOSTS:
            raise ValueError("disposable PostgreSQL must use loopback")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("valid disposable PostgreSQL port is required")
        if not isinstance(self.database, str) or not _DATABASE_NAME.fullmatch(self.database):
            raise ValueError("bounded disposable DEVELOPMENT database is required")
        if DEVELOPMENT_DATA_PROJECT_REF in self.database:
            raise ValueError("provider project references are not local database names")


class DisposableLocalPostgresConnector(Protocol):
    def connect(
        self,
        endpoint: DisposableLocalPostgresEndpoint,
        database_role: str,
    ) -> object: ...


class DevelopmentPostgresDataProbe:
    """Bounded local readiness check; it never reads tenant or provider data."""

    def __init__(self, connection_factory: Callable[[], object]):
        self._connection_factory = connection_factory

    def ready(self) -> bool:
        connection = None
        try:
            connection = self._connection_factory()
            row = connection.execute(
                "select current_user = %s and not rol.rolsuper and not rol.rolbypassrls "
                "and (select count(*) from pg_catalog.pg_tables "
                "where schemaname='public' and tablename like 'avuhz_%') = 16 "
                "and (select count(*) from pg_catalog.pg_class c join pg_catalog.pg_namespace n "
                "on n.oid=c.relnamespace where n.nspname='public' "
                "and c.relname like 'avuhz_%' and c.relrowsecurity) = 16 "
                "from pg_catalog.pg_roles rol where rol.rolname=current_user",
                (CANONICAL_APPLICATION_DATABASE_ROLE,),
            ).fetchone()
            return bool(row and row.get("?column?") is True)
        except Exception:
            return False
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()


@dataclass(frozen=True)
class LocalDevelopmentDataComposition:
    settings: DevelopmentDataSettings
    endpoint: DisposableLocalPostgresEndpoint
    store: PostgresStore
    uow_factory: type[PostgresUnitOfWork]
    readiness_probe: DevelopmentPostgresDataProbe

    def unit_of_work(self, trusted_context):
        if (
            getattr(trusted_context, "environment", None) != DEVELOPMENT_ENVIRONMENT
            or getattr(trusted_context, "audience", None) != _INTERNAL_RUNTIME_AUDIENCE
        ):
            raise ValueError("trusted DEVELOPMENT context is required")
        return self.uow_factory(self.store, trusted_context)


def create_local_development_data_composition(
    settings: DevelopmentDataSettings,
    endpoint: DisposableLocalPostgresEndpoint,
    connector: DisposableLocalPostgresConnector,
) -> LocalDevelopmentDataComposition:
    if type(settings) is not DevelopmentDataSettings or type(endpoint) is not DisposableLocalPostgresEndpoint:
        raise ValueError("exact local DEVELOPMENT DATA configuration is required")
    if connector is None or not callable(getattr(connector, "connect", None)):
        raise ValueError("disposable local PostgreSQL connector is required")

    def connection_factory():
        connection = connector.connect(endpoint, CANONICAL_APPLICATION_DATABASE_ROLE)
        if connection is None:
            raise RuntimeError("disposable local PostgreSQL is unavailable")
        return connection

    store = PostgresStore(connection_factory)
    return LocalDevelopmentDataComposition(
        settings=settings,
        endpoint=endpoint,
        store=store,
        uow_factory=PostgresUnitOfWork,
        readiness_probe=DevelopmentPostgresDataProbe(connection_factory),
    )
