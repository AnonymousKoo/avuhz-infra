"""DEVELOPMENT DATA composition for local certification and hosted runtime."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Protocol

from avuhz_runtime.postgres import (
    PostgresStore,
    PostgresUnitOfWork,
    connection_factory_from_environment,
)

from .development import (
    DEVELOPMENT_COMMAND_SERVICE_IDENTITY,
    DEVELOPMENT_DATA_PROJECT_REF,
    DEVELOPMENT_ENVIRONMENT,
    DEVELOPMENT_RLS_POLICY_REFERENCE,
    DEVELOPMENT_TENANT_BRIDGE,
)


DEVELOPMENT_MIGRATION_IDENTITY = "avuhz_data_migration_service_dev"
CANONICAL_APPLICATION_DATABASE_ROLE = "avuhz_command_service"
DEVELOPMENT_RUNTIME_LOGIN_IDENTITY = "avuhz_data_runtime_service_dev"
DEVELOPMENT_DATA_ENDPOINT_HOST = "db.gnuqaefotwgkwurjpyik.supabase.co"
DEVELOPMENT_DATA_SESSION_POOLER_HOST = "aws-1-us-west-2.pooler.supabase.com"
DEVELOPMENT_DATA_ENDPOINT_PORT = 5432
DEVELOPMENT_DATA_REQUIRED_SSLMODE = "require"
DEVELOPMENT_DATA_ALLOWED_ENDPOINT_HOSTS = frozenset({
    DEVELOPMENT_DATA_ENDPOINT_HOST,
    DEVELOPMENT_DATA_SESSION_POOLER_HOST,
})
DEVELOPMENT_POSTGRES_DSN_ENV = "AVUHZ_POSTGRES_DSN"
# Installed DEVELOPMENT DATA registries are separately permissioned.
# Being present and protected does NOT authorize this read-only runtime to use them.
_CURRENT_NO_RUNTIME_ACCESS_REGISTRIES = (
    "avuhz_tenant_organizations",
    "avuhz_tenant_owner_memberships",
    "avuhz_acquisition_intake_requests",
)
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


class HostedDevelopmentPostgresConnectionFactory:
    """Validate one hosted runtime session before exposing command-role authority."""

    def __init__(self, connection_factory: Callable[[], object]):
        if not callable(connection_factory):
            raise ValueError("hosted DEVELOPMENT PostgreSQL connection factory is required")
        self._connection_factory = connection_factory

    def __call__(self):
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None:
                raise RuntimeError
            if connection.autocommit:
                connection.autocommit = False

            info = getattr(connection, "info", None)
            get_parameters = getattr(info, "get_parameters", None) if info is not None else None
            parameters = get_parameters() if callable(get_parameters) else None
            if (
                info is None
                or getattr(info, "host", None) not in DEVELOPMENT_DATA_ALLOWED_ENDPOINT_HOSTS
                or getattr(info, "port", None) != DEVELOPMENT_DATA_ENDPOINT_PORT
                or not hasattr(parameters, "get")
                or parameters.get("sslmode") != DEVELOPMENT_DATA_REQUIRED_SSLMODE
            ):
                raise RuntimeError

            runtime = connection.execute(
                "select session_user = %s "
                "and exists (select 1 from pg_catalog.pg_roles rol "
                "where rol.rolname=session_user and rol.rolcanlogin "
                "and not rol.rolsuper and not rol.rolinherit and not rol.rolcreatedb "
                "and not rol.rolcreaterole and not rol.rolreplication and not rol.rolbypassrls) "
                "and (select count(*) from pg_catalog.pg_auth_members membership "
                "join pg_catalog.pg_roles granted_role on granted_role.oid=membership.roleid "
                "join pg_catalog.pg_roles member_role on member_role.oid=membership.member "
                "join pg_catalog.pg_roles grantor_role on grantor_role.oid=membership.grantor "
                "where granted_role.rolname=%s and member_role.rolname=session_user "
                "and grantor_role.rolname=%s and not membership.admin_option "
                "and not membership.inherit_option and membership.set_option)=1 "
                "and not pg_has_role(session_user,%s,'SET') "
                "and (select count(*) from information_schema.role_table_grants "
                "where grantee=session_user)=0 as ready",
                (
                    DEVELOPMENT_RUNTIME_LOGIN_IDENTITY,
                    CANONICAL_APPLICATION_DATABASE_ROLE,
                    DEVELOPMENT_MIGRATION_IDENTITY,
                    DEVELOPMENT_MIGRATION_IDENTITY,
                ),
            ).fetchone()
            if not runtime or runtime.get("ready") is not True:
                raise RuntimeError

            connection.execute(f"set role {CANONICAL_APPLICATION_DATABASE_ROLE}")
            effective = connection.execute(
                "select current_user=%s and session_user=%s "
                "and has_schema_privilege(current_user,'public','USAGE') "
                "and not has_schema_privilege(current_user,'public','CREATE') as ready",
                (
                    CANONICAL_APPLICATION_DATABASE_ROLE,
                    DEVELOPMENT_RUNTIME_LOGIN_IDENTITY,
                ),
            ).fetchone()
            if not effective or effective.get("ready") is not True:
                raise RuntimeError
            return connection
        except Exception:
            if connection is not None:
                try:
                    connection.rollback()
                except Exception:
                    pass
                try:
                    connection.close()
                except Exception:
                    pass
            raise RuntimeError("DEVELOPMENT DATA runtime connection is invalid") from None


class DevelopmentPostgresDataProbe:
    """Bounded readiness check; it never reads tenant or business rows."""

    def __init__(self, connection_factory: Callable[[], object]):
        self._connection_factory = connection_factory

    def ready(self) -> bool:
        connection = None
        try:
            connection = self._connection_factory()
            row = connection.execute(
                "select current_user = %s "
                "and exists (select 1 from pg_catalog.pg_roles rol "
                "where rol.rolname=current_user and not rol.rolcanlogin "
                "and not rol.rolsuper and not rol.rolbypassrls and not rol.rolcreatedb "
                "and not rol.rolcreaterole and not rol.rolreplication) "
                "and (select count(*) from pg_catalog.pg_tables "
                "where schemaname='public' and tablename like 'avuhz_%%') = 19 "
                "and (select count(*) from pg_catalog.pg_class relation "
                "join pg_catalog.pg_namespace namespace on namespace.oid=relation.relnamespace "
                "where namespace.nspname='public' and relation.relname like 'avuhz_%%' "
                "and relation.relkind in ('r','p') and relation.relrowsecurity) = 19 "
                "and (select count(*) from pg_catalog.pg_policy policy "
                "join pg_catalog.pg_class relation on relation.oid=policy.polrelid "
                "join pg_catalog.pg_namespace namespace on namespace.oid=relation.relnamespace "
                "where namespace.nspname='public' and relation.relname like 'avuhz_%%' "
                "and policy.polname='avuhz_command_service_tenant_isolation') = 19 "
                # All three new registries must retain FORCE RLS and zero
                # effective CRUD privileges for the bounded command role.
                "and (select count(*) from pg_catalog.pg_class relation "
                "join pg_catalog.pg_namespace namespace on namespace.oid=relation.relnamespace "
                "where namespace.nspname='public' "
                "and relation.relname in (%s,%s,%s) "
                "and relation.relrowsecurity and relation.relforcerowsecurity) = 3 "
                "and (select count(*) from pg_catalog.pg_tables table_info "
                "where table_info.schemaname='public' "
                "and table_info.tablename in (%s,%s,%s) "
                "and has_table_privilege(current_user,"
                "format('%%I.%%I',table_info.schemaname,table_info.tablename),"
                "'SELECT,INSERT,UPDATE,DELETE')) = 0 "
                "and (select count(*) from pg_catalog.pg_tables table_info "
                "where table_info.schemaname='public' and table_info.tablename like 'avuhz_%%' "
                "and has_table_privilege(current_user,"
                "format('%%I.%%I',table_info.schemaname,table_info.tablename),'SELECT')) = 16 "
                "and (select count(*) from pg_catalog.pg_tables table_info "
                "where table_info.schemaname='public' and table_info.tablename like 'avuhz_%%' "
                "and has_table_privilege(current_user,"
                "format('%%I.%%I',table_info.schemaname,table_info.tablename),'DELETE')) = 0 "
                "and has_schema_privilege(current_user,'public','USAGE') "
                "and not has_schema_privilege(current_user,'public','CREATE') as ready",
                (
                    CANONICAL_APPLICATION_DATABASE_ROLE,
                    *_CURRENT_NO_RUNTIME_ACCESS_REGISTRIES,
                    *_CURRENT_NO_RUNTIME_ACCESS_REGISTRIES,
                ),
            ).fetchone()
            return bool(row and row.get("ready") is True)
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


@dataclass(frozen=True)
class HostedDevelopmentDataComposition:
    settings: DevelopmentDataSettings
    store: PostgresStore
    uow_factory: type[PostgresUnitOfWork]
    readiness_probe: DevelopmentPostgresDataProbe


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


def create_hosted_development_data_composition(
    settings: DevelopmentDataSettings,
    connection_factory: Callable[[], object] | None = None,
) -> HostedDevelopmentDataComposition:
    if type(settings) is not DevelopmentDataSettings:
        raise ValueError("exact hosted DEVELOPMENT DATA configuration is required")
    raw_factory = (
        connection_factory_from_environment(DEVELOPMENT_POSTGRES_DSN_ENV)
        if connection_factory is None
        else connection_factory
    )
    hosted_factory = HostedDevelopmentPostgresConnectionFactory(raw_factory)
    store = PostgresStore(hosted_factory)
    return HostedDevelopmentDataComposition(
        settings=settings,
        store=store,
        uow_factory=PostgresUnitOfWork,
        readiness_probe=DevelopmentPostgresDataProbe(hosted_factory),
    )
