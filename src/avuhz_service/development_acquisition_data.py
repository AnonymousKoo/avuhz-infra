"""Dormant, least-privileged DEVELOPMENT DATA acquisition connection boundary.

Repository candidate only: NO hosted registration, credential, login-role grant,
Render environment change, deployment, public intake route, or n8n receiver.
The separate DEVELOPMENT AUTH project must never be used for DATA sessions.

This factory can be selected only after a separately authorized DATA login role
and SET-only membership are installed and verified. It is never substituted for
the existing avuhz_command_service command/query runtime connection.
"""
from __future__ import annotations

from typing import Callable

from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork, connection_factory_from_environment
from .development_data import (
    DEVELOPMENT_DATA_ALLOWED_ENDPOINT_HOSTS,
    DEVELOPMENT_DATA_ENDPOINT_PORT,
    DEVELOPMENT_DATA_REQUIRED_SSLMODE,
    DEVELOPMENT_MIGRATION_IDENTITY,
)

ACQUISITION_RUNTIME_LOGIN = "avuhz_acquisition_runtime_service_dev"
ACQUISITION_DATABASE_ROLE = "avuhz_acquisition_service_dev"
ACQUISITION_POSTGRES_DSN_ENV = "AVUHZ_ACQUISITION_POSTGRES_DSN"
_COMMAND_DATABASE_ROLE = "avuhz_command_service"


class HostedDevelopmentAcquisitionConnectionFactory:
    """Reject every session except the isolated acquisition-role connection.

    The future login must be LOGIN NOINHERIT NOBYPASSRLS with exactly one
    non-admin, non-inheriting SET membership in the acquisition NOLOGIN role.
    No provider credentials, service_role fallback or elevated roles are used.
    """

    def __init__(self, connection_factory: Callable[[], object]) -> None:
        if not callable(connection_factory):
            raise ValueError("dedicated DEVELOPMENT acquisition factory required")
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
            parameters_method = getattr(info, "get_parameters", None)
            parameters = parameters_method() if callable(parameters_method) else None
            if (
                info is None
                or getattr(info, "host", None) not in DEVELOPMENT_DATA_ALLOWED_ENDPOINT_HOSTS
                or getattr(info, "port", None) != DEVELOPMENT_DATA_ENDPOINT_PORT
                or not hasattr(parameters, "get")
                or parameters.get("sslmode") != DEVELOPMENT_DATA_REQUIRED_SSLMODE
            ):
                raise RuntimeError

            preflight = connection.execute(
                "select session_user=%s and current_user=session_user "
                "and exists (select 1 from pg_catalog.pg_roles role "
                "where role.rolname=session_user and role.rolcanlogin "
                "and not role.rolsuper and not role.rolinherit "
                "and not role.rolcreatedb and not role.rolcreaterole "
                "and not role.rolreplication and not role.rolbypassrls) "
                "and exists (select 1 from pg_catalog.pg_roles role "
                "where role.rolname=%s and not role.rolcanlogin "
                "and not role.rolsuper and not role.rolinherit "
                "and not role.rolcreatedb and not role.rolcreaterole "
                "and not role.rolreplication and not role.rolbypassrls) "
                "and (select count(*) from pg_catalog.pg_auth_members m "
                "join pg_catalog.pg_roles member_role on member_role.oid=m.member "
                "join pg_catalog.pg_roles target_role on target_role.oid=m.roleid "
                "join pg_catalog.pg_roles grantor on grantor.oid=m.grantor "
                "where member_role.rolname=session_user "
                "and target_role.rolname=%s and grantor.rolname=%s "
                "and not m.admin_option and not m.inherit_option and m.set_option)=1 "
                "and (select count(*) from pg_catalog.pg_auth_members m "
                "join pg_catalog.pg_roles r on r.oid=m.member "
                "where r.rolname=session_user)=1 "
                "and not pg_has_role(session_user,%s,'MEMBER') "
                "and not pg_has_role(session_user,%s,'MEMBER') "
                "and (select count(*) from information_schema.role_table_grants "
                "where grantee=session_user)=0 "
                "and not has_schema_privilege(session_user,'public','CREATE') "
                "as ready",
                (
                    ACQUISITION_RUNTIME_LOGIN,
                    ACQUISITION_DATABASE_ROLE,
                    ACQUISITION_DATABASE_ROLE,
                    DEVELOPMENT_MIGRATION_IDENTITY,
                    _COMMAND_DATABASE_ROLE,
                    DEVELOPMENT_MIGRATION_IDENTITY,
                ),
            ).fetchone()
            if not preflight or preflight.get("ready") is not True:
                raise RuntimeError

            # The name is a code-owned constant, never composed from a request,
            # token, environment variable, or caller-controlled identifier.
            connection.execute("set role avuhz_acquisition_service_dev")
            effective = connection.execute(
                "select current_user=%s and session_user=%s "
                "and has_schema_privilege(current_user,'public','USAGE') "
                "and not has_schema_privilege(current_user,'public','CREATE') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_tenant_organizations','organization_id','SELECT') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_tenant_owner_memberships','verified_at','SELECT') "
                "and not has_column_privilege(current_user,"
                "'public.avuhz_tenant_owner_memberships','principal_subject_digest','SELECT') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_acquisition_intake_requests','contact_email','INSERT') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_acquisition_intake_requests','contact_email','SELECT') "
                "and not has_column_privilege(current_user,"
                "'public.avuhz_acquisition_intake_requests','intake_state','SELECT') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_lifecycle_events','lifecycle_event_id','INSERT') "
                "and has_column_privilege(current_user,"
                "'public.avuhz_outbox_deliveries','status','INSERT') "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_acquisition_intake_requests','DELETE') "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_lifecycle_events','UPDATE') "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_outbox_deliveries','SELECT') "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_outbox_deliveries','UPDATE') "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_engagements','SELECT') "
                "and (select count(*) from pg_catalog.pg_class c "
                "join pg_catalog.pg_namespace n on n.oid=c.relnamespace "
                "where n.nspname='public' and c.relname in "
                "('avuhz_tenant_organizations',"
                "'avuhz_tenant_owner_memberships',"
                "'avuhz_acquisition_intake_requests') "
                "and c.relrowsecurity and c.relforcerowsecurity)=3 "
                "and (select count(*) from pg_catalog.pg_class c "
                "join pg_catalog.pg_namespace n on n.oid=c.relnamespace "
                "where n.nspname='public' and c.relname in "
                "('avuhz_lifecycle_events','avuhz_outbox_deliveries') "
                "and c.relrowsecurity)=2 "
                "and (select count(*) from pg_catalog.pg_policies p "
                "where p.schemaname='public' "
                "and ((p.tablename='avuhz_acquisition_intake_requests' "
                "and p.policyname='avuhz_acquisition_intake_insert') "
                "or (p.tablename='avuhz_lifecycle_events' and "
                "p.policyname in ('avuhz_acquisition_event_read',"
                "'avuhz_acquisition_event_insert')) "
                "or (p.tablename='avuhz_outbox_deliveries' and "
                "p.policyname='avuhz_acquisition_outbox_insert')) "
                "and p.roles=ARRAY[%s]::name[])=4 as ready",
                (ACQUISITION_DATABASE_ROLE, ACQUISITION_RUNTIME_LOGIN, ACQUISITION_DATABASE_ROLE),
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
            raise RuntimeError("DEVELOPMENT acquisition DATA connection is invalid") from None


def create_hosted_development_acquisition_store(
    connection_factory: Callable[[], object] | None = None,
) -> PostgresStore:
    """Construct a separate dormant store; never mount a route or read rows."""
    raw = (
        connection_factory_from_environment(ACQUISITION_POSTGRES_DSN_ENV)
        if connection_factory is None else connection_factory
    )
    return PostgresStore(HostedDevelopmentAcquisitionConnectionFactory(raw))


def acquisition_unit_of_work(store: PostgresStore, trusted_context: object) -> PostgresUnitOfWork:
    """Preserve shared verified tenant binding; no client tenant parameters."""
    if type(store) is not PostgresStore:
        raise ValueError("dedicated acquisition store required")
    if (
        getattr(trusted_context, "environment", None) != "DEVELOPMENT"
        or getattr(trusted_context, "audience", None) != "avuhz-command-api"
        or getattr(trusted_context, "caller_type", None) != "INTERNAL_SERVICE"
        or getattr(trusted_context, "capabilities", None) != frozenset({"acquisition_intake:receive"})
    ):
        raise ValueError("verified DEVELOPMENT acquisition context required")
    return PostgresUnitOfWork(store, trusted_context=trusted_context)
