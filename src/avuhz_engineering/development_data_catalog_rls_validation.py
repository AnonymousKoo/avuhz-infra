"""One-transaction DEVELOPMENT DATA catalog/RLS validation.

This module has no migration, repair, business-row, AUTH-data, Render, or
service-role path. The runtime database credential is supplied only through an
injected connection factory after separate authorization by the executor script.
Raw connection material and raw catalog metadata are never returned as evidence.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn

from avuhz_runtime.implementation_handoff import canonical_digest


DEVELOPMENT_DATA_PROJECT_REF = "gnuqaefotwgkwurjpyik"
DEVELOPMENT_DATA_ENDPOINT_HOST = "db.gnuqaefotwgkwurjpyik.supabase.co"
DEVELOPMENT_DATA_RUNTIME_LOGIN = "avuhz_data_runtime_service_dev"
DEVELOPMENT_DATA_MIGRATION_IDENTITY = "avuhz_data_migration_service_dev"
CANONICAL_COMMAND_ROLE = "avuhz_command_service"
DATA_RUNTIME_READ_CREDENTIAL_CLASS = "SUPABASE_DATA_RUNTIME_READ"
DATA_RUNTIME_DSN_ENV_REFERENCE = "AVUHZ_POSTGRES_DSN"

EXPECTED_TABLE_COUNT = 16
EXPECTED_COLUMN_COUNT = 306
EXPECTED_CONSTRAINT_COUNT = 266
EXPECTED_POLICY_COUNT = 16
EXPECTED_TABLE_GRANT_COUNT = 31
EXPECTED_COLUMN_GRANT_COUNT = 638
EXPECTED_CATALOG_DIGEST = (
    "sha256:4824fdc375da9561e5a4ea261c634d1f84e006bc5a5c770c2b5f706ff19fe59b"
)

BEGIN_READ_ONLY_SQL = "set transaction read only"
SET_COMMAND_ROLE_SQL = f"set role {CANONICAL_COMMAND_ROLE}"

RUNTIME_STATE_SQL = (
    "select current_setting('transaction_read_only')='on' "
    "and session_user=%s "
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
    "where grantee=session_user)=0 "
    "and coalesce((select ssl from pg_catalog.pg_stat_ssl "
    "where pid=pg_backend_pid()),false) as ready"
)

EFFECTIVE_STATE_SQL = (
    "select current_user=%s and session_user=%s "
    "and exists (select 1 from pg_catalog.pg_roles rol "
    "where rol.rolname=current_user and not rol.rolcanlogin "
    "and not rol.rolsuper and not rol.rolinherit and not rol.rolcreatedb "
    "and not rol.rolcreaterole and not rol.rolreplication and not rol.rolbypassrls) "
    "and has_schema_privilege(current_user,'public','USAGE') "
    "and not has_schema_privilege(current_user,'public','CREATE') as ready"
)

CATALOG_SHAPE_SQL = r"""
select json_build_object(
  'tables', coalesce((select json_agg(
      json_build_array(c.relname,c.relrowsecurity,c.relforcerowsecurity)
      order by c.relname)
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind in ('r','p')
      and c.relname like 'avuhz\_%' escape '\'), '[]'::json),
  'columns', coalesce((select json_agg(
      json_build_array(
        c.relname,a.attnum,a.attname,
        pg_catalog.format_type(a.atttypid,a.atttypmod),
        a.attnotnull,
        coalesce(pg_catalog.pg_get_expr(d.adbin,d.adrelid),''),
        a.attidentity,a.attgenerated)
      order by c.relname,a.attnum)
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    join pg_catalog.pg_attribute a
      on a.attrelid=c.oid and a.attnum>0 and not a.attisdropped
    left join pg_catalog.pg_attrdef d
      on d.adrelid=c.oid and d.adnum=a.attnum
    where n.nspname='public' and c.relkind in ('r','p')
      and c.relname like 'avuhz\_%' escape '\'), '[]'::json),
  'constraints', coalesce((select json_agg(
      json_build_array(
        c.relname,k.conname,k.contype,
        pg_catalog.pg_get_constraintdef(k.oid,true))
      order by c.relname,k.conname)
    from pg_catalog.pg_constraint k
    join pg_catalog.pg_class c on c.oid=k.conrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public'
      and c.relname like 'avuhz\_%' escape '\'), '[]'::json),
  'policies', coalesce((select json_agg(
      json_build_array(
        c.relname,p.polname,p.polpermissive,p.polcmd,
        (select array_agg(
            pg_catalog.pg_get_userbyid(role_oid)
            order by pg_catalog.pg_get_userbyid(role_oid))
         from unnest(p.polroles) role_oid),
        coalesce(pg_catalog.pg_get_expr(p.polqual,p.polrelid),''),
        coalesce(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''))
      order by c.relname,p.polname)
    from pg_catalog.pg_policy p
    join pg_catalog.pg_class c on c.oid=p.polrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public'
      and c.relname like 'avuhz\_%' escape '\'), '[]'::json),
  'table_grants', coalesce((select json_agg(
      json_build_array(table_name,privilege_type,is_grantable)
      order by table_name,privilege_type)
    from information_schema.role_table_grants
    where table_schema='public'
      and table_name like 'avuhz\_%' escape '\'
      and grantee=current_user), '[]'::json),
  'column_grants', coalesce((select json_agg(
      json_build_array(table_name,column_name,privilege_type,is_grantable)
      order by table_name,column_name,privilege_type)
    from information_schema.column_privileges
    where table_schema='public'
      and table_name like 'avuhz\_%' escape '\'
      and grantee=current_user), '[]'::json),
  'schema_usage', has_schema_privilege(current_user,'public','USAGE'),
  'schema_create', has_schema_privilege(current_user,'public','CREATE')
) as catalog_shape
"""


class DataCatalogValidationClassification(str, Enum):
    PASS = "DATA_CATALOG_RLS_VALIDATED"


class SafeDevelopmentDataValidationStop(RuntimeError):
    """Fail closed with a fixed code and no database-derived text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"SafeDevelopmentDataValidationStop(code={self.code!r})"


def _stop(code: str) -> NoReturn:
    raise SafeDevelopmentDataValidationStop(code)


@dataclass(frozen=True)
class DataCatalogValidationResult:
    classification: DataCatalogValidationClassification
    catalog_digest: str
    table_count: int
    column_count: int
    constraint_count: int
    policy_count: int
    table_grant_count: int
    column_grant_count: int
    schema_usage: bool
    schema_create: bool


def _catalog_result(shape: Any) -> DataCatalogValidationResult:
    if not isinstance(shape, dict):
        _stop("DATA_CATALOG_SHAPE_INVALID")
    required = {
        "tables",
        "columns",
        "constraints",
        "policies",
        "table_grants",
        "column_grants",
        "schema_usage",
        "schema_create",
    }
    if set(shape) != required:
        _stop("DATA_CATALOG_SHAPE_INVALID")
    collections = (
        "tables",
        "columns",
        "constraints",
        "policies",
        "table_grants",
        "column_grants",
    )
    if any(not isinstance(shape[name], list) for name in collections):
        _stop("DATA_CATALOG_SHAPE_INVALID")
    if not isinstance(shape["schema_usage"], bool) or not isinstance(
        shape["schema_create"], bool
    ):
        _stop("DATA_CATALOG_SHAPE_INVALID")

    observed = {
        "table_count": len(shape["tables"]),
        "column_count": len(shape["columns"]),
        "constraint_count": len(shape["constraints"]),
        "policy_count": len(shape["policies"]),
        "table_grant_count": len(shape["table_grants"]),
        "column_grant_count": len(shape["column_grants"]),
    }
    expected = {
        "table_count": EXPECTED_TABLE_COUNT,
        "column_count": EXPECTED_COLUMN_COUNT,
        "constraint_count": EXPECTED_CONSTRAINT_COUNT,
        "policy_count": EXPECTED_POLICY_COUNT,
        "table_grant_count": EXPECTED_TABLE_GRANT_COUNT,
        "column_grant_count": EXPECTED_COLUMN_GRANT_COUNT,
    }
    if observed != expected:
        _stop("DATA_CATALOG_COUNT_MISMATCH")
    if shape["schema_usage"] is not True or shape["schema_create"] is not False:
        _stop("DATA_CATALOG_SCHEMA_PRIVILEGE_MISMATCH")

    digest = canonical_digest(shape)
    if digest != EXPECTED_CATALOG_DIGEST:
        _stop("DATA_CATALOG_DIGEST_MISMATCH")
    return DataCatalogValidationResult(
        classification=DataCatalogValidationClassification.PASS,
        catalog_digest=digest,
        schema_usage=shape["schema_usage"],
        schema_create=shape["schema_create"],
        **observed,
    )


def inspect_development_data_catalog(
    *,
    connection_factory: Callable[[], Any],
) -> DataCatalogValidationResult:
    """Open one read-only runtime session and validate only catalog metadata."""

    connection = None
    try:
        try:
            connection = connection_factory()
        except Exception:
            _stop("DATA_CATALOG_CONNECTION_UNAVAILABLE")
        if connection is None:
            _stop("DATA_CATALOG_CONNECTION_UNAVAILABLE")

        if getattr(connection, "autocommit", False):
            connection.autocommit = False
        info = getattr(connection, "info", None)
        if info is None or getattr(info, "host", None) != DEVELOPMENT_DATA_ENDPOINT_HOST:
            _stop("DATA_CATALOG_ENDPOINT_MISMATCH")

        # First SQL statement: make the transaction read-only before inspection.
        connection.execute(BEGIN_READ_ONLY_SQL)

        runtime = connection.execute(
            RUNTIME_STATE_SQL,
            (
                DEVELOPMENT_DATA_RUNTIME_LOGIN,
                CANONICAL_COMMAND_ROLE,
                DEVELOPMENT_DATA_MIGRATION_IDENTITY,
                DEVELOPMENT_DATA_MIGRATION_IDENTITY,
            ),
        ).fetchone()
        if not isinstance(runtime, dict) or runtime.get("ready") is not True:
            _stop("DATA_CATALOG_RUNTIME_ROLE_MISMATCH")

        connection.execute(SET_COMMAND_ROLE_SQL)
        effective = connection.execute(
            EFFECTIVE_STATE_SQL,
            (
                CANONICAL_COMMAND_ROLE,
                DEVELOPMENT_DATA_RUNTIME_LOGIN,
            ),
        ).fetchone()
        if not isinstance(effective, dict) or effective.get("ready") is not True:
            _stop("DATA_CATALOG_EFFECTIVE_ROLE_MISMATCH")

        row = connection.execute(CATALOG_SHAPE_SQL).fetchone()
        if not isinstance(row, dict):
            _stop("DATA_CATALOG_SHAPE_INVALID")
        return _catalog_result(row.get("catalog_shape"))
    except SafeDevelopmentDataValidationStop:
        raise
    except Exception:
        _stop("DATA_CATALOG_QUERY_FAILED")
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
            try:
                connection.close()
            except Exception:
                pass


def sanitized_data_catalog_evidence(
    result: DataCatalogValidationResult,
    *,
    plan_id: str,
    plan_digest: str,
    attempted_at: str,
) -> dict[str, Any]:
    """Return bounded evidence without raw metadata or credential material."""

    return {
        "environment": "DEVELOPMENT",
        "project_reference": DEVELOPMENT_DATA_PROJECT_REF,
        "responsibility": "DATA",
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "attempted_at": attempted_at,
        "validation_classification": result.classification.value,
        "catalog_digest": result.catalog_digest,
        "expected_catalog_digest": EXPECTED_CATALOG_DIGEST,
        "table_count": result.table_count,
        "column_count": result.column_count,
        "constraint_count": result.constraint_count,
        "policy_count": result.policy_count,
        "table_grant_count": result.table_grant_count,
        "column_grant_count": result.column_grant_count,
        "schema_usage": result.schema_usage,
        "schema_create": result.schema_create,
        "connection_count": 1,
        "transaction_read_only": True,
        "rollback_attempted": True,
        "business_rows_read": False,
        "auth_data_read": False,
        "provider_mutation_attempted": False,
        "ddl_attempted": False,
        "credential_material_retained": False,
        "raw_catalog_metadata_retained": False,
        "render_touched": False,
        "n8n_touched": False,
        "staging_touched": False,
        "production_touched": False,
    }
