"""Dormant, fail-closed DEVELOPMENT AUTH owner-session record verifier.

The AUTH provider (pwlhruwutoitnieactol) is separate from DEVELOPMENT DATA
(gnuqaefotwgkwurjpyik). This private, read-only candidate is the missing
confirm_session_record(subject, session_id) dependency of the existing
DevelopmentAuthUserSessionCheck. It is NOT composed into hosted routes.

This module grants no database privileges, enrolls no user/MFA factor, reads
no production resource, and creates no credential. A future, separate AUTH
approval must provide an isolated LOGIN role with exact column-only SELECT,
the two exact subject-scoped AUTH SELECT RLS policies, and a protected
TLS-verifying connection. Until those resources actually exist, the check
returns False and no owner can enroll.
Do not replace this with provider postgres, service_role, AUTH admin, or a
synthetic True callback in a hosted runtime.

The signed token, subject, and TOTP freshness are checked upstream by
DevelopmentOwnerMfaFreshnessCheck. This verifier checks ONLY authoritative,
current AUTH session+factor records, returning a boolean with no PII.
"""
from __future__ import annotations

import uuid
from typing import Callable

DEVELOPMENT_AUTH_PROJECT_REF = "pwlhruwutoitnieactol"
DEVELOPMENT_DATA_PROJECT_REF = "gnuqaefotwgkwurjpyik"
AUTH_DIRECT_DATABASE_HOST = "db.pwlhruwutoitnieactol.supabase.co"
AUTH_DATABASE_PORT = 5432
AUTH_REQUIRED_SSLMODE = "verify-full"
AUTH_OWNER_SESSION_READER_ROLE = "avuhz_owner_session_reader_dev"

# Strictly row-less boolean verification with no untrusted interpolated SQL.
# A row's existence proves it has not been deleted by the AUTH provider and
# its server-managed TOTP factor is still verified, but not a live MFA
# ceremony. The caller must separately verify the signed recent TOTP AMR,
# user endpoint, and current subject before invoking this checker.
# Policy shape observed in PostgreSQL 17 after creating a
# user_id = nullif(current_setting(...), '')::uuid tenant-scope predicate.
# The existing DATA counter policy renders the same expression form.
# Any extra AUTH policy, broadened policy, or altered predicate stops the
# shared owner session checker before it can SELECT sensitive AUTH rows.
_APPROVED_OWNER_SUBJECT_POLICY_NAME = "avuhz_owner_session_reader_dev_scope"
_APPROVED_OWNER_SUBJECT_POLICY_QUAL = (
    "(user_id = (NULLIF(current_setting('avuhz.owner_subject'::text, true), "
    "''::text))::uuid)"
)
_BIND_OWNER_SUBJECT_SQL = (
    "SELECT set_config('avuhz.owner_subject', %s, true) AS owner_subject"
)

_SESSION_PROOF_SQL = (
    "SELECT EXISTS ("
    "SELECT 1 FROM auth.sessions AS session "
    "JOIN auth.mfa_factors AS factor "
    "ON factor.id=session.factor_id AND factor.user_id=session.user_id "
    "WHERE session.id=%s::uuid AND session.user_id=%s::uuid "
    "AND session.aal='aal2' "
    "AND (session.not_after IS NULL OR session.not_after>now()) "
    "AND factor.status='verified' AND factor.factor_type='totp'"
    ") AS current_verified_session"
)

_ROLE_PREFLIGHT_SQL = (
    "SELECT "
    "current_user=%s AND session_user=%s "
    "AND current_user=session_user "
    "AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r "
    "WHERE r.rolname=current_user AND r.rolcanlogin "
    "AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolbypassrls "
    "AND NOT r.rolcreatedb AND NOT r.rolcreaterole "
    "AND NOT r.rolreplication AND r.rolconnlimit=1) "
    "AND (SELECT count(*) FROM pg_catalog.pg_auth_members m "
    "JOIN pg_catalog.pg_roles member ON member.oid=m.member "
    "WHERE member.rolname=current_user)=0 "
    "AND has_schema_privilege(current_user,'auth','USAGE') "
    "AND NOT has_schema_privilege(current_user,'auth','CREATE') "
    "AND NOT has_schema_privilege(current_user,'public','CREATE') "
    "AND NOT has_table_privilege(current_user,'auth.sessions','SELECT') "
    "AND NOT has_table_privilege(current_user,'auth.mfa_factors','SELECT') "
    "AND NOT has_table_privilege(current_user,'auth.sessions',"
    "'INSERT,UPDATE,DELETE,TRUNCATE') "
    "AND NOT has_table_privilege(current_user,'auth.mfa_factors',"
    "'INSERT,UPDATE,DELETE,TRUNCATE') "
    "AND has_column_privilege(current_user,'auth.sessions','id','SELECT') "
    "AND has_column_privilege(current_user,'auth.sessions','user_id','SELECT') "
    "AND has_column_privilege(current_user,'auth.sessions','aal','SELECT') "
    "AND has_column_privilege(current_user,'auth.sessions','not_after','SELECT') "
    "AND has_column_privilege(current_user,'auth.sessions','factor_id','SELECT') "
    "AND has_column_privilege(current_user,'auth.mfa_factors','id','SELECT') "
    "AND has_column_privilege(current_user,'auth.mfa_factors','user_id','SELECT') "
    "AND has_column_privilege(current_user,'auth.mfa_factors','status','SELECT') "
    "AND has_column_privilege(current_user,'auth.mfa_factors','factor_type','SELECT') "
    "AND (SELECT count(*) FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
    "WHERE n.nspname='auth' AND c.relname IN ('sessions','mfa_factors') "
    "AND c.relrowsecurity)=2 "
    "AND (SELECT count(*) FROM pg_catalog.pg_policies p "
    "WHERE p.schemaname='auth' "
    "AND p.tablename IN ('sessions','mfa_factors') "
    "AND p.policyname=%s "
    "AND p.roles=ARRAY['avuhz_owner_session_reader_dev']::name[] "
    "AND p.cmd='SELECT' AND p.permissive='PERMISSIVE' "
    "AND p.qual=%s AND p.with_check IS NULL)=2 "
    "AND (SELECT count(*) FROM pg_catalog.pg_policies p "
    "WHERE p.schemaname='auth' "
    "AND p.tablename IN ('sessions','mfa_factors'))=2 "
    "AS approved_reader"
)


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


class DevelopmentAuthSessionRecordCheck:
    """Read-only, per-call AUTH SQL session verifier, never a JWT parser.

    The injected callable must open a dedicated, exact-project PostgreSQL
    connection configured server-side. The class verifies the project's
    direct database host, port, TLS verify-full setting, effective role,
    absence of elevated role membership, column-only ACLs, and exactly two
    subject-scoped AUTH SELECT RLS policies before querying. The subject is
    already independently verified upstream; its value is bound in a
    transaction-local GUC, not accepted from raw browser headers. The RLS
    setting alone is not proof of authentication or ownership.

    No DSN is stored here and no generic DATA/command connection is reused.
    Local/mock connections are permitted only for tests, not hosted proof.
    """

    def __init__(self, connection_factory: Callable[[], object]):
        if not callable(connection_factory):
            raise ValueError("dedicated DEVELOPMENT AUTH session reader required")
        self._connection_factory = connection_factory

    def __call__(self, subject: object, session_id: object) -> bool:
        if not _uuid(subject) or not _uuid(session_id):
            return False
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not False:
                return False
            info = getattr(connection, "info", None)
            params_method = getattr(info, "get_parameters", None)
            params = params_method() if callable(params_method) else None
            if (
                info is None
                or getattr(info, "host", None) != AUTH_DIRECT_DATABASE_HOST
                or getattr(info, "port", None) != AUTH_DATABASE_PORT
                or not hasattr(params, "get")
                or params.get("sslmode") != AUTH_REQUIRED_SSLMODE
                or getattr(info, "user", None) != AUTH_OWNER_SESSION_READER_ROLE
            ):
                return False

            # No write / state-changing SQL is permitted in the transaction.
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '3000ms'")
            preflight = connection.execute(
                _ROLE_PREFLIGHT_SQL,
                (
                    AUTH_OWNER_SESSION_READER_ROLE,
                    AUTH_OWNER_SESSION_READER_ROLE,
                    _APPROVED_OWNER_SUBJECT_POLICY_NAME,
                    _APPROVED_OWNER_SUBJECT_POLICY_QUAL,
                ),
            ).fetchone()
            if type(preflight) is not dict or preflight.get("approved_reader") is not True:
                return False

            # PostgreSQL's current_setting is not an authentication source:
            # upstream signed DEVELOPMENT AUTH JWT + current user verification
            # have already derived the canonical UUID. Scope only this
            # transaction; rollback/close always clears it.
            scope = connection.execute(
                _BIND_OWNER_SUBJECT_SQL, (subject,),
            ).fetchone()
            if type(scope) is not dict or scope.get("owner_subject") != subject:
                return False

            proof = connection.execute(
                _SESSION_PROOF_SQL, (session_id, subject),
            ).fetchone()
            return (
                type(proof) is dict
                and proof.get("current_verified_session") is True
            )
        except Exception:
            # Never log bearer, UUID, session state, DB error or provider SQL.
            return False
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
