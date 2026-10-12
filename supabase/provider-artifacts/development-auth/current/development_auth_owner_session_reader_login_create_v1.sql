-- REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION.
-- Single dormant DEVELOPMENT AUTH owner session-reader LOGIN role.
-- Exact target: Supabase DEVELOPMENT AUTH pwlhruwutoitnieactol, PG17.
-- DEVELOPMENT DATA gnuqaefotwgkwurjpyik and production are excluded.
-- This file is not a grant approval or an automatic migration.
-- Future apply_migration must own the transaction; no execute_sql or retry.
-- No credentials, schema/column privileges, RLS policy or enrollment.
-- PASSWORD NULL is not proof that all authentication methods are disabled.
-- Schema-owner AUTH RLS and grants require distinct, separate approvals.

DO $owner_session_reader_login_preflight$
BEGIN
  IF session_user <> 'postgres'
    OR current_user <> 'postgres'
    OR NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname='postgres'
      AND rolcreaterole AND NOT rolsuper AND rolcanlogin
    )
    OR coalesce(current_setting('createrole_self_grant',true),'') <> ''
    OR EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname='avuhz_owner_session_reader_dev'
    )
  THEN
    RAISE EXCEPTION 'AUTH_OWNER_READER_LOGIN_EXECUTOR_OR_PREEXISTENCE_STOP';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM pg_namespace
      WHERE nspname='auth' AND pg_get_userbyid(nspowner)='supabase_admin'
    )
    OR (SELECT count(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='auth'
        AND c.relname IN ('sessions','mfa_factors')
        AND c.relkind='r'
        AND pg_get_userbyid(c.relowner)='supabase_auth_admin'
        AND c.relrowsecurity
    ) <> 2
    OR (SELECT count(*) FROM pg_policies p
      WHERE p.schemaname='auth'
        AND p.tablename IN ('sessions','mfa_factors')
    ) <> 0
    OR pg_has_role('postgres','supabase_auth_admin','SET')
    OR has_schema_privilege('postgres','auth','CREATE')
  THEN
    RAISE EXCEPTION 'AUTH_OWNER_READER_LOGIN_AUTH_SCHEMA_DRIFT_STOP';
  END IF;

  IF (SELECT count(*) FROM pg_roles WHERE rolname='avuhz_migration_service_dev'
       AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) <> 1
  THEN
    RAISE EXCEPTION 'AUTH_OWNER_READER_LOGIN_MIGRATION_BOUNDARY_STOP';
  END IF;
END
$owner_session_reader_login_preflight$;

CREATE ROLE avuhz_owner_session_reader_dev
  LOGIN PASSWORD NULL CONNECTION LIMIT 1
  NOINHERIT NOSUPERUSER NOBYPASSRLS
  NOCREATEDB NOCREATEROLE NOREPLICATION;

DO $owner_session_reader_login_postcondition$
DECLARE
  reader_oid oid;
  creator_oid oid;
BEGIN
  SELECT oid INTO STRICT reader_oid FROM pg_roles
    WHERE rolname='avuhz_owner_session_reader_dev'
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper
      AND NOT rolbypassrls AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolreplication
      AND rolconnlimit=1;
  SELECT oid INTO STRICT creator_oid FROM pg_roles WHERE rolname='postgres';

  IF (SELECT rolpassword IS NOT NULL FROM pg_authid
      WHERE oid=reader_oid)
    OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=reader_oid)
    -- PostgreSQL 17's non-superuser CREATEROLE creator receives only
    -- the unavoidable superuser-granted ADMIN/NOSET/NOINHERIT edge.
    OR (SELECT count(*) FROM pg_auth_members WHERE roleid=reader_oid)<>1
    OR (SELECT count(*) FROM pg_auth_members m
      JOIN pg_roles grantor ON grantor.oid=m.grantor
      WHERE m.roleid=reader_oid
        AND m.member=creator_oid
        AND grantor.rolsuper AND grantor.oid<>creator_oid
        AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1
    OR has_schema_privilege('avuhz_owner_session_reader_dev','auth','USAGE')
    OR has_schema_privilege('avuhz_owner_session_reader_dev','auth','CREATE')
    OR has_schema_privilege('avuhz_owner_session_reader_dev','public','CREATE')
    OR has_table_privilege('avuhz_owner_session_reader_dev',
      'auth.sessions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
    OR has_table_privilege('avuhz_owner_session_reader_dev',
      'auth.mfa_factors','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
    OR (SELECT count(*) FROM information_schema.role_table_grants
      WHERE grantee='avuhz_owner_session_reader_dev')<>0
    OR EXISTS (SELECT 1 FROM pg_attribute a
      WHERE a.attrelid IN (
        'auth.sessions'::regclass,'auth.mfa_factors'::regclass)
      AND a.attnum>0 AND NOT a.attisdropped AND a.attacl::text
        LIKE '%avuhz_owner_session_reader_dev%')
    OR EXISTS (SELECT 1 FROM pg_policies p
      WHERE p.schemaname='auth' AND p.tablename IN
        ('sessions','mfa_factors'))
  THEN
    RAISE EXCEPTION 'AUTH_OWNER_READER_LOGIN_POSTCONDITION_STOP';
  END IF;
END
$owner_session_reader_login_postcondition$;
