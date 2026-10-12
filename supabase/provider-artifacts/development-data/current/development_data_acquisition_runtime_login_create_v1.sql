-- REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION.
-- Stage 3 continuation: one dormant DEVELOPMENT DATA acquisition LOGIN role.
-- Exact provider target: Supabase DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
-- Never DEVELOPMENT AUTH pwlhruwutoitnieactol or production.
-- This file is NOT an approval, deployment instruction, or automatic migration.
-- Candidate for one future separately authorized Supabase apply_migration call.
-- apply_migration must own its transaction; no raw execute_sql or retry.
-- The new role has PASSWORD NULL, no membership, no direct table privilege,
-- no issuer identity and no database connection path to acquisition tables.
-- PASSWORD NULL alone does NOT prove every external auth method is disabled.
-- Credential issuance, SET-only membership, Render binding and tenant proof
-- are distinct later resource changes, none permitted by this artifact.

DO $acq_runtime_login_preflight$
DECLARE
  acq_oid oid;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR NOT EXISTS (SELECT 1 FROM pg_roles
       WHERE rolname='postgres' AND (rolsuper OR rolcreaterole))
     OR coalesce(current_setting('createrole_self_grant',true),'') <> ''
     OR EXISTS (SELECT 1 FROM pg_roles
       WHERE rolname='avuhz_acquisition_runtime_service_dev')
  THEN
    RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_OWNER_OR_PREEXISTENCE_STOP';
  END IF;

  SELECT oid INTO acq_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_service_dev'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolreplication AND NOT rolbypassrls;
  IF acq_oid IS NULL
     OR EXISTS (SELECT 1 FROM pg_auth_members
       WHERE member=acq_oid)
     OR EXISTS (SELECT 1 FROM pg_auth_members m
       JOIN pg_roles r ON r.oid=m.member
       WHERE m.roleid=acq_oid AND
         (r.rolname<>'postgres' OR NOT m.admin_option
          OR m.set_option OR m.inherit_option))
     OR pg_has_role('avuhz_acquisition_service_dev',
                    'avuhz_command_service','MEMBER')
     OR pg_has_role('avuhz_acquisition_service_dev',
                    'avuhz_data_migration_service_dev','MEMBER')
  THEN
    RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_STAGE1_ROLE_DRIFT_STOP';
  END IF;

  IF (SELECT count(*) FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public'
          AND c.relname IN (
            'avuhz_tenant_organizations',
            'avuhz_tenant_owner_memberships',
            'avuhz_acquisition_intake_requests'
          ) AND c.relrowsecurity AND c.relforcerowsecurity)<>3
     OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public'
          AND p.tablename IN (
            'avuhz_tenant_organizations',
            'avuhz_tenant_owner_memberships',
            'avuhz_acquisition_intake_requests'
          ) AND p.policyname IN (
            'avuhz_acquisition_select',
            'avuhz_acquisition_lock_only',
            'avuhz_acquisition_intake_insert'
          ) AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[])<>7
     OR NOT has_column_privilege(
          'avuhz_acquisition_service_dev',
          'public.avuhz_acquisition_intake_requests',
          'contact_email','INSERT')
     OR has_table_privilege(
          'avuhz_acquisition_service_dev',
          'public.avuhz_acquisition_intake_requests','DELETE')
  THEN
    RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_REGISTRY_RLS_DRIFT_STOP';
  END IF;
END
$acq_runtime_login_preflight$;

-- One future identity only. No password, memberships, direct rights or grants.
CREATE ROLE avuhz_acquisition_runtime_service_dev
  LOGIN PASSWORD NULL CONNECTION LIMIT 1
  NOINHERIT NOSUPERUSER NOBYPASSRLS
  NOCREATEDB NOCREATEROLE NOREPLICATION;

DO $acq_runtime_login_postcondition$
DECLARE
  runtime_oid oid;
  creator_oid oid;
  creator_super boolean;
  actual_edges integer;
  expected_edges integer;
BEGIN
  SELECT oid INTO STRICT runtime_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_runtime_service_dev'
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper
      AND NOT rolbypassrls AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolreplication
      AND rolconnlimit=1;
  SELECT oid,rolsuper INTO STRICT creator_oid,creator_super
    FROM pg_roles WHERE rolname=current_user;

  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member=runtime_oid)
     OR pg_has_role('avuhz_acquisition_runtime_service_dev',
                    'avuhz_acquisition_service_dev','MEMBER')
     OR pg_has_role('avuhz_acquisition_runtime_service_dev',
                    'avuhz_command_service','MEMBER')
     OR pg_has_role('avuhz_acquisition_runtime_service_dev',
                    'avuhz_data_migration_service_dev','MEMBER')
     OR (SELECT count(*) FROM information_schema.role_table_grants
         WHERE grantee='avuhz_acquisition_runtime_service_dev')<>0
     OR EXISTS (SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p')
          AND c.relname LIKE 'avuhz_%'
          AND (has_table_privilege(
            'avuhz_acquisition_runtime_service_dev',c.oid,'SELECT')
            OR has_table_privilege(
            'avuhz_acquisition_runtime_service_dev',c.oid,'INSERT')
            OR has_table_privilege(
            'avuhz_acquisition_runtime_service_dev',c.oid,'UPDATE')
            OR has_table_privilege(
            'avuhz_acquisition_runtime_service_dev',c.oid,'DELETE')))
  THEN
    RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_UNEXPECTED_AUTHORITY_STOP';
  END IF;

  -- PostgreSQL 17 can add exactly one ADMIN/NOSET/NOINHERIT creator
  -- management edge when the creator is a non-superuser CREATEROLE.
  SELECT count(*) INTO actual_edges FROM pg_auth_members
    WHERE roleid=runtime_oid;
  IF creator_super THEN
    IF actual_edges<>0 THEN
      RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_CREATOR_EDGE_STOP';
    END IF;
  ELSE
    SELECT count(*) INTO expected_edges FROM pg_auth_members m
      JOIN pg_roles grantor ON grantor.oid=m.grantor
      WHERE m.roleid=runtime_oid AND m.member=creator_oid
        AND grantor.rolsuper AND m.admin_option
        AND NOT m.set_option AND NOT m.inherit_option;
    IF actual_edges<>1 OR expected_edges<>1 THEN
      RAISE EXCEPTION 'ACQ_RUNTIME_LOGIN_CREATOR_EDGE_STOP';
    END IF;
  END IF;
END
$acq_runtime_login_postcondition$;
