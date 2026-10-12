-- REVIEW ONLY; NOT AUTHORIZED FOR PROVIDER EXECUTION.
-- One future SET-only PostgreSQL 17 membership; no other resource mutation.
-- Repository: AnonymousKoo/avuhz-infra (shared Avuhz core).
-- DEVELOPMENT DATA Supabase project: gnuqaefotwgkwurjpyik ONLY.
-- DEVELOPMENT AUTH pwlhruwutoitnieactol and production are excluded.
-- Source is outside automatic migrations: future, separately approved
-- apply_migration owns transaction/migration history. Never raw execute_sql.
-- This step does NOT create credentials, modify login roles, modify RLS,
-- insert a tenant/customer, dispatch n8n or deploy an application.
-- The runtime has PASSWORD NULL. Other auth mechanisms may still exist.
-- An arbitrary avuhz.tenant_id session GUC is NOT proof of user or tenant
-- authority. Do not activate runtime connection before trusted AUTH service
-- identity, signed owner/tenant binding and receiver provenance are verified.

DO $acq_set_grant_preflight$
DECLARE
  login_oid oid;
  acquisition_oid oid;
  postgres_oid oid;
BEGIN
  IF current_user <> 'postgres' OR session_user <> 'postgres'
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='postgres'
         AND NOT rolsuper AND rolcreaterole)
  THEN
    RAISE EXCEPTION 'ACQ_SET_GRANT_OWNER_IDENTITY_STOP';
  END IF;

  SELECT oid INTO login_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_runtime_service_dev'
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper
      AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=1;
  SELECT oid INTO acquisition_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_service_dev'
      AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper
      AND NOT rolcreatedb AND NOT rolcreaterole
      AND NOT rolreplication AND NOT rolbypassrls;
  SELECT oid INTO postgres_oid FROM pg_roles WHERE rolname='postgres';

  IF login_oid IS NULL OR acquisition_oid IS NULL
     OR NOT EXISTS (SELECT 1 FROM pg_authid
       WHERE oid=login_oid AND rolpassword IS NULL)
     OR (SELECT count(*) FROM pg_auth_members m
       JOIN pg_roles g ON g.oid=m.grantor
       WHERE m.roleid=login_oid AND m.member=postgres_oid
         AND m.admin_option AND NOT m.inherit_option
         AND NOT m.set_option AND g.rolname='supabase_admin'
         AND g.rolsuper)<>1
     OR (SELECT count(*) FROM pg_auth_members m
       JOIN pg_roles g ON g.oid=m.grantor
       WHERE m.roleid=acquisition_oid AND m.member=postgres_oid
         AND m.admin_option AND NOT m.inherit_option
         AND NOT m.set_option AND g.rolname='supabase_admin'
         AND g.rolsuper)<>1
     OR (SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid IN (login_oid,acquisition_oid))<>2
     OR EXISTS (SELECT 1 FROM pg_auth_members m
       WHERE m.member IN (login_oid,acquisition_oid))
     OR pg_has_role('avuhz_acquisition_runtime_service_dev',
                    'avuhz_acquisition_service_dev','MEMBER')
     OR pg_has_role('avuhz_acquisition_service_dev',
                    'avuhz_command_service','MEMBER')
     OR has_schema_privilege(
       'avuhz_acquisition_runtime_service_dev','public','CREATE')
     OR has_schema_privilege(
       'avuhz_acquisition_service_dev','public','CREATE')
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
    RAISE EXCEPTION 'ACQ_SET_GRANT_ROLE_OR_MEMBERSHIP_DRIFT_STOP';
  END IF;

  IF (SELECT count(*) FROM pg_class c
       JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relname IN (
          'avuhz_tenant_organizations',
          'avuhz_tenant_owner_memberships',
          'avuhz_acquisition_intake_requests'
       ) AND c.relrowsecurity AND c.relforcerowsecurity)<>3
     OR (SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public' AND p.roles=ARRAY[
         'avuhz_acquisition_service_dev']::name[]
         AND p.tablename IN (
           'avuhz_tenant_organizations',
           'avuhz_tenant_owner_memberships',
           'avuhz_acquisition_intake_requests'
         ) AND p.policyname='avuhz_acquisition_select'
         AND p.qual LIKE '%avuhz.tenant_id%')<>3
     OR (SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public' AND p.roles=ARRAY[
         'avuhz_acquisition_service_dev']::name[]
         AND p.tablename IN (
           'avuhz_tenant_organizations',
           'avuhz_tenant_owner_memberships',
           'avuhz_acquisition_intake_requests'
         ) AND p.policyname='avuhz_acquisition_lock_only'
         AND p.qual LIKE '%avuhz.tenant_id%'
         AND p.with_check='false')<>3
     OR (SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public'
         AND p.tablename='avuhz_acquisition_intake_requests'
         AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
         AND p.policyname='avuhz_acquisition_intake_insert'
         AND p.with_check LIKE '%avuhz.tenant_id%')<>1
     OR (SELECT count(*) FROM pg_class c
       JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relname IN (
         'avuhz_lifecycle_events','avuhz_outbox_deliveries'
       ) AND c.relrowsecurity)<>2
     OR (SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public'
         AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
         AND p.policyname IN (
         'avuhz_acquisition_event_read',
         'avuhz_acquisition_event_insert',
         'avuhz_acquisition_outbox_insert'))<>3
     OR NOT has_column_privilege('avuhz_acquisition_service_dev',
        'public.avuhz_acquisition_intake_requests',
        'contact_email','INSERT')
     OR has_table_privilege('avuhz_acquisition_service_dev',
        'public.avuhz_acquisition_intake_requests','DELETE')
  THEN
    RAISE EXCEPTION 'ACQ_SET_GRANT_RLS_OR_PRIVILEGE_DRIFT_STOP';
  END IF;
END
$acq_set_grant_preflight$;

-- This is the entire scope of the requested future provider mutation.
GRANT avuhz_acquisition_service_dev
  TO avuhz_acquisition_runtime_service_dev
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;

DO $acq_set_grant_postcondition$
DECLARE
  login_oid oid;
  acquisition_oid oid;
  postgres_oid oid;
BEGIN
  SELECT oid INTO STRICT login_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_runtime_service_dev';
  SELECT oid INTO STRICT acquisition_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_service_dev';
  SELECT oid INTO STRICT postgres_oid FROM pg_roles
    WHERE rolname='postgres';

  IF (SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid=acquisition_oid AND m.member=login_oid
         AND m.grantor=postgres_oid
         AND NOT m.admin_option AND NOT m.inherit_option
         AND m.set_option)<>1
     OR (SELECT count(*) FROM pg_auth_members m
       WHERE m.member=login_oid)<>1
     OR (SELECT count(*) FROM pg_auth_members m
       WHERE m.member=acquisition_oid)<>0
     OR (SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid=acquisition_oid)<>2
     OR (SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid=login_oid)<>1
     OR NOT pg_has_role(
       'avuhz_acquisition_runtime_service_dev',
       'avuhz_acquisition_service_dev','SET')
     OR pg_has_role(
       'avuhz_acquisition_runtime_service_dev',
       'avuhz_acquisition_service_dev','USAGE')
     OR pg_has_role(
       'avuhz_acquisition_runtime_service_dev',
       'avuhz_command_service','MEMBER')
     OR pg_has_role(
       'avuhz_acquisition_runtime_service_dev',
       'avuhz_data_migration_service_dev','MEMBER')
     OR (SELECT count(*) FROM information_schema.role_table_grants
       WHERE grantee='avuhz_acquisition_runtime_service_dev')<>0
     OR has_schema_privilege(
       'avuhz_acquisition_runtime_service_dev','public','CREATE')
     OR (SELECT rolpassword IS NOT NULL FROM pg_authid
       WHERE oid=login_oid)
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
    RAISE EXCEPTION 'ACQ_SET_GRANT_POSTCONDITION_STOP';
  END IF;
END
$acq_set_grant_postcondition$;
