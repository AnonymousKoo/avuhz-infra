-- REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION.
-- DEVELOPMENT DATA gnuqaefotwgkwurjpyik (PostgreSQL 17) ONLY.
-- DEVELOPMENT AUTH pwlhruwutoitnieactol and production are excluded.
-- One shared Avuhz DATA table: public.avuhz_acquisition_rate_limit_counters.
-- No login, credential, AUTH, owner/tenant row, route or n8n mutation.
-- Future Supabase apply_migration requires separate exact approval and digest.
-- The server must establish tenant authority before setting avuhz.tenant_id;
-- a client-provided tenant_id or session GUC never establishes authority.
-- The provider migration applies this SQL transactionally.

DO $acq_counter_access_preflight$
DECLARE
  table_oid oid;
BEGIN
  IF current_user <> 'postgres' OR session_user <> 'postgres' THEN
    RAISE EXCEPTION 'ACQ_COUNTER_ACCESS_EXECUTOR_STOP';
  END IF;

  table_oid := to_regclass('public.avuhz_acquisition_rate_limit_counters');
  IF table_oid IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid=table_oid
      AND c.relkind='r' AND pg_get_userbyid(c.relowner)='postgres'
      AND c.relrowsecurity AND c.relforcerowsecurity)
    OR (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=table_oid
      AND a.attnum>0 AND NOT a.attisdropped
      AND ((a.attname='tenant_id' AND a.atttypid='uuid'::regtype AND a.attnotnull)
       OR (a.attname='principal_digest' AND a.atttypid='text'::regtype AND a.attnotnull)
       OR (a.attname='window_started_at' AND a.atttypid='timestamptz'::regtype AND a.attnotnull)
       OR (a.attname='request_count' AND a.atttypid='integer'::regtype AND a.attnotnull)))<>4
    OR (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=table_oid
       AND a.attnum>0 AND NOT a.attisdropped)<>4
    OR (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public'
       AND p.tablename='avuhz_acquisition_rate_limit_counters')<>1
    OR (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public'
       AND p.tablename='avuhz_acquisition_rate_limit_counters'
       AND p.policyname='avuhz_command_service_tenant_isolation'
       AND p.roles=ARRAY['avuhz_command_service']::name[]
       AND p.cmd='ALL' AND p.qual LIKE '%avuhz.tenant_id%'
       AND p.with_check LIKE '%avuhz.tenant_id%')<>1
    OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname IN
       ('avuhz_tenant_organizations','avuhz_tenant_owner_memberships',
        'avuhz_acquisition_intake_requests')
       AND c.relrowsecurity AND c.relforcerowsecurity)<>3
  THEN
    RAISE EXCEPTION 'ACQ_COUNTER_ACCESS_TABLE_OR_RLS_DRIFT_STOP';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles
      WHERE rolname='avuhz_acquisition_service_dev' AND NOT rolcanlogin
      AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication)
    OR NOT EXISTS (SELECT 1 FROM pg_roles
      WHERE rolname='avuhz_acquisition_runtime_service_dev' AND rolcanlogin
      AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
      AND rolconnlimit=1)
    OR NOT pg_has_role('avuhz_acquisition_runtime_service_dev',
      'avuhz_acquisition_service_dev','SET')
    OR pg_has_role('avuhz_acquisition_runtime_service_dev',
      'avuhz_acquisition_service_dev','USAGE')
    OR pg_has_role('avuhz_acquisition_runtime_service_dev',
      'avuhz_command_service','MEMBER')
    OR (SELECT count(*) FROM pg_auth_members m
      WHERE m.member='avuhz_acquisition_runtime_service_dev'::regrole)<>1
    OR (SELECT count(*) FROM pg_auth_members m
      JOIN pg_roles r ON r.oid=m.roleid
      JOIN pg_roles g ON g.oid=m.grantor
      WHERE m.member='avuhz_acquisition_runtime_service_dev'::regrole
      AND r.rolname='avuhz_acquisition_service_dev'
      AND g.rolname='postgres'
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
    OR (SELECT rolpassword IS NOT NULL FROM pg_authid
      WHERE rolname='avuhz_acquisition_runtime_service_dev')
    OR (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public'
      AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
      AND p.policyname LIKE 'avuhz_acquisition_%')<>10
  THEN
    RAISE EXCEPTION 'ACQ_COUNTER_ACCESS_ROLE_DRIFT_STOP';
  END IF;

  IF EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=table_oid
       AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
       AND a.attacl::text LIKE '%avuhz_acquisition_service_dev%')
    OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'SELECT')
    OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'INSERT')
    OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'UPDATE')
    OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'DELETE')
    OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
      ('anon','authenticated','service_role')
      AND (has_table_privilege(rolname,table_oid,'SELECT')
        OR has_table_privilege(rolname,table_oid,'INSERT')
        OR has_table_privilege(rolname,table_oid,'UPDATE')))
    OR has_table_privilege('avuhz_command_service',table_oid,'DELETE')
    OR NOT has_column_privilege('avuhz_command_service',table_oid,'request_count','UPDATE')
  THEN
    RAISE EXCEPTION 'ACQ_COUNTER_ACCESS_ACL_DRIFT_STOP';
  END IF;
END
$acq_counter_access_preflight$;

-- Only the same trusted-tenant predicate as the existing command policy.
-- The runtime still has zero direct table privileges; privileges belong to
-- its restricted NOLOGIN role, available only through explicit SET ROLE.
CREATE POLICY avuhz_acquisition_rate_counter_tenant_isolation
  ON public.avuhz_acquisition_rate_limit_counters
  FOR ALL TO avuhz_acquisition_service_dev
  USING (tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid);

-- The shared atomic INSERT ... ON CONFLICT DO UPDATE requires SELECT
-- on these four columns and UPDATE only on the window/count values.
GRANT SELECT (tenant_id, principal_digest, window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters
  TO avuhz_acquisition_service_dev;
GRANT INSERT (tenant_id, principal_digest, window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters
  TO avuhz_acquisition_service_dev;
GRANT UPDATE (window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters
  TO avuhz_acquisition_service_dev;

DO $acq_counter_access_postcondition$
DECLARE table_oid oid;
BEGIN
 table_oid := 'public.avuhz_acquisition_rate_limit_counters'::regclass;
 IF (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public'
     AND p.tablename='avuhz_acquisition_rate_limit_counters')<>2
   OR (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public'
     AND p.tablename='avuhz_acquisition_rate_limit_counters'
     AND p.policyname='avuhz_acquisition_rate_counter_tenant_isolation'
     AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
     AND p.cmd='ALL'
     AND p.qual LIKE '%avuhz.tenant_id%'
     AND p.with_check LIKE '%avuhz.tenant_id%')<>1
   OR (SELECT count(*) FROM pg_class WHERE oid=table_oid
      AND relrowsecurity AND relforcerowsecurity)<>1
   OR (SELECT count(*) FROM (VALUES
      ('tenant_id'),('principal_digest'),('window_started_at'),('request_count')
      ) AS allowed(col)
      WHERE has_column_privilege('avuhz_acquisition_service_dev',table_oid,
       allowed.col,'SELECT') AND has_column_privilege(
       'avuhz_acquisition_service_dev',table_oid,allowed.col,'INSERT'))<>4
   OR NOT has_column_privilege('avuhz_acquisition_service_dev',table_oid,
      'window_started_at','UPDATE')
   OR NOT has_column_privilege('avuhz_acquisition_service_dev',table_oid,
      'request_count','UPDATE')
   OR has_column_privilege('avuhz_acquisition_service_dev',table_oid,
      'tenant_id','UPDATE')
   OR has_column_privilege('avuhz_acquisition_service_dev',table_oid,
      'principal_digest','UPDATE')
   OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'DELETE')
   OR has_table_privilege('avuhz_acquisition_service_dev',table_oid,'TRUNCATE')
   OR has_table_privilege('avuhz_acquisition_runtime_service_dev',table_oid,'SELECT')
   OR has_table_privilege('avuhz_acquisition_runtime_service_dev',table_oid,'INSERT')
   OR has_table_privilege('avuhz_acquisition_runtime_service_dev',table_oid,'UPDATE')
   OR (SELECT count(*) FROM information_schema.role_table_grants
      WHERE grantee='avuhz_acquisition_runtime_service_dev')<>0
   OR NOT pg_has_role('avuhz_acquisition_runtime_service_dev',
      'avuhz_acquisition_service_dev','SET')
   OR pg_has_role('avuhz_acquisition_runtime_service_dev',
      'avuhz_acquisition_service_dev','USAGE')
 THEN
   RAISE EXCEPTION 'ACQ_COUNTER_ACCESS_POSTCONDITION_STOP';
 END IF;
END
$acq_counter_access_postcondition$;
