-- REVIEW ONLY — DEVELOPMENT DATA acquisition writer column-grants candidate v1.
-- Target: Supabase DEVELOPMENT DATA gnuqaefotwgkwurjpyik, public namespace.
-- NEVER AUTH pwlhruwutoitnieactol, STAGING, or PRODUCTION.
-- No remote execution authority. Requires separate exact owner approval.
-- No role creation, SET ROLE, credential, tenant/owner creation, DML, or RLS changes.
-- IMPORTANT: command role is shared across Avuhz; these PII column grants
-- expose same-tenant contact fields to that DB role. A separate security
-- approval is required before any hosted activation of this writer.
BEGIN;

DO $avuhz_acquisition_column_grants_preflight$
DECLARE
  target_table text;
  owner_name text;
  rls_on boolean;
  rls_forced boolean;
BEGIN
  IF current_user <> 'postgres' OR session_user <> 'postgres'
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname='avuhz_command_service'
         AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
         AND NOT rolcreaterole AND NOT rolcreatedb
     ) THEN
    RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_IDENTITY_STOP';
  END IF;

  FOREACH target_table IN ARRAY ARRAY[
    'avuhz_tenant_organizations',
    'avuhz_tenant_owner_memberships',
    'avuhz_acquisition_intake_requests'
  ] LOOP
    SELECT pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity
      INTO owner_name,rls_on,rls_forced FROM pg_class c
      WHERE c.oid=to_regclass('public.' || target_table) AND c.relkind='r';
    IF owner_name IS DISTINCT FROM 'postgres'
       OR rls_on IS DISTINCT FROM true
       OR rls_forced IS DISTINCT FROM true
       OR (SELECT count(*) FROM pg_policies
           WHERE schemaname='public' AND tablename=target_table
             AND policyname='avuhz_command_service_tenant_isolation'
             AND cmd='ALL'
             AND roles=ARRAY['avuhz_command_service']::name[]
             AND qual LIKE '%avuhz.tenant_id%'
             AND with_check LIKE '%avuhz.tenant_id%')<>1
    THEN
      RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_OWNER_OR_RLS_DRIFT_STOP';
    END IF;
    IF EXISTS (
      SELECT 1 FROM information_schema.role_table_grants g
      WHERE g.table_schema='public' AND g.table_name=target_table
        AND g.grantee IN ('PUBLIC','anon','authenticated','service_role','avuhz_command_service')
    ) OR EXISTS (
      SELECT 1 FROM information_schema.column_privileges g
      WHERE g.table_schema='public' AND g.table_name=target_table
        AND g.grantee IN ('PUBLIC','anon','authenticated','service_role','avuhz_command_service')
    ) OR has_table_privilege('avuhz_command_service',
             ('public.' || target_table)::regclass,'SELECT')
      OR has_table_privilege('avuhz_command_service',
             ('public.' || target_table)::regclass,'INSERT')
      OR has_table_privilege('avuhz_command_service',
             ('public.' || target_table)::regclass,'UPDATE')
      OR has_table_privilege('avuhz_command_service',
             ('public.' || target_table)::regclass,'DELETE')
    THEN
      RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_PREEXISTING_ACCESS_STOP';
    END IF;
  END LOOP;
  IF NOT has_schema_privilege('avuhz_command_service','public','USAGE')
     OR has_schema_privilege('avuhz_command_service','public','CREATE')
  THEN
    RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_SCHEMA_BOUNDARY_STOP';
  END IF;
END
$avuhz_acquisition_column_grants_preflight$;

-- Only server-verified ACTIVE organization and verified owner predicates.
GRANT SELECT (tenant_id,organization_id,lifecycle_state)
  ON public.avuhz_tenant_organizations TO avuhz_command_service;
GRANT SELECT (tenant_id,organization_id,member_role,membership_state,verified_at)
  ON public.avuhz_tenant_owner_memberships TO avuhz_command_service;

-- The existing writer inserts only these fields and reads the same immutable
-- fields solely for exact idempotency replay, under preexisting tenant RLS.
-- Do not grant UPDATE or DELETE; replay must use FOR SHARE, not FOR UPDATE.
GRANT INSERT (
  intake_id,tenant_id,organization_id,external_request_id,source_system,
  route_reference,business_name,contact_name,contact_email,contact_phone,
  preferred_contact_method,contact_requested,diagnostic_summary
) ON public.avuhz_acquisition_intake_requests TO avuhz_command_service;
GRANT SELECT (
  intake_id,tenant_id,organization_id,external_request_id,source_system,
  route_reference,business_name,contact_name,contact_email,contact_phone,
  preferred_contact_method,contact_requested,diagnostic_summary
) ON public.avuhz_acquisition_intake_requests TO avuhz_command_service;

DO $avuhz_acquisition_column_grants_postcondition$
DECLARE
  target_table text;
  expected_count integer;
  actual_count integer;
BEGIN
  FOREACH target_table IN ARRAY ARRAY[
    'avuhz_tenant_organizations',
    'avuhz_tenant_owner_memberships',
    'avuhz_acquisition_intake_requests'
  ] LOOP
    expected_count := CASE target_table
      WHEN 'avuhz_tenant_organizations' THEN 3
      WHEN 'avuhz_tenant_owner_memberships' THEN 5
      ELSE 26 END;
    SELECT count(*) INTO actual_count
      FROM information_schema.column_privileges g
      WHERE g.table_schema='public' AND g.table_name=target_table
        AND g.grantee='avuhz_command_service'
        AND g.privilege_type IN ('SELECT','INSERT');
    IF actual_count<>expected_count
       OR EXISTS (
         SELECT 1 FROM information_schema.role_table_grants g
         WHERE g.table_schema='public' AND g.table_name=target_table
           AND g.grantee IN ('PUBLIC','anon','authenticated','service_role','avuhz_command_service')
       ) OR EXISTS (
         SELECT 1 FROM information_schema.column_privileges g
         WHERE g.table_schema='public' AND g.table_name=target_table
           AND g.grantee IN ('PUBLIC','anon','authenticated','service_role')
       )
       OR has_table_privilege('avuhz_command_service',
            ('public.' || target_table)::regclass,'UPDATE')
       OR has_table_privilege('avuhz_command_service',
            ('public.' || target_table)::regclass,'DELETE')
       OR has_table_privilege('avuhz_command_service',
            ('public.' || target_table)::regclass,'TRUNCATE')
       OR NOT EXISTS (
          SELECT 1 FROM pg_class c
          WHERE c.oid=('public.' || target_table)::regclass
            AND pg_get_userbyid(c.relowner)='postgres'
            AND c.relrowsecurity AND c.relforcerowsecurity
       )
    THEN
      RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_POSTCONDITION_STOP';
    END IF;
  END LOOP;

  IF NOT has_column_privilege('avuhz_command_service',
      'public.avuhz_acquisition_intake_requests','contact_email','SELECT')
     OR NOT has_column_privilege('avuhz_command_service',
      'public.avuhz_acquisition_intake_requests','contact_email','INSERT')
     OR has_column_privilege('avuhz_command_service',
      'public.avuhz_acquisition_intake_requests','intake_state','SELECT')
     OR has_column_privilege('avuhz_command_service',
      'public.avuhz_tenant_owner_memberships','principal_subject_digest','SELECT')
  THEN
    RAISE EXCEPTION 'ACQUISITION_WRITER_GRANT_EXACT_COLUMN_STOP';
  END IF;
END
$avuhz_acquisition_column_grants_postcondition$;

COMMIT;
