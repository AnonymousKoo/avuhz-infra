-- REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION.
-- DEVELOPMENT DATA: gnuqaefotwgkwurjpyik, schema public only.
-- NEVER use against AUTH pwlhruwutoitnieactol or production.
-- Stage 1 of isolated shared-core acquisition execution identity.
-- Does not grant access to Avuhz lifecycle events, outbox, rate counters,
-- provider credentials, or any website/n8n route. Requires fresh exact approval.
-- A non-login role is NOT sufficient to authenticate a future service.
-- Local tests MUST prove locked reads work but row UPDATE fails under RLS.
BEGIN;

DO $acquisition_registry_preflight$
DECLARE
  target_table text;
BEGIN
  IF current_user <> 'postgres' OR session_user <> 'postgres'
     OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='avuhz_acquisition_service_dev')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='avuhz_command_service'
                   AND NOT rolcanlogin AND NOT rolbypassrls)
  THEN
    RAISE EXCEPTION 'ACQUISITION_ROLE_IDENTITY_OR_PREEXISTENCE_STOP';
  END IF;
  FOREACH target_table IN ARRAY ARRAY[
    'avuhz_tenant_organizations',
    'avuhz_tenant_owner_memberships',
    'avuhz_acquisition_intake_requests'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class c WHERE c.oid=('public.'||target_table)::regclass
        AND c.relkind='r' AND pg_get_userbyid(c.relowner)='postgres'
        AND c.relrowsecurity AND c.relforcerowsecurity
    ) OR (
      SELECT count(*) FROM pg_policies p
      WHERE p.schemaname='public' AND p.tablename=target_table
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.qual LIKE '%avuhz.tenant_id%'
        AND p.with_check LIKE '%avuhz.tenant_id%'
    )<>1 OR EXISTS (
      SELECT 1 FROM pg_policies p WHERE p.schemaname='public'
        AND p.tablename=target_table
        AND p.policyname LIKE 'avuhz_acquisition_%'
    ) THEN
      RAISE EXCEPTION 'ACQUISITION_ROLE_REGISTRY_RLS_OR_OWNER_DRIFT_STOP';
    END IF;
  END LOOP;
END
$acquisition_registry_preflight$;

CREATE ROLE avuhz_acquisition_service_dev
  NOLOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION
  NOSUPERUSER NOBYPASSRLS;

-- No membership in the broad avuhz_command_service runtime role.
-- Application auth/tenant-binding and connection role selection are separate.
GRANT USAGE ON SCHEMA public TO avuhz_acquisition_service_dev;

-- Organization/owner authority remains unmodifiable by the acquisition role.
-- PostgreSQL requires UPDATE privilege to acquire FOR SHARE/FOR UPDATE locks.
-- Grant UPDATE on one non-authority column only, then enforce an RLS UPDATE
-- WITH CHECK false policy; locked reads use USING, actual writes fail.
GRANT SELECT (tenant_id,organization_id,lifecycle_state)
  ON public.avuhz_tenant_organizations TO avuhz_acquisition_service_dev;
GRANT UPDATE (record_version)
  ON public.avuhz_tenant_organizations TO avuhz_acquisition_service_dev;
GRANT SELECT (tenant_id,organization_id,member_role,membership_state,verified_at)
  ON public.avuhz_tenant_owner_memberships TO avuhz_acquisition_service_dev;
GRANT UPDATE (record_version)
  ON public.avuhz_tenant_owner_memberships TO avuhz_acquisition_service_dev;

GRANT INSERT (
  intake_id,tenant_id,organization_id,external_request_id,source_system,
  route_reference,business_name,contact_name,contact_email,contact_phone,
  preferred_contact_method,contact_requested,diagnostic_summary
) ON public.avuhz_acquisition_intake_requests TO avuhz_acquisition_service_dev;
GRANT SELECT (
  intake_id,tenant_id,organization_id,external_request_id,source_system,
  route_reference,business_name,contact_name,contact_email,contact_phone,
  preferred_contact_method,contact_requested,diagnostic_summary
) ON public.avuhz_acquisition_intake_requests TO avuhz_acquisition_service_dev;
GRANT UPDATE (record_version)
  ON public.avuhz_acquisition_intake_requests TO avuhz_acquisition_service_dev;

DO $acquisition_registry_policies$
DECLARE
  target_table text;
  tenant_predicate constant text :=
    'tenant_id = nullif(current_setting(''avuhz.tenant_id'',true),'''')::uuid';
BEGIN
  FOREACH target_table IN ARRAY ARRAY[
    'avuhz_tenant_organizations',
    'avuhz_tenant_owner_memberships',
    'avuhz_acquisition_intake_requests'
  ] LOOP
    EXECUTE format(
      'CREATE POLICY avuhz_acquisition_select ON public.%I FOR SELECT '
      ||'TO avuhz_acquisition_service_dev USING (%s)',
      target_table,tenant_predicate
    );
    EXECUTE format(
      'CREATE POLICY avuhz_acquisition_lock_only ON public.%I FOR UPDATE '
      ||'TO avuhz_acquisition_service_dev '
      ||'USING (%s) WITH CHECK (false)',
      target_table,tenant_predicate
    );
  END LOOP;
END
$acquisition_registry_policies$;

CREATE POLICY avuhz_acquisition_intake_insert
  ON public.avuhz_acquisition_intake_requests
  FOR INSERT TO avuhz_acquisition_service_dev
  WITH CHECK (
    tenant_id = nullif(current_setting('avuhz.tenant_id',true),'')::uuid
  );

DO $acquisition_registry_postcondition$
DECLARE
  target_table text;
  policy_count integer;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles
      WHERE rolname='avuhz_acquisition_service_dev'
        AND NOT rolcanlogin AND NOT rolinherit AND NOT rolcreaterole
        AND NOT rolbypassrls AND NOT rolsuper)
     -- A non-superuser CREATEROLE creator may automatically receive an
     -- ADMIN/NOSET/NOINHERIT membership in PostgreSQL 17. Permit only
     -- that well-known administrative edge, never runtime SET or INHERIT.
     OR EXISTS (SELECT 1 FROM pg_auth_members m
       JOIN pg_roles r ON r.oid=m.roleid
       JOIN pg_roles grantee ON grantee.oid=m.member
       WHERE r.rolname='avuhz_acquisition_service_dev'
         AND (grantee.rolname<>'postgres' OR NOT m.admin_option
              OR m.set_option OR m.inherit_option))
     OR EXISTS (SELECT 1 FROM pg_auth_members m
       JOIN pg_roles r ON r.oid=m.member
       WHERE r.rolname='avuhz_acquisition_service_dev')
  THEN
    RAISE EXCEPTION 'ACQUISITION_ROLE_UNEXPECTED_CAPABILITY_OR_MEMBERSHIP_STOP';
  END IF;
  FOREACH target_table IN ARRAY ARRAY[
    'avuhz_tenant_organizations',
    'avuhz_tenant_owner_memberships',
    'avuhz_acquisition_intake_requests'
  ] LOOP
    SELECT count(*) INTO policy_count FROM pg_policies p
      WHERE p.schemaname='public' AND p.tablename=target_table
        AND p.policyname IN ('avuhz_acquisition_select',
                             'avuhz_acquisition_lock_only',
                             'avuhz_acquisition_intake_insert')
        AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[];
    IF policy_count<>(CASE WHEN target_table=
        'avuhz_acquisition_intake_requests' THEN 3 ELSE 2 END)
       OR NOT EXISTS (SELECT 1 FROM pg_class c
          WHERE c.oid=('public.'||target_table)::regclass
            AND c.relrowsecurity AND c.relforcerowsecurity)
       OR has_table_privilege('avuhz_command_service',
           ('public.'||target_table)::regclass,'SELECT')
       OR has_table_privilege('avuhz_command_service',
           ('public.'||target_table)::regclass,'INSERT')
       OR has_table_privilege('avuhz_acquisition_service_dev',
           ('public.'||target_table)::regclass,'DELETE')
       OR has_table_privilege('avuhz_acquisition_service_dev',
           ('public.'||target_table)::regclass,'TRUNCATE')
       OR has_column_privilege('avuhz_acquisition_service_dev',
           ('public.'||target_table)::regclass,'tenant_id','UPDATE')
    THEN
      RAISE EXCEPTION 'ACQUISITION_ROLE_POSTCONDITION_STOP';
    END IF;
  END LOOP;
  IF has_column_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_tenant_owner_memberships',
          'principal_subject_digest','SELECT')
     OR has_column_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_acquisition_intake_requests',
          'intake_state','SELECT')
  THEN
    RAISE EXCEPTION 'ACQUISITION_ROLE_HIDDEN_FIELDS_EXPOSED_STOP';
  END IF;
END
$acquisition_registry_postcondition$;

COMMIT;
