-- Avuhz System #001: one tenant owner-membership metadata read only.
-- Repository source ONLY. Remote execution is unauthorized by default.
-- Future target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
-- Never apply to DEVELOPMENT AUTH pwlhruwutoitnieactol or production.
-- One existing membership table's column ACL; no RLS, policy, role, owner,
-- credential, tenant, membership or business record changes.
-- The pseudonymous subject digest is sensitive: accept only a server-verified
-- AUTH-derived digest in future runtime; never derive it from n8n or an event.
-- This grant does not prove that a person owns a business or establish identity.
BEGIN;

DO $avuhz_owner_membership_metadata_preflight$
DECLARE
  v_table regclass := to_regclass('public.avuhz_tenant_owner_memberships');
  v_command_role oid;
  v_policy text :=
    '(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)';
BEGIN
  SELECT oid INTO v_command_role FROM pg_roles WHERE rolname='avuhz_command_service';
  IF v_table IS NULL OR v_command_role IS NULL THEN
    RAISE EXCEPTION 'AVUHZ_MEMBERSHIP_METADATA_PREFLIGHT_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_roles owner ON owner.oid=c.relowner
    WHERE c.oid=v_table AND c.relkind='r' AND owner.rolname=current_user
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.oid=v_command_role
      AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolreplication
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members m WHERE m.member=v_command_role
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=v_command_role
  )<>2 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
    WHERE m.roleid=v_command_role
      AND r.rolname='avuhz_data_migration_service_dev'
      AND NOT r.rolcanlogin AND NOT r.rolinherit
      AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
    WHERE m.roleid=v_command_role
      AND r.rolname='avuhz_data_runtime_service_dev'
      AND r.rolcanlogin AND NOT r.rolinherit
      AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_tenant_owner_memberships'
  )<>3 OR NOT EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_tenant_owner_memberships'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND p.qual=v_policy AND p.with_check=v_policy
  ) OR EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_tenant_owner_memberships'
      AND p.policyname<>'avuhz_command_service_tenant_isolation'
      AND p.roles && ARRAY['avuhz_command_service','public']::name[]
  ) OR (
    SELECT count(*) FROM pg_attribute a WHERE a.attrelid=v_table
      AND a.attname IN ('tenant_id','organization_id','principal_subject_digest','member_role','membership_state','verified_at')
      AND a.attnum>0 AND NOT a.attisdropped
  )<>6 OR has_table_privilege('avuhz_command_service',v_table,'SELECT')
  OR has_table_privilege('avuhz_command_service',v_table,'INSERT')
  OR has_table_privilege('avuhz_command_service',v_table,'UPDATE')
  OR has_table_privilege('avuhz_command_service',v_table,'DELETE')
  OR has_any_column_privilege('avuhz_command_service',v_table,'SELECT')
  OR EXISTS (
    SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND a.attnum>0 AND NOT a.attisdropped
      AND acl.grantee=v_command_role
  ) OR EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) acl
    WHERE c.oid=v_table AND acl.grantee=0
  ) OR EXISTS (
    SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND acl.grantee=0
  ) OR has_any_column_privilege('anon',v_table,'SELECT')
  OR has_any_column_privilege('authenticated',v_table,'SELECT')
  THEN
    RAISE EXCEPTION 'AVUHZ_MEMBERSHIP_METADATA_PREFLIGHT_STOP';
  END IF;
END;
$avuhz_owner_membership_metadata_preflight$;

GRANT SELECT (tenant_id,organization_id,principal_subject_digest,member_role,membership_state,verified_at)
  ON public.avuhz_tenant_owner_memberships TO avuhz_command_service;

DO $avuhz_owner_membership_metadata_postconditions$
DECLARE
  v_table regclass := 'public.avuhz_tenant_owner_memberships'::regclass;
  v_role oid := (SELECT oid FROM pg_roles WHERE rolname='avuhz_command_service');
  v_policy text :=
    '(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)';
BEGIN
  IF v_role IS NULL OR NOT EXISTS (
    SELECT 1 FROM pg_class c WHERE c.oid=v_table
      AND c.relrowsecurity AND c.relforcerowsecurity
      AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.oid=v_role
      AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolreplication
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members m WHERE m.member=v_role
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=v_role
  )<>2 OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_tenant_owner_memberships'
  )<>3 OR NOT EXISTS (
    SELECT 1 FROM pg_policies p WHERE p.schemaname='public'
      AND p.tablename='avuhz_tenant_owner_memberships'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND p.qual=v_policy AND p.with_check=v_policy
  ) OR EXISTS (
    SELECT 1 FROM pg_policies p WHERE p.schemaname='public'
      AND p.tablename='avuhz_tenant_owner_memberships'
      AND p.policyname<>'avuhz_command_service_tenant_isolation'
      AND p.roles && ARRAY['avuhz_command_service','public']::name[]
  ) OR has_table_privilege('avuhz_command_service',v_table,'SELECT')
  OR has_table_privilege('avuhz_command_service',v_table,'INSERT')
  OR has_table_privilege('avuhz_command_service',v_table,'UPDATE')
  OR has_table_privilege('avuhz_command_service',v_table,'DELETE')
  OR (
    SELECT count(*) FROM pg_attribute a
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND a.attnum>0 AND NOT a.attisdropped
      AND acl.grantee=v_role
  )<>6 OR EXISTS (
    SELECT 1 FROM pg_attribute a
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND a.attnum>0 AND NOT a.attisdropped
      AND acl.grantee=v_role AND (
        a.attname NOT IN ('tenant_id','organization_id','principal_subject_digest','member_role','membership_state','verified_at')
        OR acl.privilege_type<>'SELECT' OR acl.is_grantable
      )
  ) OR has_column_privilege('avuhz_command_service',v_table,'record_version','SELECT')
  OR has_column_privilege('avuhz_command_service',v_table,'created_at','SELECT')
  OR has_column_privilege('avuhz_command_service',v_table,'updated_at','SELECT')
  OR has_any_column_privilege('anon',v_table,'SELECT')
  OR has_any_column_privilege('authenticated',v_table,'SELECT')
  OR EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) acl
    WHERE c.oid=v_table AND acl.grantee=0
  ) OR EXISTS (
    SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND acl.grantee=0
  ) THEN
    RAISE EXCEPTION 'AVUHZ_MEMBERSHIP_METADATA_POSTCONDITION_STOP';
  END IF;
END;
$avuhz_owner_membership_metadata_postconditions$;

COMMIT;
