-- Avuhz System #001: smallest shared acquisition-to-Work Item metadata read.
-- Repository source ONLY. Remote execution is unauthorized by default.
-- Future explicit project: DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
-- Never apply to DEVELOPMENT AUTH pwlhruwutoitnieactol or production.
-- One existing table/ACL change; no role/table/policy/tenant/owner creation.
-- Requires verified owning database role and independent single-resource approval.
-- Existing acquisition writer stays distinct; DO NOT grant it intake_state SELECT.
BEGIN;

DO $avuhz_acquisition_handoff_preflight$
DECLARE
  v_table regclass;
  v_command_role oid;
  v_policy text :=
    '(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)';
BEGIN
  v_table := to_regclass('public.avuhz_acquisition_intake_requests');
  SELECT oid INTO v_command_role FROM pg_roles WHERE rolname='avuhz_command_service';
  IF v_table IS NULL OR v_command_role IS NULL THEN
    RAISE EXCEPTION 'AVUHZ_ACQUISITION_HANDOFF_METADATA_PREFLIGHT_STOP';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_roles owner ON owner.oid=c.relowner
    WHERE c.oid=v_table AND c.relkind='r'
      AND owner.rolname=current_user
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.oid=v_command_role
      AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolinherit AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolreplication
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members m WHERE m.member=v_command_role
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=v_command_role
  )<>2 OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname='avuhz_data_migration_service_dev'
      AND NOT r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
      AND NOT r.rolbypassrls AND NOT r.rolcreaterole
      AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname='avuhz_data_runtime_service_dev'
      AND r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
      AND NOT r.rolbypassrls AND NOT r.rolcreaterole
      AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_migration_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=(SELECT oid FROM pg_roles
      WHERE rolname='avuhz_data_migration_service_dev')
      AND member.rolname='postgres' AND m.admin_option
      AND NOT m.inherit_option AND NOT m.set_option
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.member=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_migration_service_dev')
  )<>1 OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.member=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_runtime_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=v_command_role
      AND member.rolname='avuhz_data_migration_service_dev'
      AND NOT member.rolcanlogin AND NOT member.rolinherit
      AND NOT member.rolsuper AND NOT member.rolbypassrls
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=v_command_role
      AND member.rolname='avuhz_data_runtime_service_dev'
      AND member.rolcanlogin AND NOT member.rolinherit
      AND NOT member.rolsuper AND NOT member.rolbypassrls
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE
      m.roleid=(SELECT oid FROM pg_roles
        WHERE rolname='avuhz_data_runtime_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=(SELECT oid FROM pg_roles
      WHERE rolname='avuhz_data_runtime_service_dev')
      AND member.rolname='postgres' AND m.admin_option
      AND NOT m.inherit_option AND NOT m.set_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public'
      AND p.tablename='avuhz_acquisition_intake_requests'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND p.qual=v_policy AND p.with_check=v_policy
  ) OR EXISTS (
    -- Deny another command/PUBLIC-accessible policy that could widen tenant reads.
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public'
      AND p.tablename='avuhz_acquisition_intake_requests'
      AND p.policyname<>'avuhz_command_service_tenant_isolation'
      AND (p.roles && ARRAY['avuhz_command_service','public']::name[])
  ) OR (
    SELECT count(*) FROM pg_attribute a
    WHERE a.attrelid=v_table AND a.attname IN
      ('intake_id','tenant_id','organization_id','intake_state','record_version')
      AND a.attnum>0 AND NOT a.attisdropped
  )<>5 OR
  has_table_privilege('avuhz_command_service',v_table,'SELECT')
  OR has_table_privilege('avuhz_command_service',v_table,'INSERT')
  OR has_table_privilege('avuhz_command_service',v_table,'UPDATE')
  OR has_table_privilege('avuhz_command_service',v_table,'DELETE')
  OR EXISTS (
    -- A previous grant must not be silently reinterpreted as this migration.
    SELECT 1 FROM pg_attribute a
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND a.attnum>0 AND NOT a.attisdropped
      AND acl.grantee=v_command_role
  ) OR EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) acl
    WHERE c.oid=v_table AND acl.grantee=0
  ) OR EXISTS (
    SELECT 1 FROM pg_attribute a
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND acl.grantee=0
  ) OR has_any_column_privilege('anon',v_table,'SELECT')
  OR has_any_column_privilege('authenticated',v_table,'SELECT')
  OR has_column_privilege('avuhz_acquisition_service_dev',v_table,'intake_state','SELECT')
  THEN
    RAISE EXCEPTION 'AVUHZ_ACQUISITION_HANDOFF_METADATA_PREFLIGHT_STOP';
  END IF;
END;
$avuhz_acquisition_handoff_preflight$;

GRANT SELECT (intake_id,tenant_id,organization_id,intake_state,record_version)
  ON public.avuhz_acquisition_intake_requests TO avuhz_command_service;

DO $avuhz_acquisition_handoff_postconditions$
DECLARE
  v_table regclass := 'public.avuhz_acquisition_intake_requests'::regclass;
  v_role oid;
  v_policy text :=
    '(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)';
BEGIN
  SELECT oid INTO v_role FROM pg_roles WHERE rolname='avuhz_command_service';
  IF v_role IS NULL OR NOT EXISTS (
    SELECT 1 FROM pg_class c WHERE c.oid=v_table
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.oid=v_role
      AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolinherit AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolreplication
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members m WHERE m.member=v_role
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=v_role
  )<>2 OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname='avuhz_data_migration_service_dev'
      AND NOT r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
      AND NOT r.rolbypassrls AND NOT r.rolcreaterole
      AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname='avuhz_data_runtime_service_dev'
      AND r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
      AND NOT r.rolbypassrls AND NOT r.rolcreaterole
      AND NOT r.rolcreatedb AND NOT r.rolreplication
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.roleid=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_migration_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=(SELECT oid FROM pg_roles
      WHERE rolname='avuhz_data_migration_service_dev')
      AND member.rolname='postgres' AND m.admin_option
      AND NOT m.inherit_option AND NOT m.set_option
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.member=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_migration_service_dev')
  )<>1 OR (
    SELECT count(*) FROM pg_auth_members m WHERE m.member=(
      SELECT oid FROM pg_roles WHERE rolname='avuhz_data_runtime_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=v_role
      AND member.rolname='avuhz_data_migration_service_dev'
      AND NOT member.rolcanlogin AND NOT member.rolinherit
      AND NOT member.rolsuper AND NOT member.rolbypassrls
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=v_role AND member.rolname='avuhz_data_runtime_service_dev'
      AND member.rolcanlogin AND NOT member.rolinherit
      AND NOT member.rolsuper AND NOT member.rolbypassrls
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) OR (
    SELECT count(*) FROM pg_auth_members m WHERE
      m.roleid=(SELECT oid FROM pg_roles
        WHERE rolname='avuhz_data_runtime_service_dev')
  )<>1 OR NOT EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    WHERE m.roleid=(SELECT oid FROM pg_roles
      WHERE rolname='avuhz_data_runtime_service_dev')
      AND member.rolname='postgres'
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_policies p WHERE p.schemaname='public'
      AND p.tablename='avuhz_acquisition_intake_requests'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND p.qual=v_policy AND p.with_check=v_policy
  ) OR EXISTS (
    SELECT 1 FROM pg_policies p WHERE p.schemaname='public'
      AND p.tablename='avuhz_acquisition_intake_requests'
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
  )<>5 OR EXISTS (
    SELECT 1 FROM pg_attribute a
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND a.attnum>0 AND NOT a.attisdropped
      AND acl.grantee=v_role AND (
        a.attname NOT IN
          ('intake_id','tenant_id','organization_id','intake_state','record_version')
        OR acl.privilege_type<>'SELECT' OR acl.is_grantable
      )
  ) OR has_column_privilege('avuhz_command_service',v_table,'contact_email','SELECT')
  OR has_column_privilege('avuhz_command_service',v_table,'contact_name','SELECT')
  OR has_column_privilege('avuhz_command_service',v_table,'contact_phone','SELECT')
  OR has_column_privilege('avuhz_command_service',v_table,'diagnostic_summary','SELECT')
  OR has_any_column_privilege('anon',v_table,'SELECT')
  OR has_any_column_privilege('authenticated',v_table,'SELECT')
  OR has_column_privilege('avuhz_acquisition_service_dev',v_table,'intake_state','SELECT')
  OR EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) acl
    WHERE c.oid=v_table AND acl.grantee=0
  ) OR EXISTS (
    SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
    WHERE a.attrelid=v_table AND acl.grantee=0
  )
  THEN
    RAISE EXCEPTION 'AVUHZ_ACQUISITION_HANDOFF_METADATA_POSTCONDITION_STOP';
  END IF;
END;
$avuhz_acquisition_handoff_postconditions$;

COMMIT;
