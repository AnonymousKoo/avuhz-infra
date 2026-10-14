-- System #001 shared Revenue Engine: one optional persisted Work Item deadline.
-- Repository-only candidate. Remote execution is unauthorized by default.
-- Target when later authorized: DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
-- NEVER use for AUTH pwlhruwutoitnieactol, production, or another tenant DB.
-- Requires the verified table owner session; owner-role authorization and
-- temporary SET grants require separate exact approval. This SQL grants no owner access.
-- No tenant, role, user, owner, customer, credential, workflow or invoice creation.
BEGIN;

DO $avuhz_work_item_deadline_preflight$
DECLARE
  work_table regclass;
BEGIN
  work_table := to_regclass('public.avuhz_work_items');
  IF work_table IS NULL THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP';
  END IF;
  IF current_user='avuhz_command_service'
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
      WHERE c.oid=work_table AND r.rolname=current_user
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid=work_table AND c.relkind='r'
        AND c.relrowsecurity AND c.relforcerowsecurity
    )
    OR (SELECT count(*) FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_work_items')<>1
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_work_items'
        AND policyname='avuhz_command_service_tenant_isolation'
        AND roles=ARRAY['avuhz_command_service']::name[]
        AND cmd='ALL' AND permissive='PERMISSIVE'
        AND qual='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)'
        AND with_check='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_roles r
      WHERE r.rolname='avuhz_command_service'
        AND NOT r.rolcanlogin AND NOT r.rolsuper
        AND NOT r.rolbypassrls AND NOT r.rolcreaterole
        AND NOT r.rolcreatedb AND NOT r.rolreplication
        AND NOT r.rolinherit
    )
    OR EXISTS (
      -- Deny even one parent edge: that also denies transitive SET/inherit
      -- paths to owner, bypassrls, superuser or unknown future roles.
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles r ON r.oid=m.member
      WHERE r.rolname='avuhz_command_service'
    )
    OR NOT has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','SELECT')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','INSERT')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','UPDATE')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','DELETE')
    OR has_column_privilege(
      'avuhz_command_service','public.avuhz_work_items','tenant_id','UPDATE')
    OR EXISTS (
      -- PUBLIC pseudo-role has oid 0 and must be checked even in disposable
      -- PG without Supabase's named anon/authenticated/service_role roles.
      SELECT 1 FROM pg_class c
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      WHERE c.oid=work_table AND acl.grantee=0
    )
    OR EXISTS (
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      WHERE a.attrelid=work_table AND a.attnum>0
        AND NOT a.attisdropped AND acl.grantee=0
    )
    OR EXISTS (
      SELECT 1 FROM pg_class c
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      JOIN pg_roles r ON r.oid=acl.grantee
      WHERE c.oid=work_table
        AND r.rolname IN ('anon','authenticated','service_role')
    )
    OR EXISTS (
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      JOIN pg_roles r ON r.oid=acl.grantee
      WHERE a.attrelid=work_table AND a.attnum>0 AND NOT a.attisdropped
        AND r.rolname IN ('anon','authenticated','service_role')
    )
    OR EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid=work_table
        AND attname='next_action_due_at' AND NOT attisdropped
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP';
  END IF;
END
$avuhz_work_item_deadline_preflight$;

-- Nullable for backwards-compatible state. Never pretend an unset due date
-- has been scheduled or acknowledged. The approved shared command must set
-- this field atomically with a Work Item version, lifecycle event and outbox.
ALTER TABLE public.avuhz_work_items
    ADD COLUMN next_action_due_at timestamptz;

-- Column-scoped only; no table-wide UPDATE, DELETE, service role or anon.
GRANT INSERT(next_action_due_at), UPDATE(next_action_due_at)
  ON public.avuhz_work_items TO avuhz_command_service;

DO $avuhz_work_item_deadline_postconditions$
DECLARE
  work_table regclass;
  runtime_role oid;
BEGIN
  work_table := to_regclass('public.avuhz_work_items');
  SELECT oid INTO runtime_role FROM pg_roles WHERE rolname='avuhz_command_service';
  IF work_table IS NULL OR runtime_role IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid=work_table AND c.relkind='r'
        AND c.relrowsecurity AND c.relforcerowsecurity
    )
    OR (SELECT count(*) FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_work_items')<>1
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_work_items'
        AND policyname='avuhz_command_service_tenant_isolation'
        AND roles=ARRAY['avuhz_command_service']::name[]
        AND cmd='ALL' AND permissive='PERMISSIVE'
        AND qual='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)'
        AND with_check='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_roles r
      WHERE r.rolname='avuhz_command_service'
        AND NOT r.rolcanlogin AND NOT r.rolsuper
        AND NOT r.rolbypassrls AND NOT r.rolcreaterole
        AND NOT r.rolcreatedb AND NOT r.rolreplication
        AND NOT r.rolinherit
    )
    OR EXISTS (
      -- Deny even one parent edge: that also denies transitive SET/inherit
      -- paths to owner, bypassrls, superuser or unknown future roles.
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles r ON r.oid=m.member
      WHERE r.rolname='avuhz_command_service'
    )
    OR NOT has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','SELECT')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','INSERT')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','UPDATE')
    OR has_table_privilege(
      'avuhz_command_service','public.avuhz_work_items','DELETE')
    OR has_column_privilege(
      'avuhz_command_service','public.avuhz_work_items','tenant_id','UPDATE')
    OR EXISTS (
      -- PUBLIC pseudo-role has oid 0 and must be checked even in disposable
      -- PG without Supabase's named anon/authenticated/service_role roles.
      SELECT 1 FROM pg_class c
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      WHERE c.oid=work_table AND acl.grantee=0
    )
    OR EXISTS (
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      WHERE a.attrelid=work_table AND a.attnum>0
        AND NOT a.attisdropped AND acl.grantee=0
    )
    OR EXISTS (
      SELECT 1 FROM pg_class c
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      JOIN pg_roles r ON r.oid=acl.grantee
      WHERE c.oid=work_table
        AND r.rolname IN ('anon','authenticated','service_role')
    )
    OR EXISTS (
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      JOIN pg_roles r ON r.oid=acl.grantee
      WHERE a.attrelid=work_table AND a.attnum>0 AND NOT a.attisdropped
        AND r.rolname IN ('anon','authenticated','service_role')
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid=work_table AND attname='next_action_due_at'
        AND NOT attisdropped AND atttypid='pg_catalog.timestamptz'::regtype
        AND NOT attnotnull AND NOT atthasdef
    )
    OR NOT has_column_privilege(
      'avuhz_command_service','public.avuhz_work_items','next_action_due_at','INSERT')
    OR NOT has_column_privilege(
      'avuhz_command_service','public.avuhz_work_items','next_action_due_at','UPDATE')
    OR (
      SELECT count(*) FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      WHERE a.attrelid=work_table AND a.attname='next_action_due_at'
        AND NOT a.attisdropped
    )<>2
    OR EXISTS (
      -- Exactly two direct non-grantable entries for the command role.
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      WHERE a.attrelid=work_table AND a.attname='next_action_due_at'
        AND NOT a.attisdropped
        AND (acl.grantee<>runtime_role OR acl.is_grantable
             OR acl.privilege_type NOT IN ('INSERT','UPDATE'))
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEM_DEADLINE_POSTCONDITION_STOP';
  END IF;
END
$avuhz_work_item_deadline_postconditions$;
COMMIT;
