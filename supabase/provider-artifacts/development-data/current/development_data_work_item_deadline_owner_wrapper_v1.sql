-- DEVELOPMENT DATA REVIEW ONLY: System #001 shared Work Item deadline owner wrapper.
-- NOT APPROVED FOR REMOTE EXECUTION. PR merges do not authorize provider writes.
-- Target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik only.
-- NEVER: DEVELOPMENT AUTH pwlhruwutoitnieactol, production or another project.
-- Canonical source: supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql
-- Canonical source SHA-256: 8511708bce3e2236772d41775ab5fd1fd255cf4097141f621cb604b203bbc9d2
-- One nullable column and its two column-specific grants; one temporary SET edge
-- revoked within the transaction. No customer data, billing, keys, workflow or runtime activation.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;

DO $work_item_deadline_owner_preflight$
DECLARE
  owner_oid oid; executor_oid oid; command_oid oid; runtime_oid oid;
BEGIN
  SELECT oid INTO STRICT executor_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT runtime_oid FROM pg_roles
    WHERE rolname='avuhz_data_runtime_service_dev'
    AND rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  IF session_user <> 'postgres' OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_DEADLINE_EXECUTOR_STOP';
  END IF;
  SELECT oid INTO STRICT executor_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
    AND NOT rolreplication;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole
    AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT runtime_oid FROM pg_roles
    WHERE rolname='avuhz_data_runtime_service_dev'
      AND rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolbypassrls AND NOT rolcreaterole
      AND NOT rolcreatedb AND NOT rolreplication;

  IF pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid OR m.member=owner_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid AND m.member=executor_oid
          AND m.grantor=executor_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=owner_oid AND m.member=executor_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.member=command_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=command_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=command_oid AND m.member=owner_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=command_oid AND m.member=runtime_oid
          AND m.grantor=owner_oid
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=runtime_oid OR m.member=runtime_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=runtime_oid AND m.member=executor_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR pg_has_role('avuhz_data_migration_service_dev',
                   'avuhz_command_service','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_DEADLINE_MEMBERSHIP_DRIFT_STOP';
  END IF;


  IF NOT EXISTS (
       SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('public.avuhz_work_items')
         AND c.relkind='r' AND c.relowner=owner_oid AND c.relrowsecurity AND c.relforcerowsecurity
    )
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_work_items')<>1
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_work_items'
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
        AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')
           ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
        AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')
           ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6')<>1
    OR (SELECT count(*) FROM pg_constraint c
        WHERE c.conrelid='public.avuhz_idempotency_records'::regclass
        AND c.conname='avuhz_idempotency_records_command_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(c.oid),'UTF8')),'hex')
           ='ae3f54bdf5768e8f4ce9473272ff965bdcdcfdea807c2eeb04f44aed40c31fbe')<>1
    OR (SELECT count(*) FROM pg_constraint c
        WHERE c.conrelid='public.avuhz_idempotency_records'::regclass
        AND c.conname='avuhz_idempotency_records_subject_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(c.oid),'UTF8')),'hex')
           ='2ff513bf4ad6cb9ad181a9c8693d57a27aa0b1c8ec17eca8747ce0aec01d3b50')<>1
    OR (SELECT count(*) FROM pg_class c
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_work_items'::regclass)<>9
    OR EXISTS (
        SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_work_items'::regclass
        AND (a.grantor<>owner_oid OR a.is_grantable OR NOT (
          (a.grantee=owner_oid AND a.privilege_type IN
            ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'))
           OR (a.grantee=command_oid AND a.privilege_type='SELECT')))
    )
    OR (SELECT count(*) FROM pg_attribute col
        CROSS JOIN LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_work_items'::regclass
         AND col.attnum>0 AND NOT col.attisdropped)<>13
    OR EXISTS (
        SELECT 1 FROM pg_attribute col
        CROSS JOIN LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_work_items'::regclass
         AND col.attnum>0 AND NOT col.attisdropped
         AND (a.grantee<>command_oid OR a.grantor<>owner_oid
          OR a.is_grantable OR (col.attname,a.privilege_type) NOT IN (
             ('tenant_id','INSERT'),
             ('work_item_id','INSERT'),
             ('owner_reference','INSERT'),
             ('owner_reference','UPDATE'),
             ('pending_recipient_reference','INSERT'),
             ('pending_recipient_reference','UPDATE'),
             ('source','INSERT'),
             ('classification','INSERT'),
             ('state','INSERT'),
             ('state','UPDATE'),
             ('record_version','INSERT'),
             ('record_version','UPDATE'),
             ('updated_at','UPDATE')
          ))
    )
    OR EXISTS (
       SELECT 1 FROM pg_attribute a WHERE a.attrelid='public.avuhz_work_items'::regclass
       AND a.attname='next_action_due_at' AND NOT a.attisdropped
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEM_DEADLINE_OWNER_SCHEMA_DRIFT_STOP';
  END IF;

END
$work_item_deadline_owner_preflight$;

GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;
DO $work_item_deadline_temporary_grant$
BEGIN
  IF NOT pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid='avuhz_data_migration_service_dev'::regrole
          AND m.member='postgres'::regrole
          AND m.grantor='postgres'::regrole
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
  THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_DEADLINE_TEMP_ROLE_STOP';
  END IF;
END
$work_item_deadline_temporary_grant$;

SET LOCAL ROLE avuhz_data_migration_service_dev;

-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_BEGIN
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
-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_END

RESET ROLE;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $work_item_deadline_owner_postcondition$
DECLARE
  owner_oid oid; executor_oid oid; command_oid oid; runtime_oid oid;
BEGIN
  SELECT oid INTO STRICT executor_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT runtime_oid FROM pg_roles
    WHERE rolname='avuhz_data_runtime_service_dev'
    AND rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication;
  IF session_user <> 'postgres' OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_DEADLINE_EXECUTOR_STOP';
  END IF;
  SELECT oid INTO STRICT executor_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
    AND NOT rolreplication;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
    AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
    AND NOT rolbypassrls AND NOT rolcreaterole
    AND NOT rolcreatedb AND NOT rolreplication;
  SELECT oid INTO STRICT runtime_oid FROM pg_roles
    WHERE rolname='avuhz_data_runtime_service_dev'
      AND rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolbypassrls AND NOT rolcreaterole
      AND NOT rolcreatedb AND NOT rolreplication;

  IF pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid OR m.member=owner_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid AND m.member=executor_oid
          AND m.grantor=executor_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=owner_oid AND m.member=executor_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.member=command_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=command_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=command_oid AND m.member=owner_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=command_oid AND m.member=runtime_oid
          AND m.grantor=owner_oid
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=runtime_oid OR m.member=runtime_oid)<>2
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles g ON g.oid=m.grantor
        WHERE m.roleid=runtime_oid AND m.member=executor_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND g.rolsuper AND g.rolname='supabase_admin')<>1
    OR pg_has_role('avuhz_data_migration_service_dev',
                   'avuhz_command_service','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_DEADLINE_MEMBERSHIP_DRIFT_STOP';
  END IF;


  IF NOT EXISTS (
       SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('public.avuhz_work_items')
         AND c.relkind='r' AND c.relowner=owner_oid AND c.relrowsecurity AND c.relforcerowsecurity
    )
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_work_items')<>1
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_work_items'
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
        AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')
           ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
        AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')
           ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6')<>1
    OR (SELECT count(*) FROM pg_constraint c
        WHERE c.conrelid='public.avuhz_idempotency_records'::regclass
        AND c.conname='avuhz_idempotency_records_command_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(c.oid),'UTF8')),'hex')
           ='ae3f54bdf5768e8f4ce9473272ff965bdcdcfdea807c2eeb04f44aed40c31fbe')<>1
    OR (SELECT count(*) FROM pg_constraint c
        WHERE c.conrelid='public.avuhz_idempotency_records'::regclass
        AND c.conname='avuhz_idempotency_records_subject_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(c.oid),'UTF8')),'hex')
           ='2ff513bf4ad6cb9ad181a9c8693d57a27aa0b1c8ec17eca8747ce0aec01d3b50')<>1
    OR (SELECT count(*) FROM pg_class c
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_work_items'::regclass)<>9
    OR EXISTS (
        SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_work_items'::regclass
        AND (a.grantor<>owner_oid OR a.is_grantable OR NOT (
          (a.grantee=owner_oid AND a.privilege_type IN
            ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'))
           OR (a.grantee=command_oid AND a.privilege_type='SELECT')))
    )
    OR (SELECT count(*) FROM pg_attribute col
        CROSS JOIN LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_work_items'::regclass
         AND col.attnum>0 AND NOT col.attisdropped)<>15
    OR EXISTS (
        SELECT 1 FROM pg_attribute col
        CROSS JOIN LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_work_items'::regclass
         AND col.attnum>0 AND NOT col.attisdropped
         AND (a.grantee<>command_oid OR a.grantor<>owner_oid
          OR a.is_grantable OR (col.attname,a.privilege_type) NOT IN (
             ('tenant_id','INSERT'),
             ('work_item_id','INSERT'),
             ('owner_reference','INSERT'),
             ('owner_reference','UPDATE'),
             ('pending_recipient_reference','INSERT'),
             ('pending_recipient_reference','UPDATE'),
             ('source','INSERT'),
             ('classification','INSERT'),
             ('state','INSERT'),
             ('state','UPDATE'),
             ('record_version','INSERT'),
             ('record_version','UPDATE'),
             ('updated_at','UPDATE'),
             ('next_action_due_at','INSERT'),
             ('next_action_due_at','UPDATE')
          ))
    )
    OR NOT EXISTS (
       SELECT 1 FROM pg_attribute a WHERE a.attrelid='public.avuhz_work_items'::regclass
       AND a.attname='next_action_due_at' AND NOT a.attisdropped
       AND a.atttypid='pg_catalog.timestamptz'::regtype
       AND NOT a.attnotnull AND NOT a.atthasdef
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEM_DEADLINE_OWNER_SCHEMA_DRIFT_STOP';
  END IF;

END
$work_item_deadline_owner_postcondition$;

COMMIT;
