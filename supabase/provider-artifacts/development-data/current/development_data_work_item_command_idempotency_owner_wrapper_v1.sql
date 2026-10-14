-- DEVELOPMENT DATA REVIEW ONLY: one shared Work Item idempotency owner wrapper.
-- NOT APPROVED FOR REMOTE EXECUTION. A PR merge is not Supabase approval.
-- Target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik only.
-- NEVER: DEVELOPMENT AUTH pwlhruwutoitnieactol; staging; production.
-- Canonical file: supabase/migrations/20261014041000_enable_shared_work_item_command_idempotency.sql
-- Canonical source main@6455a110fb6a944dc784bf95bb6ac4fc63ccde45 SHA-256: e3b4fc664b95fe4395b1b885a727f25a92cd4d941492bd324c51d54939b77d33
-- Scope: two CHECK constraint replacements on EXISTING shared idempotency ledger,
-- and one temporary SET role edge, revoked before COMMIT. No new table, role,
-- policy, ACL, credentials, customer rows, workflow or website activation.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;

DO $work_item_idempotency_owner_preflight$
DECLARE
  owner_oid oid;
  executor_oid oid;
  command_oid oid;
  runtime_oid oid;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_EXECUTOR_STOP';
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
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_MEMBERSHIP_DRIFT_STOP';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid=to_regclass('public.avuhz_work_items')
      AND c.relkind='r' AND c.relowner=owner_oid
      AND c.relrowsecurity AND c.relforcerowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid=to_regclass('public.avuhz_idempotency_records')
      AND c.relkind='r' AND c.relowner=owner_oid
      AND c.relrowsecurity AND NOT c.relforcerowsecurity
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
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_idempotency_records')<>1
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_idempotency_records'
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
        AND encode(sha256(convert_to(
          coalesce(p.qual,'<NULL>')||'|'||coalesce(p.with_check,'<NULL>'),'UTF8')),
          'hex')='1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88')<>1
    OR (SELECT count(*) FROM pg_constraint con
        WHERE con.conrelid='public.avuhz_idempotency_records'::regclass
        AND con.conname='avuhz_idempotency_records_command_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(con.oid),'UTF8')),'hex')
          ='ffe09fa849ce1bc165c7565e24be9dc14b96b33752a79276264181b378ecaa58')<>1
    OR (SELECT count(*) FROM pg_constraint con
        WHERE con.conrelid='public.avuhz_idempotency_records'::regclass
        AND con.conname='avuhz_idempotency_records_subject_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(con.oid),'UTF8')),'hex')
          ='5fe8ad76352fc2f3a43b698f37097df4e647b6a353022c99f96eaff4dc24f268')<>1
    OR (SELECT count(*) FROM pg_class c,
         LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_idempotency_records'::regclass)<>10
    OR EXISTS (
      SELECT 1 FROM pg_class c,
        LATERAL aclexplode(c.relacl) a
      WHERE c.oid='public.avuhz_idempotency_records'::regclass
        AND (a.grantor<>owner_oid OR a.is_grantable
          OR NOT (
            (a.grantee=owner_oid AND a.privilege_type IN (
              'SELECT','INSERT','UPDATE','DELETE','TRUNCATE',
              'REFERENCES','TRIGGER','MAINTAIN'))
            OR (a.grantee=command_oid AND a.privilege_type IN ('SELECT','INSERT'))
          ))
    )
    OR (SELECT count(*) FROM pg_attribute col,
        LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_idempotency_records'::regclass
          AND col.attnum>0 AND NOT col.attisdropped)<>4
    OR EXISTS (
      SELECT 1 FROM pg_attribute col,
        LATERAL aclexplode(col.attacl) a
      WHERE col.attrelid='public.avuhz_idempotency_records'::regclass
        AND col.attnum>0 AND NOT col.attisdropped
        AND (a.grantee<>command_oid OR a.grantor<>owner_oid
          OR a.is_grantable OR a.privilege_type<>'UPDATE'
          OR col.attname NOT IN ('completed_at','processing_status',
                                  'record_version','result_reference'))
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_SCHEMA_DRIFT_STOP';
  END IF;
END
$work_item_idempotency_owner_preflight$;

GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;
DO $work_item_idempotency_temporary_grant$
BEGIN
  IF NOT pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid='avuhz_data_migration_service_dev'::regrole
          AND m.member='postgres'::regrole
          AND m.grantor='postgres'::regrole
          AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
  THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_TEMP_ROLE_STOP';
  END IF;
END
$work_item_idempotency_temporary_grant$;

SET LOCAL ROLE avuhz_data_migration_service_dev;

-- CANONICAL_WORK_ITEM_IDEMPOTENCY_SQL_BODY_BEGIN
DO $avuhz_work_item_command_preflight$
BEGIN
  IF to_regclass('public.avuhz_work_items') IS NULL
    OR to_regclass('public.avuhz_idempotency_records') IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid='public.avuhz_work_items'::regclass
        AND relrowsecurity AND relforcerowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_class
      WHERE oid='public.avuhz_idempotency_records'::regclass
        AND relrowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_idempotency_records'
        AND policyname='avuhz_command_service_tenant_isolation'
        AND roles=ARRAY['avuhz_command_service']::name[]
        AND cmd='ALL'
        AND strpos(qual,'avuhz.tenant_id')>0
        AND strpos(with_check,'avuhz.tenant_id')>0
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid='public.avuhz_idempotency_records'::regclass
        AND conname='avuhz_idempotency_records_command_type_check'
        AND pg_get_constraintdef(oid) LIKE '%AcceptImplementationHandoff%'
        AND pg_get_constraintdef(oid) LIKE '%RecordDeploymentVerification%'
        AND pg_get_constraintdef(oid) NOT LIKE '%TransitionWorkItem%'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid='public.avuhz_idempotency_records'::regclass
        AND conname='avuhz_idempotency_records_subject_type_check'
        AND pg_get_constraintdef(oid) LIKE '%IMPLEMENTATION_HANDOFF%'
        AND pg_get_constraintdef(oid) LIKE '%DEPLOYMENT_VERIFICATION%'
        AND pg_get_constraintdef(oid) NOT LIKE '%WORK_ITEM%'
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_COMMAND_PREFLIGHT_STOP';
  END IF;
END
$avuhz_work_item_command_preflight$;

alter table public.avuhz_idempotency_records
  drop constraint if exists avuhz_idempotency_records_command_type_check;
alter table public.avuhz_idempotency_records
  add constraint avuhz_idempotency_records_command_type_check check (command_type in (
    'AcceptAcquisitionHandoff','AcceptImplementationHandoff','TransitionWorkItem','OpenEngagement',
    'DraftImplementationBrief','ReviseImplementationBrief',
    'RecordImplementationBriefApproval','ApproveImplementationBrief',
    'ProposeImplementationAuthorization','ReviseImplementationAuthorization',
    'RecordImplementationAuthorizationApproval','ActivateImplementationAuthorization',
    'RevokeImplementationAuthorization','DraftCodexBuildPackage','ReviseCodexBuildPackage',
    'RecordCodexBuildPackageApproval','ReleaseCodexBuildPackage','StartBuildExecution',
    'CompleteBuildExecution','RecordQAResult','RecordClientAcceptance',
    'ProposeDeploymentAuthorization','ReviseDeploymentAuthorization',
    'RecordDeploymentAuthorizationApproval','ActivateDeploymentAuthorization',
    'RevokeDeploymentAuthorization','StartDeploymentExecution',
    'CompleteDeploymentExecution','RecordDeploymentVerification'
  ));

alter table public.avuhz_idempotency_records
  drop constraint if exists avuhz_idempotency_records_subject_type_check;
alter table public.avuhz_idempotency_records
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','IMPLEMENTATION_HANDOFF','WORK_ITEM','ENGAGEMENT','IMPLEMENTATION_BRIEF',
    'IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT',
    'QA_RESULT','CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION','DEPLOYMENT_EXECUTION',
    'DEPLOYMENT_VERIFICATION'
  ));
-- CANONICAL_WORK_ITEM_IDEMPOTENCY_SQL_BODY_END

RESET ROLE;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $work_item_idempotency_owner_postcondition$
DECLARE owner_oid oid; executor_oid oid; command_oid oid; runtime_oid oid;
BEGIN
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev';
  SELECT oid INTO STRICT executor_oid FROM pg_roles WHERE rolname='postgres';
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
  IF current_user<>'postgres' OR session_user<>'postgres'
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid AND m.member=executor_oid AND
          m.grantor=executor_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members m
        WHERE m.roleid=owner_oid OR m.member=owner_oid)<>2
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
  THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_TEMP_ROLE_NOT_REVOKED_STOP';
  END IF;

  IF (SELECT count(*) FROM pg_constraint con
      WHERE con.conrelid='public.avuhz_idempotency_records'::regclass
      AND con.conname='avuhz_idempotency_records_command_type_check'
      AND pg_get_constraintdef(con.oid) LIKE '%TransitionWorkItem%'
      AND pg_get_constraintdef(con.oid) LIKE '%RecordDeploymentVerification%')<>1
    OR (SELECT count(*) FROM pg_constraint con
      WHERE con.conrelid='public.avuhz_idempotency_records'::regclass
      AND con.conname='avuhz_idempotency_records_subject_type_check'
      AND pg_get_constraintdef(con.oid) LIKE '%WORK_ITEM%'
      AND pg_get_constraintdef(con.oid) LIKE '%DEPLOYMENT_VERIFICATION%')<>1
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
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_idempotency_records')<>1
    OR (SELECT count(*) FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename='avuhz_idempotency_records'
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
        AND encode(sha256(convert_to(
          coalesce(p.qual,'<NULL>')||'|'||coalesce(p.with_check,'<NULL>'),'UTF8')),
          'hex')='1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88')<>1
    OR (SELECT count(*) FROM pg_class c,
         LATERAL aclexplode(c.relacl) a
        WHERE c.oid='public.avuhz_idempotency_records'::regclass)<>10
    OR EXISTS (
      SELECT 1 FROM pg_class c,
        LATERAL aclexplode(c.relacl) a
      WHERE c.oid='public.avuhz_idempotency_records'::regclass
        AND (a.grantor<>owner_oid OR a.is_grantable
          OR NOT (
            (a.grantee=owner_oid AND a.privilege_type IN (
              'SELECT','INSERT','UPDATE','DELETE','TRUNCATE',
              'REFERENCES','TRIGGER','MAINTAIN'))
            OR (a.grantee=command_oid AND a.privilege_type IN ('SELECT','INSERT'))
          ))
    )
    OR (SELECT count(*) FROM pg_attribute col,
        LATERAL aclexplode(col.attacl) a
        WHERE col.attrelid='public.avuhz_idempotency_records'::regclass
          AND col.attnum>0 AND NOT col.attisdropped)<>4
    OR EXISTS (
      SELECT 1 FROM pg_attribute col,
        LATERAL aclexplode(col.attacl) a
      WHERE col.attrelid='public.avuhz_idempotency_records'::regclass
        AND col.attnum>0 AND NOT col.attisdropped
        AND (a.grantee<>command_oid OR a.grantor<>owner_oid
          OR a.is_grantable OR a.privilege_type<>'UPDATE'
          OR col.attname NOT IN ('completed_at','processing_status',
                                  'record_version','result_reference'))
    )
  THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_IDEMPOTENCY_POSTCONDITION_STOP';
  END IF;
END
$work_item_idempotency_owner_postcondition$;

COMMIT;
