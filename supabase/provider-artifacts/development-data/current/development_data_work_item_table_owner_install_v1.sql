-- REVIEW ONLY; NOT APPROVED FOR HOSTED EXECUTION by source merge.
-- One new shared System #001 work item DATA table, no customer rows.
-- Target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
-- NEVER: DEVELOPMENT AUTH pwlhruwutoitnieactol, production, staging.
-- Canonical source Avuhz main@fd489ec8b4063a21f7012c0c7d9fb14b918d4c88
-- Canonical source file: supabase/migrations/20261014034000_create_shared_work_items.sql
-- Canonical source SHA-256: 0e78557df12d063d1aad2af7bc267f7be1e89b13e08822746f19ebf76f783f68
-- Security model: the caller owns CREATE on public but the dedicated DATA
-- owner does not. Create one table using canonical SQL, temporarily grant
-- schema CREATE and membership SET only to transfer ownership to existing
-- avuhz_data_migration_service_dev; revoke BOTH grants before COMMIT.
-- No permanent CREATE privilege, SET membership, extra app grants or roles.
BEGIN;
-- Resolve privileged SQL only through trusted PostgreSQL catalog objects.
SET LOCAL search_path = pg_catalog, pg_temp;

DO $work_item_owner_install_preflight$
DECLARE
  postgres_oid oid; migration_oid oid; command_oid oid;
  provider_edges integer; transient_edges integer; command_edges integer; owner_edges integer;
BEGIN
  IF session_user<>'postgres' OR current_user<>'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_SESSION_STOP';
  END IF;
  SELECT oid INTO STRICT postgres_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT migration_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
      AND NOT rolbypassrls;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
      AND NOT rolbypassrls;
  SELECT count(*) INTO provider_edges FROM pg_auth_members m
    JOIN pg_roles grantor_role ON grantor_role.oid=m.grantor
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND grantor_role.rolsuper AND grantor_role.oid<>postgres_oid;
  SELECT count(*) INTO transient_edges FROM pg_auth_members m
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.grantor=postgres_oid;
  SELECT count(*) INTO command_edges FROM pg_auth_members m
    JOIN pg_roles grantor_role ON grantor_role.oid=m.grantor
    WHERE m.roleid=command_oid AND m.member=migration_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND grantor_role.rolsuper AND grantor_role.oid<>migration_oid;
  SELECT count(*) INTO owner_edges FROM pg_auth_members m
    WHERE m.roleid=migration_oid OR m.member=migration_oid;
  IF provider_edges<>1 OR transient_edges<>0 OR command_edges<>1 OR owner_edges<>2
    OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=command_oid)
    OR (SELECT count(*) FROM pg_auth_members m WHERE m.roleid=command_oid) NOT IN (1,2)
    OR EXISTS (
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles runtime ON runtime.oid=m.member
      WHERE m.roleid=command_oid AND m.member<>migration_oid
        AND NOT (
          runtime.rolname='avuhz_data_runtime_service_dev'
          AND runtime.rolcanlogin AND NOT runtime.rolsuper AND NOT runtime.rolinherit
          AND NOT runtime.rolcreaterole AND NOT runtime.rolcreatedb
          AND NOT runtime.rolreplication AND NOT runtime.rolbypassrls
          AND m.grantor=migration_oid AND NOT m.admin_option
          AND NOT m.inherit_option AND m.set_option
        )
    )
    OR EXISTS (
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles runtime
        ON runtime.oid=m.roleid OR runtime.oid=m.member
      WHERE runtime.rolname='avuhz_data_runtime_service_dev'
        AND NOT (
          (
            m.roleid=command_oid AND m.member=runtime.oid
            AND m.grantor=migration_oid AND NOT m.admin_option
            AND NOT m.inherit_option AND m.set_option
          )
          OR (
            -- Provider-authorized ADMIN-only membership; never SET or inherit.
            m.roleid=runtime.oid AND m.member=postgres_oid
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
            AND EXISTS (
              SELECT 1 FROM pg_roles provider
              WHERE provider.oid=m.grantor AND provider.rolsuper
                AND provider.rolname='supabase_admin'
                AND provider.oid<>postgres_oid
            )
          )
        )
    )
    OR NOT pg_has_role('postgres','avuhz_data_migration_service_dev','MEMBER')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
    OR pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET')
    THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_OWNER_MEMBERSHIP_DRIFT_STOP';
  END IF;
  IF to_regclass('public.avuhz_work_items') IS NOT NULL
    OR NOT has_schema_privilege('postgres','public','CREATE')
    OR (SELECT datdba FROM pg_database WHERE datname=current_database())<>postgres_oid
    OR EXISTS (
      SELECT 1 FROM pg_default_acl d
      CROSS JOIN LATERAL aclexplode(d.defaclacl) grant_row
      WHERE d.defaclrole=postgres_oid AND d.defaclobjtype='r'
        AND d.defaclnamespace IN (0,'public'::regnamespace)
        AND grant_row.grantee NOT IN (
          postgres_oid,coalesce(to_regrole('anon')::oid,0),
          coalesce(to_regrole('authenticated')::oid,0),
          coalesce(to_regrole('service_role')::oid,0))
    )
    OR NOT has_schema_privilege('avuhz_data_migration_service_dev','public','USAGE')
    OR has_schema_privilege('avuhz_data_migration_service_dev','public','CREATE')
    OR NOT EXISTS (
      SELECT 1 FROM pg_namespace
      WHERE nspname='public' AND nspowner='pg_database_owner'::regrole
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid='public.avuhz_lifecycle_events'::regclass
        AND c.relkind='r' AND c.relowner=migration_oid
        AND c.relrowsecurity AND NOT c.relforcerowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_class c
      WHERE c.oid='public.avuhz_idempotency_records'::regclass
        AND c.relkind='r' AND c.relowner=migration_oid
        AND c.relrowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid='public.avuhz_lifecycle_events'::regclass
        AND conname='avuhz_lifecycle_events_event_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='f3ea1451119d4ae7c7f1fd1e2bb74b53de53457d44912a227fc9d5f4a0dd956a'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conrelid='public.avuhz_lifecycle_events'::regclass
        AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
        AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='0dbc491813853561ec9c09f22046984b829245647d00482f9fe2601ffb65556e'
    )
    OR (SELECT count(*) FROM pg_policies
        WHERE schemaname='public' AND tablename='avuhz_lifecycle_events')<>3
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_lifecycle_events'
        AND policyname='avuhz_acquisition_event_read'
        AND roles=ARRAY['avuhz_acquisition_service_dev']::name[]
        AND cmd='SELECT' AND permissive='PERMISSIVE'
        AND encode(sha256(convert_to(coalesce(qual,'<NULL>'),'UTF8')),'hex')
          ='3d5784ab3919fb8b3d72e585c614f437a38bcbef7520712113ef1a0aa78cc78a'
        AND encode(sha256(convert_to(coalesce(with_check,'<NULL>'),'UTF8')),'hex')
          ='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_lifecycle_events'
        AND policyname='avuhz_acquisition_event_insert'
        AND roles=ARRAY['avuhz_acquisition_service_dev']::name[]
        AND cmd='INSERT' AND permissive='PERMISSIVE'
        AND encode(sha256(convert_to(coalesce(qual,'<NULL>'),'UTF8')),'hex')
          ='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
        AND encode(sha256(convert_to(coalesce(with_check,'<NULL>'),'UTF8')),'hex')
          ='63e10ab9c7b31d52d9fd1d525af0d5233509632c32b330173952e7a057e0e323'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_policies
      WHERE schemaname='public' AND tablename='avuhz_lifecycle_events'
        AND policyname='avuhz_command_service_tenant_isolation'
        AND roles=ARRAY['avuhz_command_service']::name[]
        AND cmd='ALL' AND permissive='PERMISSIVE'
        AND encode(sha256(convert_to(coalesce(qual,'<NULL>'),'UTF8')),'hex')
          ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
        AND encode(sha256(convert_to(coalesce(with_check,'<NULL>'),'UTF8')),'hex')
          ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_SCHEMA_OR_EVENT_DRIFT_STOP';
  END IF;
END
$work_item_owner_install_preflight$;

-- Transaction-local grants. Both must be REVOKED before the final COMMIT.
GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;
GRANT CREATE ON SCHEMA public TO avuhz_data_migration_service_dev;

DO $work_item_owner_install_temporary_grant_check$
BEGIN
  IF NOT pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR NOT has_schema_privilege('avuhz_data_migration_service_dev','public','CREATE')
    THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_TEMPORARY_GRANT_STOP';
  END IF;
END
$work_item_owner_install_temporary_grant_check$;

-- CANONICAL_WORK_ITEM_TABLE_SQL_BODY_BEGIN
DO $avuhz_shared_work_items_preflight$
BEGIN
  IF to_regclass('public.avuhz_work_items') IS NOT NULL
    OR to_regclass('public.avuhz_lifecycle_events') IS NULL
    OR to_regclass('public.avuhz_idempotency_records') IS NULL
    OR NOT has_schema_privilege(current_user,'public','CREATE')
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname='avuhz_command_service' AND NOT rolcanlogin
        AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class c
      WHERE c.oid='public.avuhz_lifecycle_events'::regclass
        AND c.relrowsecurity
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_policies p
      WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
        AND p.policyname='avuhz_command_service_tenant_isolation'
        AND p.roles=ARRAY['avuhz_command_service']::name[]
        AND p.cmd='ALL'
        AND strpos(p.qual,'avuhz.tenant_id')>0
        AND strpos(p.with_check,'avuhz.tenant_id')>0
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint con
      WHERE con.conrelid='public.avuhz_lifecycle_events'::regclass
        AND con.conname='avuhz_lifecycle_events_event_type_check'
        AND pg_get_constraintdef(con.oid) LIKE '%work_intake.resolved%'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint con
      WHERE con.conrelid='public.avuhz_lifecycle_events'::regclass
        AND con.conname='avuhz_lifecycle_events_authoritative_subject_type_check'
        AND pg_get_constraintdef(con.oid) LIKE '%WORK_ITEM%'
    )
  THEN
    RAISE EXCEPTION 'AVUHZ_SHARED_WORK_ITEMS_PREFLIGHT_STOP';
  END IF;
END
$avuhz_shared_work_items_preflight$;

CREATE TABLE public.avuhz_work_items (
  tenant_id uuid NOT NULL,
  work_item_id uuid NOT NULL,
  owner_reference text NOT NULL
    CHECK (owner_reference ~ '^[a-z][a-z0-9._:-]{1,95}$'),
  pending_recipient_reference text
    CHECK (pending_recipient_reference IS NULL OR
      pending_recipient_reference ~ '^[a-z][a-z0-9._:-]{1,95}$'),
  source text NOT NULL CHECK (source IN
    ('phone','email','web','internal','api','other')),
  classification text NOT NULL CHECK (classification IN
    ('service_request','work_order','support_request','incident',
     'approval_request','internal_task','customer_question','other')),
  state text NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN','BLOCKED','RESOLVED')),
  record_version integer NOT NULL DEFAULT 1 CHECK
    (record_version BETWEEN 1 AND 2147483647),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, work_item_id),
  CHECK (pending_recipient_reference IS NULL OR
    (state='OPEN' AND pending_recipient_reference<>owner_reference))
);

-- This is the ONLY new authoritative table. Tenant access is exclusively
-- through an independently authenticated transaction-local avuhz.tenant_id.
ALTER TABLE public.avuhz_work_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_work_items FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.avuhz_work_items FROM PUBLIC;
DO $avuhz_shared_work_items_revoke$
DECLARE grantee_name text;
BEGIN
  FOREACH grantee_name IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=grantee_name) THEN
      EXECUTE format('REVOKE ALL ON TABLE public.avuhz_work_items FROM %I',grantee_name);
    END IF;
  END LOOP;
END
$avuhz_shared_work_items_revoke$;

CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_work_items FOR ALL TO avuhz_command_service
  USING (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
  WITH CHECK (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);

-- Privileges are shared-command-service only. Immutable identity/classification
-- are never UPDATE-able; no DELETE, TRUNCATE, REFERENCES or tenant_id UPDATE.
GRANT SELECT ON TABLE public.avuhz_work_items TO avuhz_command_service;
GRANT INSERT (
  tenant_id,work_item_id,owner_reference,pending_recipient_reference,
  source,classification,state,record_version
) ON public.avuhz_work_items TO avuhz_command_service;
GRANT UPDATE (
  owner_reference,pending_recipient_reference,state,record_version,updated_at
) ON public.avuhz_work_items TO avuhz_command_service;

-- CANONICAL_WORK_ITEM_TABLE_SQL_BODY_END

-- The canonical SQL ran as the restricted provider executor because it must
-- create its table with its own existing schema permission. Transfer owner
-- only while the owner role has temporary schema CREATE + SET rights.
ALTER TABLE public.avuhz_work_items OWNER TO avuhz_data_migration_service_dev;

REVOKE CREATE ON SCHEMA public FROM avuhz_data_migration_service_dev;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $work_item_owner_install_postcondition$
DECLARE
  postgres_oid oid; migration_oid oid; command_oid oid;
BEGIN
  SELECT oid INTO STRICT postgres_oid FROM pg_roles WHERE rolname='postgres';
  SELECT oid INTO STRICT migration_oid FROM pg_roles WHERE rolname='avuhz_data_migration_service_dev';
  SELECT oid INTO STRICT command_oid FROM pg_roles WHERE rolname='avuhz_command_service';
  IF current_user<>'postgres' OR session_user<>'postgres'
    OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=command_oid)
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles grantor_role ON grantor_role.oid=m.grantor
        WHERE m.roleid=migration_oid AND m.member=postgres_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND grantor_role.rolsuper AND grantor_role.oid<>postgres_oid)<>1
    OR (SELECT count(*) FROM pg_auth_members m
        JOIN pg_roles grantor_role ON grantor_role.oid=m.grantor
        WHERE m.roleid=command_oid AND m.member=migration_oid
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
          AND grantor_role.rolsuper AND grantor_role.oid<>migration_oid)<>1
    OR EXISTS (
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles runtime
        ON runtime.oid=m.roleid OR runtime.oid=m.member
      WHERE runtime.rolname='avuhz_data_runtime_service_dev'
        AND NOT (
          (
            m.roleid=command_oid AND m.member=runtime.oid
            AND m.grantor=migration_oid AND NOT m.admin_option
            AND NOT m.inherit_option AND m.set_option
          )
          OR (
            -- Provider-authorized ADMIN-only membership; never SET or inherit.
            m.roleid=runtime.oid AND m.member=postgres_oid
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
            AND EXISTS (
              SELECT 1 FROM pg_roles provider
              WHERE provider.oid=m.grantor AND provider.rolsuper
                AND provider.rolname='supabase_admin'
                AND provider.oid<>postgres_oid
            )
          )
        )
    )
    OR pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
    OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
    OR has_schema_privilege('avuhz_data_migration_service_dev','public','CREATE')
    OR (SELECT count(*) FROM pg_auth_members
       WHERE roleid=migration_oid AND member=postgres_oid AND grantor=postgres_oid)<>0
    OR (SELECT count(*) FROM pg_auth_members
       WHERE roleid=migration_oid OR member=migration_oid)<>2
    THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_PERMISSIONS_NOT_RESEALED_STOP';
  END IF;
  IF (SELECT count(*) FROM pg_auth_members m
      WHERE m.roleid=command_oid) NOT IN (1,2)
    OR EXISTS (
      SELECT 1 FROM pg_auth_members m
      JOIN pg_roles runtime ON runtime.oid=m.member
      WHERE m.roleid=command_oid AND m.member<>migration_oid
        AND NOT (runtime.rolname='avuhz_data_runtime_service_dev'
          AND runtime.rolcanlogin AND NOT runtime.rolsuper AND NOT runtime.rolinherit
          AND NOT runtime.rolcreaterole AND NOT runtime.rolcreatedb
          AND NOT runtime.rolreplication AND NOT runtime.rolbypassrls
          AND m.grantor=migration_oid AND NOT m.admin_option
          AND NOT m.inherit_option AND m.set_option)
    )
    THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_COMMAND_MEMBERSHIP_DRIFT_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c WHERE c.oid='public.avuhz_work_items'::regclass
      AND c.relkind='r' AND c.relowner=migration_oid
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
        AND encode(sha256(convert_to(coalesce(qual,'<NULL>'),'UTF8')),'hex')
            ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
        AND encode(sha256(convert_to(coalesce(with_check,'<NULL>'),'UTF8')),'hex')
            ='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
    )
    OR EXISTS (
      SELECT 1 FROM pg_class c
      CROSS JOIN LATERAL aclexplode(c.relacl) grant_row
      WHERE c.oid='public.avuhz_work_items'::regclass
        AND (
          grant_row.grantee NOT IN (migration_oid,command_oid)
          OR (grant_row.grantee=command_oid AND (
            grant_row.grantor<>migration_oid OR grant_row.is_grantable
            OR grant_row.privilege_type<>'SELECT'))
        )
    )
    OR (
      SELECT count(*) FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) grant_row
      WHERE a.attrelid='public.avuhz_work_items'::regclass
        AND a.attnum>0 AND NOT a.attisdropped
    )<>13
    OR EXISTS (
      SELECT 1 FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) grant_row
      WHERE a.attrelid='public.avuhz_work_items'::regclass
        AND a.attnum>0 AND NOT a.attisdropped
        AND (
          grant_row.grantee<>command_oid OR grant_row.grantor<>migration_oid
          OR grant_row.is_grantable
          OR NOT (
            (grant_row.privilege_type='INSERT' AND a.attname IN
              ('tenant_id','work_item_id','owner_reference','pending_recipient_reference',
               'source','classification','state','record_version'))
            OR (grant_row.privilege_type='UPDATE' AND a.attname IN
              ('owner_reference','pending_recipient_reference','state','record_version','updated_at'))
          )
        )
    )
    OR NOT has_table_privilege('avuhz_command_service','public.avuhz_work_items','SELECT')
    OR has_table_privilege('avuhz_command_service','public.avuhz_work_items','DELETE')
    OR has_column_privilege('avuhz_command_service','public.avuhz_work_items','tenant_id','UPDATE')
    OR coalesce(has_table_privilege(to_regrole('anon'),'public.avuhz_work_items','SELECT'),false)
    OR coalesce(has_table_privilege(to_regrole('authenticated'),'public.avuhz_work_items','SELECT'),false)
    OR coalesce(has_table_privilege(to_regrole('service_role'),'public.avuhz_work_items','SELECT'),false)
    THEN RAISE EXCEPTION 'AVUHZ_WORK_ITEM_INSTALL_TABLE_RLS_OR_ACL_STOP';
  END IF;
END
$work_item_owner_install_postcondition$;

COMMIT;
