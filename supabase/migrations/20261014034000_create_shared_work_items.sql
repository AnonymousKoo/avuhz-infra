-- Forward-only, provider-neutral candidate for Avuhz System #001 work-item truth.
-- Remote application is unauthorized by default: this committed SQL is NOT
-- approval to run against DEVELOPMENT DATA, AUTH, staging, or production.
-- Exact separate DEVELOPMENT DATA owner approval and RLS verification required.
-- Shared Avuhz domain table only; no tenant-specific infrastructure.
-- No PII, secrets, token, workflow execution or customer record insertion.
-- Existing shared identity, command runtime, event/outbox, and billing remain
-- the only infrastructure. Do not mount Work Intake without trusted membership,
-- durable idempotency and atomic lifecycle event/outbox writer certification.
BEGIN;

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

COMMIT;
