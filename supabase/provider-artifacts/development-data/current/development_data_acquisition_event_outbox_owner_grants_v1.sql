-- REVIEW ONLY. NOT APPROVED FOR REMOTE EXECUTION.
-- Avuhz shared-core acquisition, DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
-- Never AUTH pwlhruwutoitnieactol, production, or any other environment.
-- Requires Stage 1 avuhz_acquisition_service_dev registry-role candidate
-- to be separately reviewed, approved, and installed first.
-- One transaction; one temporary SET edge; revocation before commit.
-- No new roles, customer inserts, credentials, billing, or n8n activation.
BEGIN;

DO $acq_outbox_preflight$
DECLARE
  owner_oid oid;
  executor_oid oid;
  acq_oid oid;
  owner_policies integer;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres'
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='postgres'
          AND NOT rolsuper AND rolcreaterole)
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_OWNER_EXECUTOR_STOP';
  END IF;
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolbypassrls;
  SELECT oid INTO STRICT executor_oid FROM pg_roles WHERE rolname='postgres';
  SELECT oid INTO STRICT acq_oid FROM pg_roles
    WHERE rolname='avuhz_acquisition_service_dev'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolbypassrls;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.grantor
      WHERE m.roleid=owner_oid AND m.member=executor_oid
        AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
        AND g.rolsuper AND g.oid<>executor_oid)<>1
     OR (SELECT count(*) FROM pg_auth_members m
         WHERE m.roleid=owner_oid AND m.member=executor_oid
           AND m.grantor=executor_oid)<>0
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR pg_has_role('avuhz_acquisition_service_dev','avuhz_command_service','MEMBER')
     OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=acq_oid)
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_OWNER_MEMBERSHIP_DRIFT_STOP';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_class
     WHERE oid='public.avuhz_acquisition_intake_requests'::regclass
       AND relrowsecurity AND relforcerowsecurity)
     OR NOT has_column_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_acquisition_intake_requests','intake_id','SELECT')
     OR NOT has_column_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_acquisition_intake_requests','contact_email','INSERT')
     OR has_table_privilege('avuhz_command_service',
          'public.avuhz_acquisition_intake_requests','SELECT')
     OR NOT EXISTS (SELECT 1 FROM pg_policies
         WHERE schemaname='public'
           AND tablename='avuhz_acquisition_intake_requests'
           AND policyname='avuhz_acquisition_intake_insert'
           AND roles=ARRAY['avuhz_acquisition_service_dev']::name[])
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_REGISTRY_STAGE_NOT_READY_STOP';
  END IF;

  FOR owner_policies IN
    SELECT 1
    FROM (VALUES ('avuhz_lifecycle_events'),('avuhz_outbox_deliveries')) tbl(name)
    JOIN pg_class c ON c.oid=('public.'||tbl.name)::regclass
    WHERE c.relowner=owner_oid AND c.relrowsecurity
      AND NOT c.relforcerowsecurity
      AND (SELECT count(*) FROM pg_policies p
           WHERE p.schemaname='public' AND p.tablename=tbl.name
             AND p.policyname='avuhz_command_service_tenant_isolation'
             AND p.roles @> ARRAY['avuhz_command_service']::name[]
             AND p.qual LIKE '%avuhz.tenant_id%'
             AND p.with_check LIKE '%avuhz.tenant_id%')=1
      AND NOT EXISTS (
        SELECT 1 FROM pg_policies p
        WHERE p.schemaname='public' AND p.tablename=tbl.name
          AND p.policyname LIKE 'avuhz_acquisition_%'
      )
  LOOP
    NULL;
  END LOOP;
  IF (SELECT count(*) FROM (
    SELECT c.oid
    FROM (VALUES ('avuhz_lifecycle_events'),('avuhz_outbox_deliveries')) tbl(name)
    JOIN pg_class c ON c.oid=('public.'||tbl.name)::regclass
    WHERE c.relowner=owner_oid AND c.relrowsecurity AND NOT c.relforcerowsecurity
      AND (SELECT count(*) FROM pg_policies p
       WHERE p.schemaname='public' AND p.tablename=tbl.name
         AND p.policyname='avuhz_command_service_tenant_isolation'
         AND p.roles @> ARRAY['avuhz_command_service']::name[]) = 1
      AND NOT EXISTS (SELECT 1 FROM pg_policies p
       WHERE p.schemaname='public' AND p.tablename=tbl.name
         AND p.policyname LIKE 'avuhz_acquisition_%')
  ) checked)<>2
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_OWNER_TABLE_POLICY_DRIFT_STOP';
  END IF;
END
$acq_outbox_preflight$;

GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;

DO $acq_outbox_edge_check$
BEGIN
  IF NOT pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR (SELECT count(*) FROM pg_auth_members m
         WHERE m.roleid=(SELECT oid FROM pg_roles
                        WHERE rolname='avuhz_data_migration_service_dev')
           AND m.member=(SELECT oid FROM pg_roles WHERE rolname='postgres')
           AND m.grantor=m.member
           AND NOT m.admin_option AND NOT m.inherit_option
           AND m.set_option)<>1
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_TEMPORARY_EDGE_STOP';
  END IF;
END
$acq_outbox_edge_check$;

SET LOCAL ROLE avuhz_data_migration_service_dev;

-- Exact event writer: one sanitized unqualified intake receipt.
GRANT INSERT (
  lifecycle_event_id,tenant_id,engagement_id,event_type,event_schema_version,
  authoritative_subject_type,authoritative_subject_id,
  authoritative_subject_version,occurred_at,producer_reference,correlation_id,
  causation_id,idempotency_key,visibility,sanitized_metadata
) ON public.avuhz_lifecycle_events TO avuhz_acquisition_service_dev;

-- The outbox repository derives tenant_id from the just-inserted event.
GRANT SELECT (tenant_id,lifecycle_event_id)
  ON public.avuhz_lifecycle_events TO avuhz_acquisition_service_dev;

GRANT INSERT (
  tenant_id,lifecycle_event_id,destination_reference,status,
  delivery_idempotency_key
) ON public.avuhz_outbox_deliveries TO avuhz_acquisition_service_dev;

CREATE POLICY avuhz_acquisition_event_read
  ON public.avuhz_lifecycle_events FOR SELECT
  TO avuhz_acquisition_service_dev
  USING (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id',true),'')::uuid
    AND event_type='acquisition.intake.received'
    AND authoritative_subject_type='ACQUISITION_INTAKE'
  );

CREATE POLICY avuhz_acquisition_event_insert
  ON public.avuhz_lifecycle_events FOR INSERT
  TO avuhz_acquisition_service_dev
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id',true),'')::uuid
    AND event_type='acquisition.intake.received'
    AND authoritative_subject_type='ACQUISITION_INTAKE'
    AND authoritative_subject_id IS NOT NULL
    AND authoritative_subject_version=1
    AND event_schema_version=1
    AND engagement_id IS NULL
    AND causation_id IS NULL
    AND visibility='INTEGRATION_INTERNAL'
    AND idempotency_key='acquisition-intake:'||authoritative_subject_id::text
    AND sanitized_metadata=jsonb_build_object(
      'intake_id',authoritative_subject_id,
      'intake_state','RECEIVED'
    )
    AND EXISTS (
      SELECT 1 FROM public.avuhz_acquisition_intake_requests intake
      WHERE intake.tenant_id=avuhz_lifecycle_events.tenant_id
        AND intake.intake_id=avuhz_lifecycle_events.authoritative_subject_id
        AND intake.intake_state='RECEIVED'
    )
  );

CREATE POLICY avuhz_acquisition_outbox_insert
  ON public.avuhz_outbox_deliveries FOR INSERT
  TO avuhz_acquisition_service_dev
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id',true),'')::uuid
    AND status='PENDING'
    AND destination_reference='internal.lifecycle-events'
    AND delivery_idempotency_key='outbox-delivery:'||lifecycle_event_id::text
    AND EXISTS (
      SELECT 1 FROM public.avuhz_lifecycle_events event
      WHERE event.tenant_id=avuhz_outbox_deliveries.tenant_id
        AND event.lifecycle_event_id=avuhz_outbox_deliveries.lifecycle_event_id
        AND event.event_type='acquisition.intake.received'
    )
  );

RESET ROLE;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $acq_outbox_postcondition$
DECLARE
  owner_oid oid;
BEGIN
  SELECT oid INTO STRICT owner_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev';
  IF session_user<>'postgres' OR current_user<>'postgres'
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR EXISTS (SELECT 1 FROM pg_auth_members m
        WHERE m.roleid=owner_oid
          AND m.member=(SELECT oid FROM pg_roles WHERE rolname='postgres')
          AND m.grantor=m.member)
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_OWNER_NOT_RESEALED_STOP';
  END IF;

  IF (SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public'
      AND p.tablename IN ('avuhz_lifecycle_events','avuhz_outbox_deliveries')
      AND p.policyname IN (
        'avuhz_acquisition_event_read',
        'avuhz_acquisition_event_insert',
        'avuhz_acquisition_outbox_insert')
      AND p.roles=ARRAY['avuhz_acquisition_service_dev']::name[])<>3
    OR has_table_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_lifecycle_events','UPDATE')
    OR has_table_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_outbox_deliveries','SELECT')
    OR has_table_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_outbox_deliveries','UPDATE')
    OR has_table_privilege('avuhz_acquisition_service_dev',
          'public.avuhz_outbox_deliveries','DELETE')
    OR NOT EXISTS (SELECT 1 FROM pg_class c
      WHERE c.oid='public.avuhz_lifecycle_events'::regclass
        AND c.relowner=owner_oid AND c.relrowsecurity
        AND NOT c.relforcerowsecurity)
    OR NOT EXISTS (SELECT 1 FROM pg_class c
      WHERE c.oid='public.avuhz_outbox_deliveries'::regclass
        AND c.relowner=owner_oid AND c.relrowsecurity
        AND NOT c.relforcerowsecurity)
  THEN
    RAISE EXCEPTION 'ACQ_EVENT_OUTBOX_POLICY_OR_GRANT_POSTCONDITION_STOP';
  END IF;
END
$acq_outbox_postcondition$;

COMMIT;
