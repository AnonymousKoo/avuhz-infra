-- DEVELOPMENT DATA: exact-source, one-shot owner-bound acquisition event vocabulary.
-- REVIEW-ONLY. NOT APPROVED FOR REMOTE EXECUTION. No migration, role or
-- credential operation is authorized merely by merging this artifact.
-- Target project: DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
-- NEVER: DEVELOPMENT AUTH pwlhruwutoitnieactol, staging or production.
-- Source: AnonymousKoo/avuhz-infra @ 2ed7c6c3b35536409a9bfeb50594a6588ac04cd5
-- Canonical migration: supabase/migrations/20261012140000_enable_shared_acquisition_intake_received_event.sql
-- Source git blob: a8510c3bfcc74713cc26aea8e13e9de44acbae10
-- Source SHA-256: 0c4fbc10952666afe72d57e2a0d29ac486b603fe4a4bbcf7be07694310d758ff
-- Before any fresh, separately authorized attempt verify provider namespace,
-- sealed membership, exact digest, source revision, and expected SQL preflight.
-- Do not submit the original migration separately. No retry on failure.
BEGIN;

DO $avuhz_intake_owner_preflight$
DECLARE
  postgres_oid oid;
  migration_oid oid;
  command_oid oid;
  provider_edge_count integer;
  owner_set_edge_count integer;
  command_edge_count integer;
  total_edge_count integer;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_SESSION_MISMATCH_STOP';
  END IF;
  SELECT oid INTO STRICT postgres_oid FROM pg_roles
    WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole;
  SELECT oid INTO STRICT migration_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolcreatedb
      AND NOT rolreplication AND NOT rolbypassrls;
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolcreatedb
      AND NOT rolreplication AND NOT rolbypassrls;

  SELECT count(*) INTO provider_edge_count FROM pg_auth_members m
    JOIN pg_roles g ON g.oid=m.grantor
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND g.rolsuper AND g.oid<>postgres_oid;
  SELECT count(*) INTO owner_set_edge_count FROM pg_auth_members m
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.grantor=postgres_oid;
  SELECT count(*) INTO command_edge_count FROM pg_auth_members m
    JOIN pg_roles g ON g.oid=m.grantor
    WHERE m.roleid=command_oid AND m.member=migration_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND g.rolsuper AND g.oid<>migration_oid;
  SELECT count(*) INTO total_edge_count FROM pg_auth_members m
    WHERE m.roleid=migration_oid OR m.member=migration_oid;

  IF provider_edge_count<>1 OR owner_set_edge_count<>0
     OR command_edge_count<>1 OR total_edge_count<>2
     OR NOT pg_has_role('postgres','avuhz_data_migration_service_dev','MEMBER')
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_SEALED_MEMBERSHIP_DRIFT_STOP';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    WHERE c.oid='public.avuhz_lifecycle_events'::regclass
      AND c.relkind='r' AND c.relowner=migration_oid
      AND c.relrowsecurity AND NOT c.relforcerowsecurity
  ) OR (
    SELECT count(*) FROM pg_policies
    WHERE schemaname='public' AND tablename='avuhz_lifecycle_events'
      AND policyname='avuhz_command_service_tenant_isolation'
      AND roles @> ARRAY['avuhz_command_service']::name[]
      AND qual LIKE '%avuhz.tenant_id%'
      AND with_check LIKE '%avuhz.tenant_id%'
  )<>1 THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP';
  END IF;
  IF (
    SELECT count(*) FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname IN (
        'avuhz_lifecycle_events_event_type_check',
        'avuhz_lifecycle_events_authoritative_subject_type_check'
      )
  )<>2 OR EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND (pg_get_constraintdef(oid) LIKE '%acquisition.intake.received%'
           OR pg_get_constraintdef(oid) LIKE '%ACQUISITION_INTAKE%')
  ) THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP';
  END IF;
END
$avuhz_intake_owner_preflight$;

GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;

DO $avuhz_intake_owner_temporary_edge$
DECLARE
  migration_oid oid;
  postgres_oid oid;
BEGIN
  SELECT oid INTO STRICT migration_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev';
  SELECT oid INTO STRICT postgres_oid FROM pg_roles WHERE rolname='postgres';
  IF (SELECT count(*) FROM pg_auth_members m
      WHERE m.roleid=migration_oid AND m.member=postgres_oid
        AND m.grantor=postgres_oid
        AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1
     OR NOT pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_TEMPORARY_SET_EDGE_STOP';
  END IF;
END
$avuhz_intake_owner_temporary_edge$;

SET LOCAL ROLE avuhz_data_migration_service_dev;

-- CANONICAL_INTAKE_EVENT_SQL_BODY_BEGIN (exact original source, minus BEGIN/COMMIT)
DO $avuhz_acquisition_intake_event_preflight$
BEGIN
  IF to_regclass('public.avuhz_lifecycle_events') IS NULL THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_TABLE_ABSENT_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class
    WHERE oid='public.avuhz_lifecycle_events'::regclass
      AND relrowsecurity
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname='public'
      AND tablename='avuhz_lifecycle_events'
      AND policyname='avuhz_command_service_tenant_isolation'
      AND roles @> ARRAY['avuhz_command_service']::name[]
      AND qual LIKE '%avuhz.tenant_id%'
      AND with_check LIKE '%avuhz.tenant_id%'
  ) THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_RLS_NOT_SCOPED_STOP';
  END IF;
  IF (
    SELECT count(*) FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND contype='c'
      AND conname IN (
        'avuhz_lifecycle_events_event_type_check',
        'avuhz_lifecycle_events_authoritative_subject_type_check'
      )
  ) <> 2 THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_CONSTRAINTS_UNEXPECTED_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_event_type_check'
      AND pg_get_constraintdef(oid) LIKE '%implementation_handoff.accepted%'
      AND pg_get_constraintdef(oid) NOT LIKE '%acquisition.intake.received%'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
      AND pg_get_constraintdef(oid) LIKE '%IMPLEMENTATION_HANDOFF%'
      AND pg_get_constraintdef(oid) NOT LIKE '%ACQUISITION_INTAKE%'
  ) THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_VOCABULARY_DRIFT_STOP';
  END IF;
END
$avuhz_acquisition_intake_event_preflight$;

ALTER TABLE public.avuhz_lifecycle_events
  DROP CONSTRAINT avuhz_lifecycle_events_event_type_check;
ALTER TABLE public.avuhz_lifecycle_events
  ADD CONSTRAINT avuhz_lifecycle_events_event_type_check
  CHECK (event_type IN (
    'acquisition.intake.received','engagement.handoff.accepted','implementation_handoff.accepted',
    'implementation_handoff.revoked','engagement.opened','implementation_brief.drafted',
    'implementation_brief.revised','implementation_brief.approval_recorded','implementation_brief.approved',
    'implementation_authorization.proposed','implementation_authorization.revised','implementation_authorization.approval_recorded',
    'implementation_authorization.activated','implementation_authorization.revoked','codex_build_package.drafted',
    'codex_build_package.revised','codex_build_package.approval_recorded','codex_build_package.released',
    'build_execution.started','build_execution.completed','qa_result.recorded',
    'client_acceptance.recorded','deployment_authorization.proposed','deployment_authorization.revised',
    'deployment_authorization.approval_recorded','deployment_authorization.activated','deployment_authorization.revoked',
    'deployment_execution.started','deployment_execution.completed','deployment_verification.recorded'
  ));

ALTER TABLE public.avuhz_lifecycle_events
  DROP CONSTRAINT avuhz_lifecycle_events_authoritative_subject_type_check;
ALTER TABLE public.avuhz_lifecycle_events
  ADD CONSTRAINT avuhz_lifecycle_events_authoritative_subject_type_check
  CHECK (authoritative_subject_type IN (
    'ACQUISITION_INTAKE','ACQUISITION_HANDOFF','IMPLEMENTATION_HANDOFF',
    'ENGAGEMENT','IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION',
    'CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT','QA_RESULT',
    'CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION','DEPLOYMENT_EXECUTION',
    'DEPLOYMENT_VERIFICATION'
  ));
-- CANONICAL_INTAKE_EVENT_SQL_BODY_END

RESET ROLE;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $avuhz_intake_owner_postcondition$
DECLARE
  postgres_oid oid;
  migration_oid oid;
  command_oid oid;
  provider_edge_count integer;
  owner_set_edge_count integer;
  command_edge_count integer;
  total_edge_count integer;
BEGIN
  IF session_user <> 'postgres' OR current_user <> 'postgres' THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_POST_SESSION_MISMATCH_STOP';
  END IF;
  SELECT oid INTO STRICT postgres_oid FROM pg_roles WHERE rolname='postgres';
  SELECT oid INTO STRICT migration_oid FROM pg_roles
    WHERE rolname='avuhz_data_migration_service_dev';
  SELECT oid INTO STRICT command_oid FROM pg_roles
    WHERE rolname='avuhz_command_service';

  SELECT count(*) INTO provider_edge_count FROM pg_auth_members m
    JOIN pg_roles g ON g.oid=m.grantor
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND g.rolsuper AND g.oid<>postgres_oid;
  SELECT count(*) INTO owner_set_edge_count FROM pg_auth_members m
    WHERE m.roleid=migration_oid AND m.member=postgres_oid
      AND m.grantor=postgres_oid;
  SELECT count(*) INTO command_edge_count FROM pg_auth_members m
    JOIN pg_roles g ON g.oid=m.grantor
    WHERE m.roleid=command_oid AND m.member=migration_oid
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
      AND g.rolsuper AND g.oid<>migration_oid;
  SELECT count(*) INTO total_edge_count FROM pg_auth_members m
    WHERE m.roleid=migration_oid OR m.member=migration_oid;
  IF provider_edge_count<>1 OR owner_set_edge_count<>0
     OR command_edge_count<>1 OR total_edge_count<>2
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
     OR pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_MEMBERSHIP_NOT_RESEALED_STOP';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    WHERE c.oid='public.avuhz_lifecycle_events'::regclass
      AND c.relowner=migration_oid AND c.relrowsecurity
      AND NOT c.relforcerowsecurity
  ) OR (
    SELECT count(*) FROM pg_policies
    WHERE schemaname='public' AND tablename='avuhz_lifecycle_events'
      AND policyname='avuhz_command_service_tenant_isolation'
      AND roles @> ARRAY['avuhz_command_service']::name[]
      AND qual LIKE '%avuhz.tenant_id%'
      AND with_check LIKE '%avuhz.tenant_id%'
  )<>1 THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_RLS_CHANGED_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_event_type_check'
      AND pg_get_constraintdef(oid) LIKE '%acquisition.intake.received%'
      AND pg_get_constraintdef(oid) LIKE '%implementation_handoff.accepted%'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
      AND pg_get_constraintdef(oid) LIKE '%ACQUISITION_INTAKE%'
      AND pg_get_constraintdef(oid) LIKE '%IMPLEMENTATION_HANDOFF%'
  ) THEN
    RAISE EXCEPTION 'AVUHZ_INTAKE_OWNER_VOCABULARY_POSTCONDITION_STOP';
  END IF;
END
$avuhz_intake_owner_postcondition$;

COMMIT;
