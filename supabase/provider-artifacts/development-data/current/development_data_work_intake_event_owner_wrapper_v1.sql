-- DEVELOPMENT DATA: REVIEW ONLY, source-bound System #001 lifecycle event owner wrapper.
-- NOT APPROVED FOR REMOTE EXECUTION. A merged PR grants no provider authority.
-- Target project: DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
-- NEVER: DEVELOPMENT AUTH pwlhruwutoitnieactol, staging, production.
-- Canonical source: AnonymousKoo/avuhz-infra main@04076c4003ce787f6ef1aa955b6c3ef977eab509
-- Source file: supabase/migrations/20261014031000_enable_shared_work_intake_lifecycle_events.sql
-- Canonical source SHA-256: a16f6dfda1b02146170f0feb3a49f139b403a32de7db70a163436730dca2da9e
-- Before any future separately approved, one-shot execution: verify original
-- source digest, exact DATA project, sealed membership, owner, table/RLS policy,
-- previous acquisition vocabulary, and postcondition sealing. No retry.
-- Do not submit the original migration separately.
-- Canonical PostgreSQL 17 rendered event CHECK constraints are SHA-256
-- pinned in preflight/postcondition; this matches live DEVELOPMENT DATA
-- read-only metadata and independently reproduced disposable PG17 output.
-- All existing policies are sealed by exact name, role, command, mode and
-- SHA-256 of their full USING/WITH CHECK expressions (not marker substrings).
-- The provider already contains two acquisition event policies; disposable
-- baseline fixtures may have only the original command-service policy.
-- Any additional or broadened policy, partial acquisition policy pair, or
-- changed CHECK value set stops before DDL. Review-only / no host authority.
BEGIN;

DO $avuhz_work_intake_owner_preflight$
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
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_SESSION_MISMATCH_STOP';
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
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_SEALED_MEMBERSHIP_DRIFT_STOP';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    WHERE c.oid='public.avuhz_lifecycle_events'::regclass
      AND c.relkind='r' AND c.relowner=migration_oid
      AND c.relrowsecurity AND NOT c.relforcerowsecurity
  ) OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
      AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
  )<>1 OR EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND (
        p.policyname NOT IN (
          'avuhz_command_service_tenant_isolation',
          'avuhz_acquisition_event_read','avuhz_acquisition_event_insert')
        OR (p.policyname='avuhz_acquisition_event_read' AND NOT (
          p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
          AND p.cmd='SELECT' AND p.permissive='PERMISSIVE'
          AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='3d5784ab3919fb8b3d72e585c614f437a38bcbef7520712113ef1a0aa78cc78a'
          AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
        ))
        OR (p.policyname='avuhz_acquisition_event_insert' AND NOT (
          p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
          AND p.cmd='INSERT' AND p.permissive='PERMISSIVE'
          AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
          AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='a9c17452f8bf556508980269ac37db8b44e2f3beeb3b17c7e680a1edc273aaf1'
        ))
      )
  ) OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND p.policyname IN (
        'avuhz_acquisition_event_read','avuhz_acquisition_event_insert')
  ) NOT IN (0,2) THEN
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP';
  END IF;
  IF (
    SELECT count(*) FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname IN (
        'avuhz_lifecycle_events_event_type_check',
        'avuhz_lifecycle_events_authoritative_subject_type_check'
      )
  )<>2 OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_event_type_check'
      AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='dfdcd70b20fc76199efb538625f981fc223a150343b5af49e2e6237939bc1916'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
      AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='f9fc11082330f0b1c585f853bc9ec4991a07e1e732aec013ba1d5b8418669738'
  ) THEN
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP';
  END IF;
END
$avuhz_work_intake_owner_preflight$;

GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE
  GRANTED BY CURRENT_USER;

DO $avuhz_work_intake_owner_temporary_edge$
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
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_TEMPORARY_SET_EDGE_STOP';
  END IF;
END
$avuhz_work_intake_owner_temporary_edge$;

SET LOCAL ROLE avuhz_data_migration_service_dev;

-- CANONICAL_WORK_INTAKE_EVENT_SQL_BODY_BEGIN (exact original source, minus BEGIN/COMMIT)
DO $avuhz_work_intake_event_preflight$
BEGIN
  IF to_regclass('public.avuhz_lifecycle_events') IS NULL THEN
    RAISE EXCEPTION 'WORK_INTAKE_EVENT_TABLE_ABSENT_STOP';
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
    RAISE EXCEPTION 'WORK_INTAKE_EVENT_RLS_NOT_SCOPED_STOP';
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
    RAISE EXCEPTION 'WORK_INTAKE_EVENT_CONSTRAINTS_UNEXPECTED_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_event_type_check'
      AND pg_get_constraintdef(oid) LIKE '%acquisition.intake.received%'
      AND pg_get_constraintdef(oid) NOT LIKE '%work_intake.opened%'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
      AND pg_get_constraintdef(oid) LIKE '%ACQUISITION_INTAKE%'
      AND pg_get_constraintdef(oid) NOT LIKE '%WORK_ITEM%'
  ) THEN
    RAISE EXCEPTION 'WORK_INTAKE_EVENT_VOCABULARY_DRIFT_STOP';
  END IF;
END
$avuhz_work_intake_event_preflight$;

ALTER TABLE public.avuhz_lifecycle_events
  DROP CONSTRAINT avuhz_lifecycle_events_event_type_check;
ALTER TABLE public.avuhz_lifecycle_events
  ADD CONSTRAINT avuhz_lifecycle_events_event_type_check
  CHECK (event_type IN (
    'acquisition.intake.received',
    'work_intake.opened','work_intake.handoff_offered','work_intake.handoff_accepted',
    'work_intake.handoff_cancelled','work_intake.blocked','work_intake.resumed',
    'work_intake.resolved','engagement.handoff.accepted','implementation_handoff.accepted',
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
    'WORK_ITEM','ACQUISITION_INTAKE','ACQUISITION_HANDOFF','IMPLEMENTATION_HANDOFF',
    'ENGAGEMENT','IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION',
    'CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT','QA_RESULT',
    'CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION','DEPLOYMENT_EXECUTION',
    'DEPLOYMENT_VERIFICATION'
  ));
-- CANONICAL_WORK_INTAKE_EVENT_SQL_BODY_END

RESET ROLE;
REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;

DO $avuhz_work_intake_owner_postcondition$
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
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_POST_SESSION_MISMATCH_STOP';
  END IF;
  SELECT oid INTO STRICT postgres_oid FROM pg_roles WHERE rolname='postgres';
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
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     OR pg_has_role('postgres','avuhz_data_migration_service_dev','USAGE')
     OR pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET')
  THEN
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_MEMBERSHIP_NOT_RESEALED_STOP';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_class c
    WHERE c.oid='public.avuhz_lifecycle_events'::regclass
      AND c.relkind='r' AND c.relowner=migration_oid AND c.relrowsecurity
      AND NOT c.relforcerowsecurity
  ) OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND p.policyname='avuhz_command_service_tenant_isolation'
      AND p.roles=ARRAY['avuhz_command_service']::name[]
      AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
      AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
      AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6'
  )<>1 OR EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND (
        p.policyname NOT IN (
          'avuhz_command_service_tenant_isolation',
          'avuhz_acquisition_event_read','avuhz_acquisition_event_insert')
        OR (p.policyname='avuhz_acquisition_event_read' AND NOT (
          p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
          AND p.cmd='SELECT' AND p.permissive='PERMISSIVE'
          AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='3d5784ab3919fb8b3d72e585c614f437a38bcbef7520712113ef1a0aa78cc78a'
          AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
        ))
        OR (p.policyname='avuhz_acquisition_event_insert' AND NOT (
          p.roles=ARRAY['avuhz_acquisition_service_dev']::name[]
          AND p.cmd='INSERT' AND p.permissive='PERMISSIVE'
          AND encode(sha256(convert_to(coalesce(p.qual,'<NULL>'),'UTF8')),'hex')='8ab60881072b62721284dd0081f2a14de0bbf755fa88c55ddd64a319bb23a734'
          AND encode(sha256(convert_to(coalesce(p.with_check,'<NULL>'),'UTF8')),'hex')='a9c17452f8bf556508980269ac37db8b44e2f3beeb3b17c7e680a1edc273aaf1'
        ))
      )
  ) OR (
    SELECT count(*) FROM pg_policies p
    WHERE p.schemaname='public' AND p.tablename='avuhz_lifecycle_events'
      AND p.policyname IN (
        'avuhz_acquisition_event_read','avuhz_acquisition_event_insert')
  ) NOT IN (0,2) THEN
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_RLS_CHANGED_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_event_type_check'
      AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='f3ea1451119d4ae7c7f1fd1e2bb74b53de53457d44912a227fc9d5f4a0dd956a'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.avuhz_lifecycle_events'::regclass
      AND conname='avuhz_lifecycle_events_authoritative_subject_type_check'
      AND encode(sha256(convert_to(pg_get_constraintdef(oid),'UTF8')),'hex')
          ='0dbc491813853561ec9c09f22046984b829245647d00482f9fe2601ffb65556e'
  ) THEN
    RAISE EXCEPTION 'AVUHZ_WORK_INTAKE_OWNER_VOCABULARY_POSTCONDITION_STOP';
  END IF;
END
$avuhz_work_intake_owner_postcondition$;

COMMIT;
