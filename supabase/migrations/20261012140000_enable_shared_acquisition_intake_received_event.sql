-- Forward-only candidate to make the existing lifecycle event table represent
-- one unqualified acquisition-intake RECEIVED notification.
-- Remote application is unauthorized by default; requires separate exact
-- owner approval for DEVELOPMENT DATA, never DEVELOPMENT AUTH or production.
-- One existing table, one atomic transaction. No credential, DML, role grant,
-- RLS-policy change, or real customer event creation. Never rewrite migrations.
BEGIN;

DO $avuhz_acquisition_intake_event_preflight$
BEGIN
  IF to_regclass('public.avuhz_lifecycle_events') IS NULL THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_TABLE_ABSENT_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class
    WHERE oid='public.avuhz_lifecycle_events'::regclass
      AND relrowsecurity AND relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_EVENT_RLS_NOT_FORCED_STOP';
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

COMMIT;
