-- Forward-only shared Work Item transition idempotency vocabulary.
-- Remote application is unauthorized by default; source only, NOT an approved
-- hosted migration on DEVELOPMENT DATA, AUTH, staging or production.
-- Reuse the existing avuhz_idempotency_records ledger; no new dedupe store,
-- command route, auth grant, billing/automation path, or client data insertion.
-- Table owner applies only after independently approved exact DATA preflight.
BEGIN;

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

COMMIT;
