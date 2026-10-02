-- Activate the existing provider-neutral ImplementationHandoff as a governed command subject.
-- Remote application is unauthorized by default. Applying this migration to any provider requires
-- separate owner authorization and explicit confirmation of the target project/environment.
-- Repository-local migration only; this file performs no provider operation.

begin;

alter table public.avuhz_idempotency_records
  drop constraint if exists avuhz_idempotency_records_command_type_check;
alter table public.avuhz_idempotency_records
  add constraint avuhz_idempotency_records_command_type_check check (command_type in (
    'AcceptAcquisitionHandoff','AcceptImplementationHandoff','OpenEngagement',
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
    'ACQUISITION_HANDOFF','IMPLEMENTATION_HANDOFF','ENGAGEMENT','IMPLEMENTATION_BRIEF',
    'IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT',
    'QA_RESULT','CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION','DEPLOYMENT_EXECUTION',
    'DEPLOYMENT_VERIFICATION'
  ));

alter table public.avuhz_lifecycle_events
  drop constraint if exists avuhz_lifecycle_events_event_type_check;
alter table public.avuhz_lifecycle_events
  add constraint avuhz_lifecycle_events_event_type_check check (event_type in (
    'engagement.handoff.accepted','implementation_handoff.accepted',
    'implementation_handoff.revoked','engagement.opened','implementation_brief.drafted',
    'implementation_brief.revised','implementation_brief.approval_recorded',
    'implementation_brief.approved','implementation_authorization.proposed',
    'implementation_authorization.revised','implementation_authorization.approval_recorded',
    'implementation_authorization.activated','implementation_authorization.revoked',
    'codex_build_package.drafted','codex_build_package.revised',
    'codex_build_package.approval_recorded','codex_build_package.released',
    'build_execution.started','build_execution.completed','qa_result.recorded',
    'client_acceptance.recorded','deployment_authorization.proposed',
    'deployment_authorization.revised','deployment_authorization.approval_recorded',
    'deployment_authorization.activated','deployment_authorization.revoked',
    'deployment_execution.started','deployment_execution.completed',
    'deployment_verification.recorded'
  ));

alter table public.avuhz_lifecycle_events
  drop constraint if exists avuhz_lifecycle_events_authoritative_subject_type_check;
alter table public.avuhz_lifecycle_events
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check
  check (authoritative_subject_type in (
    'ACQUISITION_HANDOFF','IMPLEMENTATION_HANDOFF','ENGAGEMENT','IMPLEMENTATION_BRIEF',
    'IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT',
    'QA_RESULT','CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION','DEPLOYMENT_EXECUTION',
    'DEPLOYMENT_VERIFICATION'
  ));

commit;
