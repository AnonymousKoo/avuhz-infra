-- Local additive Phase 5D-D1 BuildExecutionResult persistence only.
-- Remote application is not authorized. Build results grant no QA, client acceptance, or deployment authority.

alter table public.avuhz_idempotency_records
  drop constraint avuhz_idempotency_records_tenant_principal_command_scope_key,
  drop constraint avuhz_idempotency_records_command_type_check,
  drop constraint avuhz_idempotency_records_subject_type_check,
  drop column idempotency_scope;

alter table public.avuhz_idempotency_records
  add column idempotency_scope text generated always as (
    case when command_type in (
      'CreateAssessmentAccessProposal','RecordAssessmentAccessApproval','IssueAssessmentAccessGrant',
      'VerifyAssessmentAccess','ExpireAssessmentAccess','RevokeAssessmentAccess',
      'CloseAssessmentAccessForAgreementEnd','RecordDiagnosticAgreementAuthority',
      'RecordDiagnosticPaymentVerification','InvalidateDiagnosticPaymentVerification',
      'OpenOIAAssessment','RecordOIAEvidence','CreateOIAAssessmentPlan','ReviseOIAAssessmentPlan',
      'ReviewOIAAssessmentPlan','ApproveOIAAssessmentPlan','CreateOIAInspectionItem',
      'UpdateOIAInspectionItem','MarkOIAInspectionItemBlocked','RecordOIAObservation',
      'SupersedeOIAObservation','RecordOIARootCause','CreateOIAFinding','UpdateOIAFindingAnalysis',
      'FinalizeOIAFinding','MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings',
      'ReviseDeliveredOIAFinding','CloseOIAAssessment','RecordOIAConversionDecision',
      'AcceptOIAConversion','ProposeOngoingAgreement','RecordOngoingAgreementApproval',
      'ActivateOngoingAgreement','TerminateOngoingAgreement','RecordOngoingPaymentVerification',
      'InvalidateOngoingPaymentVerification','ProposeOngoingAccessGrant','RecordOngoingAccessApproval',
      'ApproveOngoingAccessGrant','VerifyOngoingAccess','RevokeOngoingAccess','CloseOngoingAccess',
      'InitiateOngoingOffboarding','VerifyOngoingAccessRevocation','CompleteOngoingOffboarding',
      'DraftImplementationBrief','ReviseImplementationBrief','RecordImplementationBriefApproval',
      'ApproveImplementationBrief','ProposeImplementationAuthorization',
      'ReviseImplementationAuthorization','RecordImplementationAuthorizationApproval',
      'ActivateImplementationAuthorization','RevokeImplementationAuthorization',
      'DraftCodexBuildPackage','ReviseCodexBuildPackage','RecordCodexBuildPackageApproval',
      'ReleaseCodexBuildPackage',
      'StartBuildExecution','CompleteBuildExecution'
    ) then 'COMMAND' else 'SUBJECT:' || subject_id::text end
  ) stored,
  add constraint avuhz_idempotency_records_command_type_check check (command_type in (
    'AcceptAcquisitionHandoff','OpenEngagement','SubmitDiagnosticScope','RecordHumanApproval',
    'ApproveDiagnosticScope','CanonicalizeDiagnosticScope','CreateAssessmentAccessProposal',
    'RecordAssessmentAccessApproval','IssueAssessmentAccessGrant','VerifyAssessmentAccess',
    'ExpireAssessmentAccess','RevokeAssessmentAccess','CloseAssessmentAccessForAgreementEnd',
    'RecordDiagnosticAgreementAuthority','RecordDiagnosticPaymentVerification',
    'InvalidateDiagnosticPaymentVerification','OpenOIAAssessment','RecordOIAEvidence',
    'CreateOIAAssessmentPlan','ReviseOIAAssessmentPlan','ReviewOIAAssessmentPlan',
    'ApproveOIAAssessmentPlan','CreateOIAInspectionItem','UpdateOIAInspectionItem',
    'MarkOIAInspectionItemBlocked','RecordOIAObservation','SupersedeOIAObservation',
    'RecordOIARootCause','CreateOIAFinding','UpdateOIAFindingAnalysis','FinalizeOIAFinding',
    'MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings','ReviseDeliveredOIAFinding',
    'CloseOIAAssessment','RecordOIAConversionDecision','AcceptOIAConversion',
    'ProposeOngoingAgreement','RecordOngoingAgreementApproval','ActivateOngoingAgreement',
    'TerminateOngoingAgreement','RecordOngoingPaymentVerification',
    'InvalidateOngoingPaymentVerification','ProposeOngoingAccessGrant',
    'RecordOngoingAccessApproval','ApproveOngoingAccessGrant','VerifyOngoingAccess',
    'RevokeOngoingAccess','CloseOngoingAccess','InitiateOngoingOffboarding',
    'VerifyOngoingAccessRevocation','CompleteOngoingOffboarding','DraftImplementationBrief',
    'ReviseImplementationBrief','RecordImplementationBriefApproval','ApproveImplementationBrief',
    'ProposeImplementationAuthorization','ReviseImplementationAuthorization',
    'RecordImplementationAuthorizationApproval','ActivateImplementationAuthorization',
    'RevokeImplementationAuthorization','DraftCodexBuildPackage','ReviseCodexBuildPackage',
    'RecordCodexBuildPackageApproval','ReleaseCodexBuildPackage',
    'StartBuildExecution','CompleteBuildExecution'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
    'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
    'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
    'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
    'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
    'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT'
  )),
  add constraint avuhz_idempotency_records_tenant_principal_command_scope_key
    unique (tenant_id,trusted_principal_id,command_type,subject_type,idempotency_scope,idempotency_key);

alter table public.avuhz_lifecycle_events
  drop constraint avuhz_lifecycle_events_event_type_check,
  drop constraint avuhz_lifecycle_events_authoritative_subject_type_check;

alter table public.avuhz_lifecycle_events
  add constraint avuhz_lifecycle_events_event_type_check check (event_type in (
    'engagement.handoff.accepted','engagement.opened','diagnostic_scope.submitted',
    'diagnostic_scope.approved','diagnostic_scope.rejected','human_approval.recorded',
    'diagnostic_scope.canonicalized','assessment_access.proposal_created',
    'assessment_access.approval_recorded','assessment_access.grant_issued',
    'assessment_access.verified_and_activated','assessment_access.expired',
    'assessment_access.revoked','assessment_access.closed','diagnostic_agreement.authority_recorded',
    'diagnostic_payment.verified','diagnostic_payment.invalidated','oia.assessment_opened',
    'oia.evidence_recorded','oia.observation_recorded','oia.observation_superseded',
    'oia.root_cause_recorded','oia.finding_created','oia.finding_updated',
    'oia.finding_finalized','oia.assessment_ready_for_delivery','oia.findings_delivered',
    'oia.finding_revision_opened','oia.assessment_closed','oia.assessment_plan_created',
    'oia.assessment_plan_revised','oia.assessment_plan_reviewed','oia.assessment_plan_approved',
    'oia.inspection_item_created','oia.inspection_item_blocked','oia.inspection_item_progressed',
    'conversion.decision_recorded','conversion.accepted','ongoing_agreement.proposed',
    'ongoing_agreement.approval_recorded','ongoing_agreement.activated','ongoing_agreement.terminated',
    'ongoing_payment.verified','ongoing_payment.invalidated','ongoing_access.proposed',
    'ongoing_access.approval_recorded','ongoing_access.approved','ongoing_access.activated',
    'ongoing_access.revoked','ongoing_access.closed','offboarding.initiated',
    'ongoing_access.revocation_verified','offboarding.completed','implementation_brief.drafted',
    'implementation_brief.revised','implementation_brief.approval_recorded','implementation_brief.approved',
    'implementation_authorization.proposed','implementation_authorization.revised',
    'implementation_authorization.approval_recorded','implementation_authorization.activated',
    'implementation_authorization.revoked','codex_build_package.drafted',
    'codex_build_package.revised','codex_build_package.approval_recorded',
    'codex_build_package.released',
    'build_execution.started','build_execution.completed'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
      'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
      'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
      'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
      'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_build_execution_results (
  tenant_id uuid not null,
  build_execution_result_id uuid not null,
  execution_attempt integer not null check (execution_attempt > 0),
  engagement_id uuid not null,
  codex_build_package_id uuid not null,
  package_version integer not null check (package_version > 0),
  package_digest text not null check (package_digest ~ '^sha256:[0-9a-f]{64}$'),
  implementation_authorization_id uuid not null,
  authorization_version integer not null check (authorization_version > 0),
  implementation_authority_digest text not null check (implementation_authority_digest ~ '^sha256:[0-9a-f]{64}$'),
  supersedes_build_execution_result_id uuid,
  supersedes_record_version integer check (supersedes_record_version > 0),
  status text not null check (status in ('IN_PROGRESS','SUCCEEDED','FAILED')),
  execution_fingerprint text not null check (execution_fingerprint ~ '^fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}$'),
  execution_digest text check (execution_digest is null or execution_digest ~ '^sha256:[0-9a-f]{64}$'),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  started_at timestamptz not null,
  completed_at timestamptz,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,build_execution_result_id),
  unique (tenant_id,codex_build_package_id,package_version,execution_attempt),
  foreign key (tenant_id,engagement_id)
    references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages
      (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,implementation_authorization_id,authorization_version)
    references public.avuhz_implementation_authorizations
      (tenant_id,implementation_authorization_id,authorization_version),
  foreign key (tenant_id,supersedes_build_execution_result_id)
    references public.avuhz_build_execution_results
      (tenant_id,build_execution_result_id),
  check ((execution_attempt=1 and supersedes_build_execution_result_id is null
      and supersedes_record_version is null)
    or (execution_attempt>1 and supersedes_build_execution_result_id is not null
      and supersedes_record_version is not null)),
  check ((status='IN_PROGRESS' and execution_digest is null and completed_at is null)
    or (status in ('SUCCEEDED','FAILED') and execution_digest is not null
      and completed_at is not null)),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'engagement_id'=engagement_id::text
    and record->>'build_execution_result_id'=build_execution_result_id::text
    and (record->>'execution_attempt')::integer=execution_attempt
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest
    and record->'implementation_authorization_reference'->>'reference_id'=implementation_authorization_id::text
    and (record->'implementation_authorization_reference'->>'reference_version')::integer=authorization_version
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->>'status'=status
    and record->>'execution_fingerprint'=execution_fingerprint
    and (record->>'record_version')::integer=record_version
    and ((execution_digest is null and not record ? 'execution_digest')
      or record->>'execution_digest'=execution_digest))
);

create index avuhz_build_execution_package_history
  on public.avuhz_build_execution_results
  (tenant_id,codex_build_package_id,package_version,execution_attempt);
create index avuhz_build_execution_engagement_history
  on public.avuhz_build_execution_results
  (tenant_id,engagement_id,created_at);

create function public.avuhz_guard_build_execution_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
  if old.status<>'IN_PROGRESS' or new.status not in ('SUCCEEDED','FAILED') then
    raise exception 'invalid BuildExecutionResult state transition';
  end if;
  if new.record_version <> old.record_version + 1 then
    raise exception 'BuildExecutionResult record version must advance exactly once';
  end if;
  if (old.record - array['status','changed_targets','artifact_references',
      'test_result_references','failure_summary','execution_digest','completed_at',
      'record_version','updated_at'])
     <> (new.record - array['status','changed_targets','artifact_references',
      'test_result_references','failure_summary','execution_digest','completed_at',
      'record_version','updated_at']) then
    raise exception 'BuildExecutionResult immutable bindings cannot be rewritten';
  end if;
  return new;
end $$;

create trigger avuhz_guard_build_execution_transition
before update on public.avuhz_build_execution_results
for each row execute function public.avuhz_guard_build_execution_transition();

alter table public.avuhz_build_execution_results enable row level security;
revoke all on table public.avuhz_build_execution_results from anon,authenticated,public;
grant select,insert on table public.avuhz_build_execution_results to avuhz_command_service;
grant update (status,execution_digest,record_version,record,completed_at,updated_at)
  on public.avuhz_build_execution_results to avuhz_command_service;

create policy avuhz_command_service_tenant_isolation
  on public.avuhz_build_execution_results for all to avuhz_command_service
  using (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
  with check (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
