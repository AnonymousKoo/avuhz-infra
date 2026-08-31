-- Local additive Phase 5D-D2 QAResult persistence only.
-- Remote application is not authorized. QA results grant no client acceptance or deployment authority.

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
      'ReleaseCodexBuildPackage','StartBuildExecution','CompleteBuildExecution','RecordQAResult'
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
    'StartBuildExecution','CompleteBuildExecution','RecordQAResult'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
    'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
    'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
    'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
    'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
    'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE',
    'BUILD_EXECUTION_RESULT','QA_RESULT'
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
    'codex_build_package.released','build_execution.started','build_execution.completed',
    'qa_result.recorded'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
      'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
      'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
      'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
      'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE',
      'BUILD_EXECUTION_RESULT','QA_RESULT'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_qa_results (
  tenant_id uuid not null,
  qa_result_id uuid not null,
  qa_attempt integer not null check (qa_attempt > 0),
  engagement_id uuid not null,
  build_execution_result_id uuid not null,
  build_record_version integer not null check (build_record_version > 0),
  build_execution_digest text not null check (build_execution_digest ~ '^sha256:[0-9a-f]{64}$'),
  codex_build_package_id uuid not null,
  package_version integer not null check (package_version > 0),
  package_digest text not null check (package_digest ~ '^sha256:[0-9a-f]{64}$'),
  supersedes_qa_result_id uuid,
  supersedes_record_version integer check (supersedes_record_version > 0),
  overall_status text not null check (overall_status in ('PASSED','FAILED','BLOCKED')),
  qa_digest text not null check (qa_digest ~ '^sha256:[0-9a-f]{64}$'),
  record_version integer not null check (record_version = 1),
  record jsonb not null check (jsonb_typeof(record)='object'),
  recorded_at timestamptz not null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,qa_result_id),
  unique (tenant_id,codex_build_package_id,package_version,qa_attempt),
  foreign key (tenant_id,engagement_id)
    references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,build_execution_result_id)
    references public.avuhz_build_execution_results (tenant_id,build_execution_result_id),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages
      (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,supersedes_qa_result_id)
    references public.avuhz_qa_results (tenant_id,qa_result_id),
  check ((qa_attempt=1 and supersedes_qa_result_id is null
      and supersedes_record_version is null)
    or (qa_attempt>1 and supersedes_qa_result_id is not null
      and supersedes_record_version is not null)),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'engagement_id'=engagement_id::text
    and record->>'qa_result_id'=qa_result_id::text
    and (record->>'qa_attempt')::integer=qa_attempt
    and record->'build_execution_reference'->>'reference_type'='BUILD_EXECUTION_RESULT'
    and record->'build_execution_reference'->>'reference_id'=build_execution_result_id::text
    and (record->'build_execution_reference'->>'reference_version')::integer=build_record_version
    and record->>'build_execution_digest'=build_execution_digest
    and record->'codex_build_package_reference'->>'reference_type'='CODEX_BUILD_PACKAGE'
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest
    and jsonb_array_length(record->'criterion_results') > 0
    and record->>'overall_status'=overall_status
    and record->>'qa_digest'=qa_digest
    and (record->>'record_version')::integer=record_version)
);

create index avuhz_qa_package_history
  on public.avuhz_qa_results
  (tenant_id,codex_build_package_id,package_version,qa_attempt);
create index avuhz_qa_build_history
  on public.avuhz_qa_results
  (tenant_id,build_execution_result_id,recorded_at);
create index avuhz_qa_engagement_history
  on public.avuhz_qa_results
  (tenant_id,engagement_id,recorded_at);

create function public.avuhz_guard_qa_result_immutable() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
  raise exception 'QAResult history is immutable';
end $$;

create trigger avuhz_guard_qa_result_immutable
before update on public.avuhz_qa_results
for each row execute function public.avuhz_guard_qa_result_immutable();

alter table public.avuhz_qa_results enable row level security;
revoke all on table public.avuhz_qa_results from anon,authenticated,public;
grant select,insert on table public.avuhz_qa_results to avuhz_command_service;

create policy avuhz_command_service_tenant_isolation
  on public.avuhz_qa_results for all to avuhz_command_service
  using (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
  with check (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
