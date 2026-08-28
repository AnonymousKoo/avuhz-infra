-- Local additive Phase 5D-B3 CodexBuildPackage persistence only.
-- Remote application is not authorized. Packages grant no deployment or production authority.

alter table public.avuhz_human_approvals
  drop constraint avuhz_human_approvals_subject_type_check,
  drop constraint avuhz_human_approvals_approval_category_check,
  drop constraint avuhz_human_approvals_subject_binding_check;

alter table public.avuhz_human_approvals
  add constraint avuhz_human_approvals_subject_type_check check (
    subject_type is null or subject_type in (
      'DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL','OIA_CONVERSION_DECISION',
      'ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT','IMPLEMENTATION_BRIEF',
      'IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE'
    )
  ),
  add constraint avuhz_human_approvals_approval_category_check check (
    approval_category is null or approval_category in (
      'ASSESSMENT_ACCESS','CONVERSION','ONGOING_AGREEMENT','ONGOING_ACCESS',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE'
    )
  ),
  add constraint avuhz_human_approvals_subject_binding_check check (
    subject_type is null
    or (
      subject_type='DIAGNOSTIC_SCOPE' and subject_id=diagnostic_scope_id
      and diagnostic_scope_id is not null and approved_scope_version is not null
      and canonical_scope_digest is not null and action_set_version is not null
      and assessment_access_proposal_id is null and assessment_access_authority_digest is null
      and subject_version is null and phase5c_authority_digest is null
      and phase5d_authority_digest is null and approval_category is null
    )
    or (
      subject_type='ASSESSMENT_ACCESS_PROPOSAL' and subject_id=assessment_access_proposal_id
      and assessment_access_proposal_id is not null and assessment_access_authority_digest is not null
      and approval_category='ASSESSMENT_ACCESS' and diagnostic_scope_id is null
      and approved_scope_version is null and canonical_scope_digest is null
      and action_set_version is null and subject_version is null
      and phase5c_authority_digest is null and phase5d_authority_digest is null
      and actor_identity is not null and actor_organization is not null and actor_role=approval_role
    )
    or (
      subject_type in ('OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT')
      and subject_id is not null and subject_version is not null and phase5c_authority_digest is not null
      and phase5d_authority_digest is null
      and approval_category = case subject_type
        when 'OIA_CONVERSION_DECISION' then 'CONVERSION'
        when 'ONGOING_AGREEMENT_AUTHORITY' then 'ONGOING_AGREEMENT'
        when 'ONGOING_ACCESS_GRANT' then 'ONGOING_ACCESS'
      end
      and diagnostic_scope_id is null and approved_scope_version is null
      and canonical_scope_digest is null and action_set_version is null
      and assessment_access_proposal_id is null and assessment_access_authority_digest is null
      and actor_identity is not null and actor_organization is not null and actor_role=approval_role
    )
    or (
      subject_type in ('IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE')
      and subject_id is not null and subject_version is not null
      and phase5d_authority_digest is not null and phase5c_authority_digest is null
      and approval_category=subject_type
      and diagnostic_scope_id is null and approved_scope_version is null
      and canonical_scope_digest is null and action_set_version is null
      and assessment_access_proposal_id is null and assessment_access_authority_digest is null
      and actor_identity is not null and actor_organization is not null and actor_role=approval_role
      and actor_role in ('CLIENT_IMPLEMENTATION_AUTHORITY','SEKINFRA_IMPLEMENTATION_AUTHORITY')
    )
  );

create unique index avuhz_human_approvals_active_phase5d_package_role_key
  on public.avuhz_human_approvals
  (tenant_id,subject_type,subject_id,subject_version,phase5d_authority_digest,approval_role)
  where subject_type='CODEX_BUILD_PACKAGE' and status='ACTIVE';

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
      'ReleaseCodexBuildPackage'
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
    'RecordCodexBuildPackageApproval','ReleaseCodexBuildPackage'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
    'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
    'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
    'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
    'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
    'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE'
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
    'codex_build_package.released'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
      'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
      'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
      'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
      'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_codex_build_packages (
  tenant_id uuid not null,
  codex_build_package_id uuid not null,
  package_version integer not null check (package_version > 0),
  engagement_id uuid not null,
  implementation_brief_id uuid not null,
  implementation_brief_version integer not null check (implementation_brief_version > 0),
  implementation_brief_digest text not null check (implementation_brief_digest ~ '^sha256:[0-9a-f]{64}$'),
  implementation_authorization_id uuid not null,
  authorization_version integer not null check (authorization_version > 0),
  implementation_authority_digest text not null check (implementation_authority_digest ~ '^sha256:[0-9a-f]{64}$'),
  package_digest text not null check (package_digest ~ '^sha256:[0-9a-f]{64}$'),
  state text not null check (state in ('DRAFT','RELEASED','SUPERSEDED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,engagement_id)
    references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_brief_id,implementation_brief_version)
    references public.avuhz_implementation_briefs
      (tenant_id,implementation_brief_id,implementation_brief_version),
  foreign key (tenant_id,implementation_authorization_id,authorization_version)
    references public.avuhz_implementation_authorizations
      (tenant_id,implementation_authorization_id,authorization_version),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'engagement_id'=engagement_id::text
    and record->>'codex_build_package_id'=codex_build_package_id::text
    and (record->>'package_version')::integer=package_version
    and record->>'state'=state and (record->>'record_version')::integer=record_version
    and record->'implementation_brief_reference'->>'reference_id'=implementation_brief_id::text
    and (record->'implementation_brief_reference'->>'reference_version')::integer=implementation_brief_version
    and record->>'implementation_brief_digest'=implementation_brief_digest
    and record->'implementation_authorization_reference'->>'reference_id'=implementation_authorization_id::text
    and (record->'implementation_authorization_reference'->>'reference_version')::integer=authorization_version
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->>'package_digest'=package_digest),
  check ((package_version=1 and not record ? 'supersedes_codex_build_package_reference')
    or (package_version>1 and record ? 'supersedes_codex_build_package_reference'))
);

create unique index avuhz_codex_build_package_one_current
  on public.avuhz_codex_build_packages (tenant_id,codex_build_package_id)
  where state<>'SUPERSEDED';
create index avuhz_codex_build_package_engagement_history
  on public.avuhz_codex_build_packages
  (tenant_id,engagement_id,codex_build_package_id,package_version desc);

create function public.avuhz_guard_codex_build_package_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
  if new.record_version <> old.record_version + 1 then
    raise exception 'CodexBuildPackage record version must advance exactly once';
  end if;
  if not ((old.state='DRAFT' and new.state='RELEASED')
    or (old.state='RELEASED' and new.state='SUPERSEDED')) then
    raise exception 'invalid CodexBuildPackage state transition';
  end if;
  if (old.record - array['state','client_approval_reference','sekinfra_approval_reference',
      'released_at','record_version','updated_at'])
     <> (new.record - array['state','client_approval_reference','sekinfra_approval_reference',
      'released_at','record_version','updated_at']) then
    raise exception 'CodexBuildPackage immutable body cannot be rewritten';
  end if;
  return new;
end $$;

create trigger avuhz_guard_codex_build_package_transition
before update on public.avuhz_codex_build_packages
for each row execute function public.avuhz_guard_codex_build_package_transition();

alter table public.avuhz_codex_build_packages enable row level security;
revoke all on table public.avuhz_codex_build_packages from anon,authenticated,public;
grant select,insert on table public.avuhz_codex_build_packages to avuhz_command_service;
grant update (state,record_version,record,updated_at)
  on public.avuhz_codex_build_packages to avuhz_command_service;

create policy avuhz_command_service_tenant_isolation
  on public.avuhz_codex_build_packages for all to avuhz_command_service
  using (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
  with check (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
