-- Local additive Phase 5D-B2 ImplementationAuthorization persistence only.
-- Remote application is not authorized. Deployment and production authority remain unavailable.

alter table public.avuhz_human_approvals
  drop constraint avuhz_human_approvals_subject_type_check,
  drop constraint avuhz_human_approvals_approval_category_check,
  drop constraint avuhz_human_approvals_subject_binding_check;

alter table public.avuhz_human_approvals
  add constraint avuhz_human_approvals_subject_type_check check (
    subject_type is null or subject_type in (
      'DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL','OIA_CONVERSION_DECISION',
      'ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT','IMPLEMENTATION_BRIEF',
      'IMPLEMENTATION_AUTHORIZATION'
    )
  ),
  add constraint avuhz_human_approvals_approval_category_check check (
    approval_category is null or approval_category in (
      'ASSESSMENT_ACCESS','CONVERSION','ONGOING_AGREEMENT','ONGOING_ACCESS',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION'
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
      subject_type in ('IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION')
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

create unique index avuhz_human_approvals_active_phase5d_authorization_role_key
  on public.avuhz_human_approvals
  (tenant_id,subject_type,subject_id,subject_version,phase5d_authority_digest,approval_role)
  where subject_type='IMPLEMENTATION_AUTHORIZATION' and status='ACTIVE';

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
      'ActivateImplementationAuthorization','RevokeImplementationAuthorization'
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
    'RevokeImplementationAuthorization'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
    'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
    'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
    'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
    'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
    'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION'
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
    'implementation_authorization.revoked'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY','DIAGNOSTIC_PAYMENT_VERIFICATION',
      'OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN','OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM',
      'OIA_OBSERVATION','OIA_ROOT_CAUSE','OIA_FINDING','OIA_FINDINGS_DELIVERY',
      'OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION',
      'ONGOING_ACCESS_GRANT','ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING',
      'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_implementation_authorizations (
  tenant_id uuid not null,
  implementation_authorization_id uuid not null,
  authorization_version integer not null check (authorization_version > 0),
  engagement_id uuid not null,
  implementation_brief_id uuid not null,
  implementation_brief_version integer not null check (implementation_brief_version > 0),
  implementation_brief_digest text not null check (implementation_brief_digest ~ '^sha256:[0-9a-f]{64}$'),
  oia_conversion_decision_id uuid not null,
  decision_version integer not null check (decision_version > 0),
  ongoing_agreement_authority_id uuid not null,
  agreement_version integer not null check (agreement_version > 0),
  ongoing_payment_verification_id uuid not null,
  payment_record_version integer not null check (payment_record_version > 0),
  ongoing_access_grant_id uuid not null,
  access_record_version integer not null check (access_record_version > 0),
  authorized_scope_digest text not null check (authorized_scope_digest ~ '^sha256:[0-9a-f]{64}$'),
  implementation_authority_digest text not null check (implementation_authority_digest ~ '^sha256:[0-9a-f]{64}$'),
  effective_at timestamptz not null,
  expires_at timestamptz not null,
  state text not null check (state in ('PROPOSED','ACTIVE','EXPIRED','REVOKED','SUPERSEDED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,implementation_authorization_id,authorization_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_brief_id,implementation_brief_version)
    references public.avuhz_implementation_briefs
      (tenant_id,implementation_brief_id,implementation_brief_version),
  foreign key (tenant_id,oia_conversion_decision_id,decision_version)
    references public.avuhz_oia_conversion_decisions
      (tenant_id,oia_conversion_decision_id,decision_version),
  foreign key (tenant_id,ongoing_agreement_authority_id,agreement_version)
    references public.avuhz_ongoing_agreement_authorities
      (tenant_id,ongoing_agreement_authority_id,agreement_version),
  foreign key (tenant_id,ongoing_payment_verification_id)
    references public.avuhz_ongoing_payment_verifications
      (tenant_id,ongoing_payment_verification_id),
  foreign key (tenant_id,ongoing_access_grant_id)
    references public.avuhz_ongoing_access_grants (tenant_id,ongoing_access_grant_id),
  check (effective_at < expires_at),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'implementation_authorization_id'=implementation_authorization_id::text
    and (record->>'authorization_version')::integer=authorization_version
    and record->>'state'=state and (record->>'record_version')::integer=record_version
    and record->>'implementation_brief_digest'=implementation_brief_digest
    and record->>'authorized_scope_digest'=authorized_scope_digest
    and record->>'implementation_authority_digest'=implementation_authority_digest),
  check ((authorization_version=1 and not record ? 'supersedes_implementation_authorization_reference')
    or (authorization_version>1 and record ? 'supersedes_implementation_authorization_reference'))
);

create unique index avuhz_implementation_authorization_one_current
  on public.avuhz_implementation_authorizations (tenant_id,implementation_authorization_id)
  where state<>'SUPERSEDED';
create index avuhz_implementation_authorization_engagement_history
  on public.avuhz_implementation_authorizations
  (tenant_id,engagement_id,implementation_authorization_id,authorization_version desc);

create function public.avuhz_guard_implementation_authorization_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
  if new.record_version <> old.record_version + 1 then
    raise exception 'ImplementationAuthorization record version must advance exactly once';
  end if;
  if not ((old.state='PROPOSED' and new.state in ('ACTIVE','REVOKED'))
    or (old.state='ACTIVE' and new.state in ('EXPIRED','REVOKED','SUPERSEDED'))) then
    raise exception 'invalid ImplementationAuthorization state transition';
  end if;
  if (old.record - array['state','client_approval_reference','sekinfra_approval_reference',
      'activated_at','revoked_at','revocation_reason','record_version','updated_at'])
     <> (new.record - array['state','client_approval_reference','sekinfra_approval_reference',
      'activated_at','revoked_at','revocation_reason','record_version','updated_at']) then
    raise exception 'ImplementationAuthorization immutable body cannot be rewritten';
  end if;
  return new;
end $$;

create trigger avuhz_guard_implementation_authorization_transition
before update on public.avuhz_implementation_authorizations
for each row execute function public.avuhz_guard_implementation_authorization_transition();

alter table public.avuhz_implementation_authorizations enable row level security;
revoke all on table public.avuhz_implementation_authorizations from anon,authenticated,public;
grant select,insert on table public.avuhz_implementation_authorizations to avuhz_command_service;
grant update (state,record_version,record,updated_at)
  on public.avuhz_implementation_authorizations to avuhz_command_service;

create policy avuhz_command_service_tenant_isolation
  on public.avuhz_implementation_authorizations for all to avuhz_command_service
  using (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
  with check (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
