-- Local additive Phase 5C durable schema. Remote application is not authorized.

alter table public.avuhz_human_approvals
  drop constraint avuhz_human_approvals_subject_type_check,
  drop constraint avuhz_human_approvals_approval_category_check,
  drop constraint avuhz_human_approvals_subject_binding_check,
  add column subject_version integer check (subject_version is null or subject_version > 0),
  add column phase5c_authority_digest text check (
    phase5c_authority_digest is null or phase5c_authority_digest ~ '^sha256:[0-9a-f]{64}$'
  );

alter table public.avuhz_human_approvals
  add constraint avuhz_human_approvals_subject_type_check check (
    subject_type is null or subject_type in (
      'DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL','OIA_CONVERSION_DECISION',
      'ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT'
    )
  ),
  add constraint avuhz_human_approvals_approval_category_check check (
    approval_category is null or approval_category in (
      'ASSESSMENT_ACCESS','CONVERSION','ONGOING_AGREEMENT','ONGOING_ACCESS'
    )
  ),
  add constraint avuhz_human_approvals_subject_binding_check check (
    subject_type is null
    or (
      subject_type='DIAGNOSTIC_SCOPE' and subject_id=diagnostic_scope_id
      and diagnostic_scope_id is not null and approved_scope_version is not null
      and canonical_scope_digest is not null and action_set_version is not null
      and assessment_access_proposal_id is null and assessment_access_authority_digest is null
      and subject_version is null and phase5c_authority_digest is null and approval_category is null
    )
    or (
      subject_type='ASSESSMENT_ACCESS_PROPOSAL' and subject_id=assessment_access_proposal_id
      and assessment_access_proposal_id is not null and assessment_access_authority_digest is not null
      and approval_category='ASSESSMENT_ACCESS' and diagnostic_scope_id is null
      and approved_scope_version is null and canonical_scope_digest is null
      and action_set_version is null and subject_version is null
      and phase5c_authority_digest is null and actor_identity is not null
      and actor_organization is not null and actor_role=approval_role
    )
    or (
      subject_type in ('OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT')
      and subject_id is not null and subject_version is not null
      and phase5c_authority_digest is not null
      and approval_category = case subject_type
        when 'OIA_CONVERSION_DECISION' then 'CONVERSION'
        when 'ONGOING_AGREEMENT_AUTHORITY' then 'ONGOING_AGREEMENT'
        when 'ONGOING_ACCESS_GRANT' then 'ONGOING_ACCESS'
      end
      and diagnostic_scope_id is null and approved_scope_version is null
      and canonical_scope_digest is null and action_set_version is null
      and assessment_access_proposal_id is null and assessment_access_authority_digest is null
      and actor_identity is not null and actor_organization is not null
      and actor_role=approval_role
    )
  );

create unique index avuhz_human_approvals_active_phase5c_role_key
  on public.avuhz_human_approvals
  (tenant_id,subject_type,subject_id,subject_version,phase5c_authority_digest,approval_role)
  where subject_type in ('OIA_CONVERSION_DECISION','ONGOING_AGREEMENT_AUTHORITY','ONGOING_ACCESS_GRANT')
    and status='ACTIVE';

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
      'OpenOIAAssessment','RecordOIAEvidence','CreateOIAAssessmentPlan',
      'ReviseOIAAssessmentPlan','ReviewOIAAssessmentPlan','ApproveOIAAssessmentPlan',
      'CreateOIAInspectionItem','UpdateOIAInspectionItem','MarkOIAInspectionItemBlocked',
      'RecordOIAObservation','SupersedeOIAObservation','RecordOIARootCause',
      'CreateOIAFinding','UpdateOIAFindingAnalysis','FinalizeOIAFinding',
      'MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings','ReviseDeliveredOIAFinding',
      'CloseOIAAssessment','RecordOIAConversionDecision','AcceptOIAConversion',
      'ProposeOngoingAgreement','RecordOngoingAgreementApproval','ActivateOngoingAgreement',
      'TerminateOngoingAgreement','RecordOngoingPaymentVerification',
      'InvalidateOngoingPaymentVerification','ProposeOngoingAccessGrant',
      'RecordOngoingAccessApproval','ApproveOngoingAccessGrant','VerifyOngoingAccess',
      'RevokeOngoingAccess','CloseOngoingAccess','InitiateOngoingOffboarding',
      'VerifyOngoingAccessRevocation','CompleteOngoingOffboarding'
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
    'VerifyOngoingAccessRevocation','CompleteOngoingOffboarding'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY',
    'DIAGNOSTIC_PAYMENT_VERIFICATION','OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN',
    'OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM','OIA_OBSERVATION','OIA_ROOT_CAUSE',
    'OIA_FINDING','OIA_FINDINGS_DELIVERY','OIA_CONVERSION_DECISION',
    'ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION','ONGOING_ACCESS_GRANT',
    'ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING'
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
    'oia.root_cause_recorded','oia.finding_created','oia.finding_updated','oia.finding_finalized',
    'oia.assessment_ready_for_delivery','oia.findings_delivered','oia.finding_revision_opened',
    'oia.assessment_closed','oia.assessment_plan_created','oia.assessment_plan_revised',
    'oia.assessment_plan_reviewed','oia.assessment_plan_approved','oia.inspection_item_created',
    'oia.inspection_item_blocked','oia.inspection_item_progressed',
    'conversion.decision_recorded','conversion.accepted','ongoing_agreement.proposed',
    'ongoing_agreement.approval_recorded','ongoing_agreement.activated',
    'ongoing_agreement.terminated','ongoing_payment.verified','ongoing_payment.invalidated',
    'ongoing_access.proposed','ongoing_access.approval_recorded','ongoing_access.approved',
    'ongoing_access.activated','ongoing_access.revoked','ongoing_access.closed',
    'offboarding.initiated','ongoing_access.revocation_verified','offboarding.completed'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY',
      'DIAGNOSTIC_PAYMENT_VERIFICATION','OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN',
      'OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM','OIA_OBSERVATION','OIA_ROOT_CAUSE',
      'OIA_FINDING','OIA_FINDINGS_DELIVERY','OIA_CONVERSION_DECISION',
      'ONGOING_AGREEMENT_AUTHORITY','ONGOING_PAYMENT_VERIFICATION','ONGOING_ACCESS_GRANT',
      'ONGOING_ACCESS_REVOCATION_VERIFICATION','ONGOING_OFFBOARDING'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_oia_conversion_decisions (
  tenant_id uuid not null,
  oia_conversion_decision_id uuid not null,
  decision_version integer not null check (decision_version > 0),
  engagement_id uuid not null,
  oia_assessment_id uuid not null,
  oia_findings_delivery_id uuid not null,
  state text not null check (state in ('PENDING_SEKINFRA','ACCEPTED','DECLINED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,oia_conversion_decision_id,decision_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  foreign key (tenant_id,oia_findings_delivery_id) references public.avuhz_oia_findings_deliveries (tenant_id,oia_findings_delivery_id),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'oia_conversion_decision_id'=oia_conversion_decision_id::text
    and (record->>'decision_version')::integer=decision_version
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_ongoing_agreement_authorities (
  tenant_id uuid not null,
  ongoing_agreement_authority_id uuid not null,
  agreement_version integer not null check (agreement_version > 0),
  engagement_id uuid not null,
  oia_conversion_decision_id uuid not null,
  decision_version integer not null,
  state text not null check (state in ('DRAFT','ACTIVE','SUPERSEDED','ENDED','TERMINATED','REVOKED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null,
  updated_at timestamptz not null,
  primary key (tenant_id,ongoing_agreement_authority_id,agreement_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,oia_conversion_decision_id,decision_version)
    references public.avuhz_oia_conversion_decisions (tenant_id,oia_conversion_decision_id,decision_version),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'ongoing_agreement_authority_id'=ongoing_agreement_authority_id::text
    and (record->>'agreement_version')::integer=agreement_version
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);
create unique index avuhz_ongoing_agreement_one_active
  on public.avuhz_ongoing_agreement_authorities (tenant_id,engagement_id) where state='ACTIVE';

create table public.avuhz_ongoing_payment_verifications (
  tenant_id uuid not null,
  ongoing_payment_verification_id uuid not null,
  engagement_id uuid not null,
  ongoing_agreement_authority_id uuid not null,
  agreement_version integer not null,
  status text not null check (status in ('VERIFIED','INVALIDATED')),
  coverage_from timestamptz not null,
  coverage_until timestamptz not null check (coverage_from < coverage_until),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  verified_at timestamptz not null,
  primary key (tenant_id,ongoing_payment_verification_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,ongoing_agreement_authority_id,agreement_version)
    references public.avuhz_ongoing_agreement_authorities (tenant_id,ongoing_agreement_authority_id,agreement_version),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'ongoing_payment_verification_id'=ongoing_payment_verification_id::text
    and record->>'status'=status and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_ongoing_access_grants (
  tenant_id uuid not null,
  ongoing_access_grant_id uuid not null,
  engagement_id uuid not null,
  oia_conversion_decision_id uuid not null,
  decision_version integer not null,
  ongoing_agreement_authority_id uuid not null,
  agreement_version integer not null,
  ongoing_payment_verification_id uuid not null,
  state text not null check (state in ('PROPOSED','APPROVED','ACTIVE','EXPIRED','REVOKED','CLOSED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  proposed_at timestamptz not null,
  primary key (tenant_id,ongoing_access_grant_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,oia_conversion_decision_id,decision_version)
    references public.avuhz_oia_conversion_decisions (tenant_id,oia_conversion_decision_id,decision_version),
  foreign key (tenant_id,ongoing_agreement_authority_id,agreement_version)
    references public.avuhz_ongoing_agreement_authorities (tenant_id,ongoing_agreement_authority_id,agreement_version),
  foreign key (tenant_id,ongoing_payment_verification_id)
    references public.avuhz_ongoing_payment_verifications (tenant_id,ongoing_payment_verification_id),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'ongoing_access_grant_id'=ongoing_access_grant_id::text
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_ongoing_offboardings (
  tenant_id uuid not null,
  ongoing_offboarding_id uuid not null,
  engagement_id uuid not null,
  oia_conversion_decision_id uuid not null,
  decision_version integer not null,
  state text not null check (state in ('INITIATED','ACCESS_REVOCATION_PENDING','COMPLETED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  initiated_at timestamptz not null,
  primary key (tenant_id,ongoing_offboarding_id),
  unique (tenant_id,engagement_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,oia_conversion_decision_id,decision_version)
    references public.avuhz_oia_conversion_decisions (tenant_id,oia_conversion_decision_id,decision_version),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'ongoing_offboarding_id'=ongoing_offboarding_id::text
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_ongoing_access_revocation_verifications (
  tenant_id uuid not null,
  ongoing_access_revocation_verification_id uuid not null,
  engagement_id uuid not null,
  ongoing_access_grant_id uuid not null,
  grant_record_version integer not null check (grant_record_version > 0),
  ongoing_offboarding_id uuid,
  offboarding_record_version integer,
  record jsonb not null check (jsonb_typeof(record)='object'),
  verified_at timestamptz not null,
  primary key (tenant_id,ongoing_access_revocation_verification_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,ongoing_access_grant_id)
    references public.avuhz_ongoing_access_grants (tenant_id,ongoing_access_grant_id),
  foreign key (tenant_id,ongoing_offboarding_id)
    references public.avuhz_ongoing_offboardings (tenant_id,ongoing_offboarding_id),
  check ((ongoing_offboarding_id is null)=(offboarding_record_version is null)),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'ongoing_access_revocation_verification_id'=ongoing_access_revocation_verification_id::text
    and (record->>'record_version')::integer=1)
);

create index avuhz_conversion_engagement on public.avuhz_oia_conversion_decisions (tenant_id,engagement_id,decision_version desc);
create index avuhz_ongoing_agreement_engagement on public.avuhz_ongoing_agreement_authorities (tenant_id,engagement_id,agreement_version desc);
create index avuhz_ongoing_payment_engagement on public.avuhz_ongoing_payment_verifications (tenant_id,engagement_id,status,coverage_until);
create index avuhz_ongoing_access_engagement on public.avuhz_ongoing_access_grants (tenant_id,engagement_id,state);
create index avuhz_ongoing_revocation_grant on public.avuhz_ongoing_access_revocation_verifications (tenant_id,ongoing_access_grant_id,verified_at);

do $$
declare table_name text;
begin
  foreach table_name in array array[
    'avuhz_oia_conversion_decisions','avuhz_ongoing_agreement_authorities',
    'avuhz_ongoing_payment_verifications','avuhz_ongoing_access_grants',
    'avuhz_ongoing_offboardings','avuhz_ongoing_access_revocation_verifications'
  ] loop
    execute format('alter table public.%I enable row level security',table_name);
    execute format('revoke all on table public.%I from anon,authenticated,public',table_name);
    execute format('grant select on table public.%I to avuhz_command_service',table_name);
    execute format(
      'create policy avuhz_command_service_tenant_isolation on public.%I for all to avuhz_command_service using (tenant_id = nullif(current_setting(''avuhz.tenant_id'',true),'''')::uuid) with check (tenant_id = nullif(current_setting(''avuhz.tenant_id'',true),'''')::uuid)',
      table_name
    );
  end loop;
end $$;

grant insert on table public.avuhz_oia_conversion_decisions,
  public.avuhz_ongoing_agreement_authorities,public.avuhz_ongoing_payment_verifications,
  public.avuhz_ongoing_access_grants,public.avuhz_ongoing_offboardings,
  public.avuhz_ongoing_access_revocation_verifications to avuhz_command_service;

grant update (state,record_version,record,updated_at)
  on public.avuhz_oia_conversion_decisions to avuhz_command_service;
grant update (state,record_version,record,updated_at)
  on public.avuhz_ongoing_agreement_authorities to avuhz_command_service;
grant update (status,record_version,record)
  on public.avuhz_ongoing_payment_verifications to avuhz_command_service;
grant update (state,record_version,record)
  on public.avuhz_ongoing_access_grants to avuhz_command_service;
grant update (state,record_version,record)
  on public.avuhz_ongoing_offboardings to avuhz_command_service;

grant insert (approval_id,tenant_id,engagement_id,approval_role,authority_category,
  approving_principal_reference,approving_organization_reference,decision,status,conditions,
  effective_at,evidence_reference,correlation_id,idempotency_key,subject_type,subject_id,
  subject_version,approval_category,actor_identity,actor_organization,actor_role,
  phase5c_authority_digest,created_at)
  on public.avuhz_human_approvals to avuhz_command_service;
