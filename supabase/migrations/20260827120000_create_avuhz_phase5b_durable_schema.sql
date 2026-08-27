-- Local additive Phase 5B durable schema. Remote application requires separate owner authorization.

alter table public.avuhz_assessment_access_grants
  drop constraint avuhz_assessment_access_grants_closure_reason_check,
  add constraint avuhz_assessment_access_grants_closure_reason_check check (closure_reason is null or closure_reason in ('AGREEMENT_ENDED','FINDINGS_DELIVERED','ASSESSMENT_CLOSED'));

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
      'MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings',
      'ReviseDeliveredOIAFinding','CloseOIAAssessment'
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
    'RecordOIARootCause','CreateOIAFinding','UpdateOIAFindingAnalysis',
    'FinalizeOIAFinding','MarkOIAAssessmentReadyForDelivery','DeliverOIAFindings',
    'ReviseDeliveredOIAFinding','CloseOIAAssessment'
  )),
  add constraint avuhz_idempotency_records_subject_type_check check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
    'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY',
    'DIAGNOSTIC_PAYMENT_VERIFICATION','OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN',
    'OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM','OIA_OBSERVATION','OIA_ROOT_CAUSE',
    'OIA_FINDING','OIA_FINDINGS_DELIVERY'
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
    'assessment_access.revoked','assessment_access.closed',
    'diagnostic_agreement.authority_recorded','diagnostic_payment.verified',
    'diagnostic_payment.invalidated','oia.assessment_opened','oia.evidence_recorded',
    'oia.observation_recorded','oia.observation_superseded','oia.root_cause_recorded',
    'oia.finding_created','oia.finding_updated','oia.finding_finalized',
    'oia.assessment_ready_for_delivery','oia.findings_delivered',
    'oia.finding_revision_opened','oia.assessment_closed',
    'oia.assessment_plan_created','oia.assessment_plan_revised',
    'oia.assessment_plan_reviewed','oia.assessment_plan_approved',
    'oia.inspection_item_created','oia.inspection_item_blocked','oia.inspection_item_progressed'
  )),
  add constraint avuhz_lifecycle_events_authoritative_subject_type_check check (
    authoritative_subject_type in (
      'ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE','ASSESSMENT_ACCESS_PROPOSAL',
      'ASSESSMENT_ACCESS_GRANT','DIAGNOSTIC_AGREEMENT_AUTHORITY',
      'DIAGNOSTIC_PAYMENT_VERIFICATION','OIA_ASSESSMENT','OIA_ASSESSMENT_PLAN',
      'OIA_INSPECTION_ITEM','OIA_EVIDENCE_ITEM','OIA_OBSERVATION','OIA_ROOT_CAUSE',
      'OIA_FINDING','OIA_FINDINGS_DELIVERY'
    ) or authoritative_subject_type is null
  );

create table public.avuhz_oia_assessments (
  tenant_id uuid not null,
  oia_assessment_id uuid not null,
  engagement_id uuid not null,
  diagnostic_scope_id uuid not null,
  diagnostic_scope_version integer not null check (diagnostic_scope_version > 0),
  assessment_access_grant_id uuid not null,
  state text not null check (state in ('IN_PROGRESS','READY_FOR_DELIVERY','FINDINGS_DELIVERED','CLOSED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_assessment_id),
  unique (tenant_id,assessment_access_grant_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,diagnostic_scope_id) references public.avuhz_diagnostic_scopes (tenant_id,diagnostic_scope_id),
  foreign key (tenant_id,assessment_access_grant_id) references public.avuhz_assessment_access_grants (tenant_id,assessment_access_grant_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_assessment_id'=oia_assessment_id::text
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_oia_assessment_plans (
  tenant_id uuid not null,
  oia_assessment_plan_id uuid not null,
  plan_version integer not null check (plan_version > 0),
  oia_assessment_id uuid not null,
  engagement_id uuid not null,
  state text not null check (state in ('DRAFT','REVIEWED','APPROVED','SUPERSEDED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_assessment_plan_id,plan_version),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_assessment_plan_id'=oia_assessment_plan_id::text
    and (record->>'plan_version')::integer=plan_version and record->>'state'=state
    and (record->>'record_version')::integer=record_version)
);
create unique index avuhz_oia_assessment_plans_one_current
  on public.avuhz_oia_assessment_plans (tenant_id,oia_assessment_id) where state <> 'SUPERSEDED';

create table public.avuhz_oia_inspection_items (
  tenant_id uuid not null,
  oia_inspection_item_id uuid not null,
  oia_assessment_id uuid not null,
  oia_assessment_plan_id uuid not null,
  plan_version integer not null,
  engagement_id uuid not null,
  coverage_state text not null check (coverage_state in ('NOT_STARTED','IN_PROGRESS','PARTIALLY_EVIDENCED','SUFFICIENTLY_EVIDENCED','BLOCKED','NOT_APPLICABLE')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_inspection_item_id),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  foreign key (tenant_id,oia_assessment_plan_id,plan_version) references public.avuhz_oia_assessment_plans (tenant_id,oia_assessment_plan_id,plan_version),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_inspection_item_id'=oia_inspection_item_id::text
    and record->>'coverage_state'=coverage_state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_oia_evidence_items (
  tenant_id uuid not null,
  oia_evidence_id uuid not null,
  oia_assessment_id uuid not null,
  content_digest text not null check (content_digest ~ '^sha256:[0-9a-f]{64}$'),
  retention_status text not null check (retention_status in ('AVAILABLE','REDACTED','RETIRED')),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  primary key (tenant_id,oia_evidence_id),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_evidence_id'=oia_evidence_id::text
    and record->>'content_digest'=content_digest and record->>'retention_status'=retention_status)
);

create table public.avuhz_oia_inspection_evidence (
  tenant_id uuid not null,
  oia_inspection_item_id uuid not null,
  oia_evidence_id uuid not null,
  primary key (tenant_id,oia_inspection_item_id,oia_evidence_id),
  foreign key (tenant_id,oia_inspection_item_id) references public.avuhz_oia_inspection_items (tenant_id,oia_inspection_item_id),
  foreign key (tenant_id,oia_evidence_id) references public.avuhz_oia_evidence_items (tenant_id,oia_evidence_id)
);

create table public.avuhz_oia_observations (
  tenant_id uuid not null,
  oia_observation_id uuid not null,
  oia_assessment_id uuid not null,
  state text not null check (state in ('RECORDED','SUPERSEDED')),
  record_version integer not null check (record_version > 0),
  superseded_by_observation_id uuid,
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_observation_id),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  foreign key (tenant_id,superseded_by_observation_id) references public.avuhz_oia_observations (tenant_id,oia_observation_id),
  check ((state='RECORDED' and superseded_by_observation_id is null) or (state='SUPERSEDED' and superseded_by_observation_id is not null)),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_observation_id'=oia_observation_id::text
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_oia_observation_evidence (
  tenant_id uuid not null,
  oia_observation_id uuid not null,
  oia_evidence_id uuid not null,
  primary key (tenant_id,oia_observation_id,oia_evidence_id),
  foreign key (tenant_id,oia_observation_id) references public.avuhz_oia_observations (tenant_id,oia_observation_id),
  foreign key (tenant_id,oia_evidence_id) references public.avuhz_oia_evidence_items (tenant_id,oia_evidence_id)
);

create table public.avuhz_oia_root_causes (
  tenant_id uuid not null,
  oia_root_cause_id uuid not null,
  oia_assessment_id uuid not null,
  confidence text not null check (confidence in ('HYPOTHESIS','SUPPORTED','VERIFIED')),
  record_version integer not null check (record_version > 0),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_root_cause_id),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_root_cause_id'=oia_root_cause_id::text
    and record->>'confidence'=confidence and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_oia_root_cause_observations (
  tenant_id uuid not null,
  oia_root_cause_id uuid not null,
  oia_observation_id uuid not null,
  primary key (tenant_id,oia_root_cause_id,oia_observation_id),
  foreign key (tenant_id,oia_root_cause_id) references public.avuhz_oia_root_causes (tenant_id,oia_root_cause_id),
  foreign key (tenant_id,oia_observation_id) references public.avuhz_oia_observations (tenant_id,oia_observation_id)
);

create table public.avuhz_oia_root_cause_evidence (
  tenant_id uuid not null,
  oia_root_cause_id uuid not null,
  oia_evidence_id uuid not null,
  primary key (tenant_id,oia_root_cause_id,oia_evidence_id),
  foreign key (tenant_id,oia_root_cause_id) references public.avuhz_oia_root_causes (tenant_id,oia_root_cause_id),
  foreign key (tenant_id,oia_evidence_id) references public.avuhz_oia_evidence_items (tenant_id,oia_evidence_id)
);

create table public.avuhz_oia_findings (
  tenant_id uuid not null,
  oia_finding_id uuid not null,
  finding_revision integer not null check (finding_revision > 0),
  oia_assessment_id uuid not null,
  state text not null check (state in ('DRAFT','FINAL','SUPERSEDED')),
  priority text not null check (priority in ('LOW','MEDIUM','HIGH','CRITICAL')),
  content_digest text check (content_digest is null or content_digest ~ '^sha256:[0-9a-f]{64}$'),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id,oia_finding_id,finding_revision),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_finding_id'=oia_finding_id::text
    and (record->>'finding_revision')::integer=finding_revision and record->>'state'=state
    and record->>'priority'=priority)
);
create unique index avuhz_oia_findings_one_current
  on public.avuhz_oia_findings (tenant_id,oia_finding_id) where state <> 'SUPERSEDED';

create table public.avuhz_oia_finding_observations (
  tenant_id uuid not null,
  oia_finding_id uuid not null,
  finding_revision integer not null,
  oia_observation_id uuid not null,
  primary key (tenant_id,oia_finding_id,finding_revision,oia_observation_id),
  foreign key (tenant_id,oia_finding_id,finding_revision) references public.avuhz_oia_findings (tenant_id,oia_finding_id,finding_revision),
  foreign key (tenant_id,oia_observation_id) references public.avuhz_oia_observations (tenant_id,oia_observation_id)
);

create table public.avuhz_oia_finding_evidence (
  tenant_id uuid not null,
  oia_finding_id uuid not null,
  finding_revision integer not null,
  oia_evidence_id uuid not null,
  primary key (tenant_id,oia_finding_id,finding_revision,oia_evidence_id),
  foreign key (tenant_id,oia_finding_id,finding_revision) references public.avuhz_oia_findings (tenant_id,oia_finding_id,finding_revision),
  foreign key (tenant_id,oia_evidence_id) references public.avuhz_oia_evidence_items (tenant_id,oia_evidence_id)
);

create table public.avuhz_oia_finding_root_causes (
  tenant_id uuid not null,
  oia_finding_id uuid not null,
  finding_revision integer not null,
  oia_root_cause_id uuid not null,
  primary key (tenant_id,oia_finding_id,finding_revision,oia_root_cause_id),
  foreign key (tenant_id,oia_finding_id,finding_revision) references public.avuhz_oia_findings (tenant_id,oia_finding_id,finding_revision),
  foreign key (tenant_id,oia_root_cause_id) references public.avuhz_oia_root_causes (tenant_id,oia_root_cause_id)
);

create table public.avuhz_oia_findings_deliveries (
  tenant_id uuid not null,
  oia_findings_delivery_id uuid not null,
  oia_assessment_id uuid not null,
  delivery_sequence integer not null check (delivery_sequence > 0),
  manifest_digest text not null check (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  delivered_at timestamptz not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id,oia_findings_delivery_id),
  unique (tenant_id,oia_assessment_id,delivery_sequence),
  unique (tenant_id,manifest_digest),
  foreign key (tenant_id,oia_assessment_id) references public.avuhz_oia_assessments (tenant_id,oia_assessment_id),
  check (record->>'tenant_id'=tenant_id::text and record->>'oia_findings_delivery_id'=oia_findings_delivery_id::text
    and (record->>'delivery_sequence')::integer=delivery_sequence and record->>'manifest_digest'=manifest_digest)
);

create table public.avuhz_oia_findings_delivery_items (
  tenant_id uuid not null,
  oia_findings_delivery_id uuid not null,
  oia_finding_id uuid not null,
  finding_revision integer not null,
  content_digest text not null check (content_digest ~ '^sha256:[0-9a-f]{64}$'),
  primary key (tenant_id,oia_findings_delivery_id,oia_finding_id,finding_revision),
  foreign key (tenant_id,oia_findings_delivery_id) references public.avuhz_oia_findings_deliveries (tenant_id,oia_findings_delivery_id),
  foreign key (tenant_id,oia_finding_id,finding_revision) references public.avuhz_oia_findings (tenant_id,oia_finding_id,finding_revision)
);

create index avuhz_oia_assessments_tenant_state on public.avuhz_oia_assessments (tenant_id,state);
create index avuhz_oia_inspection_items_assessment on public.avuhz_oia_inspection_items (tenant_id,oia_assessment_id,coverage_state);
create index avuhz_oia_evidence_items_assessment on public.avuhz_oia_evidence_items (tenant_id,oia_assessment_id);
create index avuhz_oia_observations_assessment on public.avuhz_oia_observations (tenant_id,oia_assessment_id,state);
create index avuhz_oia_root_causes_assessment on public.avuhz_oia_root_causes (tenant_id,oia_assessment_id,confidence);
create index avuhz_oia_findings_assessment on public.avuhz_oia_findings (tenant_id,oia_assessment_id,state,priority);
create index avuhz_oia_deliveries_assessment on public.avuhz_oia_findings_deliveries (tenant_id,oia_assessment_id,delivery_sequence desc);

do $$
declare table_name text;
begin
  foreach table_name in array array[
    'avuhz_oia_assessments','avuhz_oia_assessment_plans','avuhz_oia_inspection_items',
    'avuhz_oia_evidence_items','avuhz_oia_inspection_evidence','avuhz_oia_observations',
    'avuhz_oia_observation_evidence','avuhz_oia_root_causes',
    'avuhz_oia_root_cause_observations','avuhz_oia_root_cause_evidence',
    'avuhz_oia_findings','avuhz_oia_finding_observations','avuhz_oia_finding_evidence',
    'avuhz_oia_finding_root_causes','avuhz_oia_findings_deliveries',
    'avuhz_oia_findings_delivery_items'
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

grant insert on table public.avuhz_oia_assessments,public.avuhz_oia_assessment_plans,
  public.avuhz_oia_inspection_items,public.avuhz_oia_evidence_items,
  public.avuhz_oia_inspection_evidence,public.avuhz_oia_observations,
  public.avuhz_oia_observation_evidence,public.avuhz_oia_root_causes,
  public.avuhz_oia_root_cause_observations,public.avuhz_oia_root_cause_evidence,
  public.avuhz_oia_findings,public.avuhz_oia_finding_observations,
  public.avuhz_oia_finding_evidence,public.avuhz_oia_finding_root_causes,
  public.avuhz_oia_findings_deliveries,public.avuhz_oia_findings_delivery_items
  to avuhz_command_service;

grant update (state,record_version,record,updated_at) on public.avuhz_oia_assessments to avuhz_command_service;
grant update (state,record_version,record,updated_at) on public.avuhz_oia_assessment_plans to avuhz_command_service;
grant update (coverage_state,record_version,record,updated_at) on public.avuhz_oia_inspection_items to avuhz_command_service;
grant update (state,record_version,superseded_by_observation_id,record,updated_at) on public.avuhz_oia_observations to avuhz_command_service;
grant update (confidence,record_version,record,updated_at) on public.avuhz_oia_root_causes to avuhz_command_service;
grant update (state,content_digest,record,updated_at) on public.avuhz_oia_findings to avuhz_command_service;
