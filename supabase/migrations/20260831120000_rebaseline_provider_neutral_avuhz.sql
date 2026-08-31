-- Local/disposable current-tree rebaseline for provider-neutral Avuhz only.
-- Never applied remotely; never push this baseline to a linked project.
-- Preserves governed execution through immutable DeploymentExecution truth; performs no provider operation.

create extension if not exists pgcrypto;
do $$ begin
  if not exists (select 1 from pg_roles where rolname='avuhz_command_service') then
    create role avuhz_command_service nologin nosuperuser nobypassrls nocreatedb nocreaterole noinherit;
  end if;
end $$;
grant usage on schema public to avuhz_command_service;

create table public.avuhz_acquisition_handoffs (
  tenant_id uuid not null, handoff_id uuid not null,
  handoff_version integer not null check (handoff_version>0),
  canonical_account_reference jsonb not null check (jsonb_typeof(canonical_account_reference)='object'),
  acquisition_opportunity_reference jsonb not null check (jsonb_typeof(acquisition_opportunity_reference)='object'),
  qualification_status text not null check (qualification_status in ('QUALIFIED','QUALIFIED_WITH_CONDITIONS')),
  target_outcome text not null check (char_length(target_outcome) between 1 and 2000),
  validated_constraints jsonb not null check (jsonb_typeof(validated_constraints)='array'),
  stakeholder_context jsonb not null check (jsonb_typeof(stakeholder_context)='array'),
  assumptions jsonb not null check (jsonb_typeof(assumptions)='array'),
  exclusions jsonb not null check (jsonb_typeof(exclusions)='array'),
  requested_engagement_type text not null check (requested_engagement_type~'^[A-Z][A-Z0-9_]{2,79}$'),
  source_system text not null check (char_length(source_system) between 1 and 200),
  source_record_version text not null check (char_length(source_record_version) between 1 and 100),
  producer_identity text not null check (char_length(producer_identity) between 1 and 200),
  produced_at timestamptz not null, correlation_id uuid not null,
  idempotency_key text not null check (char_length(idempotency_key) between 1 and 200),
  received_at timestamptz not null default now(), accepted_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (tenant_id,handoff_id,handoff_version)
);

create table public.avuhz_engagements (
  tenant_id uuid not null, engagement_id uuid not null,
  acquisition_handoff_id uuid not null, acquisition_handoff_version integer not null check (acquisition_handoff_version>0),
  account_reference jsonb not null check (jsonb_typeof(account_reference)='object'),
  acquisition_opportunity_reference jsonb not null check (jsonb_typeof(acquisition_opportunity_reference)='object'),
  engagement_type text not null check (engagement_type~'^[A-Z][A-Z0-9_]{2,79}$'),
  engagement_state text not null check (engagement_state in ('OPEN','ONBOARDING')),
  engagement_version integer not null check (engagement_version>0),
  record_version integer not null check (record_version>0), opened_at timestamptz not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  primary key (tenant_id,engagement_id),
  foreign key (tenant_id,acquisition_handoff_id,acquisition_handoff_version)
    references public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version)
);

create table public.avuhz_implementation_handoffs (
  tenant_id uuid not null, implementation_handoff_id uuid not null,
  handoff_version integer not null check (handoff_version>0),
  source_engagement_reference text not null check (char_length(source_engagement_reference) between 1 and 200),
  handoff_digest text not null check (handoff_digest~'^sha256:[0-9a-f]{64}$'),
  state text not null check (state in ('APPROVED','REVOKED')),
  record jsonb not null check (jsonb_typeof(record)='object'), created_at timestamptz not null,
  primary key (tenant_id,implementation_handoff_id,handoff_version),
  check (record->>'tenant_id'=tenant_id::text
    and record->>'implementation_handoff_id'=implementation_handoff_id::text
    and (record->>'handoff_version')::integer=handoff_version
    and record->>'source_engagement_reference'=source_engagement_reference
    and record->>'handoff_digest'=handoff_digest and record->>'state'=state)
);

create table public.avuhz_human_approvals (
  approval_id uuid primary key, tenant_id uuid not null, engagement_id uuid not null,
  approval_role text not null check (approval_role in (
    'CLIENT_IMPLEMENTATION_AUTHORITY','PROVIDER_IMPLEMENTATION_AUTHORITY',
    'CLIENT_DEPLOYMENT_AUTHORITY','PROVIDER_DEPLOYMENT_AUTHORITY')),
  authority_category text not null check (authority_category in ('CLIENT_AUTHORITY','PROVIDER_AUTHORITY')),
  approving_principal_reference text not null check (char_length(approving_principal_reference) between 1 and 200),
  approving_organization_reference text not null check (char_length(approving_organization_reference) between 1 and 200),
  decision text not null check (decision='APPROVE'),
  status text not null check (status in ('ACTIVE','EXPIRED','REVOKED','SUPERSEDED')),
  conditions jsonb not null check (jsonb_typeof(conditions)='array'), effective_at timestamptz not null,
  evidence_reference jsonb not null check (jsonb_typeof(evidence_reference)='object'),
  correlation_id uuid not null, idempotency_key text not null check (char_length(idempotency_key) between 1 and 200),
  subject_type text not null check (subject_type in (
    'IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE','DEPLOYMENT_AUTHORIZATION')),
  subject_id uuid not null, subject_version integer not null check (subject_version>0),
  approval_category text not null check (approval_category=subject_type),
  actor_identity text not null check (char_length(actor_identity) between 1 and 200),
  actor_organization text not null check (char_length(actor_organization) between 1 and 200),
  actor_role text not null check (actor_role=approval_role),
  phase5d_authority_digest text not null check (phase5d_authority_digest~'^sha256:[0-9a-f]{64}$'),
  created_at timestamptz not null,
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  check ((authority_category='CLIENT_AUTHORITY')=(approval_role in (
    'CLIENT_IMPLEMENTATION_AUTHORITY','CLIENT_DEPLOYMENT_AUTHORITY'))),
  check ((subject_type='DEPLOYMENT_AUTHORIZATION')=(approval_role in (
    'CLIENT_DEPLOYMENT_AUTHORITY','PROVIDER_DEPLOYMENT_AUTHORITY')))
);
create unique index avuhz_human_approvals_active_subject_role_key on public.avuhz_human_approvals
  (tenant_id,subject_type,subject_id,subject_version,phase5d_authority_digest,approval_role)
  where status='ACTIVE';

create table public.avuhz_idempotency_records (
  id uuid primary key, tenant_id uuid not null,
  trusted_principal_id text not null check (char_length(trusted_principal_id) between 1 and 200),
  command_type text not null check (command_type in (
    'AcceptAcquisitionHandoff','OpenEngagement','DraftImplementationBrief','ReviseImplementationBrief',
    'RecordImplementationBriefApproval','ApproveImplementationBrief','ProposeImplementationAuthorization',
    'ReviseImplementationAuthorization','RecordImplementationAuthorizationApproval',
    'ActivateImplementationAuthorization','RevokeImplementationAuthorization','DraftCodexBuildPackage',
    'ReviseCodexBuildPackage','RecordCodexBuildPackageApproval','ReleaseCodexBuildPackage',
    'StartBuildExecution','CompleteBuildExecution','RecordQAResult','RecordClientAcceptance',
    'ProposeDeploymentAuthorization','ReviseDeploymentAuthorization','RecordDeploymentAuthorizationApproval',
    'ActivateDeploymentAuthorization','RevokeDeploymentAuthorization','StartDeploymentExecution',
    'CompleteDeploymentExecution')),
  subject_type text not null check (subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION',
    'CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT','QA_RESULT','CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION',
    'DEPLOYMENT_EXECUTION')),
  subject_id uuid not null, subject_version integer not null check (subject_version>0),
  idempotency_key text not null check (char_length(idempotency_key) between 1 and 200),
  semantic_request_fingerprint text not null check (semantic_request_fingerprint~'^fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}$'),
  fingerprint_schema_version text not null check (char_length(fingerprint_schema_version) between 1 and 100),
  processing_status text not null check (processing_status in (
    'RESERVED','PROCESSING','COMPLETED','FAILED_RETRYABLE','FAILED_TERMINAL','AMBIGUOUS')),
  result_reference text, first_seen_at timestamptz not null default now(), completed_at timestamptz,
  retention_class text not null check (retention_class in ('OPERATIONAL_DEDUPLICATION','AUDIT_HISTORY')),
  attempt_count integer not null default 0 check (attempt_count>=0),
  record_version integer not null default 1 check (record_version>0), created_at timestamptz not null default now(),
  idempotency_scope text generated always as (case when command_type in (
    'DraftImplementationBrief','ReviseImplementationBrief','RecordImplementationBriefApproval',
    'ApproveImplementationBrief','ProposeImplementationAuthorization','ReviseImplementationAuthorization',
    'RecordImplementationAuthorizationApproval','ActivateImplementationAuthorization',
    'RevokeImplementationAuthorization','DraftCodexBuildPackage','ReviseCodexBuildPackage',
    'RecordCodexBuildPackageApproval','ReleaseCodexBuildPackage','StartBuildExecution',
    'CompleteBuildExecution','RecordQAResult','RecordClientAcceptance','ProposeDeploymentAuthorization',
    'ReviseDeploymentAuthorization','RecordDeploymentAuthorizationApproval',
    'ActivateDeploymentAuthorization','RevokeDeploymentAuthorization','StartDeploymentExecution',
    'CompleteDeploymentExecution') then 'COMMAND' else 'SUBJECT:'||subject_id::text end) stored,
  unique (tenant_id,trusted_principal_id,command_type,subject_type,idempotency_scope,idempotency_key),
  check (processing_status not in ('COMPLETED','FAILED_TERMINAL') or completed_at is not null),
  check (processing_status<>'COMPLETED' or result_reference is not null)
);

create table public.avuhz_lifecycle_events (
  lifecycle_event_id uuid primary key, tenant_id uuid not null, engagement_id uuid,
  event_type text not null check (event_type in (
    'engagement.handoff.accepted','engagement.opened','implementation_brief.drafted',
    'implementation_brief.revised','implementation_brief.approval_recorded','implementation_brief.approved',
    'implementation_authorization.proposed','implementation_authorization.revised',
    'implementation_authorization.approval_recorded','implementation_authorization.activated',
    'implementation_authorization.revoked','codex_build_package.drafted','codex_build_package.revised',
    'codex_build_package.approval_recorded','codex_build_package.released','build_execution.started',
    'build_execution.completed','qa_result.recorded','client_acceptance.recorded',
    'deployment_authorization.proposed','deployment_authorization.revised',
    'deployment_authorization.approval_recorded','deployment_authorization.activated',
    'deployment_authorization.revoked','deployment_execution.started','deployment_execution.completed')),
  event_schema_version integer check (event_schema_version>0),
  authoritative_subject_type text check (authoritative_subject_type in (
    'ACQUISITION_HANDOFF','ENGAGEMENT','IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION',
    'CODEX_BUILD_PACKAGE','BUILD_EXECUTION_RESULT','QA_RESULT','CLIENT_ACCEPTANCE','DEPLOYMENT_AUTHORIZATION',
    'DEPLOYMENT_EXECUTION')),
  authoritative_subject_id uuid, authoritative_subject_version integer check (authoritative_subject_version>0),
  occurred_at timestamptz, producer_reference text, correlation_id uuid, causation_id uuid,
  idempotency_key text not null check (char_length(idempotency_key) between 1 and 200),
  visibility text check (visibility in ('TENANT_OPERATIONAL','INTEGRATION_INTERNAL')),
  sanitized_metadata jsonb check (sanitized_metadata is null or jsonb_typeof(sanitized_metadata)='object'),
  created_at timestamptz not null default now(), unique (tenant_id,lifecycle_event_id),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  check ((event_schema_version is null and authoritative_subject_type is null
      and authoritative_subject_version is null and occurred_at is null)
    or (event_schema_version is not null and authoritative_subject_type is not null
      and authoritative_subject_id is not null and authoritative_subject_version is not null
      and occurred_at is not null and producer_reference is not null and correlation_id is not null
      and visibility is not null and sanitized_metadata is not null))
);

create table public.avuhz_outbox_deliveries (
  outbox_delivery_id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
  lifecycle_event_id uuid not null, destination_reference text,
  status text not null default 'PENDING' check (status in (
    'PENDING','PUBLISHING','PUBLISHED','FAILED_RETRYABLE','FAILED_TERMINAL')),
  attempt_count integer not null default 0 check (attempt_count>=0), next_attempt_at timestamptz,
  last_attempt_at timestamptz, published_at timestamptz,
  last_safe_error_code text check (last_safe_error_code is null or last_safe_error_code in (
    'OUTBOX_COMMIT_FAILED','COMMAND_REJECTED','SECURITY_BLOCKED')),
  delivery_idempotency_key text, record_version integer not null default 1 check (record_version>0),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id,lifecycle_event_id),
  foreign key (tenant_id,lifecycle_event_id) references public.avuhz_lifecycle_events (tenant_id,lifecycle_event_id)
);

create table public.avuhz_implementation_briefs (
  tenant_id uuid not null, implementation_brief_id uuid not null,
  implementation_brief_version integer not null check (implementation_brief_version>0), engagement_id uuid not null,
  implementation_handoff_id uuid not null, handoff_version integer not null check (handoff_version>0),
  handoff_digest text not null check (handoff_digest~'^sha256:[0-9a-f]{64}$'),
  source_truth_digest text not null check (source_truth_digest~'^sha256:[0-9a-f]{64}$'),
  implementation_brief_digest text not null check (implementation_brief_digest~'^sha256:[0-9a-f]{64}$'),
  state text not null check (state in ('DRAFT','APPROVED','SUPERSEDED')),
  record_version integer not null check (record_version>0), record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,implementation_brief_id,implementation_brief_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_handoff_id,handoff_version)
    references public.avuhz_implementation_handoffs (tenant_id,implementation_handoff_id,handoff_version),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'implementation_brief_id'=implementation_brief_id::text
    and (record->>'implementation_brief_version')::integer=implementation_brief_version
    and record->'source_implementation_handoff_reference'->>'reference_id'=implementation_handoff_id::text
    and (record->'source_implementation_handoff_reference'->>'reference_version')::integer=handoff_version
    and record->'source_implementation_handoff_reference'->>'reference_digest'=handoff_digest
    and record->>'source_truth_digest'=source_truth_digest and record->>'implementation_brief_digest'=implementation_brief_digest
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_implementation_authorizations (
  tenant_id uuid not null, implementation_authorization_id uuid not null,
  authorization_version integer not null check (authorization_version>0), engagement_id uuid not null,
  implementation_brief_id uuid not null, implementation_brief_version integer not null check (implementation_brief_version>0),
  implementation_brief_digest text not null check (implementation_brief_digest~'^sha256:[0-9a-f]{64}$'),
  implementation_handoff_id uuid not null, handoff_version integer not null check (handoff_version>0),
  handoff_digest text not null check (handoff_digest~'^sha256:[0-9a-f]{64}$'),
  authorized_scope_digest text not null check (authorized_scope_digest~'^sha256:[0-9a-f]{64}$'),
  implementation_authority_digest text not null check (implementation_authority_digest~'^sha256:[0-9a-f]{64}$'),
  effective_at timestamptz not null, expires_at timestamptz not null check (expires_at>effective_at),
  state text not null check (state in ('PROPOSED','ACTIVE','EXPIRED','REVOKED','SUPERSEDED')),
  record_version integer not null check (record_version>0), record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,implementation_authorization_id,authorization_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_brief_id,implementation_brief_version)
    references public.avuhz_implementation_briefs (tenant_id,implementation_brief_id,implementation_brief_version),
  foreign key (tenant_id,implementation_handoff_id,handoff_version)
    references public.avuhz_implementation_handoffs (tenant_id,implementation_handoff_id,handoff_version),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'implementation_authorization_id'=implementation_authorization_id::text
    and (record->>'authorization_version')::integer=authorization_version
    and record->'implementation_brief_reference'->>'reference_id'=implementation_brief_id::text
    and (record->'implementation_brief_reference'->>'reference_version')::integer=implementation_brief_version
    and record->>'implementation_brief_digest'=implementation_brief_digest
    and record->'source_implementation_handoff_reference'->>'reference_id'=implementation_handoff_id::text
    and (record->'source_implementation_handoff_reference'->>'reference_version')::integer=handoff_version
    and record->'source_implementation_handoff_reference'->>'reference_digest'=handoff_digest
    and record->>'authorized_scope_digest'=authorized_scope_digest
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_codex_build_packages (
  tenant_id uuid not null, codex_build_package_id uuid not null,
  package_version integer not null check (package_version>0), engagement_id uuid not null,
  implementation_brief_id uuid not null, implementation_brief_version integer not null check (implementation_brief_version>0),
  implementation_brief_digest text not null check (implementation_brief_digest~'^sha256:[0-9a-f]{64}$'),
  implementation_authorization_id uuid not null, authorization_version integer not null check (authorization_version>0),
  implementation_authority_digest text not null check (implementation_authority_digest~'^sha256:[0-9a-f]{64}$'),
  package_digest text not null check (package_digest~'^sha256:[0-9a-f]{64}$'),
  state text not null check (state in ('DRAFT','RELEASED','SUPERSEDED')),
  record_version integer not null check (record_version>0), record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_brief_id,implementation_brief_version)
    references public.avuhz_implementation_briefs (tenant_id,implementation_brief_id,implementation_brief_version),
  foreign key (tenant_id,implementation_authorization_id,authorization_version)
    references public.avuhz_implementation_authorizations (tenant_id,implementation_authorization_id,authorization_version),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'codex_build_package_id'=codex_build_package_id::text
    and (record->>'package_version')::integer=package_version
    and record->'implementation_brief_reference'->>'reference_id'=implementation_brief_id::text
    and (record->'implementation_brief_reference'->>'reference_version')::integer=implementation_brief_version
    and record->>'implementation_brief_digest'=implementation_brief_digest
    and record->'implementation_authorization_reference'->>'reference_id'=implementation_authorization_id::text
    and (record->'implementation_authorization_reference'->>'reference_version')::integer=authorization_version
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->>'package_digest'=package_digest and record->>'state'=state
    and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_build_execution_results (
  tenant_id uuid not null, build_execution_result_id uuid not null,
  execution_attempt integer not null check (execution_attempt>0), engagement_id uuid not null,
  codex_build_package_id uuid not null, package_version integer not null check (package_version>0),
  package_digest text not null check (package_digest~'^sha256:[0-9a-f]{64}$'),
  implementation_authorization_id uuid not null, authorization_version integer not null check (authorization_version>0),
  implementation_authority_digest text not null check (implementation_authority_digest~'^sha256:[0-9a-f]{64}$'),
  supersedes_build_execution_result_id uuid, supersedes_record_version integer check (supersedes_record_version>0),
  status text not null check (status in ('IN_PROGRESS','SUCCEEDED','FAILED')),
  execution_fingerprint text not null check (execution_fingerprint~'^fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}$'),
  execution_digest text check (execution_digest is null or execution_digest~'^sha256:[0-9a-f]{64}$'),
  record_version integer not null check (record_version>0), record jsonb not null check (jsonb_typeof(record)='object'),
  started_at timestamptz not null, completed_at timestamptz, created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,build_execution_result_id),
  unique (tenant_id,codex_build_package_id,package_version,execution_attempt),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,implementation_authorization_id,authorization_version)
    references public.avuhz_implementation_authorizations (tenant_id,implementation_authorization_id,authorization_version),
  foreign key (tenant_id,supersedes_build_execution_result_id)
    references public.avuhz_build_execution_results (tenant_id,build_execution_result_id),
  check ((execution_attempt=1 and supersedes_build_execution_result_id is null and supersedes_record_version is null)
    or (execution_attempt>1 and supersedes_build_execution_result_id is not null and supersedes_record_version is not null)),
  check ((status='IN_PROGRESS' and execution_digest is null and completed_at is null)
    or (status in ('SUCCEEDED','FAILED') and execution_digest is not null and completed_at is not null)),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'build_execution_result_id'=build_execution_result_id::text
    and (record->>'execution_attempt')::integer=execution_attempt
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest
    and record->'implementation_authorization_reference'->>'reference_id'=implementation_authorization_id::text
    and (record->'implementation_authorization_reference'->>'reference_version')::integer=authorization_version
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->>'status'=status and record->>'execution_fingerprint'=execution_fingerprint
    and (record->>'record_version')::integer=record_version
    and ((execution_digest is null and not record?'execution_digest') or record->>'execution_digest'=execution_digest))
);

create table public.avuhz_qa_results (
  tenant_id uuid not null, qa_result_id uuid not null, qa_attempt integer not null check (qa_attempt>0),
  engagement_id uuid not null, build_execution_result_id uuid not null,
  build_record_version integer not null check (build_record_version>0),
  build_execution_digest text not null check (build_execution_digest~'^sha256:[0-9a-f]{64}$'),
  codex_build_package_id uuid not null, package_version integer not null check (package_version>0),
  package_digest text not null check (package_digest~'^sha256:[0-9a-f]{64}$'),
  supersedes_qa_result_id uuid, supersedes_record_version integer check (supersedes_record_version>0),
  overall_status text not null check (overall_status in ('PASSED','FAILED','BLOCKED')),
  qa_digest text not null check (qa_digest~'^sha256:[0-9a-f]{64}$'),
  record_version integer not null check (record_version=1), record jsonb not null check (jsonb_typeof(record)='object'),
  recorded_at timestamptz not null, created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,qa_result_id), unique (tenant_id,codex_build_package_id,package_version,qa_attempt),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,build_execution_result_id)
    references public.avuhz_build_execution_results (tenant_id,build_execution_result_id),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,supersedes_qa_result_id) references public.avuhz_qa_results (tenant_id,qa_result_id),
  check ((qa_attempt=1 and supersedes_qa_result_id is null and supersedes_record_version is null)
    or (qa_attempt>1 and supersedes_qa_result_id is not null and supersedes_record_version is not null)),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'qa_result_id'=qa_result_id::text and (record->>'qa_attempt')::integer=qa_attempt
    and record->'build_execution_reference'->>'reference_id'=build_execution_result_id::text
    and (record->'build_execution_reference'->>'reference_version')::integer=build_record_version
    and record->>'build_execution_digest'=build_execution_digest
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest and record->>'overall_status'=overall_status
    and record->>'qa_digest'=qa_digest and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_client_acceptances (
  tenant_id uuid not null, client_acceptance_id uuid not null,
  acceptance_version integer not null check (acceptance_version>0), engagement_id uuid not null,
  codex_build_package_id uuid not null, package_version integer not null check (package_version>0),
  package_digest text not null check (package_digest~'^sha256:[0-9a-f]{64}$'),
  build_execution_result_id uuid not null, build_record_version integer not null check (build_record_version>0),
  build_execution_digest text not null check (build_execution_digest~'^sha256:[0-9a-f]{64}$'),
  qa_result_id uuid not null, qa_record_version integer not null check (qa_record_version>0),
  qa_result_digest text not null check (qa_result_digest~'^sha256:[0-9a-f]{64}$'),
  artifact_reference_id text not null check (char_length(artifact_reference_id) between 1 and 200),
  artifact_class text not null check (artifact_class in (
    'SOURCE_COMMIT','BUILD_ARTIFACT','CONTAINER_IMAGE','PACKAGE_ARCHIVE')),
  artifact_version text not null check (artifact_version~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$'),
  artifact_digest text not null check (artifact_digest~'^sha256:[0-9a-f]{64}$'),
  decision text not null check (decision in ('ACCEPTED','REJECTED')),
  client_acceptance_digest text not null check (client_acceptance_digest~'^sha256:[0-9a-f]{64}$'),
  supersedes_client_acceptance_id uuid, supersedes_acceptance_version integer check (supersedes_acceptance_version>0),
  record_version integer not null check (record_version=1), record jsonb not null check (jsonb_typeof(record)='object'),
  recorded_at timestamptz not null, created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,client_acceptance_id,acceptance_version),
  constraint avuhz_client_acceptances_package_version_key
    unique (tenant_id,codex_build_package_id,package_version,acceptance_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,build_execution_result_id)
    references public.avuhz_build_execution_results (tenant_id,build_execution_result_id),
  foreign key (tenant_id,qa_result_id) references public.avuhz_qa_results (tenant_id,qa_result_id),
  foreign key (tenant_id,supersedes_client_acceptance_id,supersedes_acceptance_version)
    references public.avuhz_client_acceptances (tenant_id,client_acceptance_id,acceptance_version),
  check ((acceptance_version=1 and supersedes_client_acceptance_id is null and supersedes_acceptance_version is null)
    or (acceptance_version>1 and supersedes_client_acceptance_id=client_acceptance_id
      and supersedes_acceptance_version=acceptance_version-1)),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'client_acceptance_id'=client_acceptance_id::text
    and (record->>'acceptance_version')::integer=acceptance_version
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest
    and record->'build_execution_reference'->>'reference_id'=build_execution_result_id::text
    and (record->'build_execution_reference'->>'reference_version')::integer=build_record_version
    and record->>'build_execution_digest'=build_execution_digest
    and record->'qa_result_reference'->>'reference_id'=qa_result_id::text
    and (record->'qa_result_reference'->>'reference_version')::integer=qa_record_version
    and record->>'qa_result_digest'=qa_result_digest
    and record->'artifact_reference'->>'artifact_reference_id'=artifact_reference_id
    and record->'artifact_reference'->>'artifact_class'=artifact_class
    and record->'artifact_reference'->>'artifact_version'=artifact_version
    and record->'artifact_reference'->>'artifact_digest'=artifact_digest
    and record->>'decision'=decision and record->>'client_acceptance_digest'=client_acceptance_digest
    and (record->>'record_version')::integer=record_version)
);

create table public.avuhz_deployment_authorizations (
  tenant_id uuid not null, deployment_authorization_id uuid not null,
  authorization_version integer not null check (authorization_version>0), engagement_id uuid not null,
  implementation_authorization_id uuid not null,
  implementation_authorization_version integer not null check (implementation_authorization_version>0),
  implementation_authority_digest text not null check (implementation_authority_digest~'^sha256:[0-9a-f]{64}$'),
  codex_build_package_id uuid not null, package_version integer not null check (package_version>0),
  package_digest text not null check (package_digest~'^sha256:[0-9a-f]{64}$'),
  build_execution_result_id uuid not null, build_record_version integer not null check (build_record_version>0),
  build_execution_digest text not null check (build_execution_digest~'^sha256:[0-9a-f]{64}$'),
  qa_result_id uuid not null, qa_record_version integer not null check (qa_record_version>0),
  qa_result_digest text not null check (qa_result_digest~'^sha256:[0-9a-f]{64}$'),
  client_acceptance_id uuid not null, acceptance_version integer not null check (acceptance_version>0),
  client_acceptance_digest text not null check (client_acceptance_digest~'^sha256:[0-9a-f]{64}$'),
  artifact_digest text not null check (artifact_digest~'^sha256:[0-9a-f]{64}$'),
  target_environment text not null check (target_environment in ('DEVELOPMENT','TEST','STAGING','PRODUCTION')),
  effective_at timestamptz not null, expires_at timestamptz not null check (expires_at>effective_at),
  deployment_authority_digest text not null check (deployment_authority_digest~'^sha256:[0-9a-f]{64}$'),
  supersedes_deployment_authorization_id uuid,
  supersedes_authorization_version integer check (supersedes_authorization_version>0),
  state text not null check (state in ('PROPOSED','ACTIVE','EXPIRED','REVOKED','SUPERSEDED')),
  record_version integer not null check (record_version>0),
  record jsonb not null check (jsonb_typeof(record)='object'),
  created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,deployment_authorization_id,authorization_version),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,implementation_authorization_id,implementation_authorization_version)
    references public.avuhz_implementation_authorizations (tenant_id,implementation_authorization_id,authorization_version),
  foreign key (tenant_id,codex_build_package_id,package_version)
    references public.avuhz_codex_build_packages (tenant_id,codex_build_package_id,package_version),
  foreign key (tenant_id,build_execution_result_id)
    references public.avuhz_build_execution_results (tenant_id,build_execution_result_id),
  foreign key (tenant_id,qa_result_id) references public.avuhz_qa_results (tenant_id,qa_result_id),
  foreign key (tenant_id,client_acceptance_id,acceptance_version)
    references public.avuhz_client_acceptances (tenant_id,client_acceptance_id,acceptance_version),
  foreign key (tenant_id,supersedes_deployment_authorization_id,supersedes_authorization_version)
    references public.avuhz_deployment_authorizations (tenant_id,deployment_authorization_id,authorization_version),
  check ((authorization_version=1 and supersedes_deployment_authorization_id is null and supersedes_authorization_version is null)
    or (authorization_version>1 and supersedes_deployment_authorization_id=deployment_authorization_id
      and supersedes_authorization_version=authorization_version-1)),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'deployment_authorization_id'=deployment_authorization_id::text
    and (record->>'authorization_version')::integer=authorization_version
    and record->'implementation_authorization_reference'->>'reference_id'=implementation_authorization_id::text
    and (record->'implementation_authorization_reference'->>'reference_version')::integer=implementation_authorization_version
    and record->>'implementation_authority_digest'=implementation_authority_digest
    and record->'codex_build_package_reference'->>'reference_id'=codex_build_package_id::text
    and (record->'codex_build_package_reference'->>'reference_version')::integer=package_version
    and record->>'package_digest'=package_digest
    and record->'build_execution_reference'->>'reference_id'=build_execution_result_id::text
    and (record->'build_execution_reference'->>'reference_version')::integer=build_record_version
    and record->>'build_execution_digest'=build_execution_digest
    and record->'qa_result_reference'->>'reference_id'=qa_result_id::text
    and (record->'qa_result_reference'->>'reference_version')::integer=qa_record_version
    and record->>'qa_result_digest'=qa_result_digest
    and record->'client_acceptance_reference'->>'reference_id'=client_acceptance_id::text
    and (record->'client_acceptance_reference'->>'reference_version')::integer=acceptance_version
    and record->>'client_acceptance_digest'=client_acceptance_digest
    and record->'artifact_reference'->>'artifact_digest'=artifact_digest
    and record->>'target_environment'=target_environment
    and record->>'effective_at'=to_char(effective_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')
    and record->>'expires_at'=to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')
    and record->>'deployment_authority_digest'=deployment_authority_digest
    and record->>'state'=state and (record->>'record_version')::integer=record_version)
);

create index avuhz_acquisition_handoffs_tenant_account_idx on public.avuhz_acquisition_handoffs (tenant_id,canonical_account_reference);
create index avuhz_engagements_tenant_state_idx on public.avuhz_engagements (tenant_id,engagement_state);
create index avuhz_implementation_handoffs_history_idx on public.avuhz_implementation_handoffs (tenant_id,implementation_handoff_id,handoff_version);
create index avuhz_human_approvals_subject_idx on public.avuhz_human_approvals (tenant_id,subject_type,subject_id,subject_version);
create index avuhz_idempotency_records_tenant_key_idx on public.avuhz_idempotency_records (tenant_id,idempotency_key);
create index avuhz_lifecycle_events_tenant_time_idx on public.avuhz_lifecycle_events (tenant_id,occurred_at desc);
create index avuhz_outbox_pending_idx on public.avuhz_outbox_deliveries (tenant_id,status,next_attempt_at);
create index avuhz_implementation_brief_history_idx on public.avuhz_implementation_briefs (tenant_id,implementation_brief_id,implementation_brief_version);
create index avuhz_implementation_authorization_history_idx on public.avuhz_implementation_authorizations (tenant_id,implementation_authorization_id,authorization_version);
create index avuhz_codex_build_package_history_idx on public.avuhz_codex_build_packages (tenant_id,codex_build_package_id,package_version);
create index avuhz_build_execution_package_history_idx on public.avuhz_build_execution_results (tenant_id,codex_build_package_id,package_version,execution_attempt);
create index avuhz_qa_package_history_idx on public.avuhz_qa_results (tenant_id,codex_build_package_id,package_version,qa_attempt);
create index avuhz_client_acceptance_package_history_idx on public.avuhz_client_acceptances (tenant_id,codex_build_package_id,package_version,acceptance_version);
create index avuhz_deployment_authorization_history_idx on public.avuhz_deployment_authorizations (tenant_id,deployment_authorization_id,authorization_version);

create function public.avuhz_reject_immutable_history_mutation() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  raise exception 'immutable Avuhz history cannot be rewritten';
end $$;

create table public.avuhz_deployment_executions (
  tenant_id uuid not null, deployment_execution_id uuid not null,
  execution_attempt integer not null check (execution_attempt>0), engagement_id uuid not null,
  deployment_authorization_id uuid not null,
  deployment_authorization_version integer not null check (deployment_authorization_version>0),
  deployment_authority_digest text not null check (deployment_authority_digest~'^sha256:[0-9a-f]{64}$'),
  supersedes_deployment_execution_id uuid, supersedes_record_version integer check (supersedes_record_version>0),
  rollback_of_deployment_execution_id uuid, rollback_of_record_version integer check (rollback_of_record_version>0),
  execution_action text not null check (execution_action in ('DEPLOY_EXACT_ARTIFACT','ROLLBACK_EXACT_ARTIFACT')),
  status text not null check (status in ('IN_PROGRESS','SUCCEEDED','FAILED','PARTIAL','BLOCKED')),
  execution_fingerprint text not null check (execution_fingerprint~'^fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}$'),
  execution_digest text check (execution_digest is null or execution_digest~'^sha256:[0-9a-f]{64}$'),
  record_version integer not null check (record_version>0), record jsonb not null check (jsonb_typeof(record)='object'),
  started_at timestamptz not null, completed_at timestamptz,
  created_at timestamptz not null, updated_at timestamptz not null,
  primary key (tenant_id,deployment_execution_id),
  unique (tenant_id,deployment_authorization_id,deployment_authorization_version,execution_attempt),
  foreign key (tenant_id,engagement_id) references public.avuhz_engagements (tenant_id,engagement_id),
  foreign key (tenant_id,deployment_authorization_id,deployment_authorization_version)
    references public.avuhz_deployment_authorizations (tenant_id,deployment_authorization_id,authorization_version),
  check ((execution_attempt=1 and supersedes_deployment_execution_id is null and supersedes_record_version is null)
    or (execution_attempt>1 and supersedes_deployment_execution_id is not null and supersedes_record_version is not null)),
  check ((execution_action='ROLLBACK_EXACT_ARTIFACT')=(rollback_of_deployment_execution_id is not null and rollback_of_record_version is not null)),
  check ((status='IN_PROGRESS' and execution_digest is null and completed_at is null)
    or (status in ('SUCCEEDED','FAILED','PARTIAL','BLOCKED') and execution_digest is not null and completed_at is not null)),
  check (record->>'tenant_id'=tenant_id::text and record->>'engagement_id'=engagement_id::text
    and record->>'deployment_execution_id'=deployment_execution_id::text
    and (record->>'execution_attempt')::integer=execution_attempt
    and record->'authority_binding'->'deployment_authorization_reference'->>'reference_id'=deployment_authorization_id::text
    and (record->'authority_binding'->'deployment_authorization_reference'->>'reference_version')::integer=deployment_authorization_version
    and record->'authority_binding'->>'deployment_authority_digest'=deployment_authority_digest
    and record->>'execution_action'=execution_action and record->>'status'=status
    and record->>'execution_fingerprint'=execution_fingerprint
    and (record->>'record_version')::integer=record_version)
);
create index avuhz_deployment_execution_authority_history_idx on public.avuhz_deployment_executions
  (tenant_id,deployment_authorization_id,deployment_authorization_version,execution_attempt);

create trigger avuhz_implementation_handoffs_immutable before update or delete on public.avuhz_implementation_handoffs for each row execute function public.avuhz_reject_immutable_history_mutation();
create trigger avuhz_human_approvals_immutable before update or delete on public.avuhz_human_approvals for each row execute function public.avuhz_reject_immutable_history_mutation();
create trigger avuhz_lifecycle_events_immutable before update or delete on public.avuhz_lifecycle_events for each row execute function public.avuhz_reject_immutable_history_mutation();
create trigger avuhz_qa_results_immutable before update or delete on public.avuhz_qa_results for each row execute function public.avuhz_reject_immutable_history_mutation();
create trigger avuhz_client_acceptances_immutable before update or delete on public.avuhz_client_acceptances for each row execute function public.avuhz_reject_immutable_history_mutation();
create trigger avuhz_deployment_executions_no_delete before delete on public.avuhz_deployment_executions for each row execute function public.avuhz_reject_immutable_history_mutation();


create function public.avuhz_guard_deployment_execution_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if old.status<>'IN_PROGRESS' or new.status not in ('SUCCEEDED','FAILED','PARTIAL','BLOCKED')
    or new.record_version<>old.record_version+1
    or row(new.tenant_id,new.deployment_execution_id,new.execution_attempt,new.engagement_id,
      new.deployment_authorization_id,new.deployment_authorization_version,new.deployment_authority_digest,
      new.supersedes_deployment_execution_id,new.supersedes_record_version,
      new.rollback_of_deployment_execution_id,new.rollback_of_record_version,new.execution_action,
      new.execution_fingerprint,new.started_at,new.created_at)
      is distinct from row(old.tenant_id,old.deployment_execution_id,old.execution_attempt,old.engagement_id,
      old.deployment_authorization_id,old.deployment_authorization_version,old.deployment_authority_digest,
      old.supersedes_deployment_execution_id,old.supersedes_record_version,
      old.rollback_of_deployment_execution_id,old.rollback_of_record_version,old.execution_action,
      old.execution_fingerprint,old.started_at,old.created_at)
    then raise exception 'invalid DeploymentExecution transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_deployment_execution_transition before update on public.avuhz_deployment_executions
  for each row execute function public.avuhz_guard_deployment_execution_transition();

create function public.avuhz_guard_deployment_authorization_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if new.record_version<>old.record_version+1
    or not ((old.state='PROPOSED' and new.state in ('ACTIVE','REVOKED'))
      or (old.state='ACTIVE' and new.state in ('REVOKED','SUPERSEDED')))
    or row(new.tenant_id,new.deployment_authorization_id,new.authorization_version,new.engagement_id,
      new.implementation_authorization_id,new.implementation_authorization_version,new.implementation_authority_digest,
      new.codex_build_package_id,new.package_version,new.package_digest,new.build_execution_result_id,
      new.build_record_version,new.build_execution_digest,new.qa_result_id,new.qa_record_version,new.qa_result_digest,
      new.client_acceptance_id,new.acceptance_version,new.client_acceptance_digest,new.artifact_digest,
      new.target_environment,new.effective_at,new.expires_at,new.deployment_authority_digest,
      new.supersedes_deployment_authorization_id,new.supersedes_authorization_version,new.created_at)
      is distinct from row(old.tenant_id,old.deployment_authorization_id,old.authorization_version,old.engagement_id,
      old.implementation_authorization_id,old.implementation_authorization_version,old.implementation_authority_digest,
      old.codex_build_package_id,old.package_version,old.package_digest,old.build_execution_result_id,
      old.build_record_version,old.build_execution_digest,old.qa_result_id,old.qa_record_version,old.qa_result_digest,
      old.client_acceptance_id,old.acceptance_version,old.client_acceptance_digest,old.artifact_digest,
      old.target_environment,old.effective_at,old.expires_at,old.deployment_authority_digest,
      old.supersedes_deployment_authorization_id,old.supersedes_authorization_version,old.created_at)
    then raise exception 'invalid DeploymentAuthorization transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_deployment_authorization_transition before update on public.avuhz_deployment_authorizations
  for each row execute function public.avuhz_guard_deployment_authorization_transition();

create function public.avuhz_guard_brief_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if new.record_version<>old.record_version+1
    or not ((old.state='DRAFT' and new.state='APPROVED') or (old.state='APPROVED' and new.state='SUPERSEDED'))
    or row(new.tenant_id,new.implementation_brief_id,new.implementation_brief_version,new.engagement_id,
      new.implementation_handoff_id,new.handoff_version,new.handoff_digest,new.source_truth_digest,
      new.implementation_brief_digest,new.created_at)
      is distinct from row(old.tenant_id,old.implementation_brief_id,old.implementation_brief_version,old.engagement_id,
      old.implementation_handoff_id,old.handoff_version,old.handoff_digest,old.source_truth_digest,
      old.implementation_brief_digest,old.created_at) then raise exception 'invalid ImplementationBrief transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_brief_transition before update on public.avuhz_implementation_briefs for each row execute function public.avuhz_guard_brief_transition();

create function public.avuhz_guard_authorization_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if new.record_version<>old.record_version+1
    or not ((old.state='PROPOSED' and new.state in ('ACTIVE','REVOKED')) or (old.state='ACTIVE' and new.state in ('REVOKED','SUPERSEDED')))
    or row(new.tenant_id,new.implementation_authorization_id,new.authorization_version,new.engagement_id,
      new.implementation_brief_id,new.implementation_brief_version,new.implementation_brief_digest,
      new.implementation_handoff_id,new.handoff_version,new.handoff_digest,new.authorized_scope_digest,
      new.implementation_authority_digest,new.effective_at,new.expires_at,new.created_at)
      is distinct from row(old.tenant_id,old.implementation_authorization_id,old.authorization_version,old.engagement_id,
      old.implementation_brief_id,old.implementation_brief_version,old.implementation_brief_digest,
      old.implementation_handoff_id,old.handoff_version,old.handoff_digest,old.authorized_scope_digest,
      old.implementation_authority_digest,old.effective_at,old.expires_at,old.created_at) then raise exception 'invalid ImplementationAuthorization transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_authorization_transition before update on public.avuhz_implementation_authorizations for each row execute function public.avuhz_guard_authorization_transition();

create function public.avuhz_guard_package_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if new.record_version<>old.record_version+1
    or not ((old.state='DRAFT' and new.state='RELEASED') or (old.state='RELEASED' and new.state='SUPERSEDED'))
    or row(new.tenant_id,new.codex_build_package_id,new.package_version,new.engagement_id,new.implementation_brief_id,
      new.implementation_brief_version,new.implementation_brief_digest,new.implementation_authorization_id,
      new.authorization_version,new.implementation_authority_digest,new.package_digest,new.created_at)
      is distinct from row(old.tenant_id,old.codex_build_package_id,old.package_version,old.engagement_id,old.implementation_brief_id,
      old.implementation_brief_version,old.implementation_brief_digest,old.implementation_authorization_id,
      old.authorization_version,old.implementation_authority_digest,old.package_digest,old.created_at) then raise exception 'invalid CodexBuildPackage transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_package_transition before update on public.avuhz_codex_build_packages for each row execute function public.avuhz_guard_package_transition();

create function public.avuhz_guard_build_execution_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if old.status<>'IN_PROGRESS' or new.status not in ('SUCCEEDED','FAILED') or new.record_version<>old.record_version+1
    or row(new.tenant_id,new.build_execution_result_id,new.execution_attempt,new.engagement_id,new.codex_build_package_id,
      new.package_version,new.package_digest,new.implementation_authorization_id,new.authorization_version,
      new.implementation_authority_digest,new.supersedes_build_execution_result_id,new.supersedes_record_version,
      new.execution_fingerprint,new.started_at,new.created_at)
      is distinct from row(old.tenant_id,old.build_execution_result_id,old.execution_attempt,old.engagement_id,old.codex_build_package_id,
      old.package_version,old.package_digest,old.implementation_authorization_id,old.authorization_version,
      old.implementation_authority_digest,old.supersedes_build_execution_result_id,old.supersedes_record_version,
      old.execution_fingerprint,old.started_at,old.created_at) then raise exception 'invalid BuildExecutionResult transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_build_execution_transition before update on public.avuhz_build_execution_results for each row execute function public.avuhz_guard_build_execution_transition();

create function public.avuhz_guard_acquisition_acceptance() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if old.accepted_at is not null or new.accepted_at is null
    or (to_jsonb(new)-'accepted_at')<>(to_jsonb(old)-'accepted_at') then raise exception 'invalid acquisition handoff acceptance transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_acquisition_acceptance before update on public.avuhz_acquisition_handoffs for each row execute function public.avuhz_guard_acquisition_acceptance();

create function public.avuhz_guard_idempotency_transition() returns trigger
language plpgsql set search_path=pg_catalog,public as $$ begin
  if new.record_version<>old.record_version+1 or old.processing_status<>'RESERVED' or new.processing_status<>'COMPLETED'
    or row(new.id,new.tenant_id,new.trusted_principal_id,new.command_type,new.subject_type,new.subject_id,
      new.subject_version,new.idempotency_key,new.semantic_request_fingerprint,new.fingerprint_schema_version,
      new.first_seen_at,new.retention_class,new.attempt_count,new.created_at)
      is distinct from row(old.id,old.tenant_id,old.trusted_principal_id,old.command_type,old.subject_type,old.subject_id,
      old.subject_version,old.idempotency_key,old.semantic_request_fingerprint,old.fingerprint_schema_version,
      old.first_seen_at,old.retention_class,old.attempt_count,old.created_at) then raise exception 'invalid idempotency transition'; end if;
  return new;
end $$;
create trigger avuhz_guard_idempotency_transition before update on public.avuhz_idempotency_records for each row execute function public.avuhz_guard_idempotency_transition();

alter table public.avuhz_acquisition_handoffs enable row level security;
alter table public.avuhz_engagements enable row level security;
alter table public.avuhz_implementation_handoffs enable row level security;
alter table public.avuhz_human_approvals enable row level security;
alter table public.avuhz_idempotency_records enable row level security;
alter table public.avuhz_lifecycle_events enable row level security;
alter table public.avuhz_outbox_deliveries enable row level security;
alter table public.avuhz_implementation_briefs enable row level security;
alter table public.avuhz_implementation_authorizations enable row level security;
alter table public.avuhz_codex_build_packages enable row level security;
alter table public.avuhz_build_execution_results enable row level security;
alter table public.avuhz_qa_results enable row level security;
alter table public.avuhz_client_acceptances enable row level security;
alter table public.avuhz_deployment_authorizations enable row level security;
alter table public.avuhz_deployment_executions enable row level security;

do $$ declare table_name text; grantee_name text; begin
  foreach table_name in array array[
    'avuhz_acquisition_handoffs','avuhz_engagements','avuhz_implementation_handoffs','avuhz_human_approvals',
    'avuhz_idempotency_records','avuhz_lifecycle_events','avuhz_outbox_deliveries','avuhz_implementation_briefs',
    'avuhz_implementation_authorizations','avuhz_codex_build_packages','avuhz_build_execution_results',
    'avuhz_qa_results','avuhz_client_acceptances','avuhz_deployment_authorizations',
    'avuhz_deployment_executions'] loop
    execute format('revoke all on table public.%I from public',table_name);
    foreach grantee_name in array array['anon','authenticated'] loop
      if exists (select 1 from pg_roles where rolname=grantee_name) then
        execute format('revoke all on table public.%I from %I',table_name,grantee_name);
      end if;
    end loop;
    execute format($policy$create policy avuhz_command_service_tenant_isolation on public.%I
      for all to avuhz_command_service
      using (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
      with check (tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)$policy$,table_name);
  end loop;
end $$;

grant select on table public.avuhz_acquisition_handoffs,public.avuhz_engagements,public.avuhz_implementation_handoffs,
  public.avuhz_human_approvals,public.avuhz_idempotency_records,public.avuhz_lifecycle_events,
  public.avuhz_outbox_deliveries,public.avuhz_implementation_briefs,public.avuhz_implementation_authorizations,
  public.avuhz_codex_build_packages,public.avuhz_build_execution_results,public.avuhz_qa_results,
  public.avuhz_client_acceptances,public.avuhz_deployment_authorizations,public.avuhz_deployment_executions to avuhz_command_service;
grant insert on table public.avuhz_engagements,public.avuhz_implementation_handoffs,public.avuhz_human_approvals,
  public.avuhz_idempotency_records,public.avuhz_lifecycle_events,public.avuhz_outbox_deliveries,
  public.avuhz_implementation_briefs,public.avuhz_implementation_authorizations,public.avuhz_codex_build_packages,
  public.avuhz_build_execution_results,public.avuhz_qa_results,public.avuhz_client_acceptances,
  public.avuhz_deployment_authorizations,public.avuhz_deployment_executions to avuhz_command_service;
grant update (accepted_at) on public.avuhz_acquisition_handoffs to avuhz_command_service;
grant update (processing_status,result_reference,completed_at,record_version) on public.avuhz_idempotency_records to avuhz_command_service;
grant update (state,record_version,record,updated_at) on public.avuhz_implementation_briefs to avuhz_command_service;
grant update (state,record_version,record,updated_at) on public.avuhz_implementation_authorizations to avuhz_command_service;
grant update (state,record_version,record,updated_at) on public.avuhz_codex_build_packages to avuhz_command_service;
grant update (status,execution_digest,record_version,record,completed_at,updated_at) on public.avuhz_build_execution_results to avuhz_command_service;
grant update (state,record_version,record,updated_at) on public.avuhz_deployment_authorizations to avuhz_command_service;
grant update (status,execution_digest,record_version,record,completed_at,updated_at) on public.avuhz_deployment_executions to avuhz_command_service;
