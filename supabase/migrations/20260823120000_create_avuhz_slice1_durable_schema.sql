-- Canonical additive Slice 1 schema. Access policies and grants are deferred.
create table public.avuhz_acquisition_handoffs (
  tenant_id uuid not null, handoff_id uuid not null, handoff_version integer not null check (handoff_version >= 1),
  canonical_account_reference text not null check (char_length(canonical_account_reference) between 1 and 200),
  acquisition_opportunity_reference text not null check (char_length(acquisition_opportunity_reference) between 1 and 200),
  qualification_status text not null check (qualification_status in ('QUALIFIED', 'QUALIFIED_WITH_CONDITIONS')),
  target_outcome text not null check (char_length(target_outcome) between 1 and 2000),
  validated_constraints jsonb not null check (jsonb_typeof(validated_constraints) = 'array'),
  stakeholder_context jsonb not null check (jsonb_typeof(stakeholder_context) = 'array'),
  assumptions jsonb not null check (jsonb_typeof(assumptions) = 'array'), exclusions jsonb not null check (jsonb_typeof(exclusions) = 'array'),
  requested_engagement_type text not null check (requested_engagement_type = 'DIAGNOSTIC_OIA'),
  source_system text not null check (char_length(source_system) between 1 and 200), source_record_version text not null check (char_length(source_record_version) between 1 and 100),
  producer_identity text not null check (char_length(producer_identity) between 1 and 200), produced_at timestamptz not null, correlation_id uuid not null,
  idempotency_key text not null check (char_length(idempotency_key) between 1 and 200), received_at timestamptz not null default now(), accepted_at timestamptz not null default now(), created_at timestamptz not null default now(),
  primary key (tenant_id, handoff_id, handoff_version)
);
create table public.avuhz_engagements (
  engagement_id uuid primary key, tenant_id uuid not null, acquisition_handoff_id uuid not null, acquisition_handoff_version integer not null check (acquisition_handoff_version >= 1),
  account_reference text not null check (char_length(account_reference) between 1 and 200), acquisition_opportunity_reference text not null check (char_length(acquisition_opportunity_reference) between 1 and 200),
  engagement_type text not null check (engagement_type = 'DIAGNOSTIC_OIA'), engagement_state text not null check (engagement_state in ('OPEN', 'ONBOARDING')),
  engagement_version integer not null default 1 check (engagement_version >= 1), record_version integer not null default 1 check (record_version >= 1),
  opened_at timestamptz not null, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique (tenant_id, engagement_id),
  foreign key (tenant_id, acquisition_handoff_id, acquisition_handoff_version) references public.avuhz_acquisition_handoffs (tenant_id, handoff_id, handoff_version)
);
create table public.avuhz_diagnostic_scopes (
  diagnostic_scope_id uuid primary key, tenant_id uuid not null, engagement_id uuid not null, scope_version integer not null check (scope_version >= 1), record_version integer not null default 1 check (record_version >= 1),
  status text not null check (status in ('DRAFT', 'REVIEW_PENDING', 'APPROVED', 'REJECTED', 'SUPERSEDED', 'CANCELLED')),
  canonical_scope_digest text not null check (canonical_scope_digest ~ '^sha256:[0-9a-f]{64}$'), action_set_version integer not null default 1 check (action_set_version >= 1),
  target_outcome text not null check (char_length(target_outcome) between 1 and 2000),
  in_scope_systems jsonb not null check (jsonb_typeof(in_scope_systems) = 'array' and jsonb_array_length(in_scope_systems) between 1 and 20),
  excluded_systems jsonb not null check (jsonb_typeof(excluded_systems) = 'array' and jsonb_array_length(excluded_systems) <= 20),
  permitted_actions text[] not null check (cardinality(permitted_actions) between 1 and 10 and permitted_actions <@ array['VIEW_CONFIGURATION','VIEW_OPERATIONAL_STATE','VIEW_LOGS','VIEW_METRICS','VIEW_ACCESS_CONFIGURATION','VIEW_NETWORK_CONFIGURATION','VIEW_SECURITY_CONFIGURATION','VIEW_COMPLIANCE_EVIDENCE','NON_DESTRUCTIVE_CONNECTIVITY_TEST','NON_DESTRUCTIVE_PERMISSION_TEST']::text[]),
  prohibited_actions text[] not null check (cardinality(prohibited_actions) = 10 and prohibited_actions @> array['CREATE','MODIFY','DELETE','DEPLOY','RESTART','ROTATE','GRANT','REVOKE','CHANGE_CONFIGURATION','PRODUCTION_CHANGE']::text[]),
  assumptions jsonb not null check (jsonb_typeof(assumptions) = 'array'), constraint_references jsonb not null check (jsonb_typeof(constraint_references) = 'array'), effective_at timestamptz not null, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id, diagnostic_scope_id), unique (tenant_id, diagnostic_scope_id, scope_version), foreign key (tenant_id, engagement_id) references public.avuhz_engagements (tenant_id, engagement_id)
);
create table public.avuhz_human_approvals (
  approval_id uuid primary key, tenant_id uuid not null, engagement_id uuid not null, diagnostic_scope_id uuid not null, approved_scope_version integer not null check (approved_scope_version >= 1),
  approval_role text not null check (approval_role in ('CLIENT_DECISION_AUTHORITY','SEKINFRA_ENGAGEMENT_AUTHORITY')), authority_category text not null check (authority_category in ('CLIENT_AUTHORITY','SEKINFRA_AUTHORITY')),
  approving_principal_reference text not null check (char_length(approving_principal_reference) between 1 and 200), approving_organization_reference text not null check (char_length(approving_organization_reference) between 1 and 200),
  canonical_scope_digest text not null check (canonical_scope_digest ~ '^sha256:[0-9a-f]{64}$'), action_set_version integer not null check (action_set_version >= 1), decision text not null check (decision in ('APPROVE','REJECT','REVOKE','SUPERSEDE')), status text not null check (status in ('ACTIVE','EXPIRED','REVOKED','SUPERSEDED')),
  conditions jsonb not null check (jsonb_typeof(conditions) = 'array'), effective_at timestamptz not null, expires_at timestamptz, evidence_reference text not null check (char_length(evidence_reference) between 1 and 300), correlation_id uuid not null, idempotency_key text not null check (char_length(idempotency_key) between 1 and 200), created_at timestamptz not null default now(), unique (tenant_id, approval_id),
  check ((approval_role = 'CLIENT_DECISION_AUTHORITY') = (authority_category = 'CLIENT_AUTHORITY')),
  foreign key (tenant_id, engagement_id) references public.avuhz_engagements (tenant_id, engagement_id), foreign key (tenant_id, diagnostic_scope_id, approved_scope_version) references public.avuhz_diagnostic_scopes (tenant_id, diagnostic_scope_id, scope_version)
);
create table public.avuhz_idempotency_records (
  id uuid primary key, tenant_id uuid not null, trusted_principal_id text not null check (char_length(trusted_principal_id) between 1 and 200), command_type text not null check (command_type in ('AcceptAcquisitionHandoff','OpenEngagement','SubmitDiagnosticScope','ApproveDiagnosticScope')),
  subject_type text not null check (subject_type in ('ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE')), subject_id uuid not null, subject_version integer not null check (subject_version >= 1), idempotency_key text not null check (char_length(idempotency_key) between 1 and 200),
  semantic_request_fingerprint text not null check (semantic_request_fingerprint ~ '^fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}$'), fingerprint_schema_version text not null check (char_length(fingerprint_schema_version) between 1 and 100), processing_status text not null check (processing_status in ('RESERVED','PROCESSING','COMPLETED','FAILED_RETRYABLE','FAILED_TERMINAL','AMBIGUOUS')),
  result_reference text, first_seen_at timestamptz not null default now(), completed_at timestamptz, retention_class text not null check (retention_class in ('OPERATIONAL_DEDUPLICATION','AUDIT_HISTORY')), attempt_count integer not null default 0 check (attempt_count >= 0), record_version integer not null default 1 check (record_version >= 1), created_at timestamptz not null default now(),
  unique (tenant_id, trusted_principal_id, command_type, subject_type, subject_id, idempotency_key), check (processing_status not in ('COMPLETED','FAILED_TERMINAL') or completed_at is not null), check (processing_status <> 'COMPLETED' or result_reference is not null)
);
create table public.avuhz_lifecycle_events (
  lifecycle_event_id uuid primary key, tenant_id uuid not null, engagement_id uuid, event_type text not null check (event_type in ('engagement.handoff.accepted','engagement.opened','diagnostic_scope.submitted','diagnostic_scope.approved','diagnostic_scope.rejected')), event_schema_version integer not null check (event_schema_version >= 1),
  authoritative_subject_type text not null check (authoritative_subject_type in ('ACQUISITION_HANDOFF','ENGAGEMENT','DIAGNOSTIC_SCOPE')), authoritative_subject_id uuid not null, authoritative_subject_version integer not null check (authoritative_subject_version >= 1), occurred_at timestamptz not null, producer_reference text not null check (char_length(producer_reference) between 1 and 200), correlation_id uuid not null, causation_id uuid, idempotency_key text not null check (char_length(idempotency_key) between 1 and 200), visibility text not null check (visibility in ('TENANT_OPERATIONAL','SEKINFRA_INTERNAL','INTEGRATION_INTERNAL')), sanitized_metadata jsonb not null check (jsonb_typeof(sanitized_metadata) = 'object'), created_at timestamptz not null default now(), unique (tenant_id, lifecycle_event_id), foreign key (tenant_id, engagement_id) references public.avuhz_engagements (tenant_id, engagement_id)
);
create table public.avuhz_outbox_deliveries (
  outbox_delivery_id uuid primary key, tenant_id uuid not null, lifecycle_event_id uuid not null, destination_reference text not null check (char_length(destination_reference) between 1 and 200), status text not null default 'PENDING' check (status in ('PENDING','PUBLISHING','PUBLISHED','FAILED_RETRYABLE','FAILED_TERMINAL')), attempt_count integer not null default 0 check (attempt_count >= 0), next_attempt_at timestamptz, last_attempt_at timestamptz, published_at timestamptz, last_safe_error_code text check (last_safe_error_code is null or last_safe_error_code in ('OUTBOX_COMMIT_FAILED','COMMAND_REJECTED','SECURITY_BLOCKED')), delivery_idempotency_key text not null check (char_length(delivery_idempotency_key) between 1 and 200), record_version integer not null default 1 check (record_version >= 1), created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id, lifecycle_event_id, destination_reference, delivery_idempotency_key), check (status <> 'PUBLISHED' or (published_at is not null and next_attempt_at is null)), check (status <> 'FAILED_RETRYABLE' or next_attempt_at is not null), check (status <> 'FAILED_TERMINAL' or next_attempt_at is null), foreign key (tenant_id, lifecycle_event_id) references public.avuhz_lifecycle_events (tenant_id, lifecycle_event_id)
);
create index avuhz_acquisition_handoffs_tenant_account_idx on public.avuhz_acquisition_handoffs (tenant_id, canonical_account_reference);
create index avuhz_engagements_tenant_state_idx on public.avuhz_engagements (tenant_id, engagement_state);
create index avuhz_diagnostic_scopes_tenant_scope_version_idx on public.avuhz_diagnostic_scopes (tenant_id, diagnostic_scope_id, scope_version);
create index avuhz_human_approvals_tenant_scope_role_idx on public.avuhz_human_approvals (tenant_id, diagnostic_scope_id, approval_role);
create index avuhz_idempotency_records_tenant_key_idx on public.avuhz_idempotency_records (tenant_id, idempotency_key);
create index avuhz_lifecycle_events_tenant_occurred_at_idx on public.avuhz_lifecycle_events (tenant_id, occurred_at desc);
create index avuhz_outbox_deliveries_tenant_status_next_attempt_idx on public.avuhz_outbox_deliveries (tenant_id, status, next_attempt_at);
alter table public.avuhz_acquisition_handoffs enable row level security;
alter table public.avuhz_engagements enable row level security;
alter table public.avuhz_diagnostic_scopes enable row level security;
alter table public.avuhz_human_approvals enable row level security;
alter table public.avuhz_idempotency_records enable row level security;
alter table public.avuhz_lifecycle_events enable row level security;
alter table public.avuhz_outbox_deliveries enable row level security;
