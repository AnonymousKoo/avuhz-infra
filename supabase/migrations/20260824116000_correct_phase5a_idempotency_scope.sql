alter table public.avuhz_idempotency_records drop constraint avuhz_idempotency_records_tenant_principal_command_scope_key;
alter table public.avuhz_idempotency_records drop column idempotency_scope;
alter table public.avuhz_idempotency_records add column idempotency_scope text generated always as (
  case when command_type in (
    'CreateAssessmentAccessProposal','RecordAssessmentAccessApproval','IssueAssessmentAccessGrant','VerifyAssessmentAccess','ExpireAssessmentAccess','RevokeAssessmentAccess','CloseAssessmentAccessForAgreementEnd',
    'RecordDiagnosticAgreementAuthority','RecordDiagnosticPaymentVerification','InvalidateDiagnosticPaymentVerification'
  ) then 'COMMAND' else 'SUBJECT:' || subject_id::text end
) stored;
alter table public.avuhz_idempotency_records add constraint avuhz_idempotency_records_tenant_principal_command_scope_key
  unique (tenant_id,trusted_principal_id,command_type,subject_type,idempotency_scope,idempotency_key);
