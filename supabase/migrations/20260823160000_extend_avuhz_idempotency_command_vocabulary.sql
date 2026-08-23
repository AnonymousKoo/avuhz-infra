-- Forward-only closed vocabulary extension for durable human approval command idempotency.
-- Existing idempotency semantics, uniqueness, and legacy tables remain unchanged.

alter table public.avuhz_idempotency_records
  drop constraint avuhz_idempotency_records_command_type_check;

alter table public.avuhz_idempotency_records
  add constraint avuhz_idempotency_records_command_type_check
  check (command_type in (
    'AcceptAcquisitionHandoff',
    'OpenEngagement',
    'SubmitDiagnosticScope',
    'RecordHumanApproval',
    'ApproveDiagnosticScope'
  ));
