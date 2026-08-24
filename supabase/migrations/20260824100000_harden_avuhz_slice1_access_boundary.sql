-- Phase 4C: authoritative Slice 1 tables are command-service-only.
-- No client-facing role receives direct table access; server-side access remains
-- injected into PostgresUnitOfWork and is still subject to runtime guards.

alter table public.avuhz_acquisition_handoffs enable row level security;
alter table public.avuhz_engagements enable row level security;
alter table public.avuhz_diagnostic_scopes enable row level security;
alter table public.avuhz_human_approvals enable row level security;
alter table public.avuhz_idempotency_records enable row level security;
alter table public.avuhz_lifecycle_events enable row level security;
alter table public.avuhz_outbox_deliveries enable row level security;

revoke all privileges on table public.avuhz_acquisition_handoffs from anon, authenticated;
revoke all privileges on table public.avuhz_engagements from anon, authenticated;
revoke all privileges on table public.avuhz_diagnostic_scopes from anon, authenticated;
revoke all privileges on table public.avuhz_human_approvals from anon, authenticated;
revoke all privileges on table public.avuhz_idempotency_records from anon, authenticated;
revoke all privileges on table public.avuhz_lifecycle_events from anon, authenticated;
revoke all privileges on table public.avuhz_outbox_deliveries from anon, authenticated;
