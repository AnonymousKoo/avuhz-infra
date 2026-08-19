-- Target: Supabase data project "sekinfra-growth" (ref: gnuqaefotwgkwurjpyik), PRODUCTION.
-- Tenant access is derived from public.tenant_users: auth.uid() matches
-- tenant_users.auth_user_id, and the resulting tenant_id scopes every row.

create type public.engagement_urgency as enum (
  'urgent',
  'exploring'
);
create type public.engagement_status as enum (
  'intake',
  'booking_scheduled',
  'nda_sa_audit_signed',
  'payment_received',
  'credentials_provisioned',
  'oia_walkthrough_complete',
  'findings_delivered',
  'conversion_decision_pending',
  'nda_sa_ongoing_signed',
  'remainder_payment_received',
  'ongoing_service_active',
  'closed_lost',
  'enterprise_flagged'
);
create type public.engagement_event_type as enum (
  'engagement_created',
  'status_advanced',
  'document_signed',
  'payment_received',
  'engagement_flagged',
  'credentials_provisioned'
);
create table public.engagements (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  company_name text,
  contact_name text,
  contact_email text,
  contact_phone text,
  industry text,
  problem_statement text,
  urgency public.engagement_urgency not null,
  status public.engagement_status not null default 'intake',
  enterprise_flag boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  unique (id, tenant_id)
);
create table public.engagement_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  engagement_id uuid not null,
  event_type public.engagement_event_type not null,
  event_data jsonb not null default '{}'::jsonb,
  idempotency_key text unique,
  created_at timestamptz not null default now(),

  constraint engagement_events_engagement_tenant_fkey
    foreign key (engagement_id, tenant_id)
    references public.engagements (id, tenant_id)
    on delete cascade
);
create index engagements_tenant_status_idx
  on public.engagements (tenant_id, status);
create index engagement_events_engagement_created_at_idx
  on public.engagement_events (engagement_id, created_at desc);
create index engagement_events_tenant_created_at_idx
  on public.engagement_events (tenant_id, created_at desc);
create function public.set_engagements_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;
create trigger engagements_set_updated_at
before update on public.engagements
for each row
execute function public.set_engagements_updated_at();
-- RLS is enabled and tenant-scoped for authenticated users via public.tenant_users.
-- Each policy matches auth.uid() to tenant_users.auth_user_id and requires the
-- matched tenant_id to equal the row tenant_id. engagement_events is append-only:
-- it has SELECT and INSERT policies only, with no UPDATE or DELETE policy.
alter table public.engagements enable row level security;
alter table public.engagement_events enable row level security;
create policy engagements_select_own_tenant
on public.engagements
for select
to authenticated
using (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagements.tenant_id
  )
);
create policy engagements_insert_own_tenant
on public.engagements
for insert
to authenticated
with check (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagements.tenant_id
  )
);
create policy engagements_update_own_tenant
on public.engagements
for update
to authenticated
using (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagements.tenant_id
  )
)
with check (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagements.tenant_id
  )
);
create policy engagement_events_select_own_tenant
on public.engagement_events
for select
to authenticated
using (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagement_events.tenant_id
  )
);
create policy engagement_events_insert_own_tenant
on public.engagement_events
for insert
to authenticated
with check (
  exists (
    select 1
    from public.tenant_users
    where tenant_users.auth_user_id = auth.uid()
      and tenant_users.tenant_id = engagement_events.tenant_id
  )
);
