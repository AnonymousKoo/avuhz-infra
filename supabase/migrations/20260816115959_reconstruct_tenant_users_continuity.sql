-- LOCAL-ONLY CONTINUITY RECONSTRUCTION.
-- This is not proven original historical SQL and is derived solely from the
-- current public-schema inventory. It exists to let local shadow replay apply
-- 20260816120000_create_onboarding_engagements.sql; never push it to the
-- existing linked project or treat it as a tenant_users redesign.

create table if not exists public.tenant_users (
  id uuid default gen_random_uuid() not null,
  tenant_id uuid not null,
  auth_user_id uuid,
  role text not null default 'broker',
  full_name text,
  created_at timestamptz default now()
);

alter table only public.tenant_users
  add constraint tenant_users_pkey primary key (id);

create index idx_tenant_users_tenant_id
  on public.tenant_users (tenant_id);

alter table only public.tenant_users
  add constraint tenant_users_auth_user_id_fkey
  foreign key (auth_user_id) references auth.users(id);

alter table public.tenant_users enable row level security;
