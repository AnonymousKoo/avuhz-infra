# Phase 4 access hardening

The seven Slice 1 `public.avuhz_*` tables are authoritative command-service
state: acquisition handoffs, engagements, diagnostic scopes, human approvals,
idempotency records, lifecycle events, and outbox deliveries. Row-level
security remains enabled and `anon` and `authenticated` receive no direct table
privileges or policies. Slice 1 has no client-table read requirement.

The trusted server-side command service uses its injected privileged database
connection only after command validation and trusted context resolution. Database
privilege is not business authority: `TrustedExecutionContext`, environment,
tenant, capability, subject/version, and human-approval guards remain mandatory.
Payload tenant claims, browser organization claims, n8n claims, and unverified
JWT fields do not establish tenant authority.

n8n is an orchestration client only. It must call the bounded internal command
API and must never receive a credential capable of direct `avuhz_*` writes.
The same prohibition covers browser clients and generic workloads. Outbox,
idempotency, lifecycle-event, and HumanApproval mutations are command-service
artifacts, not direct SQL capabilities.

The Phase 4C migration is local-stack tested only. The reconstructed
`20260816115959_reconstruct_tenant_users_continuity.sql` migration is local
continuity, not linked-project history. A future production rollout must first
inspect the actual remote schema and migration history, reconcile that local
continuity migration, prepare a reviewed remote-safe application plan, verify
the production service identity and secrets, apply deliberately, then run
post-deployment access assertions. Never use a blind `supabase db push` for
this local chain.
