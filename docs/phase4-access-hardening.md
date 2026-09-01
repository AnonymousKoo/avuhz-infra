# Phase 4 access hardening

The provider-neutral `public.avuhz_*` tables are authoritative command-service state. They cover generic acquisition and engagement, `ImplementationHandoff`, human approvals, idempotency, lifecycle events, transactional outbox, and frozen Phase 5D execution governance through `DeploymentVerification`.

RLS is enabled on every table. `public`, `anon`, and `authenticated` receive no direct table authority. The non-login `avuhz_command_service` role has only the select, insert, and column-scoped update privileges required by the existing repositories. It has no delete authority. Database privilege never replaces command validation, trusted tenant/capability context, expected versions, or attributable human approval.

Tenant policies compare each row's `tenant_id` with the transaction-local `avuhz.tenant_id` value established from `TrustedExecutionContext`. Unbound service reads return no rows. Cross-tenant reads and writes fail closed. Immutable handoffs, approvals, lifecycle events, QA history, and client-acceptance history reject updates; bounded transition triggers protect mutable lifecycle records.

n8n, browsers, generic workloads, and provider adapters do not receive authoritative database credentials. They use bounded public contracts and command interfaces. Secrets and raw provider payloads remain prohibited.

The active baseline is the candidate canonical initial migration and first file in an ordered Git migration lineage. It is eligible only for a target proven through separately authorized read-only evidence to have no pre-existing Avuhz schema state. Its transaction-enclosed preflight rejects unexpected `avuhz_*` schema objects, validates the exact non-login/no-inheritance/no-bypass/no-membership command-service role contract when that role already exists, requires the migration identity's schema/role authority, and verifies PostgreSQL's built-in `gen_random_uuid` support before creating anything. It installs no extension.

Candidate status does not authorize remote application. No `supabase db push`, migration-history repair, provider connection, or shared-environment mutation is authorized. A failed initial application rolls back atomically. After a successful initial application, no generic destructive down migration is defined: schema/data destruction or restoration requires a separately reviewed recovery plan and exact owner authority; development recovery remains rebuild plus ordered Git migrations and approved synthetic seed data.
