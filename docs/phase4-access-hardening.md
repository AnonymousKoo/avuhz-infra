# Phase 4 access hardening

The provider-neutral `public.avuhz_*` tables are authoritative command-service state. They cover generic acquisition and engagement, `ImplementationHandoff`, human approvals, idempotency, lifecycle events, transactional outbox, and Phase 5D execution governance through `QAResult`.

RLS is enabled on every table. `public`, `anon`, and `authenticated` receive no direct table authority. The non-login `avuhz_command_service` role has only the select, insert, and column-scoped update privileges required by the existing repositories. It has no delete authority. Database privilege never replaces command validation, trusted tenant/capability context, expected versions, or attributable human approval.

Tenant policies compare each row's `tenant_id` with the transaction-local `avuhz.tenant_id` value established from `TrustedExecutionContext`. Unbound service reads return no rows. Cross-tenant reads and writes fail closed. Immutable handoffs, approvals, lifecycle events, QA history, and client-acceptance history reject updates; bounded transition triggers protect mutable lifecycle records.

n8n, browsers, generic workloads, and provider adapters do not receive authoritative database credentials. They use bounded public contracts and command interfaces. Secrets and raw provider payloads remain prohibited.

The active migration is a local/disposable current-tree rebaseline. It is not remote lineage, has not been applied remotely, and is not authorized for `supabase db push`. Any future shared or production rollout requires a separate reviewed migration plan and explicit owner authorization.
