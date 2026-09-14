# Avuhz Architecture

This file is the current repository-level architecture source of truth. Detailed historical design material remains under `docs/`, but current implementation state is determined by this file, `docs/current-build-state.md`, canonical code, migrations/provider artifacts, and the latest bounded-authorization progress records.

## System role

Avuhz is a multi-tenant, API-first business operating-system control plane. Shared infrastructure belongs in Avuhz; verticals supply thin domain logic through governed contracts and may not create competing infrastructure paths.

Hard constraint: no vertical — roofing/home services, security/VerifiedPost, real estate/mortgage, or any other domain — may implement its own billing, authentication, tenant authority, or automation infrastructure. A vertical may define domain contracts, policies, and lifecycle logic, but it must consume the shared Avuhz backbone.

## Five control-plane primitives

### 1. Identity & Access

Implemented foundation:

- DEVELOPMENT AUTH is a dedicated Supabase project: `pwlhruwutoitnieactol`.
- `src/avuhz_service/development_identity.py` contains the provider-neutral trusted DEVELOPMENT identity resolver boundary.
- The hardened custom access-token hook exists remotely as `public.avuhz_development_custom_access_token_hook_v1(jsonb)` and is owned by the sealed migration identity.
- AUTH v16 is canonically `COMPLETED`; the hook is verified disabled and its ACL is restricted to the provider auth administrator path.
- Caller JWT role/scope/capability claims do not establish Avuhz authority. Trusted server policy constructs `TrustedExecutionContext`.

Current boundary: no synthetic DEVELOPMENT Auth identity has yet been created for end-to-end token validation, and the hosted DEVELOPMENT service still uses a fail-closed unavailable identity resolver.

### 2. Event-driven workflow/orchestration engine

Architectural rule: n8n is a bounded command/query client. It may invoke Avuhz APIs and workflows, but it may not write authoritative Avuhz tables directly or become an alternate authority path.

Current repository state: no canonical n8n workflow-export directory or n8n workflow JSON is present on `main`. Therefore orchestration infrastructure is not claimed as implemented here yet.

### 3. Data abstraction layer

Implemented foundation:

- DEVELOPMENT DATA is a separate Supabase project: `gnuqaefotwgkwurjpyik`.
- AUTH and DATA are separate physical projects and must never be conflated or substituted for one another.
- The canonical migration is `supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql`.
- The deployed DEVELOPMENT DATA surface contains 16 provider-neutral Avuhz tables.
- RLS is enabled on all 16 tables with one exact `avuhz_command_service_tenant_isolation` policy per table.
- The migration identity is sealed; application authority is distinct from migration authority.
- DATA v3 is canonically `COMPLETED` and the Supabase Security Advisor returned zero findings at the final verification.

The local DATA composition in `src/avuhz_service/development_data.py` is deliberately restricted to disposable loopback PostgreSQL. The hosted Render service does not yet inject a real Supabase DATA connector.

### 4. Communication layer

Required shared primitive: communications must be centralized behind Avuhz-owned provider adapters, including email-domain controls such as SPF/DKIM/DMARC, Twilio messaging where approved, and internal notification/event delivery.

Current repository state: no production or DEVELOPMENT email/Twilio communication adapter is present in the inspected canonical tree. No vertical may create a private communication infrastructure path to bypass the shared layer.

### 5. Billing engine

Required shared primitive: Avuhz must have one shared billing implementation using Stripe and usage metering derived from internal governed events. Vertical-specific billing engines are prohibited.

Current repository state: no Stripe billing adapter, billing service, or usage-metering implementation is present in the inspected canonical tree. This is a required future shared-core capability, not an existing implementation.

## Multi-tenant isolation model

The current DATA tenant model is implemented in PostgreSQL, not merely documented:

- every authoritative Avuhz table carries `tenant_id`;
- RLS is enabled on all 16 deployed Avuhz tables;
- each table has one `FOR ALL TO avuhz_command_service` tenant-isolation policy;
- the policy scopes access through `tenant_id = nullif(current_setting('avuhz.tenant_id', true), '')::uuid`;
- `TrustedExecutionContext.tenant_id` is transaction-locally bridged to `avuhz.tenant_id` by the governed UnitOfWork path;
- `PUBLIC`, `anon`, `authenticated`, and `service_role` have no direct Avuhz table grants;
- final DEVELOPMENT DATA certification observed the canonical command-service privilege surface only: 16 table `SELECT` grants, 15 table `INSERT` grants, and 47 narrowly scoped column `UPDATE` grants, with no unexpected command-service privileges.

Runtime identities must never own authoritative tables, receive `BYPASSRLS`, receive universal tenant authority, or receive migration/DDL authority.

## DEVELOPMENT runtime

The registered DEVELOPMENT command/query service is the Render service `avuhz-command-dev`. Its public liveness endpoint is intentionally independent from dependency readiness.

`src/avuhz_service/development.py` currently instantiates `_UnavailableIdentityResolver` and `_UnavailableUnitOfWork`. As a result, startup/liveness may be healthy while `/health/ready` remains `503`, and command/query requests fail closed before trusted identity resolution. This is the correct current behavior until separately authorized hosted AUTH and DATA adapters are wired.

## Repository resource map

- Canonical architecture: `ARCHITECTURE.md`
- Security/change controls: `SECURITY.md`
- Agent operating rules: `AGENTS.md`
- Current readiness state: `docs/current-build-state.md`
- Ordered roadmap: `docs/roadmap.md`
- Runtime and service code: `src/avuhz_runtime/`, `src/avuhz_service/`, `src/avuhz_worker/`
- Supabase migrations: `supabase/migrations/`
- Supabase provider artifacts: `supabase/provider-artifacts/`
- Bounded authorization plans/evidence: `contracts/plans/v1/`
- Tests: `tests/`
- n8n workflow exports: none present on canonical `main`
- Supabase Edge Functions: no edge-functions directory present on canonical `main`
- Dashboard application code: no dashboard application directory present on canonical `main`

## Authority boundaries

Repository registration, green CI, a healthy Render liveness endpoint, a completed AUTH/DATA migration, or a provider-read result does not authorize the next provider change. Every external resource action requires its own exact environment/project/responsibility confirmation, bounded authorization, preflight, execution, verification, and evidence consumption.

No staging or production AUTH/DATA projects are currently registered. Production remains `NOT_READY`, and Phase 6 must not begin until the engineering/production-readiness milestone is completed.

## Known Gaps

- The hosted DEVELOPMENT service is not connected to real AUTH or DATA adapters and therefore remains intentionally not ready.
- The custom access-token hook is created and hardened but remains disabled; no dedicated synthetic DEVELOPMENT Auth identity, tenant metadata binding, allowlist binding, token issuance, or end-to-end token validation is complete.
- No canonical n8n workflow exports are present in this repository.
- No shared communications provider adapter is implemented here yet.
- No shared Stripe billing/usage-metering engine is implemented here yet.
- No dashboard application code or Supabase Edge Functions are present in the inspected canonical tree.
- Hosted Grafana Cloud/OpenTelemetry, environment-scoped secret bindings, concrete network enforcement, staging, backup/restore proof, capacity/SLO proof, and production configuration remain incomplete.
- `docs/architecture.md` contains useful detailed historical design material, including older readiness snapshots. When it conflicts with this root file, current code/provider evidence, or `docs/current-build-state.md`, the newer canonical evidence wins.
