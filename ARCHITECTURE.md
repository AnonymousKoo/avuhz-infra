# Avuhz Architecture

Avuhz is a multi-tenant, API-first business operating-system control plane. This file describes what is implemented in this repository now; older design material under `docs/` is historical unless it agrees with current code, migrations/provider artifacts, and `docs/current-build-state.md`.

## Control-plane law

Shared infrastructure belongs in Avuhz. Verticals such as roofing, home services, security/VerifiedPost, real estate/mortgage, Sekinfra, or any future domain are thin domain logic on top of the shared backbone.

**Hard constraint:** no vertical may implement its own billing, authentication, tenant-authority, or automation infrastructure. Verticals may define domain contracts, policy, and lifecycle logic, but billing, auth, tenant isolation, and orchestration must remain shared Avuhz services.

## 1. Identity & Access

The implemented DEVELOPMENT identity boundary uses a dedicated Supabase AUTH project: `pwlhruwutoitnieactol`. DEVELOPMENT DATA uses a different Supabase project and must never be substituted for AUTH.

The current stack is:

- `src/avuhz_service/development_supabase_jwt.py`: ES256 JWT verification against the DEVELOPMENT Supabase JWKS, exact issuer, and exact command-service audience.
- `src/avuhz_service/development_supabase_identity.py`: one server-owned subject-digest allowlist entry mapped to one tenant and the single `engagement:read` capability.
- `src/avuhz_runtime/guards.py`: trusted execution context plus environment, tenant, capability, subject, version, and human-authority guards.
- `supabase/provider-artifacts/development-auth/`: bounded AUTH SQL artifacts, including the hardened custom access-token hook function.

AUTH v21 created exactly one passwordless synthetic DEVELOPMENT Auth identity; AUTH v24 bound the canonical tenant in provider-controlled `app_metadata`; AUTH v26 bound the one read-only server allowlist tuple; AUTH v28 enabled the hosted Custom Access Token hook on `public.avuhz_development_custom_access_token_hook_v1`. The hook rewrites `aud` to `audience.avuhz.command-service.development` and emits `avuhz_tenant_id` only from validated `app_metadata`.

RBAC/ABAC is implemented as trusted server-side policy, not as caller-supplied role claims. `TrustedExecutionContext` carries principal, caller type, tenant, organization, capabilities, authority roles, environment, audience, and authentication strength; `GuardPipeline` evaluates those attributes before command execution. Caller JWT payload fields do not independently grant Avuhz authority.

There is no canonical Avuhz user-directory or organization-directory table in the 16-table DATA migration. Users are currently external AUTH identities resolved into a trusted principal. Tenant authority is carried as one canonical tenant UUID in provider-controlled AUTH metadata, checked against one server-owned allowlist entry, propagated as `TrustedExecutionContext.tenant_id`, and rebound transaction-locally for DATA RLS. `organization_id` exists in the trusted context model, but the current synthetic DEVELOPMENT resolver does not implement an organization membership directory or organization-admin model.

Current hosted limitation: `src/avuhz_service/development.py` still instantiates `_UnavailableIdentityResolver`. The provider-specific verifier exists and is tested, but the hosted DEVELOPMENT service has not yet injected it. One short-lived synthetic-token end-to-end validation is also still not complete. The latest bounded DEVELOPMENT AUTH evidence reports two sessions and two refresh tokens and classifies the state as `SESSION_CLEANUP_REQUIRED`; cleanup v3 is prepared but unapproved and unexecuted. This unresolved state blocks hosted identity and DATA wiring.

## 2. Event-driven workflow / orchestration engine

n8n is the required shared orchestration engine, but **no canonical n8n workflow exports exist in this repository today**. File search found no workflow JSON/export directory, and `security/forbidden-path-patterns.txt` currently rejects `n8n-workflows/` and `.n8n/` paths.

The implemented event foundation beneath future orchestration is Avuhz-owned:

- `contracts/schemas/v1/orchestration/lifecycle-event.schema.json` defines append-only sanitized lifecycle events.
- `avuhz_lifecycle_events` stores non-authoritative transition events with `sanitized_metadata`.
- `avuhz_outbox_deliveries` plus `src/avuhz_worker/outbox.py` provide bounded at-least-once delivery with idempotency, leases, retries, and safe failure codes.
- n8n must consume Avuhz API/event boundaries; it must never become an alternate authority path or write authoritative Avuhz tables directly.

Because no n8n export is present, orchestration is an architectural primitive and integration target, not a claimed deployed implementation.

## 3. Data abstraction layer

DEVELOPMENT DATA is Supabase project `gnuqaefotwgkwurjpyik`. DEVELOPMENT AUTH is `pwlhruwutoitnieactol`. **These projects have different responsibilities and must never be conflated.**

The canonical provider-neutral schema is `supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql`. It creates 16 authoritative `avuhz_*` tables and the command-service database role `avuhz_command_service`.

For the authoritative Avuhz tables, the implemented isolation model is:

- every table carries `tenant_id`;
- RLS is enabled on all 16 tables;
- every table has one `avuhz_command_service_tenant_isolation` policy;
- the policy compares row `tenant_id` with transaction-local `current_setting('avuhz.tenant_id', true)`;
- `PUBLIC`, `anon`, `authenticated`, and `service_role` are explicitly revoked from direct Avuhz-table access;
- `avuhz_command_service` receives `SELECT` on all 16 tables, `INSERT` only on the 15 tables that support creation through the governed runtime, and column-scoped `UPDATE` grants for allowed transitions;
- runtime/application authority is separate from migration/DDL authority.

`src/avuhz_runtime/postgres.py` and the UnitOfWork path bridge trusted tenant context into the transaction. `src/avuhz_service/development_data.py` currently permits only disposable loopback PostgreSQL for certification; the hosted DEVELOPMENT service still uses `_UnavailableUnitOfWork`, so no real hosted Supabase DATA adapter is injected yet.

There is also a preserved legacy schema inventory at `supabase/inventory/current_public_schema.sql`. That inventory contains non-Avuhz tables with older broad policies such as `authenticated_full_access USING (true) WITH CHECK (true)` and anon demo-read policies. Those legacy policies are **not** the isolation model for the `avuhz_*` authority path and must not be copied into new Avuhz resources. They remain legacy security debt requiring separate ownership and remediation decisions.

## 4. Communication layer

The required shared communication layer includes email-domain controls (SPF, DKIM, DMARC), approved messaging providers such as Twilio, and internal notification delivery behind Avuhz-owned adapters.

What exists now is only local/provider configuration scaffolding: `supabase/config.toml` has local SMTP testing enabled and a disabled Twilio Auth configuration block that references an environment variable for the auth token. No Avuhz email adapter, Twilio adapter, SPF/DKIM/DMARC deployment configuration, or production notification provider implementation is present in the canonical tree.

No vertical may fill this gap by creating its own parallel communications infrastructure.

## 5. Billing engine

The required billing primitive is one shared Avuhz billing engine using Stripe with usage metering derived from governed internal events. Billing authority and metering must remain cross-domain infrastructure; vertical-specific Stripe integrations or billing ledgers are prohibited.

No Stripe SDK, Stripe adapter, billing service, usage-metering worker, or billing table is present in the inspected repository. This is a required shared-core capability, not an implemented one.

## API/runtime shape

The service is a Python WSGI command/query API. `src/avuhz_service/application.py` exposes `/v1/commands`, `/v1/queries`, and bounded health endpoints. Mutations have one governed Executor path; queries require trusted identity plus `engagement:read`. Responses are `no-store`, and the local request handler suppresses access logging because paths may contain authoritative identifiers.

Python dependencies include `psycopg`, `PyJWT[crypto]`, `cryptography`, and `jsonschema`. The repository also pins the Supabase CLI for local/provider artifact work. A DEVELOPMENT Render service is recorded in canonical state, but readiness remains intentionally fail-closed until hosted AUTH and DATA adapters are injected and independently verified.

## Provider boundaries and readiness

- Supabase DEVELOPMENT AUTH is project `pwlhruwutoitnieactol`; Supabase DEVELOPMENT DATA is project `gnuqaefotwgkwurjpyik`. Registration and repository evidence do not grant new provider read or mutation authority.
- `supabase/provider-artifacts/development-auth/` and `supabase/provider-artifacts/development-data/` are separate, allowlisted provider-artifact surfaces. AUTH-specific SQL is deliberately excluded from the automatic migration chain.
- `supabase/config.toml` is local configuration, not proof that a hosted service or Edge Function is deployed. Its permissive local network defaults and enabled local components are not production network policy.
- A DEVELOPMENT Render service and bounded historical health evidence are recorded in `docs/current-build-state.md`; liveness can pass while readiness remains `503` because the hosted provider adapters are unavailable.
- AUTH v28 and DATA v3 are completed provider-foundation evidence, not reusable authority. The active cleanup need, hosted adapter work, any Render change, n8n, communications, billing, staging, and production are distinct boundaries requiring their own authorization.
- Current platform production readiness is `NOT_READY`; `READY_FOR_PHASE6` is `NO`.

## Repository resource map

- Root architecture context: `ARCHITECTURE.md`
- Security/change rules: `SECURITY.md`
- Coding-agent rules: `AGENTS.md`
- Current implementation/readiness truth: `docs/current-build-state.md`
- Ordered roadmap: `docs/roadmap.md`
- Runtime/service/worker code: `src/avuhz_runtime/`, `src/avuhz_service/`, `src/avuhz_worker/`
- Contract schemas and bounded plans/evidence: `contracts/schemas/v1/`, `contracts/plans/v1/`
- Supabase canonical migration: `supabase/migrations/`
- Supabase provider-specific AUTH/DATA artifacts: `supabase/provider-artifacts/`
- Preserved legacy schema inventory: `supabase/inventory/current_public_schema.sql`
- Local Supabase configuration: `supabase/config.toml`
- Tests and security gates: `tests/`, `scripts/check-baseline.sh`, `.semgrep.yml`, `security/forbidden-path-patterns.txt`
- CI workflow definitions: `.github/workflows/`
- n8n workflow exports: **none present**
- Supabase Edge Functions: **none present**; `edge_runtime` is enabled in local config, but no function source directory exists
- Dashboard/frontend application code: **none present**

## Known Gaps

- End-to-end issuance and local validation of one short-lived synthetic DEVELOPMENT token is not complete.
- DEVELOPMENT AUTH currently has two sessions and two refresh tokens; cleanup is required, cleanup v3 has no approval or execution authority, and the dedicated credential-retirement obligation remains outstanding after cleanup completes or permanently stops.
- Hosted DEVELOPMENT identity and DATA adapters are not wired; `/health/ready` therefore remains intentionally unavailable.
- No canonical Avuhz user directory, organization directory, membership model, or organization-admin authority model is implemented in the 16-table DATA schema.
- No canonical n8n workflow exports or deployed n8n integration are present.
- No shared communications provider adapter or SPF/DKIM/DMARC deployment configuration is implemented here.
- No shared Stripe billing/usage-metering engine is implemented here.
- No dashboard application code or Supabase Edge Function source is present.
- The preserved legacy public-schema inventory contains broad authenticated and anon-demo access patterns outside the `avuhz_*` authority path; those policies must be treated as legacy security debt rather than copied forward.
- Hosted observability/alerting, concrete network enforcement, backup/restore proof, capacity/SLO proof, isolated staging, and production configuration remain incomplete.
- Production readiness is `NOT_READY`, and Phase 6 is not yet authorized by the current roadmap.
