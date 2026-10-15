# Avuhz Architecture

Avuhz is a multi-tenant, API-first business operating-system control plane. This file describes what is implemented in this repository now; older design material under `docs/` is historical unless it agrees with current code, migrations/provider artifacts, and `docs/current-build-state.md`.

## Control-plane law

Shared infrastructure belongs in Avuhz. Verticals such as roofing, home services, security/VerifiedPost, real estate/mortgage, Sekinfra, or any future domain are thin domain logic on top of the shared backbone.

**Hard constraint:** no vertical may implement its own billing, authentication, tenant-authority, or automation infrastructure. Verticals may define domain contracts, policy, and lifecycle logic, but billing, auth, tenant isolation, and orchestration must remain shared Avuhz services.

## 1. Identity & Access

The implemented DEVELOPMENT identity boundary uses a dedicated Supabase AUTH project: `pwlhruwutoitnieactol`. DEVELOPMENT DATA uses a different Supabase project and must never be substituted for AUTH.

The current stack is:

- `src/avuhz_service/development_supabase_jwt.py`: ES256 JWT verification against the DEVELOPMENT Supabase JWKS, exact issuer, and exact command-service audience.
- `src/avuhz_service/development_supabase_identity.py`: server-owned subject-digest allowlist entries for exact DEVELOPMENT identities and capabilities, including the historical human `engagement:read` and separately approved provider-adapter `implementation_handoff:accept` entries. An acquisition workload is not enrolled.
- `src/avuhz_runtime/guards.py`: trusted execution context plus environment, tenant, capability, subject, version, and human-authority guards.
- `supabase/provider-artifacts/development-auth/`: bounded AUTH SQL artifacts, including the hardened custom access-token hook function.

AUTH v21 created exactly one passwordless synthetic DEVELOPMENT Auth identity; AUTH v24 bound the canonical tenant in provider-controlled `app_metadata`; AUTH v26 bound the one read-only server allowlist tuple; AUTH v28 enabled the hosted Custom Access Token hook on `public.avuhz_development_custom_access_token_hook_v1`. The hook rewrites `aud` to `audience.avuhz.command-service.development` and emits `avuhz_tenant_id` only from validated `app_metadata`.

RBAC/ABAC is implemented as trusted server-side policy, not as caller-supplied role claims. `TrustedExecutionContext` carries principal, caller type, tenant, organization, capabilities, authority roles, environment, audience, and authentication strength; `GuardPipeline` evaluates those attributes before command execution. Caller JWT payload fields do not independently grant Avuhz authority.

The original 16-table provider-neutral DATA migration has no user/organization directory. Later DEVELOPMENT DATA acquisition registry artifacts added `public.avuhz_tenant_organizations` and `public.avuhz_tenant_owner_memberships`; see `supabase/provider-artifacts/development-data/current/development_data_shared_acquisition_registry_role_v1.sql`. October 13 aggregate evidence reports zero organizations and owner memberships. Installed tables are not owner verification. Users remain external AUTH identities resolved into trusted principals. Tenant authority is carried as one canonical tenant UUID in provider-controlled AUTH metadata, checked against one server-owned allowlist entry, propagated as `TrustedExecutionContext.tenant_id`, and rebound transaction-locally for DATA RLS. `organization_id` exists in the trusted context model, but the current synthetic DEVELOPMENT resolver does not implement an organization membership directory or organization-admin model.

Current hosted code state: `src/avuhz_service/development.py` injects the certified `DevelopmentTrustedIdentityResolver`/Supabase JWT verifier path, and synthetic-token validation v3 plus the repaired recovery/temporary-credential retirement lifecycle are complete. The DEVELOPMENT DATA path is also composed through the existing `PostgresStore`/`PostgresUnitOfWork`: the hosted connection boundary validates the canonical DATA endpoint host, the restricted `avuhz_data_runtime_service_dev` session, exact SET-only membership in `avuhz_command_service`, no migration-role SET access, zero direct runtime table grants, and SSL before `SET ROLE avuhz_command_service`. `PostgresUnitOfWork` then binds only the verified trusted tenant to transaction-local `avuhz.tenant_id`. Recorded Render v11 command-service deployment verified HTTP 200 startup/live/ready and fail-closed 401 anonymous commands/queries at its exact older commit (see `docs/current-build-state.md`). That evidence does not verify later source changes, an owner/tenant binding, or the still-unmounted acquisition HTTP route.

## 2. Event-driven workflow / orchestration engine

n8n is the required shared orchestrator. contracts/templates/n8n/ contains three inactive LOCAL/TEST source templates: a fail-closed shared receiver, a System #001 revenue-intake child, and an unconnected receipt-bridge child whose HTTP destination is intentionally unreachable and credential not bound. The separately installed local Avuhz receiver and Revenue Intake child on localhost:5678 are INACTIVE, along with an unrelated inactive AI Auto Marketing Check. None is a verified hosted integration or production workflow; security/forbidden-path-patterns.txt continues to reject n8n-workflows/ and .n8n/.

The implemented event foundation beneath future orchestration is Avuhz-owned:

- `contracts/schemas/v1/orchestration/lifecycle-event.schema.json` defines append-only sanitized lifecycle events.
- `avuhz_lifecycle_events` stores non-authoritative transition events with `sanitized_metadata`.
- `avuhz_outbox_deliveries` plus `src/avuhz_worker/outbox.py` provide bounded at-least-once delivery with idempotency, leases, retries, and safe failure codes.
- n8n must consume Avuhz API/event boundaries; it must never become an alternate authority path or write authoritative Avuhz tables directly.

Local-only n8n integration candidates now exist in `src/avuhz_worker/n8n_event_sink.py`, `local_n8n_receipt_http.py`, and `local_n8n_receipt_store.py`, with synthetic tests in `tests/integration/` and `tests/worker/`. The receipt bridge is explicitly LOCAL/TEST with a bounded loopback/private-bridge policy; it is not a hosted n8n receiver. No canonical workflow export or certified hosted delivery exists.

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

`src/avuhz_runtime/postgres.py` and the UnitOfWork path bridge trusted tenant context into the transaction. `src/avuhz_service/development_data.py` preserves the disposable loopback certification composition and separately defines the hosted DEVELOPMENT connection boundary used by `src/avuhz_service/development.py`. Missing DSN, endpoint drift, runtime-role/ACL drift, missing SSL, failed command-role activation, or canonical table/RLS readiness mismatch fails closed. The adapter does not use PostgREST, Supabase `service_role`, migration identity, DDL, or a parallel repository path.

The additional DEVELOPMENT acquisition registry is *not* part of the original 16-table baseline. Provider-specific DATA artifacts under `supabase/provider-artifacts/development-data/current/` govern `avuhz_tenant_organizations`, `avuhz_tenant_owner_memberships`, `avuhz_acquisition_intake_requests`, and `avuhz_acquisition_rate_limit_counters`. The October 13 provider readback documents FORCE RLS, acquisition-scoped policies, a distinct `avuhz_acquisition_service_dev` role, four rate-counter column grants, and SET-only membership for its non-admin login. The `development_data_acquisition_counter_role_access_v1` migration was **already applied** (version `20261012202521`); do not reapply. Installed permissions do not authorize a hosted credential, independent owner, or operational intake. Four separate Sekinfra OIA persistence tables were also reported FORCE RLS **without application runtime policies** and are not an active backend.

The shared service includes `development_owner_authentication.py`, `development_owner_mfa_freshness.py`, `development_business_owner_directory.py`, `development_tenant_registration.py`, `development_company_activation.py`, `development_acquisition_http.py` and `acquisition_intake_command.py` as tested candidates. There is no approved independent signed owner-verification source; the hosted acquisition HTTP route is still unmounted.

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

Python dependencies include `psycopg`, `PyJWT[crypto]`, `cryptography`, and `jsonschema`. The repository also pins the Supabase CLI for local/provider artifact work. A DEVELOPMENT Render service is recorded in canonical state. Hosted command-service AUTH and DATA adapters are composed in repository code, and the bounded historical DEVELOPMENT Render v11 command-service deploy/readiness check succeeded. This is **not** evidence that the current acquisition HTTP candidate, n8n receiver, OIA runtime, or public website intake is live.

## Provider boundaries and readiness

- Supabase DEVELOPMENT AUTH is project `pwlhruwutoitnieactol`; Supabase DEVELOPMENT DATA is project `gnuqaefotwgkwurjpyik`. Registration and repository evidence do not grant new provider read or mutation authority.
- `supabase/provider-artifacts/development-auth/` and `supabase/provider-artifacts/development-data/` are separate, allowlisted provider-artifact surfaces. AUTH-specific SQL is deliberately excluded from the automatic migration chain.
- `supabase/config.toml` is local configuration, not proof that a hosted service or Edge Function is deployed. Its permissive local network defaults and enabled local components are not production network policy.
- A DEVELOPMENT Render command service and historical v11 readiness (HTTP 200 for health probes, HTTP 401 for anonymous API operations) are recorded in `docs/current-build-state.md`. That evidence is pinned to its deployed commit; it must not be extrapolated to later development code or the unmounted acquisition/OIA intake. The separate Sekinfra public intake is still HTTP 503.
- AUTH recovery/token cleanup and DATA v15 runtime-login creation are completed historical evidence, not reusable authority. Connected DATA validation, any Render secret/deploy/readiness change, n8n, communications, billing, staging, and production are distinct boundaries requiring their own authorization.
- Current platform production readiness is `NOT_READY`; `READY_FOR_PHASE6` is `NO`.

## Infrastructure Authority V1 source candidate

A side-effect-free DEVELOPMENT desired-versus-observed-state candidate exists
in src/avuhz_runtime/infrastructure_state_review.py, reusing Phase 5D
target/resource digest conventions. It does not discover provider resources,
attest observation sources, persist an inventory, authorize execution or
verify deployments. There is no certified live Infrastructure Authority V1
operational loop.

## Repository resource map

- Root architecture context: `ARCHITECTURE.md`
- Security/change rules: `SECURITY.md`
- Coding-agent rules: `AGENTS.md`
- Current implementation/readiness truth: `docs/current-build-state.md` and October 13 first-client readback `docs/development-first-client-readiness-20261013.md`
- Ordered roadmap: `docs/roadmap.md`
- Runtime/service/worker code: `src/avuhz_runtime/`, `src/avuhz_service/`, `src/avuhz_worker/`
- Contract schemas and bounded plans/evidence: `contracts/schemas/v1/`, `contracts/plans/v1/`
- Supabase canonical migration: `supabase/migrations/`
- Supabase provider-specific AUTH/DATA artifacts: `supabase/provider-artifacts/`
- Preserved legacy schema inventory: `supabase/inventory/current_public_schema.sql`
- Local Supabase configuration: `supabase/config.toml`
- Tests and security gates: `tests/`, `scripts/check-baseline.sh`, `.semgrep.yml`, `security/forbidden-path-patterns.txt`
- CI workflow definitions: `.github/workflows/`
- n8n: three inactive source templates under contracts/templates/n8n/, with one new uninstalled receipt child; LOCAL/TEST event/receipt adapters in src/avuhz_worker/. No hosted receiver or production automation integration is proven.
- Supabase Edge Functions: **none present**; `edge_runtime` is enabled in local config, but no function source directory exists
- Dashboard/frontend application code: **none in this repository**; public Sekinfra website code belongs to the separate `AnonymousKoo/sekinfra` repository

## Known Gaps

- First-client DEVELOPMENT gates G0/G1 (verified owner/authority and pending/active enrollment), G2 (distinct acquisition AUTH workload), G3 (private DATA runtime credential), G5 (hosted ingress), G6 (authenticated hosted n8n receipt) and G7 (synthetic end-to-end before real consented intake) remain incomplete per `docs/development-first-client-readiness-20261013.md`. G4 counter access is already installed; retention/pruning and public anti-abuse controls still require proof. No synthetic identity or prior approval may substitute for an actual verified business owner.

- Synthetic-token validation v3, repaired recovery cleanup, and the dedicated temporary-credential retirement are complete; their consumed authority grants no further provider action.
- The historical DEVELOPMENT Render v11 command-service deploy/readiness passed for its bound commit, but the later first-client acquisition/OIA work has not been deployed or authorized. Do not label the shared acquisition HTTP ingress, n8n receipt, or Sekinfra public intake live on the strength of command-service readiness.
- The original 16-table DATA schema has no user/organization directory. Later DEVELOPMENT tenant/owner/acquisition registries exist, but no verified active business-owner binding, independently approved live owner-directory provider, or active acquisition workload exists.
- Synthetic n8n event sink and local durable receipt-bridge code exist, with three inactive source templates. The new child lacks a credential, reachable private endpoint, and a receiver connection. System #001 also includes a shared LOCAL/TEST, side-effect-free follow-up due/overdue review candidate in src/avuhz_service/shared_revenue_followup_review.py; no durable next-action deadline or notification is implemented by that reviewer. A preflight-default LOCAL/TEST receipt-service launcher exists in src/avuhz_worker/local_n8n_receipt_dev_runner.py; it has not been started or connected to credentials. A source-only candidate to add next_action_due_at to the shared Work Item is at supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql, but it has NOT been applied to DEVELOPMENT DATA and no authoritative deadline command exists. A separate source-only migration candidate proposes five non-PII acquisition metadata SELECT column privileges for the existing shared command role at supabase/migrations/20261015193000_grant_shared_acquisition_handoff_metadata_read.sql; this is NOT applied or an authorized acquisition/owner resolver. No certified hosted receiver or production orchestration integration is present.
- No shared communications provider adapter or SPF/DKIM/DMARC deployment configuration is implemented here.
- No shared Stripe billing/usage-metering engine is implemented here.
- No dashboard application code or Supabase Edge Function source is present **in this repo**. The separate Sekinfra website returns HTTP 503 for diagnostic intake; the four installed OIA tables have FORCE RLS but no application runtime policies.
- The preserved legacy public-schema inventory contains broad authenticated and anon-demo access patterns outside the `avuhz_*` authority path; those policies must be treated as legacy security debt rather than copied forward.
- Hosted observability/alerting, concrete network enforcement, backup/restore proof, capacity/SLO proof, isolated staging, and production configuration remain incomplete.
- Production readiness is `NOT_READY`, and Phase 6 is not yet authorized by the current roadmap.
