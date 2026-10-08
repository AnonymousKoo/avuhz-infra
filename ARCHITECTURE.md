# Avuhz Architecture

Avuhz is a multi-tenant, API-first business operating-system control plane. This file describes what is implemented in this repository now; older design material under `docs/` is historical unless it agrees with current code, migrations/provider artifacts, and `docs/current-build-state.md`.

## Control-plane law

Shared infrastructure belongs in Avuhz. Verticals such as roofing, home services, security/VerifiedPost, real estate/mortgage, Sekinfra, or any future domain are thin domain logic on top of the shared backbone.

**Hard constraint:** no vertical may implement its own billing, authentication, tenant-authority, or automation infrastructure. Verticals may define domain contracts, policy, and lifecycle logic, but billing, auth, tenant isolation, and orchestration must remain shared Avuhz services.

## 1. Identity & Access

The implemented DEVELOPMENT identity boundary uses a dedicated Supabase AUTH project: `pwlhruwutoitnieactol`. DEVELOPMENT DATA uses a different Supabase project and must never be substituted for AUTH.

The current stack is:

- `src/avuhz_service/development_supabase_jwt.py`: ES256 JWT verification against the DEVELOPMENT Supabase JWKS, exact issuer, and exact command-service audience.
- `src/avuhz_service/development_supabase_identity.py`: a server-owned subject-digest allowlist with two exact DEVELOPMENT entries: one synthetic `HUMAN` identity limited to `engagement:read`, and one `PROVIDER_ADAPTER` identity limited to `implementation_handoff:accept`.
- `src/avuhz_runtime/guards.py`: trusted execution context plus environment, tenant, capability, subject, version, and human-authority guards.
- `supabase/provider-artifacts/development-auth/`: bounded AUTH SQL artifacts, including the hardened custom access-token hook function.

AUTH v21 created exactly one passwordless synthetic DEVELOPMENT Auth identity; AUTH v24 bound the canonical tenant in provider-controlled `app_metadata`; AUTH v26 bound the one read-only server allowlist tuple; AUTH v28 enabled the hosted Custom Access Token hook on `public.avuhz_development_custom_access_token_hook_v1`. The hook rewrites `aud` to `audience.avuhz.command-service.development` and emits `avuhz_tenant_id` only from validated `app_metadata`. The later DEVELOPMENT provider-adapter allowlist entry is present in the deployed v11 identity resolver, but its live positive-auth probe has not passed.

RBAC/ABAC is implemented as trusted server-side policy, not as caller-supplied role claims. `TrustedExecutionContext` carries principal, caller type, tenant, organization, capabilities, authority roles, environment, audience, and authentication strength; `GuardPipeline` evaluates those attributes before command execution. Caller JWT payload fields do not independently grant Avuhz authority.

There is no canonical Avuhz user-directory or organization-directory table in the 16-table DATA migration. Users are currently external AUTH identities resolved into a trusted principal. Tenant authority is carried as one canonical tenant UUID in provider-controlled AUTH metadata, checked against the matching entry in the two-entry server-owned allowlist, propagated as `TrustedExecutionContext.tenant_id`, and rebound transaction-locally for DATA RLS. `organization_id` exists in the trusted context model, but the current synthetic DEVELOPMENT resolver does not implement an organization membership directory or organization-admin model.

Current hosted code state: `src/avuhz_service/development.py` injects the certified `DevelopmentTrustedIdentityResolver`/Supabase JWT verifier path. Synthetic-token validation v3 and its temporary-credential retirement are complete. The separate provider-adapter positive-auth v14 continuation failed closed at the live runtime probe on October 8, 2026; its corrective cleanup subsequently recorded zero sessions/refresh tokens and independently verified the temporary AUTH key and GitHub environment secret absent. The DEVELOPMENT DATA path is also composed through the existing `PostgresStore`/`PostgresUnitOfWork`: the hosted connection boundary validates the canonical DATA endpoint host, the restricted `avuhz_data_runtime_service_dev` session, exact SET-only membership in `avuhz_command_service`, no migration-role SET access, zero direct runtime table grants, and SSL before `SET ROLE avuhz_command_service`. `PostgresUnitOfWork` then binds only the verified trusted tenant to transaction-local `avuhz.tenant_id`. Render deployment v11 completed on October 4, 2026, and hosted DEVELOPMENT AUTH/DATA readiness was previously certified. This does not establish a passing provider-adapter positive-auth probe or authorize `AcceptImplementationHandoff`.

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

`src/avuhz_runtime/postgres.py` and the UnitOfWork path bridge trusted tenant context into the transaction. `src/avuhz_service/development_data.py` preserves the disposable loopback certification composition and separately defines the hosted DEVELOPMENT connection boundary used by `src/avuhz_service/development.py`. Missing DSN, endpoint drift, runtime-role/ACL drift, missing SSL, failed command-role activation, or canonical table/RLS readiness mismatch fails closed. The adapter does not use PostgREST, Supabase `service_role`, migration identity, DDL, or a parallel repository path.

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

Python dependencies include `psycopg`, `PyJWT[crypto]`, `cryptography`, and `jsonschema`. The repository also pins the Supabase CLI for local/provider artifact work. The DEVELOPMENT Render service `avuhz-command-dev` is live on deployment v11 (`8e96e486d1173039a444c67849e26048282d6e9c`), which includes the hosted AUTH/DATA adapters and the two-entry DEVELOPMENT identity mapping. Hosted readiness was verified during that boundary. End-to-end positive provider-adapter authentication remains **unverified**; the October 8 v14 continuation live probe failed with sanitized code `LIVE_AUTH_PROBE_FAILED`. Its failure does not negate the earlier readiness certification.

## Provider boundaries and readiness

- Supabase DEVELOPMENT AUTH is project `pwlhruwutoitnieactol`; Supabase DEVELOPMENT DATA is project `gnuqaefotwgkwurjpyik`. Registration and repository evidence do not grant new provider read or mutation authority.
- `supabase/provider-artifacts/development-auth/` and `supabase/provider-artifacts/development-data/` are separate, allowlisted provider-artifact surfaces. AUTH-specific SQL is deliberately excluded from the automatic migration chain.
- `supabase/config.toml` is local configuration, not proof that a hosted service or Edge Function is deployed. Its permissive local network defaults and enabled local components are not production network policy.
- Render v11 is the current live DEVELOPMENT deployment, from commit `8e96e486d1173039a444c67849e26048282d6e9c`, and its hosted readiness certification is recorded in `docs/current-build-state.md`. The failed v14 live identity probe is a distinct authorization milestone. Render logged an application start during the failed GitHub Actions run, but no sanitized HTTP status for that probe is available, so a cold-start/timeout explanation remains a hypothesis, not a verified root cause.
- AUTH recovery/token cleanup, DATA runtime-login creation, and Render v11 readiness are completed historical evidence, not reusable authority. v14 continuation Step 1 remains `CONSUMED / FAILED / FAIL` and must not be retried. Its separate corrective cleanup is complete, including independent temporary credential/binding absence verification. Any new positive-auth execution, Render mutation, DATA change, n8n, communications, billing, staging, or production work requires its own exact authorization.
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

- Synthetic-token validation v3 and its temporary-credential retirement are complete. The later provider-adapter positive-auth v14 continuation failed closed at `live_runtime_probe`; the subsequent corrective cleanup recorded zero AUTH sessions and refresh tokens, then retired and independently verified both temporary credential references absent. All historical authorization remains consumed or stopped.
- Hosted DEVELOPMENT identity and DATA adapters were deployed and readiness-verified at Render v11. The remaining authentication blocker is a passing, separately authorized provider-adapter live identity probe. The v14 failure did not expose its exact HTTP status, and no post-failure retry is authorized.
- No canonical Avuhz user directory, organization directory, membership model, or organization-admin authority model is implemented in the 16-table DATA schema; current DEVELOPMENT identity remains a two-entry fixed allowlist.
- No canonical n8n workflow exports or deployed n8n integration are present.
- No shared communications provider adapter or SPF/DKIM/DMARC deployment configuration is implemented here.
- No shared Stripe billing/usage-metering engine is implemented here.
- No dashboard application code or Supabase Edge Function source is present.
- The preserved legacy public-schema inventory contains broad authenticated and anon-demo access patterns outside the `avuhz_*` authority path; those policies must be treated as legacy security debt rather than copied forward.
- Hosted observability/alerting, concrete network enforcement, backup/restore proof, capacity/SLO proof, isolated staging, and production configuration remain incomplete.
- `AcceptImplementationHandoff` end-to-end execution remains unperformed. Production readiness is `NOT_READY`, and Phase 6 is not yet authorized by the current roadmap.
