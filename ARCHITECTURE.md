# Avuhz Architecture

Avuhz is a client-neutral infrastructure authority and governance control plane. It owns the shared boundaries that establish who may request a resource change, which tenant and resources are in scope, what policy and human approval permit, how restricted execution occurs, and what independent verification and audit can prove.

This file separates normative architecture from implemented source and recorded provider evidence. Source was inspected at cached `origin/main` commit `55ff37f2c70c31e9988340dacdb7577e43bbb5a9` on 2026-10-19. The former completion snapshot at `99130ed4c57eccd839076c46a82405eacc6b666a` is historical. No provider was contacted for this revision: hosted, AUTH/DATA, website and localhost n8n observations below retain their original evidence dates and resource/commit boundaries in `docs/current-build-state.md`, `docs/development-first-client-readiness-20261013.md` and exact execution artifacts. They are not fresh observations at `55ff37f`.

## Control-plane law

Avuhz owns identity and trusted tenant/resource ownership, approval and policy enforcement, authoritative resource/change state, execution boundaries, and attested verification/audit. These are shared, client-neutral services. Existing domain records and contracts remain valid for their original scope; their presence does not make a business operating-system journey the infrastructure release target.

| Boundary | Responsibility and limit |
|---|---|
| Avuhz | Establish trusted principals and resource scope; govern desired state, policy decisions, bounded approvals, execution state, independent verification and sanitized audit. A proposed change, event, report or observation is not authority by itself. |
| OIA | Own diagnostics, assessment methodology, findings and recommendations. Consume Avuhz authority boundaries; a diagnostic finding cannot approve or execute infrastructure changes. |
| Sekinfra | Own the client-facing experience and its domain behavior. Consume shared services without creating separate identity, tenant authority, billing or orchestration infrastructure. |
| Reusable systems, including System #001 | Own domain contracts and lifecycle logic. Domain policy may further constrain a request but cannot enlarge Avuhz authority or bypass shared controls. Avuhz must not depend on a system's private implementation. |
| n8n | Orchestrate already approved work through Avuhz APIs/events. It grants no authority and must never write authoritative Avuhz tables directly. |
| Terraform, Ansible, Helm | Supply desired-state artifacts or perform execution only inside a properly authorized Avuhz boundary. A plan, playbook, chart, tool credential or successful command cannot supply approval or independent verification. These are permitted integration roles, not claims of implemented adapters. |

**Hard constraint:** no vertical may implement its own authentication, tenant authority, billing, communications or automation infrastructure. Shared capabilities remain Avuhz-owned even when outside the infrastructure LOCAL v1 critical path. Lifecycle events, outbox records, receipts, logs and read models never substitute for authoritative resource/change state. Client-system deployment authorization and Avuhz platform change authority remain distinct.

## Normative authority loop

`AUTHENTICATE + SCOPE -> approved desired state + trusted observation -> policy -> bounded human authorization -> restricted execution -> independent verification -> audit`

1. **AUTHENTICATE + SCOPE:** authenticate the principal and derive tenant, resource ownership, environment, namespace, responsibility and allowed operation from trusted server-owned evidence. Caller fields, a supplied tenant UUID or a resource name cannot establish scope. Reject unauthenticated, cross-tenant, wrong-resource or wrong-environment requests before dispatch.
2. **Approved desired state + trusted observation:** bind an immutable desired-state version/digest to the exact resource set and its approval provenance. Independently attest the observed state, collector identity, tenant/resource/environment binding, collection time and freshness. A syntactically valid provenance reference or matching digest is insufficient. Desired-state approval does not grant execution permission.
3. **Policy:** evaluate a versioned deterministic policy over those exact inputs and trusted scope. Record allow/deny and bounded reason codes. Missing, stale, untrusted or conflicting evidence fails closed. A state mismatch is a review input, never an automatic remediation instruction; it may support a proposed change only after policy and exact approval.
4. **Bounded human authorization:** require a verifiable authorized human decision bound to the request, tenant, environment, namespace, exact resources and operation, desired-state and observation digests, policy version/decision, executor identity, validity window, attempt limit and recovery limits. Policy allow alone is not approval. Changed inputs, expiration, revocation or consumed authority require denial and, if work is still needed, fresh authorization.
5. **Restricted execution:** immediately recheck scope, approval, freshness and expected pre-state; atomically claim the bounded attempt/idempotency identity before dispatch through the governed Executor/API boundary. The adapter can perform only the approved operation on the approved resource. It cannot acquire wider credentials, change targets or self-authorize retries. Keep runtime authority separate from migration/DDL authority.
6. **Independent verification:** use a separately trusted observer/verifier to re-observe resulting state and compare it with approved postconditions. The executor's success message cannot verify itself. Failed or ambiguous execution and failed verification remain explicit unsuccessful/unverified states; recovery follows its own bounded authority and verification without erasing failed evidence.
7. **Audit:** durably retain sanitized, tenant-scoped links among request, trusted scope, desired state, attested observations, policy, approval, attempt, verification and recovery. Authoritative change state must distinguish proposed, denied, authorized, attempted, failed/ambiguous and independently verified outcomes. Audit records evidence those transitions; they cannot grant new authority. Do not persist credentials, raw provider payloads, unnecessary PII or secret-derived material.

This loop is the required architecture, **not an implemented or certified end-to-end capability**. Deterministic local fake identity, approval, observation and execution adapters are sufficient for infrastructure LOCAL v1 when they preserve these distinct trust boundaries and prove the positive and denial/failure paths in `AVUHZ_V1_COMPLETION.md`. All tenants/resources are fictional; no live infrastructure mutation, provider credentials or provider contact is part of that certification. DEVELOPMENT and production remain `NOT_READY` for this release.

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

Hosted composition in source and recorded deployment evidence: `src/avuhz_service/development.py` injects the certified `DevelopmentTrustedIdentityResolver`/Supabase JWT verifier path, and synthetic-token validation v3 plus the repaired recovery/temporary-credential retirement lifecycle are complete. The DEVELOPMENT DATA path is also composed through the existing `PostgresStore`/`PostgresUnitOfWork`: the hosted connection boundary validates the canonical DATA endpoint host, the restricted `avuhz_data_runtime_service_dev` session, exact SET-only membership in `avuhz_command_service`, no migration-role SET access, zero direct runtime table grants, and SSL before `SET ROLE avuhz_command_service`. `PostgresUnitOfWork` then binds only the verified trusted tenant to transaction-local `avuhz.tenant_id`. Recorded Render v11 command-service deployment verified HTTP 200 startup/live/ready and fail-closed 401 anonymous commands/queries at its exact older commit (see `docs/current-build-state.md`). That evidence does not verify later source changes, an owner/tenant binding, or the still-unmounted acquisition HTTP route.

## 2. Event-driven workflow / orchestration engine

n8n is the required shared orchestrator for domain orchestration, outside the infrastructure LOCAL v1 critical path. `contracts/templates/n8n/` contains five inactive LOCAL/TEST source templates at `55ff37f`: the original shared receiver, System #001 revenue-intake child and unconnected receipt-bridge child, plus the durable shared receiver v2 and receipt-gated System #001 child v2. The original receipt-bridge child has an intentionally unreachable HTTP destination and no bound credential. Recorded local installation evidence describes the Avuhz receiver and Revenue Intake child on localhost:5678 as INACTIVE, along with an unrelated inactive AI Auto Marketing Check; that installation was not re-inspected for this revision. None is a verified hosted integration or production workflow; security/forbidden-path-patterns.txt continues to reject n8n-workflows/ and .n8n/.

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

Source-only shared communications now exists in `src/avuhz_worker/shared_communications_local.py`: an adapter protocol and deterministic LOCAL/TEST fake, with coverage in `tests/worker/test_shared_communications_local.py`. It produces fictional in-memory, non-authoritative receipts and performs no external send. Constructor context checks assume trusted in-process composition; the sink protocol cannot attest its caller or a committed outbox claim. This is neither durable delivery proof nor send authority.

`supabase/config.toml` also has local SMTP testing enabled and a disabled Twilio Auth configuration block referencing an environment variable. No live Avuhz email/Twilio adapter, SPF/DKIM/DMARC deployment configuration or production notification provider implementation is established here. Shared communications is outside the infrastructure LOCAL v1 critical path.

No vertical may fill this gap by creating its own parallel communications infrastructure.

## 5. Billing engine

The required billing primitive is one shared Avuhz billing engine using Stripe with usage metering derived from governed internal events. Billing authority and metering must remain cross-domain infrastructure; vertical-specific Stripe integrations or billing ledgers are prohibited.

Source-only shared usage metering exists in `src/avuhz_worker/shared_usage_billing_local.py`, with an adapter protocol, deterministic LOCAL/TEST billing fake and `tests/worker/test_shared_usage_billing_local.py`. It records allowlisted sanitized event measurements in memory; these are non-authoritative, not a billing ledger or charges. Its sink likewise assumes trusted in-process composition and does not attest caller or event origin. It calculates no price, issues no invoice and moves no money.

No Stripe SDK, live Stripe adapter, authoritative billing service/table or hosted metering engine is implemented here. Communications and usage fakes are composed in `src/avuhz_worker/shared_engagement_delivery_local.py` and exercised by `tests/integration/test_avuhz_local_v1_unified_acceptance.py`; that historical shared-domain journey does not certify the infrastructure authority loop. Billing and usage integration are outside infrastructure LOCAL v1's critical path.

## API/runtime shape

The service is a Python WSGI command/query API. `src/avuhz_service/application.py` exposes `/v1/commands`, `/v1/queries`, and bounded health endpoints. Mutations have one governed Executor path; queries require trusted identity plus `engagement:read`. Responses are `no-store`, and the local request handler suppresses access logging because paths may contain authoritative identifiers.

Python dependencies include `psycopg`, `PyJWT[crypto]`, `cryptography`, and `jsonschema`. The repository also pins the Supabase CLI for local/provider artifact work. A DEVELOPMENT Render service is recorded in canonical state. Hosted command-service AUTH and DATA adapters are composed in repository code, and the bounded historical DEVELOPMENT Render v11 command-service deploy/readiness check succeeded. This is **not** evidence that the current acquisition HTTP candidate, n8n receiver, OIA runtime, or public website intake is live.

## Provider boundaries and readiness

- Supabase DEVELOPMENT AUTH is project `pwlhruwutoitnieactol`; Supabase DEVELOPMENT DATA is project `gnuqaefotwgkwurjpyik`. Registration and repository evidence do not grant new provider read or mutation authority.
- `supabase/provider-artifacts/development-auth/` and `supabase/provider-artifacts/development-data/` are separate, allowlisted provider-artifact surfaces. AUTH-specific SQL is deliberately excluded from the automatic migration chain.
- `supabase/config.toml` is local configuration, not proof that a hosted service or Edge Function is deployed. Its permissive local network defaults and enabled local components are not production network policy.
- A DEVELOPMENT Render command service and historical v11 readiness (HTTP 200 for health probes, HTTP 401 for anonymous API operations) are recorded in `docs/current-build-state.md`. That evidence is pinned to its deployed commit; it must not be extrapolated to later development code or the unmounted acquisition/OIA intake. The October 13 readback records the separate Sekinfra public intake as HTTP 503; no fresh website check is claimed.
- AUTH recovery/token cleanup and DATA v15 runtime-login creation are completed historical evidence, not reusable authority. Connected DATA validation, any Render secret/deploy/readiness change, n8n, communications, billing, staging, and production are distinct boundaries requiring their own authorization.
- Current platform production readiness is `NOT_READY`; `READY_FOR_PHASE6` is `NO`.

## Infrastructure Authority V1 source candidate

`src/avuhz_runtime/infrastructure_state_review.py` is a pure LOCAL/TEST comparison candidate that currently accepts only targets labeled `DEVELOPMENT`, reusing Phase 5D resource/digest conventions. That label is an input constraint, not provider access or DEVELOPMENT certification. `tests/architecture/test_infrastructure_state_review_v1.py` exercises its limited comparison behavior.

It checks shapes, supplied tenant/resource/environment consistency, duplicate/extra targets and claimed timestamps against an injected clock, then compares expected and observed artifact digests. Missing, stale or future observations yield `BLOCKED`; equal/different digests yield `MATCHED`/`MISMATCHED`. It validates provenance/fingerprint **syntax**, not provenance authenticity or actual state. A caller can supply well-shaped false claims; matching them does not establish trust.

It does **not** authenticate, discover resources, attest observations, establish approved desired state, authorize, execute, remediate, persist inventory/audit or verify deployments. The trust chain, bounded fake execution, independent post-state verification, durable audit and recovery composition remain infrastructure LOCAL v1 gaps. Reusing this module requires an explicit LOCAL/TEST composition design; relabeling fictional inputs `DEVELOPMENT` is not certification. `docs/infrastructure-authority-v1-state-review-source.md` and `docs/infrastructure-authority-v1-render-observation-candidate.md` retain their historical, separately gated provider proposals; neither is a prerequisite or authority for LOCAL v1. The normative release criteria are in `AVUHZ_V1_COMPLETION.md`.

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
- n8n: five inactive source templates under `contracts/templates/n8n/` at `55ff37f`; earlier installation evidence does not establish installation of the later templates. LOCAL/TEST event/receipt adapters are in `src/avuhz_worker/`. No hosted receiver or production automation integration is proven.
- Supabase Edge Functions: **none present**; `edge_runtime` is enabled in local config, but no function source directory exists
- Dashboard/frontend application code: **none in this repository**; public Sekinfra website code belongs to the separate `AnonymousKoo/sekinfra` repository

## Known Gaps

- Infrastructure LOCAL v1 is not certified: the complete authority loop and denial/recovery evidence specified in `AVUHZ_V1_COMPLETION.md` remain required. Domain onboarding, OIA, System #001 intake, n8n, communications and billing journeys are separate capability tracks, not substitutes for or blockers of that certification.

- First-client DEVELOPMENT gates G0/G1 (verified owner/authority and pending/active enrollment), G2 (distinct acquisition AUTH workload), G3 (private DATA runtime credential), G5 (hosted ingress), G6 (authenticated hosted n8n receipt) and G7 (synthetic end-to-end before real consented intake) remain incomplete per `docs/development-first-client-readiness-20261013.md`. G4 counter access is already installed; retention/pruning and public anti-abuse controls still require proof. No synthetic identity or prior approval may substitute for an actual verified business owner.

- Synthetic-token validation v3, repaired recovery cleanup, and the dedicated temporary-credential retirement are complete; their consumed authority grants no further provider action.
- The historical DEVELOPMENT Render v11 command-service deploy/readiness passed for its bound commit, but the later first-client acquisition/OIA work has not been deployed or authorized. Do not label the shared acquisition HTTP ingress, n8n receipt, or Sekinfra public intake live on the strength of command-service readiness.
- The original 16-table DATA schema has no user/organization directory. Later DEVELOPMENT tenant/owner/acquisition registries exist, but no verified active business-owner binding, independently approved live owner-directory provider, or active acquisition workload exists.
- Synthetic n8n event sink and local durable receipt-bridge code exist, with five inactive source templates at the inspected ref. The original receipt-bridge child lacks a credential, reachable private endpoint, and a receiver connection. System #001 also includes a shared LOCAL/TEST, side-effect-free follow-up due/overdue review candidate in src/avuhz_service/shared_revenue_followup_review.py; no durable next-action deadline or notification is implemented by that reviewer. A preflight-default LOCAL/TEST receipt-service launcher exists in src/avuhz_worker/local_n8n_receipt_dev_runner.py; it has not been started or connected to credentials. A source-only candidate to add next_action_due_at to the shared Work Item is at supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql, but it has NOT been applied to DEVELOPMENT DATA and no authoritative deadline command exists. A separate source-only migration candidate proposes five non-PII acquisition metadata SELECT column privileges for the existing shared command role at supabase/migrations/20261015193000_grant_shared_acquisition_handoff_metadata_read.sql; this is NOT applied or an authorized acquisition/owner resolver. No certified hosted receiver or production orchestration integration is present.
- A source-only shared communications protocol/fake exists; a live provider adapter and SPF/DKIM/DMARC deployment configuration remain gaps outside infrastructure LOCAL v1.
- A source-only shared usage protocol/billing fake exists; a live Stripe billing/usage-metering engine remains a gap outside infrastructure LOCAL v1.
- No dashboard application code or Supabase Edge Function source is present **in this repo**. The October 13 evidence records HTTP 503 for separate Sekinfra diagnostic intake and four installed OIA tables with FORCE RLS but no application runtime policies; no current provider read is implied.
- The preserved legacy public-schema inventory contains broad authenticated and anon-demo access patterns outside the `avuhz_*` authority path; those policies must be treated as legacy security debt rather than copied forward.
- Hosted observability/alerting, concrete network enforcement, backup/restore proof, capacity/SLO proof, isolated staging, and production configuration remain incomplete.
- Production readiness is `NOT_READY`, and Phase 6 is not yet authorized by the current roadmap.
