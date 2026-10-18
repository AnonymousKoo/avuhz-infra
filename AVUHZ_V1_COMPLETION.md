# Avuhz V1 Completion Checklist

Snapshot date: **2026-10-17**

Tracked source: **`origin/main` at `99130ed4c57eccd839076c46a82405eacc6b666a` (`99130ed`)**

Scope: **Avuhz shared platform, local first, client neutral**

This is a source snapshot, not a provider inventory. **Current provider state is unverified.** Historical provider evidence in the tree remains useful only for its exact recorded resource and commit; source, tests, templates, plans, or earlier readiness evidence do not prove that a workflow, migration, route, credential, service, or tenant is currently installed, activated, or healthy.

This checklist tracks Avuhz V1 only. **System 001 is a separate client system owned by another chat.** Its private behavior, workflow activation, deployment, data, and acceptance are not Avuhz V1 completion evidence. Shared primitives exercised by System 001 tests may count only as evidence for the client-neutral Avuhz boundary they directly test. Sekinfra is likewise one possible vertical, not the default client or first-client assumption.

## Completion boundary

**Local V1** means a clean checkout can prove one fictional, client-neutral journey through trusted identity, tenant/organization/owner denial, governed onboarding and work intake, authoritative persistence, sanitized lifecycle/outbox delivery, the shared LOCAL/TEST n8n boundary, deterministic communications and usage/billing fakes, and replay safety without provider credentials.

**DEVELOPMENT and production are separate evidence classes.** This snapshot makes no current provider claim. Any provider-dependent status requires a fresh exact read of the named environment and resource under separate authority. Production remains `NOT_READY` and is not authorized by this document.

The original provider-neutral migration defines 16 authoritative `avuhz_*` tables. Mainline is broader: `supabase/migrations/20261014034000_create_shared_work_items.sql` defines one additional authoritative shared Work Item source candidate, while DEVELOPMENT-specific artifacts separately describe tenant organizations, owner memberships, acquisition intake requests, and acquisition rate counters. Do not collapse these distinct source/provider boundaries into “only 16 tables,” and do not infer that any later candidate is applied from its presence in Git.

Status vocabulary:

- `SOURCE-VERIFIED`: the stated repository-local or LOCAL/TEST capability exists at the tracked ref and has focused source evidence; it is not a hosted-runtime claim.
- `PARTIAL`: relevant source or design exists, but the stated acceptance criterion is not complete.
- `NOT STARTED`: mainline contains no implementation of the stated shared capability.
- `BLOCKED`: promotion is prohibited until the named prerequisites and authority are satisfied.

## Four-lane 14-item tracker

| Priority | Lane | Task | Status | Owner | Dependency | Mainline evidence | Evidence-driven completion criterion |
|---:|---|---|---|---|---|---|---|
| 1 | Security | Preserve authority separation, least privilege, tenant RLS, and fail-closed changes | `SOURCE-VERIFIED` | Platform security + data owner | None | `SECURITY.md`; `ARCHITECTURE.md`; `supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql`; `supabase/migrations/20261014034000_create_shared_work_items.sql` | Source checks distinguish the original 16-table baseline, the additional Work Item candidate, and provider-specific acquisition artifacts; each authoritative table in scope has exact tenant RLS, least-privilege grants, and negative cross-tenant proof before being called complete. No provider-applied claim is made without fresh readback. |
| 2 | Business | Complete client-neutral tenant, organization, and owner onboarding | `PARTIAL` | Platform product + identity owner | 1 | `src/avuhz_service/development_owner_authentication.py`; `src/avuhz_service/development_business_owner_directory.py`; `src/avuhz_service/development_tenant_registration.py`; `src/avuhz_service/development_company_activation.py`; `tests/service/test_development_tenant_registration.py`; `tests/service/test_development_company_activation.py` | One fictional company can move through independently verified owner identity, PENDING registration, and ACTIVE enrollment using shared interfaces and transactional tenant isolation. The current dormant candidates and tests are source evidence only; no synthetic/self-approved owner or live tenant is inferred. |
| 3 | Security | Keep identity, membership, and command authority server-derived and denial-tested | `SOURCE-VERIFIED` | Runtime security owner | 1, 2 | `src/avuhz_runtime/guards.py`; `src/avuhz_service/development_owner_mfa_freshness.py`; `src/avuhz_service/shared_acquisition_commit_admission.py`; `tests/runtime/test_guard_pipeline.py`; `tests/service/test_shared_acquisition_commit_admission.py` | Focused tests deny forged claims, stale authentication, revoked membership, wrong tenant/organization, wrong capability, and caller-supplied authority; an n8n receipt or lifecycle event never grants business authority. |
| 4 | Infrastructure | Maintain the provider-neutral command/query runtime and single transaction boundary | `SOURCE-VERIFIED` | Platform runtime owner | 1, 3 | `src/avuhz_service/application.py`; `src/avuhz_runtime/runtime.py`; `src/avuhz_runtime/postgres.py`; `tests/service/test_service.py`; `tests/runtime/test_executor_repository_usage.py` | Local commands and queries use the governed executor/UoW path, bind only trusted tenant context transaction-locally, and roll back authoritative state plus outbox intent atomically on failure. |
| 5 | Business | Preserve Phase 5 contracts and connect OIA to the client-neutral lifecycle | `PARTIAL` | Platform product/contract owner | 2, 4 | `docs/oia/universal-oia-methodology.md`; `docs/oia/assessment-planning-architecture.md`; `docs/phase5b-oia-architecture.md`; `contracts/schemas/v1/`; `tests/runtime/test_phase5_end_to_end_freeze.py` | A client-neutral synthetic journey links consented discovery/OIA evidence to reviewed findings and governed implementation handoff without making reports, evidence, lifecycle events, or AI output authoritative. Current OIA material is methodology/architecture; it does not prove application access, an active OIA backend, or live client state. |
| 6 | Infrastructure | Keep DEVELOPMENT evidence separate from current source and current provider truth | `PARTIAL` | DEVELOPMENT runtime owner | 1, 3, 4 | `docs/current-build-state.md`; `docs/development-first-client-readiness-20261013.md`; `ARCHITECTURE.md` | Every DEVELOPMENT claim names an exact resource, source commit, observation time, and evidence artifact. A fresh authorized read is required before claiming current provider state; historical Render, AUTH, DATA, OIA, or localhost n8n evidence is not extrapolated to `99130ed`. |
| 7 | Automation | Retain the transactional outbox and safe local worker | `SOURCE-VERIFIED` | Platform automation owner | 4 | `src/avuhz_worker/outbox.py`; `src/avuhz_runtime/outbox_delivery.py`; `contracts/schemas/v1/orchestration/outbox-delivery.schema.json`; `tests/worker/test_outbox_worker.py`; `tests/integration/test_postgres_outbox_worker_persistence.py` | Authoritative state and outbox intent commit together; delivery is tenant-bound, idempotent, leased, retry-bounded, and records safe codes rather than raw exception/provider bodies. |
| 8 | Automation | Complete the shared LOCAL/TEST n8n orchestration boundary | `PARTIAL` | Platform automation owner | 3, 7 | `contracts/templates/n8n/avuhz-shared-event-receiver-durable-inactive-v2.json`; `src/avuhz_worker/n8n_event_sink.py`; `src/avuhz_worker/local_n8n_receipt_http.py`; `src/avuhz_worker/local_unattended_n8n_dispatch.py`; `tests/integration/test_local_unattended_n8n_dispatch_postgres.py`; `tests/worker/test_shared_n8n_durable_receiver_source_v2.py` | The existing inactive templates, guarded transport, durable receipt, replay, credential-injection, and LOCAL/TEST gates are unified into one documented client-neutral clean-checkout gate. n8n consumes only Avuhz events/APIs and cannot write authoritative tables. Source does not imply workflow activation, a running launcher, hosted delivery, or provider credentials. |
| 9 | Automation | Implement a shared communications adapter and deterministic local fake | `NOT STARTED` | Platform communications owner | 7 | `ARCHITECTURE.md`; `supabase/config.toml` | One Avuhz-owned interface and fake consume a sanitized outbox event with tenant binding, retry/idempotency, and safe error codes. Live providers and SPF/DKIM/DMARC remain separately authorized deployment work. |
| 10 | Business | Implement shared usage metering and a deterministic local billing fake | `NOT STARTED` | Platform billing owner | 5, 7 | `ARCHITECTURE.md` | Governed internal events produce tenant-scoped, idempotent usage records through an Avuhz-owned interface and fake; no vertical owns a ledger or Stripe path, and no money movement is part of local V1. |
| 11 | Business | Complete shared acquisition-to-Work-Item intake without inheriting System 001 authority | `PARTIAL` | Platform product owner | 2, 3, 4 | `src/avuhz_service/shared_acquisition_work_handoff.py`; `src/avuhz_service/shared_work_intake_postgres_candidate.py`; `supabase/migrations/20261014031000_enable_shared_work_intake_lifecycle_events.sql`; `supabase/migrations/20261014034000_create_shared_work_items.sql`; `tests/integration/test_shared_acquisition_work_handoff_postgres.py` | A fictional, independently authorized tenant/owner creates and replays one shared Work Item through the Avuhz writer, idempotency ledger, lifecycle event, and outbox in one governed flow. System 001-specific scheduling, revenue behavior, and workflow ownership remain outside this checklist. |
| 12 | Automation | Establish one clean-checkout client-neutral Local V1 release gate | `PARTIAL` | Platform automation owner | 2–5, 7–11 | `scripts/check-baseline.sh`; `tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py`; `tests/integration/test_shared_work_intake_postgres_candidate.py`; `tests/integration/test_local_unattended_n8n_dispatch_postgres.py` | One documented command proves enrollment, denials, governed intake, durable Work Item persistence, sanitized outbox/n8n receipt, communications fake, usage fake, atomic rollback, and deterministic replay with fictional data and no provider contact. Existing focused journeys are ingredients, not proof of this full gate. |
| 13 | Infrastructure | Complete staging and production operational controls | `BLOCKED` | Platform operations owner | 6, 12 | `SECURITY.md`; `ARCHITECTURE.md`; `tests/architecture/test_platform_production_readiness.py` | Separately evidenced staging/production registries, secrets, observability/alerting, network controls, backup/PITR restore, rollback rehearsal, capacity/SLOs, artifact provenance/SBOM, and post-deploy tenant denial exist under exact authority. |
| 14 | Business | Authorize and certify production launch | `BLOCKED` | Business owner + platform change authority | 13 | `SECURITY.md`; `docs/roadmap.md` | Exact production authorization exists per resource; reviewed artifact, recovery, billing, support, incident, launch, and postcondition evidence pass. Client deployment authority is never reused as Avuhz platform authority. |

## Next three actions

1. **Close client-neutral onboarding (Items 2–3).** Join the dormant owner-authentication, independent directory, PENDING registration, and ACTIVE enrollment candidates behind fictional local adapters; prove replay and wrong-owner/tenant/organization denials. This advances first-client readiness without creating a live tenant or spending provider authority.
2. **Unify the shared acquisition → Work Item → outbox → n8n local gate (Items 8, 11, 12).** Reuse the existing shared code, inactive receiver v2 template, durable receipt, and focused PostgreSQL tests. Keep System 001 behavior and ownership in its other chat. The tradeoff is deliberate: platform integration time precedes client-specific automation so a vertical does not become the infrastructure owner.
3. **Add the missing local communications and usage/billing fakes (Items 9–10), then run Item 12.** These are the remaining shared Local V1 gaps. Do not substitute live communications, Stripe, or provider configuration for deterministic repository evidence.

## Evidence-driven Local V1 gate

The gate uses only fictional identifiers and payloads. It must not resolve provider credentials, contact Supabase, Render, hosted n8n, communications, or Stripe, or depend on System 001 private code or state.

Required assertions:

1. Independently verified fictional owner evidence creates one PENDING tenant/organization enrollment and activates it through the shared boundary.
2. Forged owner evidence, stale MFA, revoked membership, wrong tenant/organization, missing capability, caller-supplied authority, and unauthenticated input fail closed without writes.
3. One shared acquisition becomes one authoritative Work Item; duplicate delivery returns the same governed outcome and creates no duplicate transition, notification, or usage record.
4. Authoritative changes, idempotency state, lifecycle event, and outbox intent commit atomically; injected failures roll back the unit.
5. The shared n8n receiver acknowledges only after a durable tenant-bound receipt. Events and receipts remain non-authoritative and cannot write authoritative tables.
6. Metadata and errors are sanitized; no credentials, raw provider payloads, unnecessary PII, or secret-derived material are persisted or logged.
7. Shared communications and usage/billing fakes consume the governed event exactly once.
8. Focused tests and `./scripts/check-baseline.sh` pass from a clean checkout.

Passing this gate certifies **source behavior at the reviewed ref only**. It does not certify current DEVELOPMENT, staging, production, or any live client.

## Update and approval rules

- Re-read the exact tracked ref and validate every cited path before changing a status.
- Record the acceptance criterion and the narrow evidence that satisfies it; preserve failed, stopped, superseded, and historical evidence.
- Never infer provider application, activation, health, credentials, tenant enrollment, OIA runtime access, or workflow execution from source, tests, templates, plans, roadmap sequence, or a prior provider observation.
- Stop on credential exposure, RLS/ACL widening, AUTH/DATA confusion, unnecessary PII, elevated authority, or n8n/vertical writes to authoritative state.
- Provider reads, mutations, deployments, secret operations, hosted sessions, staging, and production each require fresh exact authority, preflight, and postcondition evidence.

## Deferred beyond Local V1

- System 001 or another client's private workflow, domain data, deployment, and acceptance.
- Real-client OIA evidence, application access to OIA tables, and any live tenant/owner enrollment.
- Hosted acquisition ingress, activated/hosted n8n, live communications, Stripe, DNS/email authentication, or money movement.
- Dashboard/frontend and Supabase Edge Function work not present in this repository snapshot.
- Staging and production resources, secrets, deployment, observability, restore, rollback, capacity/SLO, provenance/SBOM, and incident operations.
- Phase 6 intelligence, monitoring, incident remediation, managed operations, outcomes, and continuous improvement until separately authorized.

The explicit next action is Item 2: complete the fictional client-neutral onboarding gate locally, with no provider contact or client-specific dependency.
