# DEVELOPMENT first synthetic ImplementationHandoff — live-command readiness v1

**Status: REPOSITORY-ONLY READINESS PLAN; NOT EXECUTABLE AUTHORIZATION.** No provider operation, HTTP request, authentication session, credential creation, secret binding, customer handoff, or production change is authorized by this document. Never interpret PR merge or a green Main PR Gate as permission to send a command.

## Confirmed boundary and existing evidence

| Item | Exact bound / existing implementation |
| --- | --- |
| Repository | `AnonymousKoo/avuhz-infra`; starting canonical `main` commit `9897f8559688c2c6975d0c19e566a272a3741128`. Reconfirm current protected `main` before any future execution. |
| Environment | **DEVELOPMENT** only; no staging or production. |
| AUTH | Supabase DEVELOPMENT **AUTH** `pwlhruwutoitnieactol`. This is not the DATA project. |
| DATA | Supabase DEVELOPMENT **DATA** `gnuqaefotwgkwurjpyik`. This is not the AUTH project. |
| Hosted service | Render DEVELOPMENT `avuhz-command-dev`, `https://avuhz-command-dev.onrender.com`. Do not deploy or alter its configuration under this plan. |
| Command ingress | Existing `POST /v1/commands` in `src/avuhz_service/application.py`, invoking the shared governed `Executor`; `202` for `ACCEPTED`, `200` for `DUPLICATE`, `409` for `CONFLICT`, `403` for `REJECTED`, `422` for validation failure. |
| Command/capability | `AcceptImplementationHandoff`, subject `IMPLEMENTATION_HANDOFF`, exact `implementation_handoff:accept` capability. See `src/avuhz_runtime/command_registry.py` and `src/avuhz_runtime/guards.py`. |
| Existing provider-adapter policy | `DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY` in `src/avuhz_service/development_supabase_identity.py`: caller type `PROVIDER_ADAPTER`, single capability `implementation_handoff:accept`, canonical DEVELOPMENT tenant `1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0`, no authority roles. Do not widen it. |
| Live identity proof | GitHub Actions corrective v15 [run 37825175071](https://github.com/AnonymousKoo/avuhz-infra/actions/runs/37825175071): successful one-session JWT validation, expected authenticated non-mutating `400 invalid_query` probe, accepted global logout. Source-bound reconciliation: `contracts/plans/v1/development-implementation-handoff-provider-adapter-positive-auth-v15-step4-corrective-v1-live-proof.reconciliation.evidence.json`. **This was not a handoff command.** |
| Terminal v15 cleanup | Separate owner-verified absence of the temporary AUTH key and GitHub DEVELOPMENT secret and owner-reported zero session/refresh aggregate: `contracts/plans/v1/development-implementation-handoff-provider-adapter-positive-auth-v15-corrective-cleanup-v1.reconciliation.evidence.json`. No usable session or retired credential is carried forward. |
| DATA command vocabulary and isolation | Existing migration `supabase/migrations/20261002213000_enable_implementation_handoff_command_intake.sql`; `contracts/plans/v1/development-data-implementation-handoff-intake-v1-success.evidence.json` records DEVELOPMENT DATA application success, 16/16 RLS-enabled tables and tenant policies, zero direct exposed-role table grants, and no security-advisor findings **at the time of that check**. Fresh readback needs separate authority where required. |
| Local correctness | `tests/runtime/test_implementation_handoff_command_intake.py`: successful acceptance, tenant/capability rejection, secret-field rejection, event/outbox, exact replay and conflict, revocation. `tests/cross_repo/test_sekinfra_handoff.py` covers local Sekinfra/Avuhz contract; it is not a proof of a live cross-repository integration. |

## One measurable objective

Demonstrate **one** approved, fictional, tenant-scoped `AcceptImplementationHandoff` command through the already-hosted DEVELOPMENT `/v1/commands` route and establish independently verified persistence, idempotency, and sanitized event evidence. Do not onboard an actual customer or trigger downstream build, deployment, n8n, billing, notification, or other workflow.

A successful authenticated `POST /v1/queries` returning deliberate `400 invalid_query` is already demonstrated, but does **not** satisfy this objective.

## Frozen synthetic request and source preparation

The existing positive fixture is `contracts/fixtures/v1/phase5d-implementation-package.cases.json` → `positive.implementation_handoff`, and the command envelope shape is in `tests/runtime/test_implementation_handoff_command_intake.py::raw`. Use their canonical schema and field structure, **not** the fixture verbatim:

1. Use the existing DEVELOPMENT provider-adapter tenant `1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0` for **both** envelope and handoff body; the fixture's TEST tenant `d5000000-0000-4000-8000-000000000002` cannot be sent as this caller.
2. Generate a fresh unique synthetic `implementation_handoff_id` and `command_id`, one immutable idempotency key and correlation ID; use fictional, non-PII opaque client, engagement, source, and approval references. The references to `CLIENT_APPROVER` and `PROVIDER_APPROVER` must be distinct and **clearly synthetic**, never presented as real human/client consent.
3. Build an `APPROVED`, version-1 handoff with both required synthetic upstream approval references and at least one bounded source artifact reference. Preserve exact approved/excluded scope and the established prohibited-change set; allowed access remains `SANDBOX_ONLY`.
4. Generate current, internally consistent UTC timestamps for command, creation and synthetic approvals; never reuse fixture timestamps from 2030. Recompute `handoff_digest` via `src/avuhz_runtime/implementation_handoff.py::canonical_digest` **after** updating the body. Validate the expanded v1 payload and envelope with the shipped contract schemas before any transmission.
5. Keep the request in volatile executor memory where feasible; never commit an authorization header, JWT, full request body, provider response, real PII, synthetic user identifier, or other sensitive source material. Retain only approved opaque references and digests as evidence.

## Ordered execution gates — one resource at a time

| Gate | Verification / allowable future action | Stop condition |
| --- | --- | --- |
| **A. Repository-only preparation (this document)** | Confirm `main`/source digests; inspect command ingress, provider-adapter tenant/capability, fixture/schema, RLS and migration evidence. Run local no-network validation. | Any code/contract/tenant mismatch; no remote operation is authorized here. |
| **B. Fresh DEVELOPMENT readiness / authority** | Obtain a new **exact owner-approved** plan binding the specific synthetic command's identifier, digest, target, environment, execution class, one-shot semantics, evidence requirements and failure handling. Recheck hosted readiness and exact AUTH/DATA references without widening roles. | Expired/missing authority, changed SHA, unexpected readiness, missing RLS/grant confidence, an actual client payload, or any attempt to reuse historical v15 authority. |
| **C. Authentication strategy, separately approved** | Resolve one supported, least-privileged, **server-side** way to obtain a short-lived JWT for the existing allowlisted provider-adapter identity. Source secret only from an approved runtime secret boundary if required; bind exact creation/retirement steps separately. Do **not** recreate the retired v15 key or GitHub secret. Do not use `service_role` as a shortcut. | No fresh supported login path; need for credentials in source, logs or CLI arguments; any new user, password, policy, allowlist or Auth project change outside exact owner authority. |
| **D. Exactly one synthetic command mutation** | Only after A–C pass and the exact one-command operation is separately authorized, make **one** HTTPS `POST /v1/commands` with the validated synthetic envelope and short-lived bearer token. Expect `202`/`ACCEPTED`. On timeout/ambiguous result, **do not retry** until an authorized readback establishes the committed state. | `401`/`403`/`409`/`422`/`500`, mismatch, scope drift, invalid tenant, unexpected response, or unresolved network result. Record a safe status code; stop. |
| **E. Independent evidence and retirement** | Under independently scoped read-only DATA authority, verify only the exact synthetic tenant+handoff reference/version: one authoritative row, corresponding idempotency record, sanitized `implementation_handoff.accepted` event and pending outbox; verify negative cross-tenant behavior using existing local tests and any separately authorized provider-safe checks. Ensure no additional authoritative writes, no exposed grants/RLS change, session/refresh cleanup and ephemeral credential retirement/absence if any was used. | Missing/conflicting readback, extra row, unrestricted read path, PII in event metadata, lingering session/secret, or inability to prove correct tenant; stop before new work. |

No multi-command batch, no automatic retry, no automatic follow-on `OpenEngagement`, `DraftImplementationBrief`, real onboarding or outbox delivery. Each provider change remains separately guarded, even if a future exact owner plan describes the entire bounded sequence.

## Concrete PASS criteria

All of the following are required before declaring the *synthetic DEVELOPMENT live-command boundary* complete:

- A fresh exact approval and preflight bind one source/payload digest, caller/capability, canonical tenant, hosted service and DEVELOPMENT AUTH/DATA project refs.
- One command returns `202 ACCEPTED` **and** authorized DATA readback confirms exactly one version-1 APPROVED implementation handoff for that tenant and ID.
- Persisted idempotency, immutable handoff digest, event `implementation_handoff.accepted`, and sanitized metadata/outbox are verified, with **no** secret or PII in operational evidence.
- Cross-tenant, missing-capability, malformed/revised payload, and forbidden-secret rejection remain covered by passing local tests. Do not spin up a second live identity just to claim a live negative test.
- Tenant RLS, grants, effective runtime database role and AUTH/DATA separation are unchanged.
- Any new temporary session/secret has been revoked/retired and verified absent; zero remaining sessions/refresh tokens are independently established if the authentication method creates such state.
- No customer handoff, business engagement, billable usage, n8n workflow, production or deployment operation occurred.

A green PR or passing local tests satisfy **none** of the remote PASS criteria by themselves. The earliest legitimate next implementation step is preparing and certifying the **single-command source-bound execution authority plus an approved short-lived authentication strategy**, not dispatching another v15 login.

## Known gaps / facts not yet proven

- No live `AcceptImplementationHandoff` request or resulting DEVELOPMENT DATA row has been demonstrated. The prior verified live call was to the query endpoint only.
- The retired v15 credential is absent and the reported session/refresh aggregate is zero. **There is no authorized reusable v15 session** for a later command. A credential/session strategy for a new one-shot command remains a separately gated implementation decision, not a hidden prerequisite assumed complete.
- The current public `/v1/queries` router has no `implementation_handoff` read query type. An authoritative postcondition must therefore use a separately approved tenant-scoped DATA read, not a fabricated API route or direct `service_role` table access.
- The local cross-repository Sekinfra contract and DEVELOPMENT DATA migration evidence do not establish a deployed, end-to-end Sekinfra → Avuhz intake path.
- The evidence for 16/16 RLS policy status comes from the earlier DEVELOPMENT DATA migration verification; it must not be represented as a fresh provider read in this document.
- Organization-admin controls, shared billing, shared n8n automation, communications and full production readiness remain larger roadmap gaps. They are not implemented by this proposal and real client onboarding remains separately gated.

## Next action

Complete a **repository-only**, credential-free certification of one corrected synthetic handoff envelope and the chosen bounded postcondition-read method; then prepare the exact fresh DEVELOPMENT authorization for **one** live `AcceptImplementationHandoff` plus its separately authorized session path. Do not issue a bearer token, mutate DATA or dispatch a workflow under this document.
