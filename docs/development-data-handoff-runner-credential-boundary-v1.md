# DEVELOPMENT DATA handoff runner — credential and trust boundary v1

**REVIEW ONLY — no secret, password, role grant, provider operation, workflow dispatch, or live handoff is approved by this document.**

Source: protected `AnonymousKoo/avuhz-infra` `main` at `4c435852a50225bf247769f8b466b6fa30393adc`, verified 2026-10-09 after PR #596. Before any subsequent operation, re-read protected `main`, exact changed-resource state and any newly merged restrictions. This record is descriptive, not an authorization plan, approval artifact or runnable migration.

## Confirmed namespace and observed state

| Resource | Exact boundary | Read-only observation on 2026-10-09 |
| --- | --- | --- |
| Shared GitHub repository | `AnonymousKoo/avuhz-infra`; protected `main` | PR #596 merged and exact-head Main PR Gate passed |
| Supabase DEVELOPMENT DATA | `gnuqaefotwgkwurjpyik`; database `postgres`; Postgres 17 | `avuhz_handoff_claim_runner_dev` exists and is restricted; password is NULL, no runner-to-writer membership, no schema USAGE, no direct ledger INSERT |
| Shared handoff security store | `avuhz_handoff_control.avuhz_handoff_approval_claims` in DEVELOPMENT DATA | FORCE RLS, one ledger policy, zero consumed claims |
| Supabase DEVELOPMENT AUTH | `pwlhruwutoitnieactol` | **Different project. Out of scope for all DATA-role/credential work.** |
| Proposed writer privilege | `avuhz_handoff_claim_writer` | No runner SET membership; `supabase/provider-artifacts/development-data/current/development_data_handoff_claim_runner_writer_set_grant_v1.sql` is **review-only** |

Read-only provider inspection reported zero canonical `public.avuhz_*` tables with RLS disabled. An observed `PASSWORD NULL` value is **not** proof that every alternative Postgres login method is disabled. Never query, print, retain or compare a password hash as part of the credential plan. Current state is safe precisely because the runner cannot write a claim.

## Actual proof from code; do not overstate it

- PR #596 introduced `tests/integration/test_postgres_development_handoff_authenticated_runner_candidate.py`: a dedicated **local disposable** Postgres 17 container with generated test-only SCRAM secret, genuine network login, runner `session_user`, `SET ROLE`, signed four-stage candidate claim, replay, and negative-rights tests. No hosted Supabase credential or session was tested.
- `src/avuhz_engineering/development_handoff_durable_claim_candidate.py` enforces exact `session_user`/`current_user`, NOINHERIT/SET-only membership, no direct INSERT and forced RLS. These checks alone do not establish a human owner, trusted GitHub job, or signed tenant.
- `src/avuhz_engineering/development_handoff_trusted_one_shot_executor.py` composes source/owner-pin/signature checks with a candidate Postgres atomic claim, but is injection-only and not invoked by a live workflow.
- `.github/workflows/development-first-handoff-trusted-dispatch-v1.yml` is **OFFLINE ONLY**. Do not dispatch or repurpose it for credentials or live execution.
- `avuhz.handoff_claim_tenant` remains **caller-settable**. RLS comparing a row to that session setting is not independent tenant authentication.

## Provider-supported candidate, not an activated design

For a **future fictional DEVELOPMENT-only proof**, assess a dedicated custom PostgreSQL login authenticated by a high-entropy, **temporary SCRAM password**, on the existing restricted runner role. This is not a new auth service and must never be used by Sekinfra directly. Supabase documents custom Postgres login roles and connection methods; the docs do **not** independently prove this specific runner, GitHub OIDC-to-Postgres federation, one-time credential handling, or any particular connection configuration in this project.

- **Endpoint:** independently read the exact DEVELOPMENT DATA connection settings. Prefer a direct Postgres connection for one single controlled session when network compatibility is verified; consider **session-mode** Supavisor only if direct access is unavailable and role/transaction semantics are independently certified. Do not use transaction-mode pooling for an unreviewed session-level `SET ROLE` flow. Do not assume any host, pooler username or port from a generic example.
- **Transport:** require TLS with server identity checked (for example, `sslmode=verify-full` and a verified project-specific CA trust chain). Fail closed on wrong host, namespace, certificate, server role, or plaintext/downgraded transport.
- **Authentication:** a future explicitly authorized credential issuer must create the secret **only inside an approved private execution boundary**, deliver it by an approved non-logging mechanism, and apply the password change without the value entering Git, chat, GitHub Actions logs, job arguments, PR comments, workflow JSON, URLs, provider logs, migration artifacts, or the agent's tools. A secret written in a Supabase SQL Editor query, connector request, migration history, evidence JSON or GitHub variable is **not permitted**. Password parameterization alone is not proof that every admin/SQL-provider log is safe.
- **Lifetime:** set a concrete short expiry at issuance and prove it is enforced by Postgres on **new** connections. Expiry does **not** prove existing sessions are terminated or that a SET membership is removed. Rotate/revoke by a **separately scoped, approved** cleanup step, and independently verify password is NULL and no runner sessions remain. Do not claim short-lived credential support just because a static GitHub secret was created.
- **Storage:** no reusable/long-lived role password, connection string, admin credential or service-role secret may be introduced. If the approved executor cannot securely exchange an ephemeral secret with the exact provider connection, **STOP instead of substituting a GitHub repository secret, Supabase service_role or PAT.**
- **Not an option without separate proof:** GitHub OIDC directly authenticating as a PostgreSQL login. GitHub OIDC is not equivalent to database password auth or Supabase Auth JWT handling, and no compatible direct Postgres OIDC exchange is established in this repository.

Current provider documentation:
- [Supabase Postgres roles](https://supabase.com/docs/guides/database/postgres/roles)
- [Connecting to Postgres](https://supabase.com/docs/guides/database/connecting-to-postgres)
- [Connecting with PSQL and verified TLS](https://supabase.com/docs/guides/database/psql)
- [Upgrade caveat: custom-role passwords are not backed up](https://supabase.com/docs/guides/platform/upgrading)

## Hard security gates before any credential or SET grant

Every future resource requires its **own exact active approval** after a fresh read-only preflight. Do not bundle independent provider, GitHub, credential, DATA grant, AUTH session, Render, or live-command changes under this review document.

1. **Owner / source gate:** prove a protected GitHub `development` job is authorized for the exact checked-out protected-main SHA, actor identity and immutable owner-signed stage authorization. Human attribution must be independently verified; public key equality, a caller-provided environment dictionary, a green CI run, or a GitHub `run_number` is insufficient. Verify environment restrictions and permissions from the **actual** GitHub settings before credentials can be exposed.
2. **Hosted endpoint gate:** separately certify correct DEVELOPMENT DATA project `gnuqaefotwgkwurjpyik`, exact provider-supported connection mode, TLS server validation, no unintended access from another identity, and the ability to authenticate a password-enabled custom role. Do not use the AUTH project or general postgres/service_role identity as the application login.
3. **Credential transport gate:** independently threat-model every place the secret could appear (provider SQL history/telemetry, application exceptions, CI command line and debug tracing, shell history, workspace files, environment inspection, metrics and artifacts). Identify an actually available issuer/transport with a documented sanitized readback and guaranteed bounded retirement. **If this proof fails, issue no password.**
4. **Tenant/authorization gate:** bind the claimed tenant UUID to the exact four independently owner-approved, valid, source/digest-bound stages **before** any connection or transaction-local GUC is set. An authenticated runner credential has power to select another GUC value; this remains a residual compromise risk. Never authorize real customer data until tenant provenance and abuse isolation are independently resolved.
5. **RLS and least privilege gate:** read back that the runner is LOGIN, NOINHERIT, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION, connection-limit 1; the writer is NOLOGIN; FORCE RLS/policy remain exact; runner has no direct ledger schema/table grants and no command-service rights; no surprise membership edges. Any mismatch is a hard STOP.
6. **Recovery gate:** pre-authorize, separately from issuance, how a failed or ambiguous credential/claim operation will be contained and retired **without replay**. If credential retirement cannot be proven or an active connection remains, mark the boundary **STOPPED / UNVERIFIED** and prohibit any live command.

## Ordered, one-resource-at-a-time progression

| Boundary | Allowed after separate approval | Required sanitized evidence | Explicitly forbidden at this boundary |
| --- | --- | --- | --- |
| **A. Repository-only transport certification** | Tests/prototype for the existing shared Avuhz executor with **fake/sentinel** credentials and protected-context checks | Exact-head CI pass, negative tests, unchanged provider state | Real credential, provider write, GitHub secret, new auth infrastructure |
| **B. Provider connection feasibility read** | Read-only check of exact DEVELOPMENT DATA TLS/connection method and role state | Project/ref, safe booleans, zero secret values | Password issuance or table/role grant |
| **C. Credential issuance proposal** | Prepare a fresh, source-bound **one-resource** issuance plan after verified safe transport | Secret class, private boundary, expiry and retirement mechanism **without the secret** | Execute `ALTER ROLE`, paste a password, use connector `execute_sql` with a secret |
| **D. Credential activation + negative-rights proof** | Under a separate owner approval, one temporary runner credential operation and one separately authorized test/readback | True authenticated `session_user`, exact DATA endpoint/TLS, no direct grants, sanitized result, retirement obligation | SET writer grant, approval claim, customer/OIA data |
| **E. Secret retirement** | Separate approved password invalidation, connection/session cleanup and independent readback | Password NULL, zero active runner sessions, no leaked value | Assume TTL alone invalidates active sessions |
| **F. Later writer SET permission** | Fresh one-resource migration approval **only after** runner/owner/tenant/credential feasibility passes | Exact membership edge, no INHERIT/ADMIN/direct rights, RLS/zero-claim readback | Treat merged PR #593 or this document as grant authority |
| **G. First fictional DEVELOPMENT handoff** | Fresh separately approved four-stage AUTH/DATA execution, one-at-most command and independently authorized postcondition checks | Tenant-scoped data state/idempotency/event/outbox readback, AUTH global logout and credential retirement evidence | Production, customer data, retries, Sekinfra-specific auth or orchestration |

If a phase cannot be completed without batching independent resource changes, return for an explicitly scoped approval; do not infer batch authorization. A provider operation with an ambiguous result is not safe to retry simply because no receipt was seen.

## STOP, known gaps, and business boundary

- No provider-proven end-to-end temporary runner credential delivery, GitHub protected-job provenance, or independent owner attribution is currently implemented.
- No approved hosted credential issuance, writer SET grant, signed live stage set, AUTH session/token issuance or DEVELOPMENT business command is in this record.
- No trusted application connection is proven on Supabase by the local SCRAM certification; the live runner still has password NULL and no writer membership.
- A custom-role password may require reset after a Supabase backup restore or upgrade; never count provider restore as durable preservation of runner access.
- No secret-bearing material, raw customer/phone/email data or exception bodies may be retained in plans, CI or operational logs.
- No vertical (including Sekinfra/OIA) may implement shared billing/auth/orchestration or direct-write the Avuhz ledger. A thin Sekinfra domain adapter is the intended downstream integration.

**Four-lane tradeoff:** Security and infrastructure work is a prerequisite for automated tenant-safe handoffs, but should not delay manually scoped Sekinfra paid-pilot sales, contracts and separate payment collection when those activities have their own appropriate controls. Do not present the current Sekinfra diagnostic intake (`503 INTAKE_NOT_CONNECTED`) as a working Avuhz connection.

**Next action after exact-head review and CI:** implement **Boundary A only** — one repo-only fake-credential/protected-context transport certification (no provider contacts, no secrets, no live grants). Then review the result before requesting any provider authority.
