# DEVELOPMENT handoff — runner provenance and credential go/no-go (R2 v1)

**REVIEW ONLY — NO LIVE GRANT OR WORKFLOW AUTHORITY.** This decision record is based on the protected `AnonymousKoo/avuhz-infra` main commit `ceadcc977541fdfd5d3c6857c2dd7afb5491a8ff` after merged PR #594. It authorizes no provider read/mutation, database login or credential creation, GitHub environment change, workflow dispatch, session/token issuance, customer operation, or production deployment. Re-observe the main SHA before any later action.

## Exact scope

- Shared Avuhz control plane only, not Sekinfra's OIA/domain logic or another vertical infrastructure path.
- Supabase **DEVELOPMENT DATA**: `gnuqaefotwgkwurjpyik`, and only its isolated handoff-control resources.
- Distinct **DEVELOPMENT AUTH**: `pwlhruwutoitnieactol` — untouched and never interchangeable with DATA.
- No staging, production, live customer, Render, n8n, Stripe, or external messaging change.
- Target runner role: `avuhz_handoff_claim_runner_dev`. Existing writer role: `avuhz_handoff_claim_writer`. Neither is the ordinary `avuhz_data_runtime_service_dev` / `avuhz_command_service` command identity.

## What the code and merge actually prove

1. `.github/workflows/development-first-handoff-trusted-dispatch-v1.yml` is explicitly **OFFLINE ONLY**, checks GitHub source/actor/first attempt, and does not import the durable claim adapter or make a provider call. Run-number checks are not a distributed approval-consumption ledger.
2. `src/avuhz_engineering/development_handoff_trusted_github_invocation.py` validates a supplied GitHub event/environment against pinned repository, actor, source, and invocation metadata. It requires a trusted job to supply those observations; an arbitrary caller-created mapping is not trusted attestation.
3. `src/avuhz_engineering/development_handoff_owner_trust_anchor.py` pins a reviewed **public** Ed25519 key. The read-only environment check compares the installed public variables, but matching variables and a repository source pin do **not** independently attribute the signing private key to the human owner. Never collect or publish the private key/passphrase.
4. `src/avuhz_engineering/development_handoff_trusted_one_shot_executor.py` composes four signed-stage/plan checks with a candidate PostgreSQL claim. Its production callback/credential sources are still injection-only; the older executable path has a host-local SQLite claim, not cross-run authority.
5. PR #594 updated `src/avuhz_engineering/development_handoff_durable_claim_candidate.py` so each atomic claim requires `session_user=avuhz_handoff_claim_runner_dev`, `current_user=avuhz_handoff_claim_writer`, narrow SET-only membership, no inherited INSERT, and FORCE RLS. Disposable tests exercise `SET SESSION AUTHORIZATION` in a privileged fixture. **They do not authenticate a real database workload or prove a credential-delivery mechanism.**
6. The DATA claim ledger is reported installed with forced RLS and zero consumed claims in PR #594's read-only preflight. The SQL grant artifact `supabase/provider-artifacts/development-data/current/development_data_handoff_claim_runner_writer_set_grant_v1.sql` remains **review-only**; no new permission is granted by merging it.
7. The tenant setting `avuhz.handoff_claim_tenant` is caller-settable PostgreSQL session state. Forced RLS compares the row to that setting; it does not authenticate the owner, runner, or tenant on its own.

## Threats, controls, and remaining evidence

| Threat or trust gap | Control already implemented | Missing proof before remote writer SET grant or live claim |
| --- | --- | --- |
| General `postgres` / migration session impersonates writer | PR #594 session/current-role plus membership restrictions | Authenticate a dedicated runner session using a verified provider-supported mechanism; privileged `SET SESSION AUTHORIZATION` is **fixture-only** |
| GitHub event or source is caller-supplied, modified, or replayed | Exact repo/owner/main/workflow/run/source checks in offline verifier | Bind those observations to an actual protected job and immutable checked-out source; verify environment restrictions rather than trusting a Python mapping |
| Untrusted signing identity authorizes the four stages | Ed25519 signature, pinned public fingerprint, source/tenant/plan binding | Owner-controlled out-of-band human attribution and fresh stage-specific signatures; public variable equality alone is insufficient |
| Authenticated writer changes the tenant GUC | Signed tenant/command binding upstream; INSERT policy with FORCE RLS | Verify exact signed tenant in an authenticated job before setting the GUC; explicitly accept that compromise of the writer credential can defeat tenant selection. **No real-customer writer access with this unresolved threat** |
| Runner gains excess rights or a persistent credential leaks | Separate NOLOGIN writer, proposed SET-only edge, zero direct ledger grants | Independently verify actual role ACL/membership, TLS endpoint, GitHub environment secret restrictions, usable authentication method, revocation, and no secret/log retention |
| Concurrent/ambiguous/replayed handoffs double-execute | One PostgreSQL transaction, unique constraints, fail-closed on ambiguous COMMIT | Source-bound trusted connection, exact one-attempt execution, independently authorized DATA readback and AUTH session/credential retirement |
| New vertical duplicates auth/billing/orchestration | Root `ARCHITECTURE.md`, `SECURITY.md`, `AGENTS.md` rules | Preserve shared Avuhz core; Sekinfra OIA stays domain logic only |

## Decision as of this source

- **GO — repository-only, offline/disposable certification:** strengthen the existing PostgreSQL integration tests to establish an actual authenticated `session_user` under a temporary **disposable-only** login mechanism, instead of simulating it solely with `SET SESSION AUTHORIZATION`. Negative cases must deny wrong role, bypass/extra grants, source/signature drift, replay and wrong tenant. Keep all secrets out of committed files, output and logs. This does not imply the hosted Supabase mechanism supports the same method.
- **NO-GO — hosted writer SET grant:** the source-bound identity, trusted job/environment restrictions, provider-supported runner authentication, credential lifetime, and tenant-GUC compromise boundary have **not** been independently proven. Do not apply the review-only SQL artifact on the strength of merged PRs or passing disposable tests.
- **NO-GO — live handoff:** no fresh four-stage owner approvals, verified runnable credential path, authenticated runner, or remote command/postcondition authority exists under this record. Do not dispatch the OFFLINE ONLY workflow or retry an earlier credential flow.

## Minimum next-step acceptance (one boundary at a time)

1. **Next repo-only change:** add the genuine-login *disposable PostgreSQL* test without altering the provider artifact, production workflow, or runtime grant. Require the existing CI baseline and targeted positive/negative tests to pass with no skip.
2. **Then independent read-only provider preflight:** under separately confirmed DEVELOPMENT DATA read authority, prove exact role state, absent SET edge, zero claim consumption, table RLS/grants and project identity. Record sanitized aggregate results only.
3. **Then credential/provider feasibility:** prove which supported mechanism can authenticate only `avuhz_handoff_claim_runner_dev` to the exact DATA host with TLS and narrowly scoped, short-lived secret handling. **Do not** assume GitHub OIDC is accepted by Supabase Postgres or that a `PASSWORD NULL` login is usable. If no suitable method is confirmed, STOP and redesign before granting SET.
4. **Only after independent owner/tenant provenance review:** propose one time-bound, source/digest-bound approval for exactly one DATA `GRANT ... SET TRUE, INHERIT FALSE, ADMIN FALSE` migration and a separate negative-rights readback; do not combine it with a credential or command action without explicit approval.
5. **Finally, a separately approved fictional DEVELOPMENT handoff:** one fresh signed four-stage package, at-most-once command, tenant-scoped persisted-state/event/outbox verification, zero sensitive logs, global logout and credential retirement. Real Sekinfra/OIA client data remains outside this proof.

**Business priority:** This safety work must not silently displace the first Sekinfra paid pilot. Sekinfra may use explicitly manual commercial intake and separate contracts/payments while the Avuhz automated handoff remains synthetic-only; do not misrepresent the website's current `503 INTAKE_NOT_CONNECTED` as an automated intake.

**Next action:** implement the single disposable authenticated-runner certification PR; do not touch hosted DATA or create credentials under this review-only record.
