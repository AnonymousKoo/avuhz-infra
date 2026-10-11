# DEVELOPMENT handoff — offline certification and runner SET-grant decision (2026-10-11)

**Status: PREPARATION / STOP BEFORE HOSTED GRANT.** This is one repository-only review record. It is **not** a migration, executable plan, approval, credential, workflow dispatch, token issuance, DATA claim, or authority to execute `AcceptImplementationHandoff`.

## Exact source, namespace, and operation

- Repository: `AnonymousKoo/avuhz-infra`; inspected protected `main@89d32ee645fc5d612407a9aa8f6c9047b741f21e` (PR #625 merged). Revalidate the exact current SHA before any later authorization or mutation.
- Supabase project: **DEVELOPMENT DATA** `gnuqaefotwgkwurjpyik`, `ACTIVE_HEALTHY`, PostgreSQL 17. Responsibility: **approval-claim DATA role access** only.
- Distinct **DEVELOPMENT AUTH** project `pwlhruwutoitnieactol`: **excluded**. Do not conflate AUTH and DATA, issue sessions/tokens, grant API roles, or change users/keys.
- Future proposed DATA resource, **not applied**: one PostgreSQL membership edge `avuhz_handoff_claim_writer` TO `avuhz_handoff_claim_runner_dev` with **ADMIN FALSE, INHERIT FALSE, SET TRUE**. The existing SQL candidate is `supabase/provider-artifacts/development-data/current/development_data_handoff_claim_runner_writer_set_grant_v1.sql` (Git blob `540e2cb9a3b826e5f89873afc4b03fd582df358f`). It is marked REVIEW ONLY, is not an executable approval, and must not be run under this record. Preserve its preflight, postcondition, and exact-grant shape; do not create a second path or silently broaden privileges.

## Offline fictional handoff — certified, not executed remotely

- Exact-head Main PR Gate **#825**, GitHub Actions run `38156717743`, completed **SUCCESS** at `22ffec95b6d83625c7308b7d8cdbb91218cf4ae3`. All 19 CI steps passed, including unit suites and disposable PostgreSQL integration. The PR #625 merge adds documentation; the two offline test files retain their inspected blobs.
- `tests/service/test_development_synthetic_handoff_offline_certification.py` (blob `19510f2fbe5412e777d46e1ddde39ec7f902063f`): **four tests passed**: schema-valid fictional DEVELOPMENT tenant/provider-adapter envelope; one offline HTTP 202/ACCEPTED with in-memory authoritative handoff, idempotency, one sanitized event and pending outbox; offline replay and conflict; fail-closed cross-tenant/missing-capability and secret-shaped input.
- `tests/service/test_development_synthetic_handoff_preflight.py` (blob `af7ac19592e9e92e31ece9501df07d5514ee6bb6`): **four tests passed**: no-network candidate certification; exact accepted-response classification as pending independent DATA readback; bound tenant/identity/capability/scope; rejection of stale or invalid times, digests, approvals and secret input.
- The fixed offline fixture uses fictional references and old timestamps; **do not POST it to Render**, claim real owner/customer consent, replay its command ID, or call it current live authority. A future live candidate needs fresh timestamps, IDs, verified signatures, and a new digest.
- This proves **repository-local correctness only**. It does not prove a deployed authorization-claim consumer, authenticated PostgreSQL claim-runner session, existing owner binding, or a live DATA handoff.

## Fresh hosted DATA read-only preflight — 2026-10-11

Performed through the read-only Supabase catalog on DEVELOPMENT DATA, with no raw PII/credential material, grants, DDL, or inserted rows:

| Exact finding | Observed |
| --- | --- |
| Project status | ACTIVE_HEALTHY |
| Claim ledger `avuhz_handoff_control.avuhz_handoff_approval_claims` | Exists, RLS enabled and **FORCED**, exactly one policy |
| `avuhz_handoff_claim_runner_dev` | LOGIN, NOINHERIT, NOBYPASSRLS, NOSUPERUSER, NOCREATEROLE, NOCREATEDB, NOREPLICATION, CONNECTION LIMIT 1 |
| `avuhz_handoff_claim_writer` | NOLOGIN, NOINHERIT, NOBYPASSRLS, NOSUPERUSER |
| Runner's role memberships | **0** |
| Runner's direct ledger privileges and schema USAGE | **None** |
| Writer's ledger schema USAGE and INSERT | Present |
| Approval claims / business handoffs | **0 / 0** |

Do not interpret `LOGIN` as proof of any usable password, federation, owner provenance, or credential delivery. Do not query or print the password hash. Do not treat the database session variable `avuhz.handoff_claim_tenant` as verified tenant identity: it can be set by a caller with an authenticated writer connection.

## Grant decision: BLOCKED pending independent identity/credential gates

The SQL candidate has narrow PostgreSQL 17 options, but **correct grant syntax is not sufficient authority to activate it**. Before an owner can approve the **one** DATA SET-grant operation:

1. Verify the true GitHub `development` runner invocation/protected `main` and independently enrolled human-owner public-key pin. A source-supplied fingerprint or a caller-provided `github.actor` dictionary alone does not establish provenance.
2. Prove a safe, supported connection path for the **exact** restricted DEVELOPMENT DATA runner: TLS server identity, effective `session_user` and `current_user`, no uncontrolled fallback to a migration or `service_role` login, and a bounded **temporary** credential lifecycle. Certify fake/sentinel transport before any real credential. Separately approve any future secret issuance, binding and retirement; never send secret values to Git, CI logs, a document or chat.
3. Prove that the trusted runner obtains tenant/project/command context from four fresh signed owner-approved stages, **not** from a request body or a caller-controlled PostgreSQL tenant GUC. Validate all four stages before acquiring the claim, and use durable cross-run replay protection. The existing `.github/workflows/development-first-handoff-trusted-dispatch-v1.yml` is **OFFLINE ONLY** and cannot serve as a live caller.
4. Only after 1–3 pass, freeze current protected main SHA, exact candidate SQL bytes and SHA-256, migration name, DATA project, PostgreSQL 17 preflight, approval window, and single-execution/no-retry terms. Obtain a **fresh specific owner approval** for **one** SET membership edge. Validate no preexisting runner-to-writer/command membership, no runner direct ledger/table/schema grants, and unchanged FORCE RLS/ACLs.
5. Execute that one separately approved provider mutation **only** via the agreed migration boundary. Then independently read back exactly one membership `SET TRUE / INHERIT FALSE / ADMIN FALSE`, zero direct/inherited schema/table rights, unchanged FORCE RLS/policy and zero claim rows. Any ambiguous outcome: STOP, no retry. No credential creation, network command or real customer data is authorized as a side effect.

**Current decision: HOLD THE GRANT.** Absence of membership is an intended fail-closed state. If the provenance, disposable fake-credential transport or tenant/signature binding is unproven, do not weaken the SQL or apply it “to unblock” the runner.

## Scope and next action

- **Security:** no password/hash, grant widening, exposed `service_role`, caller-controlled tenant authority, or PII retained. Never merge this record as approval.
- **Infrastructure:** DEVELOPMENT DATA ledger verified; no schema change or Render operation required for this record.
- **Automation:** shared Avuhz one-shot executor remains injection-only; no live workflow created or dispatched.
- **Business:** the first fictional DEVELOPMENT handoff remains the next technical checkpoint for a limited Sekinfra pilot. Do not confuse more preparatory PRs with actual client onboarding or build separate vertical authentication/automation.

**Next action after review/merge:** certify the existing one-shot executor's **repository-only fake-credential / protected-runner transport boundary** with disposable tests. Then review a provider-specific least-privilege credential feasibility proposal; request a separate owner authorization for each provider change. Do not grant membership or send a live handoff until those gates are proven.
