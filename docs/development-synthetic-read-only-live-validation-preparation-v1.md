# DEVELOPMENT synthetic read-only live validation — preparation only

**Status:** REPOSITORY-ONLY PREPARATION; NOT AN EXECUTABLE PLAN OR OWNER APPROVAL. No approval artifact, execution-progress artifact, provider mutation, or runnable workflow is created here.

## Confirmed boundary and source of truth

- **Repository:** `AnonymousKoo/avuhz-infra`, source `main@d30a92d9208bbec3ac540612e7aa49daf41a6cae` (PR #624).
- **Hosted application:** Render `My Workspace` / `avuhz-command-dev`, service `srv-dab9n4qd0e5s73dq37mg`; approved deployment `dep-db5rjkg473hc73c5vtmg` is live at that exact commit. Auto-deploy is disabled.
- **DEVELOPMENT AUTH:** Supabase `pwlhruwutoitnieactol`, responsible only for identity/session/token lifecycle.
- **DEVELOPMENT DATA:** Supabase `gnuqaefotwgkwurjpyik`, separate tenant-RLS data plane. **Do not conflate AUTH and DATA**, use a DATA service-role key to authenticate, or write directly to DATA for this test.
- **Application probe:** the existing `POST https://avuhz-command-dev.onrender.com/v1/queries` route in `src/avuhz_service/application.py`. Its request order resolves the bearer identity before running query validation. The existing bounded probe in `scripts/development_provider_adapter_live_identity_probe_v15.py` establishes the safe `{}` / HTTP 400 `{"error":"invalid_query"}` behavior. Its historical execution authority must not be reused.
- **Identity policy:** `src/avuhz_service/development_supabase_identity.py` has an exact server-owned **synthetic HUMAN** entry limited to `engagement:read`, distinct from the provider adapter granted `implementation_handoff:accept`. Do not modify either allowlist or tenant binding.

## Avoid duplicating completed work

`docs/current-build-state.md` records `development-auth-synthetic-token-validation-v3` **COMPLETED**, independent `session_count=0` and `refresh_token_count=0` readback, and separate complete retirement of its temporary Supabase key and GitHub DEVELOPMENT secret. Those are **historical proofs**, not reusable credentials or approvals. A separate October 8 v15 corrective provider-adapter run established a successful authenticated, side-effect-free HTTP 400 live probe, but for a **different principal**, followed by separately owner-reported retirement/zero-state evidence. The latest October 11 Render deploy and the reported `/health/ready` success do not themselves constitute a fresh synthetic-user authenticated request.

**Decision gate:** do not issue a second synthetic session merely to repeat prior evidence. First decide whether the accepted v3 synthetic proof plus current exact-code/health verification satisfies the intended read-only acceptance gate. If yes, record that conclusion without touching AUTH and prioritize the separately governed DEVELOPMENT ImplementationHandoff command acceptance and first-client intake plan. If a **fresh post-deployment** identity proof is specifically required, use the bounded path below with new exact approval.

## Proposed fresh proof — only after separate approvals

1. **Preflight, read-only:** confirm the current Render commit, `/health/startup`, `/health/live`, `/health/ready`, the exact synthetic `engagement:read` allowlist (not provider-adapter), AUTH `pwlhruwutoitnieactol`, and an independently scoped **aggregate-only** AUTH session/refresh baseline. Verify a compliant credential-recovery/cleanup method exists. If the baseline or provenance cannot be established, STOP. No raw Auth users, emails, phones, session IDs, JWTs, secrets, or provider payloads may be logged.
2. **Source-bound authorization:** create a separate, immutable, one-shot authorization plan and approval for the exact AUTH resource, current main SHA, method, secret boundary if truly necessary, execution window, number of expected operations, terminal cleanup, and zero retries. The plan must be reviewed before any credential creation/binding or session issuance. Never revive v3, v15, or other expired/consumed plan authority.
3. **Temporary credential, only if indispensable:** authorize each required AUTH key and environment-secret operation **one resource at a time**. Credentials must remain only in approved environment secret storage, never in code, GitHub workflow JSON, logs, this doc, or an agent response. Never use a production credential or a persistent elevation path. If an existing least-privilege method avoids an admin credential, prefer it after verifying the method from current code and documentation.
4. **One synthetic session and one read-only API request:** use the already allowlisted synthetic HUMAN only; no new user, password, tenant, capability, or MFA change. Issue **at most one** short-lived session via a verified AUTH method and send **exactly one** HTTPS `POST /v1/queries` with body `{}` and the transient bearer token held in-process. Disable redirects and automatic retries; require exact HTTP `400` and exact `{"error":"invalid_query"}` response. This demonstrates that identity acceptance precedes query-schema rejection; it does **not** prove actual read-model data access, an accepted business command, a DATA write, or client onboarding.
5. **Terminal cleanup is mandatory even on failure:** attempt the approved global logout; independently verify `session_count=0` and `refresh_token_count=0` using an exact approved aggregate-only read. Retire and separately verify absence of any temporary key and GitHub binding. If logout acceptance, aggregate zero state, or credential absence cannot be established, STOP with a specific cleanup obligation; do not classify success, issue another token, rerun, or proceed to a customer action.
6. **Sanitized evidence only:** retain commit/deployment references, pass/fail classification, exact expected status/body classification, independent zero-count results, key/binding-absence confirmation, and fixed safe failure codes. No token bytes or derived digests, raw body other than the fixed non-sensitive error, raw subject IDs, PII, or credential material.

## Hard stop / excluded scope

This document **does not authorize** a workflow dispatch, new Supabase session or token, provider credential, GitHub secret, AUTH or DATA SQL mutation, Render deployment or configuration change, tenant/user creation, row modification, `AcceptImplementationHandoff` execution, Sekinfra connection, public intake activation, or any production/staging action. Even a successful gate or read-only proof never authorizes the next resource. Stop on project/identity mismatch, missing exact authorization, stale source, unexpected HTTP response, new session/refresh residue, missing cleanup verification, credential exposure, widened grants/RLS, or any PII leak. Never bypass RLS with `service_role` or add a vertical-specific auth path.

## Four-lane tradeoff and next action

- **Security:** preserve synthetic/principal allowlist separation, AUTH/DATA separation, controlled session lifecycle, and sanitization.
- **Infrastructure:** current DEVELOPMENT Render readiness is reported healthy; no further deployment is needed for this preparation.
- **Automation:** avoid new executable/credential-bearing workflows when existing bounded primitives suffice; review any future one-shot executor separately.
- **Business:** repeating an already completed synthetic proof consumes time that could move the first paying customer toward onboarding. Do **not** treat more authentication plumbing as a substitute for acceptance of the existing shared `AcceptImplementationHandoff` command.

**Next action:** review this repository-only preparation and the completed v3 proof. Choose the evidence-reuse path unless a fresh post-deploy synthetic identity test is a firm acceptance requirement. If fresh execution is required, prepare a separate exact, non-retryable AUTH authorization package for owner review; do not execute it under this document.
