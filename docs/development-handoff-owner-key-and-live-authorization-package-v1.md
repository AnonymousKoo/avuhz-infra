# DEVELOPMENT handoff — owner-key enrollment and live authority package v1

**Status: NOT EXECUTABLE.** This is a source-grounded, repository-local
preparation for the **first fictional** `AcceptImplementationHandoff` on the
existing DEVELOPMENT command service. It provides no owner key, signed
approval, durable distributed authorization, active credential, authenticated
HTTP call, production right or provider permission. No historical v15 token or
key may be recovered or reused.

## Exact resources and responsibilities

| Boundary | Source of truth / constraint |
| --- | --- |
| GitHub source | `AnonymousKoo/avuhz-infra`, protected `main`. Resolve the current SHA after any PR merge; never reuse a previous SHA. |
| GitHub workflow | `.github/workflows/development-first-handoff-trusted-dispatch-v1.yml` — **offline-only**, read-only, one-run guard; currently does **not** invoke a live executor. Do **not dispatch** as part of enrollment. |
| Authentication | Supabase DEVELOPMENT AUTH `pwlhruwutoitnieactol`. No AUTH migration, user creation, policy change, retired key reuse or automatic token issuance under this package. |
| Business persistence | Supabase DEVELOPMENT DATA `gnuqaefotwgkwurjpyik`. Never substitute AUTH, use unrestricted `service_role` reads or bypass RLS. No DATA migration or write here. |
| Command ingress | `https://avuhz-command-dev.onrender.com/v1/commands`. No Render change or network request here. |
| Synthetic principal | `DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY` in `src/avuhz_service/development_supabase_identity.py` — tenant `1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0`, `PROVIDER_ADAPTER`, only `implementation_handoff:accept`, no authority roles. |
| Authentication/dispatch code | `src/avuhz_engineering/development_auth_token_lifecycle.py`, `development_handoff_trusted_github_invocation.py`, `development_handoff_trusted_one_shot_executor.py`, `development_source_bound_handoff_lifecycle.py`. Existing code is injection-only; neither a merged PR nor its offline tests configure a provider. |
| Claiming | `development_handoff_single_use_claim.py` uses an owner-private, preprovisioned **local SQLite** file. Atomic only for processes sharing that file. No distributed or GitHub-hosted ledger is proven. |
| Independent verification | `docs/development-first-synthetic-implementation-handoff-live-command-v1.md`; readback must verify DATA record, idempotency, sanitized event/outbox and separately verify AUTH session cleanup. Current `/v1/queries` does **not** expose an `implementation_handoff` read query. |

## Owner key enrollment — **separate trusted human action**

1. **Owner-only, on an independently trusted device:** create or select a
   dedicated **Ed25519** signing key in a reviewed local signing facility.
   Keep the private key in owner-controlled private storage **outside** this
   repository, CI runner, GitHub Actions secrets, chat, logs and screenshots.
   Do not commit even an encrypted private-key artifact. The repository does
   **not** provide a production-grade owner key generator or signing UI.
   Never ask a coding agent to receive or paste the private key.
2. Produce the **32-byte raw Ed25519 public key** and its fingerprint
   `sha256:<64 lowercase hex>` (SHA-256 of those exact raw public-key bytes).
   SSH-format public keys and SSH-signed envelopes are *not* interchangeable
   with the verifier's Ed25519 raw-key/canonical-JSON format.
3. Prepare a **fresh, domain-separated candidate statement** with exactly
   these fields:
   `purpose`, `owner_identity`, `repository`, `environment`,
   `tenant_id`, `auth_project_ref`, `data_project_ref`,
   `public_key_sha256`, `issued_at`, `expires_at`, `nonce`.
   It must bind this repository, DEVELOPMENT, the canonical tenant,
   the two **different** project refs and `github:AnonymousKoo`. Expiry is
   at most **15 minutes** after issue. Nonce is a new high-entropy,
   URL-safe string of 32–128 characters. Do not sign generic `APPROVE`
   text, a workflow screenshot or a future unbound command.
4. Using the owner-only signing facility, sign the UTF-8 bytes of
   `json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
   with **Ed25519**. Keep the 64-byte detached signature separate from
   the statement. The module
   `verify_owner_key_enrollment_candidate` performs an entirely offline
   structural/scope/signature check.
5. **CRITICAL distinction:** a self-signed statement proves *key possession*,
   **not that the signer is the owner**. The owner must independently verify
   the raw public key and fingerprint through a separately authorized,
   trusted channel and explicitly approve pinning it in the exact
   DEVELOPMENT runner's trusted configuration. Trust cannot be established
   by placing a fingerprint in a PR, by a caller Boolean, or by using the
   self-signed statement's `owner_identity` field.
6. Record only a sanitized, nonsecret fingerprint and provenance of that
   independent owner confirmation in the separately reviewed environment
   trust registry. Do **not** install a private signing key on a GitHub runner.
   **No such trusted owner-key registry or enrollment is established by this PR.**

The candidate verifier always returns
`human_owner_binding_verified=false`,
`owner_fingerprint_independently_pinned=false` and
`live_execution_authorized=false`, even for a valid signature.

## Live-execution authorization package — prepare, never auto-approve

Before **any** credential resolution or one-command execution, a future
separately reviewed owner-approved executor must verify all of the following.
Do not create active approval artifacts until the precise checkout SHA,
tenant, **fresh synthetic** command and time window are frozen.

1. **Exact source**: trusted GitHub protected-main SHA, workflow ref/actor,
   and read-only source observation. Bind one synthetic command envelope
   and its canonical digest. The existing envelope freshness constraint
   requires preparation close to the actual execution window.
2. **One approval per stage**: fresh plan, active owner approval, pristine
   progress and detached owner signature for each of
   `AUTH_GLOBAL_LOGOUT`, `AUTH_GENERATE`, `AUTH_VERIFY` and
   `DATA_COMMAND`. Each is one resource/operation with a separately
   authorized boundary. Match `EXPECTED_OPERATIONS`,
   `REQUIRED_PROHIBITIONS` and the exact
   `_bound_stage_resource_digest` in
   `development_handoff_approval_gate.py`. The aggregate
   `authorization_set_digest` **does not** create batch authority.
3. **Signature binding**: each Ed25519 stage signature covers the current
   source SHA, canonical tenant, AUTH and DATA references, HTTPS command
   URL, specific stage/project, plan digest, approval digest, command digest,
   aggregate authorization-set digest, validity window and nonce.
   Validate them using the independently enrolled key fingerprint, **not a
   fingerprint supplied alongside the signatures**.
4. **Atomic consumption and runner**: verify every stage *before*
   attempting provider access. `development_handoff_trusted_one_shot_executor.py`
   can insert all four claims in one local SQLite transaction, but there is
   **no proved cross-run durable authorization-consumption mechanism** yet.
   Bind one actual trusted execution path, not an unreviewed second
   workflow, ephemeral per-runner ledger or caller-provided callback.
   Ambiguous outcomes are terminal; no retry.
5. **Least-privilege credential strategy**: fresh exact approval for one
   supported short-lived AUTH recovery/session path for the existing synthetic
   identity; no new user, persistent password, retired v15 key, broad
   `service_role` credential or secret in Git. If the approved session
   cannot be issued and globally logged out with independent cleanup
   readback, stop before the command.
6. **One command only**: separately approve the precise HTTPS
   `POST /v1/commands` transport. It is **not** a Supabase DATA admin
   operation. No retry, `OpenEngagement`, actual client onboarding,
   notification, n8n execution or billing activity.
7. **Independent postconditions**: under a separately scoped, tenant-RLS
   respecting DEVELOPMENT DATA readback, prove exactly one
   `APPROVED` version-1 `implementation_handoff`, one matching
   idempotency record, the sanitized
   `implementation_handoff.accepted` event and expected outbox state.
   Separately verify AUTH sessions/refresh tokens and temporary credential
   retirement/absence. Neither one HTTP 202 nor a claim receipt is enough.

## Current stop conditions and handoff

- **No owner key has been independently enrolled.**
- **No fresh four-stage signed approvals/authorizations exist.**
- **No approved, truly cross-run persistent consumption backend is proven**;
  local SQLite and GitHub's workflow run-one guard have narrower guarantees.
- **No credential/session is currently authorized** for the command.
- **No approved live HTTP transport or independent DATA/AUTH readback** is
  connected to the existing offline GitHub workflow.
- **No real client data or production resource is authorized.**

**Required next owner action:** after this repository-only package is
reviewed/merged, independently establish the dedicated Ed25519 signing key on
an owner-controlled device, verify its public-key fingerprint out-of-band,
and authorize the exact DEVELOPMENT trust-anchor enrollment. Until that
separate action, the next executor must stay fail-closed and offline.

**Business priority:** these control-plane gates do not themselves onboard a
paying client. One safe fictional DEVELOPMENT transaction is the immediate
technical gate before connecting Sekinfra and a limited client pilot; do not
expand scope into another auth platform or an unrelated vertical.
