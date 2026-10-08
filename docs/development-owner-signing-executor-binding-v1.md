# DEVELOPMENT owner signing-key binding — executor guard v1

**Scope: repository-only, security hardening (R2), NO live execution.**
Source inspected on `AnonymousKoo/avuhz-infra` protected `main`
`ffe745b36b231030d658062c29f2e479a88d6325`. Future approvals must
bind a **fresh** protected-main commit SHA after this PR is merged.

## Verified existing state

- Owner holds a passphrase-encrypted private Ed25519 signing key **locally on
  Ubuntu**. No private key or passphrase is in this repository, GitHub
  environment variables, GitHub Actions secrets, ChatGPT or CI.
- The owner supplied the 32-byte raw **public key** and SHA-256 fingerprint,
  both pinned for DEVELOPMENT in
  `src/avuhz_engineering/development_handoff_owner_trust_anchor.py`.
- GitHub Actions read-only check [run 37861471138](https://github.com/AnonymousKoo/avuhz-infra/actions/runs/37861471138)
  on protected `main` SHA `ffe745b36b231030d658062c29f2e479a88d6325`
  reported `github_development_environment_public_variables_match=PASS`
  and `git_source_and_owner_dispatch_context=PASS`. This establishes
  **public-variable matching in that run**; the job explicitly reported
  `human_owner_binding_verified=false`,
  `signed_stage_approvals_verified=false`,
  `credential_resolution_authorized=false`, and
  `live_command_authorized=false`.
- GitHub Actions environment is **`development`**;
  `AVUHZ_HANDOFF_OWNER_ED25519_PUBLIC_KEY_BASE64` and
  `AVUHZ_HANDOFF_OWNER_ED25519_FINGERPRINT` are environment **variables**,
  not a store for a private signing key.
- DEVELOPMENT Supabase AUTH is `pwlhruwutoitnieactol`, DATA is
  `gnuqaefotwgkwurjpyik`. Never interchange the two. Neither is changed.

## Why this guard is necessary

Previously, `execute_trusted_development_handoff_once()` accepted a
`owner_public_key` plus `independently_pinned_key_digest` from its caller,
then checked only whether they matched each other before verifying each
stage signature. A caller able to supply new keys, a self-matching fingerprint
and signed stage documents might pass that cryptographic test with
**an unapproved signing identity**. Requiring a valid signature against
an arbitrary matching key is not owner enrollment.

This change calls
`_require_development_owner_signing_pin()` **before ANY stage proof,
claim-ledger write, credential supplier or injected provider/HTTP callback**.
It requires all of:

1. The existing trusted GitHub invocation checks still succeed.
2. Both DEVELOPMENT owner public-key and fingerprint values are present in
   the runtime-provided GitHub environment mapping, in the exact source-pinned
   Base64/SHA-256 form; missing, altered, or malformed values fail closed.
3. Owner, repository, DEVELOPMENT scope, AUTH project and DATA project match
   existing source constants.
4. The caller's public key bytes and claimed digest each match the
   **source-pinned** material, not just each other.
5. Existing four per-stage canonical signatures, exact plans, source and
   project bindings, and same-host atomic claim checks remain required.

Only nonsecret public information is compared. Failure emits a fixed code
`HANDOFF_OWNER_SIGNING_PIN_UNVERIFIED` without echoing environment values,
provider responses, PII or signatures. Offline security tests use freshly
generated ephemeral **test-only** keys patched into the module's expected
public key; this is a test-scoped fixture, **not** a runtime bypass or new
configuration path. Regression tests include a completely re-signed
four-stage document set using a different key and fingerprint: it **must
fail before any claim or injected callback**, even if caller-supplied
environment values are also replaced.

## Scope and remaining gates

- **No workflow has been activated or dispatched as part of this change.**
  The existing first-handoff trusted dispatch workflow is **OFFLINE ONLY**
  with a first-run guard; do not trigger it for this test. The separate
  read-only environment verifier has already passed; no new run is needed.
- The one-shot executor is still an **injection-only** library, NOT a reviewed
  bound live runner. Source and environment matches are necessary but not
  proof of separate human-owner attribution or live authorization.
  Future wiring must obtain GitHub environment values and source context
  **from trusted GitHub execution**, never from request data or user-written
  JSON. Do not interpret a caller-provided Python mapping as GitHub
  attestation.
- Independently attributable owner authorization, fresh signed exact-stage
  plans, true durable cross-run one-time approval consumption, scoped
  short-lived AUTH credentials and retirement, one approved HTTPS command,
  and separate tenant-RLS DATA plus AUTH readback **remain unimplemented or
  unapproved for live use**. Local SQLite is atomic only on one durable
  shared host file, not across ephemeral GitHub runners.
- The verifier result and this PR must never be treated as a generic
  `authorize_stage=True`, elevation, enrollment certificate, provider
  permission, billing permission, new vertical-specific infrastructure or
  production authority.

**Next action:** run the focused new tests and `./scripts/check-baseline.sh`
through the Main PR Gate, complete an accountable R2 human review, then
review and merge this narrow hardening PR. After merging, separately design
and authorize trustworthy durable single-use stage approval consumption
before any future live dispatch. Keep the business milestone fixed at one
fictional DEVELOPMENT `AcceptImplementationHandoff` as the prerequisite
to Sekinfra's first limited client pilot.
