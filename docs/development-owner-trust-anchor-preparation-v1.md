# First DEVELOPMENT handoff — owner public-key trust-anchor preparation v1

**Status: REVIEWABLE CONFIGURATION PROPOSAL ONLY; NOT ENROLLED AND NOT EXECUTABLE.**
The owner authorized preparing the exact public-key trust anchor for GitHub
Actions `development`, **not** modifying GitHub environment settings, creating
a credential, running a workflow, generating a token or sending a business
command. This PR commits *only public key information*, offline comparison code
and negative tests. Neither a GitHub PR merge nor an offline match establishes
verified owner attribution or live authority.

## Verified target and separation

- GitHub repository: `AnonymousKoo/avuhz-infra`. Prepare from `main`
  `33ae893a32490a04699a765e15787e78760aaa8e`; re-observe the current
  protected-main SHA after merge.
- Target job environment: GitHub Actions **`development`**, as referenced by
  `.github/workflows/development-first-handoff-trusted-dispatch-v1.yml`.
  The repository code **does not confirm the actual configured environment
  variable values** or their provenance. This PR does not create/update them.
- Owner identity claim: `github:AnonymousKoo`; independently approved human
  attribution is a future owner-controlled trust step, **not** implied by
  an enrollment statement containing that string.
- Supabase DEVELOPMENT AUTH: `pwlhruwutoitnieactol`.
- Supabase DEVELOPMENT DATA: `gnuqaefotwgkwurjpyik`. **Never conflate**
  these projects. Neither one is changed.
- This public key is for **Ed25519 owner-signed authorization documents**;
  it is **not** a Supabase AUTH key, API key, bearer token, service-role key,
  JWT signing key, SSH deploy key, GitHub Actions secret or production key.

## Exact owner-supplied proposed pin

```text
AVUHZ_HANDOFF_OWNER_ED25519_PUBLIC_KEY_BASE64=ZFWF5ABLxtDjgvCbGEKyD2P5Dy4wBNGvRlNADkwMPXc=
AVUHZ_HANDOFF_OWNER_ED25519_FINGERPRINT=sha256:e750361f337cac029969240023eac3f17864580acd32cfd8dedcd7fef0612a87
```

The first value is Base64 of **32 raw Ed25519 public-key bytes**, not a PEM,
SSH-format key or encrypted private key. The second is SHA-256 over those raw
bytes, lower-case hexadecimal with a `sha256:` prefix. The new offline
`prepare_development_owner_trust_anchor_candidate()` rejects mismatches,
incorrect repository, environment, owner claim and swapped AUTH/DATA refs.

**Critical:** the matcher deliberately returns
`actual_github_environment_setting_verified=False`,
`independent_owner_identity_verified=False`,
`owner_key_enrolled_in_trusted_runner=False`,
`signed_stage_approvals_verified=False`,
`credential_resolution_authorized=False` and
`live_command_authorized=False`.
It cannot see GitHub settings, confirm trusted enrollment, or grant authority.

## Future GitHub environment registration — separately authorize

After an approved exact-head R2 review of this PR, the owner must independently
confirm the public fingerprint from the original trusted Ubuntu device
**without using a value copied back from the repository as independent proof**.

Only under a **separate exact authorization** to mutate GitHub Actions
`development` environment **variables**, the owner may then:

1. Go to GitHub repo → Settings → Environments → `development` →
   **Environment variables** (not Secrets). Verify repository, environment
   name, current values and active restrictions before changing anything.
2. Add/change **one variable at a time**, starting with
   `AVUHZ_HANDOFF_OWNER_ED25519_PUBLIC_KEY_BASE64`, using the exact
   public Base64 value above. Inspect/confirm the resulting value.
3. Only after a separate per-resource authorization if required, add/change
   `AVUHZ_HANDOFF_OWNER_ED25519_FINGERPRINT` with the exact digest above.
   Inspect/confirm the value. Do not overwrite an unexpected existing pin;
   stop and investigate conflicts/rotation.
4. Independently verify both values **in the actual GitHub environment**
   through a separately approved *read-only* trust-checking workflow before
   claiming registration. No such workflow step is present in this PR.
   An arbitrary local Python dictionary of two matching strings is **not**
   provider-side verification.
5. Owner attribution, environment protection, and trusted runner
   provenance must be reviewed before reporting `enrolled`. These
   configuration changes alone confer no AUTH/DATA or command access.

Do not ask an agent for or publish the private PEM file, its passphrase,
the detached signatures for live stages, JWTs, provider payloads or any
secret. A public key and its fingerprint are **not secret material**.

## Current execution boundary and next business milestone

- The owner's previous ephemeral enrollment candidate has a maximum 15-minute
  validity window; it is **not reusable** as a current active approval.
  Generate a fresh enrollment statement/signature locally if the approved
  registration requires current proof. Preserve the private key on Ubuntu.
- The current workflow is explicitly **OFFLINE ONLY** and single-run by
  `GITHUB_RUN_NUMBER=1`. **Do not dispatch it** to test the pin.
- Existing `development_handoff_trusted_one_shot_executor.py` still uses
  dependency-injected callbacks and a local SQLite claim ledger. This
  preparation neither wires real providers nor proves cross-run durability.
- Fresh signed, exact-stage AUTH and DATA plans; separate least-privilege AUTH
  credential/session generation and cleanup; one command authority;
  tenant-scoped independent DATA record/idempotency/event/outbox readback
  must each be approved and verified before the first fictional
  `AcceptImplementationHandoff` command.
- No live command, credential/session, Supabase mutation, Render deployment,
  n8n automation, billing or customer data is authorized by this PR.
  See `docs/development-handoff-owner-key-and-live-authorization-package-v1.md`.

**Next action:** review/merge this repository-only public-key proposal once
the full gate passes. Then request **separate authorization for the first
exact GitHub `development` environment variable change**, and verify the
real environment state before the next variable. Avoid expanding the scope
beyond one fictional DEVELOPMENT handoff on the path to Sekinfra onboarding.
