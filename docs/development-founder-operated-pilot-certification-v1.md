# DEVELOPMENT founder-operated pilot — unincorporated business eligibility

**Status: REPOSITORY-ONLY OFFLINE CERTIFICATION / NO PROVIDER AUTHORITY.**
This is not an exemption from identity checks, ownership verification, tenancy
isolation, role grants, or customer-data consent. It does not create a Sekinfra
tenant or activate the public website.

## Verified exact scope

- Repository: `AnonymousKoo/avuhz-infra`; separate `AnonymousKoo/sekinfra`
  owns the public frontend and domain-specific OIA logic.
- Environment: **DEVELOPMENT only**; AUTH project
  `pwlhruwutoitnieactol` and DATA project `gnuqaefotwgkwurjpyik`.
  These must not be conflated. No production, AUTH/DATA provider mutations,
  environment secrets, grants, live tokens, owner rows, or customer records.
- The existing `contracts/proposals/v1/tenant-onboarding-intent.schema.json`
  recognizes `OWNER_OPERATED_PILOT`. It contains **no incorporation-status
  requirement**, but an onboarding intent cannot grant access or create rows.
- `src/avuhz_service/development_tenant_registration.py` already implements
  a dormant shared **PENDING_VERIFICATION-only** tenant + owner membership
  transaction candidate. Its inputs include a cryptographically checked
  pre-tenant AUTH bearer, independent recent MFA confirmation, and separately
  independently verified ownership/operating authority; there is no LLC,
  corporate filing, tax ID, or incorporation-document condition in this code.
  The presence of this candidate does **not** establish that it can run live.
- `src/avuhz_service/development_owner_authentication.py` and
  `development_owner_mfa_freshness.py` require project-pinned AUTH identity,
  a recent signed TOTP event, and a separate live AUTH user check.
- `src/avuhz_service/development_business_owner_directory.py` requires a
  fresh, accurately signed, server-fetched ownership decision from a **genuinely
  independent** trusted directory. It validates the signer/pin; it cannot prove
  what off-system investigation occurred. A registration-pending declaration,
  domain control, self-attestation, GitHub ownership, a matching business name,
  or test-generated signature does **not** independently prove operating
  authority. No real approved business-owner directory is bound today.

## Interpretation for an unincorporated Sekinfra pilot

Legal incorporation is **not** a technical prerequisite for an
`OWNER_OPERATED_PILOT` intent. A separately approved, independent business
ownership verifier may support a real sole-proprietor/founder-operated business
based on its actual evidence and policy **without inventing a legal entity**.
The verifier must establish (1) a real, verified human controller; (2) their
legitimate authority to operate the specific business represented by the
opaque reference; (3) trust-anchor provenance and revocation; and (4) recent
AUTH/MFA state. The precise third-party or human-reviewed evidence process has
**not** been selected or implemented here. Do not label that process complete.

Any future legal entity registration is a subsequent update to verified business
profile facts, not a license to rewrite immutable owner evidence or reassign a
tenant silently. Do not present Sekinfra as legally registered before it is.

## Offline fictional certification

`tests/service/test_development_founder_operated_pilot.py` exercises the
existing **shared** owner authentication, MFA freshness, independently signed
directory decision, and two-record transaction candidate with newly generated
TEST-only cryptographic keys and fake in-memory PostgreSQL connections.

- The positive fixture uses only a fictional owner and an opaque,
  unincorporated-founder-pilot business reference. Its only result is a
  `PENDING_VERIFICATION` receipt and one simulated atomic transaction.
- Incorrect business, non-VERIFIED decisions, invalid signatures, missing or
  stale TOTP, revoked/missing live-session signal, and injected tenant claims
  must deny before any simulated DATA writes.
- A validly signed fictional directory statement is **not** independent proof
  of a real owner's authority. Offline TEST success cannot be reused as hosted
  evidence, and the real owner directory cannot be replaced with a
  true-returning callback.
- No existing source module, command registry, identity allowlist, JWT hook,
  RLS policy, stored business, pricing, billing, automation, Render service,
  or live HTTP route is changed by this PR.

## Known blockers before a real Sekinfra onboarding

1. Determine the approved, legally appropriate **independent** verification
   method for Sekinfra founder/operator authority without requiring
   incorporation, and obtain independently attributable directory signer
   provenance/revocation. There is currently no live directory binding.
2. Independently enroll and prove a real DEVELOPMENT AUTH founder identity,
   including the existing recent MFA/live-session verification. The synthetic
   AUTH user and implementation-provider identity do not qualify.
3. Review one exact DEV-only registration operation and narrowly scoped DATA
   permissions. Even if an authorized proposal creates two
   `PENDING_VERIFICATION` rows, that is **not** an ACTIVE owner binding:
   activation/reverification has a separate authorization requirement.
4. Bind a distinct authorized acquisition service identity, audit and approve
   tenant-RLS-limited DATA access, persistent rate limits and public edge
   abuse protection. Existing `acquisition_intake:receive` candidate is
   offline only, and the hosted acquisition HTTP route remains unmounted.
5. Prove a single **fictional** Sekinfra -> Avuhz intake over DEVELOPMENT HTTPS
   and independent DATA readback with stable idempotency; authorize real
   prospect-data collection and production activation separately. The public
   `503 INTAKE_NOT_CONNECTED` must remain until then.

**Next action:** Validate CI for the one offline certification boundary.
Then choose and verify a genuinely independent, minimally invasive operating
authority proof process before any AUTH/DATA resource mutation. Do not create
an owner or mark them VERIFIED just because formal registration is pending.
