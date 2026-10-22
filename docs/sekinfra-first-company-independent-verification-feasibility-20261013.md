# Sekinfra first-company independent owner verification — feasibility checkpoint

**Status: DEVELOPMENT research/design only; NO APPROVED PROVIDER, HOSTED BINDING, OR REAL OWNER PROOF.**
Reviewed 2026-10-13. This document proposes neither a Supabase migration nor a credential, identity, tenant, billing, workflow, or production change. It is not a provider decision, authority grant, enrollment, or approval to process identity documents.

## Exact boundary and repository evidence

- Shared-core repository: `AnonymousKoo/avuhz-infra`, reviewed on `main` commit `55b907e7c40bda2c07ffb6d9e975ccae0095b57e`. Sekinfra website/OIA application is a separate repository.
- DEVELOPMENT AUTH: `pwlhruwutoitnieactol`; DEVELOPMENT DATA: `gnuqaefotwgkwurjpyik`. Never conflate them. No hosted mutation is part of this checkpoint.
- `contracts/proposals/v1/tenant-onboarding-intent.schema.json` and `src/avuhz_runtime/tenant_owner_onboarding_preflight.py` allow `OWNER_OPERATED_PILOT`; the contract does not demand incorporation.
- `src/avuhz_service/development_owner_authentication.py` and `development_owner_mfa_freshness.py` already require AUTH-pinned authentication and a fresh, live MFA/session check.
- `src/avuhz_service/development_business_owner_directory.py` verifies a fresh signed, server-fetched, project-bound owner decision using an independently pinned Ed25519 key. It **does not** fetch a real directory, check provider evidence or establish signer provenance on its own.
- `src/avuhz_service/development_tenant_registration.py` creates only PENDING_VERIFICATION records; `development_company_activation.py` is a separate, dormant ACTIVE transition. Neither is a deployed public registration API.
- Existing fictional/offline tests prove shape and rejection behavior, **not** real-world ownership. No service-role shortcut, true-returning callback, self-attestation, website/domain ownership, GitHub identity, or standalone AAL2 claim is sufficient proof.

## Evidence requirements, not vendor branding

A qualifying provider + approved shared Avuhz adapter must independently establish:
1. A genuine, consented, verified human controller, tied server-side to the exact current DEVELOPMENT AUTH subject.
2. The controller's independently corroborated right to operate **this specific business reference** as a founder/sole proprietor, without inventing incorporation, EIN, LLC records, or ownership.
3. The provenance, evidence policy and current revocation state of the verification decision, including a meaningful recency/expiry window.
4. A trusted server-side lookup of that decision bound to the exact business reference and signed by an independently attributed/pinned directory trust anchor. Keep the existing `DevelopmentBusinessOwnerDirectoryCheck` and its decision format; do not substitute an arbitrary provider response or import provider signing keys from the browser.
5. Minimal, consented PII in a restricted verification provider/system; Avuhz authoritative records retain only approved opaque references, status, provenance and bounds. No identity documents, DOB, tax identifiers, signed payloads, raw API responses or full contact values in git, n8n exports, logs or event envelopes.

A website/business-footprint match alone establishes **neither** the human-controller link **nor** operating authority. A verified ID alone also does not prove control of Sekinfra. A provider KYC/KYB “pass” is input evidence for an approved server-owned decision policy, not a direct Avuhz registration command.

## Vendor feasibility — official documentation, not hands-on certification

### Persona: exploratory candidate, NOT SELECTED

- Persona's KYB offering combines business-registry/document checks with associated-person ID and ownership verification. Its *Business Footprint Verification* targets small businesses and sole proprietors with incomplete/inconsistent registry information; Persona describes this as suited to use cases where formal registry validation is not required.
- **Pricing/availability blocker:** Persona's Business Footprint Verification help-center plan matrix marks this feature **Enterprise-only** (not Startup, Essential or Growth). Do not assume it is affordable or available for an early founder pilot; request an explicit quote/eligibility answer before choosing it.
- **Critical configuration gap:** Persona's example KYB-via-API integration lists business tax identification number and business registered address as required fields, while noting required inputs depend on configured country/workflow. We have **not** verified that a suitable unregistered-founder route is enabled, that it can independently establish operating authority, or its contract/pricing/sandbox availability.
- Provider documentation: https://withpersona.com/solutions/know-your-business ; https://help.withpersona.com/articles/1y9RqYAemIZn2jFK1HlEgS/ ; https://docs.withpersona.com/integration-guide-kyb-via-api .

### Middesk: exploratory alternative, NOT SELECTED

- Middesk documents US business KYB, identity screening of associated officers via Socure, business identity/address verification and configurable monitoring.
- **Critical eligibility gap:** We have no confirmation the offered verification product can corroborate an **unregistered** owner-operated Sekinfra pilot, or that the required owner/operating-authority linkage is available at viable pricing.
- Provider documentation: https://docs.middesk.com/home ; https://docs.middesk.com/verify-business .

### Decision

**NO_PROVIDER_APPROVED.** Persona is a reasonable first discovery conversation because of its documented footprint support for thin-file/sole-proprietor businesses. Do **not** integrate, purchase, provision API keys, create verification inquiries, or collect identity documents on this evidence alone. Middesk remains a future option, not a prerequisite.

Before selection, obtain explicit written answers for this exact founder-operated pilot:
- Can an unincorporated US sole proprietor/business that lacks LLC formation paperwork—and potentially lacks an EIN—complete a genuine human KYC **plus** independently corroborated authority to operate under its trade name?
- What legally suitable alternative evidence sources or human review are supported? Which checked sources establish the link between the verified person and specific business, rather than only online existence or a self-reported association?
- Are decision provenance, revocation/current status, retention controls, webhook authenticity, sandbox, per-verification costs and contractual minimums available?
- Can Avuhz's separately approved shared server component revalidate the decision over authenticated server-to-server access and issue a tightly scoped signed directory assertion compatible with the existing 60-second freshness check and DEVELOPMENT-specific key provenance? Never require the provider to adopt Avuhz's internal signature format.

## Exact forward path after independent evidence exists

1. Validate and approve the real verifier's authority/evidence policy and server-owned DEVELOPMENT trust anchor. Keep all provider secrets outside repository and n8n exports.
2. In a separately authorized operation, bind the verified DEVELOPMENT AUTH founder's current MFA/session check and independent directory decision to the existing shared registration candidate; test denial and wrong-owner cases.
3. Review a **distinct**, narrowly scoped DEVELOPMENT DATA registration writer role, tenant-RLS policy and exact column grants on disposable PG17 before any provider grant. Current general command role lacks enrollment INSERT and must not gain broad owner/PII privileges.
4. Separately approve one PENDING_VERIFICATION registration, independently verify resulting records, then separately approve activation after renewed proof. Do not pre-create a tenant/owner or mark them ACTIVE.
5. Only after the ACTIVE receiving business, intake service identity, least-privileged DATA access, durable rate limits and abuse control exist, run synthetic Sekinfra → Avuhz acquisition → outbox → authenticated n8n receipt → OIA review. Production website intake remains disabled until a later exact authorization.

## Business lane and known gaps

- Real prospect discovery and separately agreed founder-operated consulting may proceed outside Avuhz while onboarding is gated. Do not claim the website, n8n, OIA workspace or Command Center can onboard live clients yet; do not create vertical-specific billing/auth/automation infrastructure.
- **Known gaps:** no independently approved owner-verification provider, no real directory signer/fetch binding, no current real owner-to-business proof, no approved registration runtime role, no ACTIVE Sekinfra tenant, no hosted shared n8n receipt, and no live public intake.
- **Next action:** Seek provider confirmation of the exact sole-proprietor eligibility/authority-linking questions above. In parallel, continue separately scoped LOCAL/TEST journey checks with fictional data; do not allow a mock proof or production switch to substitute for this decision.
