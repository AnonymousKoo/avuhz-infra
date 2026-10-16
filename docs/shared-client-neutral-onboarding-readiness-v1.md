# Shared Avuhz client onboarding and System #001 operational readiness

**Scope:** SOURCE-ONLY / LOCAL/TEST. This plan applies to *any* future Avuhz customer. It is not a hosted registration service, verification provider, payment adapter, active workflow or approval to change anything. The first paying business is deliberately **not selected**. No tenant, owner or actual customer record is created.

## Outcome and current boundaries

Avuhz, not a business vertical, owns the five shared primitives: authenticated owner identities; centrally shared n8n orchestration; separate Supabase AUTH and DATA; communications; and shared billing. System #001's Work Intake, ownership, persisted due review and replay are already locally tested. A client can start discovery now without a hosted tenant.

New importable pure projection: `src/avuhz_service/shared_client_onboarding_readiness.py`. It returns independent **Business** and **Platform** next actions plus enumerated readiness checks. It never creates an owner, changes tenant state, calls a provider, mounts an endpoint, authorizes a workflow or sends any message.

- AUTH: `pwlhruwutoitnieactol` — human proof, signed session, genuine recent MFA.
- DATA: `gnuqaefotwgkwurjpyik` — tenant, organization, owner membership, intake, Work Items, RLS. Never conflate these projects.
- n8n: shared Avuhz orchestration; it receives sanitized events and durable receipts, **not** self-declared owner authority or raw customer records.
- Communications and shared billing: separate execution services; neither is authorized by registration, work-item success, this readiness report or n8n receipts.

### Two independent progress tracks

**Platform (no business chosen):** Finish independently certified shared acquisition execution identity and least-privilege DATA connection; hosted HTTPS ingress; authenticated n8n durable receipt; shared Work Item writer/recovery; due review; booking confirmations; and customer communications. Shared billing is required only for a proposed paid pilot and must remain a single centrally owned implementation. Existing local tests are `LOCAL_TESTED`, not `DEVELOPMENT_VERIFIED`.

**Business (only after a consenting customer is identified):** Independently verify the exact owner-to-business operating authority, then recent AUTH MFA/session, separately authorize a PENDING tenant registration, separately approve ACTIVE organization + owner membership, register an independently signed and pinned opaque principal binding, and separately review pilot cutover. Every source of authority must be refreshed at the actual operation, not inferred from this read-only plan.

When no customer is selected, Business reports `CONTINUE_PROSPECT_DISCOVERY`. That does **not** block Platform progress.

### Business journey once the first customer says yes

1. **Discovery/OIA:** obtain business consent and understand work intake, people/handoffs, information, visibility, recovery, approvals, and capacity. Store customer facts in an approved private boundary, never Git or test fixtures. No hosted tenant or credentials required for a conversation.
2. **Owner and organization identity:** use existing `development_owner_authentication.py`, `development_owner_mfa_freshness.py`, and `development_business_owner_directory.py`, backed by a *real independently authorized issuer*. Never use local test signatures or a true-returning callback as real owner evidence.
3. **PENDING registration:** after exact authorization, use the existing shared `development_tenant_registration.py` only in its approved DEVELOPMENT DATA boundary. PENDING is not ACTIVE and must not unlock intake.
4. **ACTIVE transition and principal:** separate authorized `development_company_activation.py` mutation, fresh verified membership, and separately verified `development_signed_work_owner_identity.py` principal mapping. Enrollment, activation, trusted issuer configuration and provider grants each require their own reviewed resource boundaries.
5. **Work Intake:** server-owned website-to-tenant mapping, consent, independently authenticated acquisition service identity, durable rate limits, tenant-RLS-bounded DATA intake and sanitized lifecycle/outbox. No vertical-specific ingestion or direct n8n table write. Use `shared_acquisition_work_handoff.py` and the existing shared Work Item writer with same-transaction admission rechecks. Future privileged intake mutators need compatible advisory serialization or an approved narrow lock design before hosted certification.
6. **Operating the work:** persist owner and deadline, review due/escalation via existing guarded reader, complete shared work handoffs, reassign and recover/replay through the central ledger. A read-only review alone does not deliver a customer message.
7. **Customer communications / booking:** certify the approved shared messaging and booking confirmation adapters separately, including consent, SPF/DKIM/DMARC and provider delivery semantics where applicable. Never represent these as already live.
8. **Pilot and revenue:** separately authorize first-client pilot/rollout with safe rollback, actual owner access, customer notifications and rate-limit observations. Shared billing/Stripe usage accounting remains a separate explicit gate if charging within the platform; no vertical-specific billing infrastructure.

### Distinguish observations from authority

`ClientOnboardingObservation` takes an optional opaque business reference and source-only observations (`NOT_READY`, `UNKNOWN`, `LOCAL_TESTED`, `DEVELOPMENT_VERIFIED`). `review_shared_client_onboarding(...)` produces **non-authoritative** next actions. Caller-reported `DEVELOPMENT_VERIFIED` is not itself independent proof, and **even when all reported checks pass**, all five `authorized_to_*` fields remain `False`.

A future provider-backed reader must obtain current signed/tenant-scoped facts from each authoritative source, with exact environment/namespace confirmations. Never construct provider authority, permissions, billing access, a signed principal or a workflow activation from a read model.

Contradictory owner and organization state reports return `RECONCILIATION_REQUIRED`; no implicit activation or retry. All input is code-owned internal state, not a public form or n8n event. No name, email, phone, bearer, subject digest, PII or credential is returned or logged.

### Repeatable LOCAL proof

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
python3 -m unittest discover -s tests/service \
-p test_shared_client_onboarding_readiness.py -v
```

Tests cover two fictional businesses using **one identical backbone**, clientless platform progress, pending-versus-active, inconsistent owner/organization state, local-versus-hosted evidence, principal binding, first-pilot approval, shared communications/booking/billing, disallowed extra provider claims, and no authority even after every reported gate appears complete. No AUTH, DATA, n8n or production mutations.

### Known gaps / next action

- No actual independently verified first business or live principal issuer enrolled, and DEVELOPMENT DATA has no organizations or owner memberships (fresh read-only observation October 16, 2026).
- No hosted acquisition and n8n end-to-end cutover certification; local PostgreSQL and n8n proof are separate.
- Booking confirmations and customer communication delivery are not certified live.
- Shared billing must not be represented as implemented merely because the readiness path includes it.
- A future privileged intake state/version writer needs the same advisory serialization protocol or a separately approved least-privilege coordination mechanism; double rechecks are not full global serializability.

**Next action:** exact-head CI for this source-only reusable readiness path; then prioritize the actual missing *shared hosted acquisition / owner verification provider* connections over more disconnected tests. Continue prospect discovery in parallel. Do not choose Sekinfra, Mid State or another business by default.
