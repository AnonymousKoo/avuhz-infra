# Sekinfra first receiving organization — DEVELOPMENT registration preflight

**Status: READ-ONLY PREFLIGHT COMPLETE / REGISTRATION BLOCKED.** This file records verified existing boundaries and the smallest safe next action. It is **not** a registration, approval to create a tenant or owner, permission grant, AUTH change, intake activation, token enrollment, credential operation, or production deployment.

## Verified target and change boundary

- Repository/source: `AnonymousKoo/avuhz-infra`, inspected `main@0175d60b3fe91e555c39cd34da75dc44b6678c17` before this document-only branch. Recheck current source immediately before any future change.
- Future **DEVELOPMENT DATA** project: `gnuqaefotwgkwurjpyik`, name `DEVELOPMENT DATA`, PostgreSQL 17, `ACTIVE_HEALTHY`. The intended first receiving business is **Sekinfra**, operating as an Avuhz pilot.
- Distinct **DEVELOPMENT AUTH** project: `pwlhruwutoitnieactol`, name `DEVELOPMENT AUTH`, `ACTIVE_HEALTHY`. This project may validate an independently enrolled human; it is not a DATA registration target. **Never conflate these projects.**
- Current action class: GitHub repository-only documentation. Provider activity for this preflight was strictly read-only aggregate/catalog SQL and project metadata. No production, Render, n8n, Cloudflare, Sekinfra website, or Command Center mutation.
- Separate PUBLIC website: `AnonymousKoo/sekinfra` `/start` browser triage -> bounded `sekinfra.website-diagnostic-intake.v1` candidate -> server-only `lib/server/avuhz-acquisition-adapter.ts` and `lib/server/avuhz-acquisition-delivery.ts`; `/api/diagnostic-intake` **still returns 503**. This is **not** an operational customer submission path.

## Live provider findings — read-only, no raw PII

The following queries were checked against the explicitly named DEVELOPMENT projects during this preflight. Re-read just before any later mutation.

| Resource / check | Observed result |
| --- | --- |
| DATA `public.avuhz_tenant_organizations` | Installed; 0 rows |
| DATA `public.avuhz_tenant_owner_memberships` | Installed; 0 rows |
| DATA `public.avuhz_acquisition_intake_requests` | Installed; 0 rows |
| DATA `public.avuhz_acquisition_rate_limit_counters` | Installed; 0 rows |
| All four tables: RLS enabled + FORCE RLS | Yes for each; exactly one policy per table |
| `avuhz_command_service` SELECT/INSERT on all four | No / No |
| Generic `anon` SELECT, `authenticated` INSERT, `service_role` INSERT | No for all four |
| AUTH `auth.users` | 2 total; both have `avuhz_tenant_id` metadata |
| AUTH identity marked `avuhz_workload=acquisition_intake` | 0 |

These aggregate checks are not individual identity certification. A tenant metadata claim is not proof of ownership; no actual owner or customer identity was disclosed or recorded here. No registered Sekinfra tenant/organization or verified membership currently exists in DATA. The zero grant status is an intentional safety stop, not an instruction to grant broad runtime access.

## Existing core implementation — reuse, do not rebuild

- `contracts/proposals/v1/shared-tenant-owner-registry-design-v1.md` explicitly **forbids** treating the historical passwordless synthetic DEVELOPMENT user or its tenant as Sekinfra real-business ownership proof.
- `src/avuhz_service/development_owner_authentication.py`: dormant project-pinned pre-tenant AUTH/JWT checkpoint. A valid `aal2` claim does not prove a fresh MFA ceremony, business ownership, or registration authorization.
- `src/avuhz_service/development_business_owner_directory.py`: dormant Ed25519 decision-verifier port. A **separately approved, independently trusted ownership source** must perform a fresh server-side business/owner lookup and have an independently attributed, fingerprint-pinned signing key. Mock callbacks, user-supplied signatures, matching email/domain, and GitHub owner status are not ownership proof.
- `src/avuhz_service/development_tenant_registration.py`: dormant shared atomic transaction candidate that can create one organization and one corresponding owner membership in **PENDING_VERIFICATION**, provided real verified external authority and separately granted least-privileged database writer are present. It does **not** activate the tenant or attach a hosted API.
- `src/avuhz_service/development_acquisition_ingress.py`, `development_acquisition_http.py`, `development_acquisition_rate_limit.py`, and `acquisition_intake_command.py`: existing shared acquisition path, still **unmounted/unauthorized** for public intake. The writer additionally requires **ACTIVE** organization and independently verified **ACTIVE OWNER** membership, durable rate admission, bounded DB rights, and exact `acquisition_intake:receive` service authority.
- Sekinfra website mapping and offline contract tests already exist; do not add a second vertical-owned auth, ledger, persistence or automation path.

## Sole-proprietor pilot decision (operator-stated, not independently verified)

- The operator intends to begin serving Sekinfra's first paying client as a **sole proprietor**, and consider formal company/entity registration afterward. This is a **planning assumption**, not proof of identity, ownership, regulatory compliance, company existence, or entitlement to activate an Avuhz tenant.
- **Do not impose LLC/corporation formation as a technical prerequisite** for the shared Avuhz owner-operated pilot. A sole proprietor can be an eligible receiving business only when the applicable jurisdiction, trade-name/DBA/licensing obligations, individual identity, authority to use the Sekinfra business name, and independently verifiable real-world business control have been confirmed through an approved source.
- Do **not** represent the business as an incorporated entity, an LLC, or separately registered legal person. Do not invent a jurisdiction, legal trade name, registration number, tax identifier, address, owner subject or tenant UUID.
- Prefer verification that ties an independently established **individual identity** to an actual sole-proprietor business operation. Depending on jurisdiction and availability, a securely reviewed trade-name record, applicable license/registration, bank-verified business ownership, or an independently verifiable authoritative business relationship may contribute evidence. **None of these examples automatically satisfies the existing owner-directory contract**, and a self-issued invoice, company website, domain control, access policy, email address, GitHub account, or claimed client interest alone is insufficient.
- Keep sensitive documents, full legal identity, account numbers, tax IDs and source records out of GitHub, chat, code, app logs and normal API payloads. A later trusted owner-directory must check current independent evidence, securely pin its signing key, verify current subject-to-business linkage and revocation, and issue a fresh signed result before any registration authorization.
- **Open information needed:** the sole proprietor's operating jurisdiction (country and state/province as applicable), the legal/trading-name arrangement, and which independent verification source can legitimately attest control. Ask for jurisdiction only in conversation; do not put personally identifying owner information into this document.
- Owner registration and public client intake remain **blocked for unverified authority**, not blocked simply for the absence of an LLC or corporation. When a genuine legal entity is formed later, handle any tenant/legal-identity change through a separate governed, independently approved transition. Do not automatically create a second tenant, transfer ownership, or migrate billing.

## Current blocking facts

1. **An independently verified first human owner is absent** from the shared registration authority path. Neither the Cloudflare owner-only Command Center login nor the synthetic DEVELOPMENT Supabase identities confer real-business owner status.
2. No approved, hosted fresh-MFA verification and trusted business-owner directory integration has been registered or proven for this first real applicant. A local cryptographic signature check by itself is not a real-world ownership check.
3. No approved restricted DATA writer/session and no live registration API/command authorization have been activated. Existing empty, RLS-forced registries should not be manually seeded or changed to `ACTIVE`.
4. There is no authorized acquisition service identity and no active, verified receiving organization; public intake must remain `503 INTAKE_NOT_CONNECTED` until the complete shared path is certified.

## Next exact work boundary — without creating any resource

**Owner decision required first:** confirm the sole proprietor's operating jurisdiction and applicable business/trade-name obligations, then select an independently trustworthy verification source linking an actual authenticated individual to the owner-operated Sekinfra business. Forming an LLC or corporation after the first client may be a business decision, but does not automatically prove or disprove the current sole-proprietor owner binding. Do not paste identity documents, tokens, complete evidence, or PII into GitHub, ChatGPT, or logs; use only an approved secure provider workflow when one is selected.

Once the evidence source is confirmed, prepare **one** fresh repository-local implementation/review boundary for the shared DEVELOPMENT owner-directory/fresh-MFA *server-side adapter* (whichever is the earliest unimplemented prerequisite). Reuse the dormant code and negative tests. Require an exact independently pinned source, evidence freshness, revocation and source outage denial; do not activate authentication, mint a subject, issue a JWT, or create tenant rows as part of that preparatory PR.

**Future, separately authorized steps in order:** validate owner evidence and fresh MFA -> verify dedicated DATA writer/grants under tenant RLS -> review one atomic PENDING organization + owner registration -> independently verify registration/ownership then separately promote to ACTIVE -> enroll least-privileged acquisition service identity and durable rate limiting -> expose authenticated Avuhz DEVELOPMENT intake -> test fictional end-to-end receipt and cross-tenant denials -> only then review and enable real Sekinfra public intake. Every provider mutation needs a distinct exact project/namespace/resource approval; never assume another step is implicitly approved.

## Invariants and stop conditions

- No raw person/phone/email, AUTH subject, token, secret, JWT, directory proof, private provider payload or signing key in plans, events, logs or commits.
- No synthetic tenant reuse, self-declared ownership, browser tenant/organization UUID, bypass-RLS role, privileged service-role convenience, default-active record or vertical-specific infrastructure.
- No registration on the basis of a CLI success, fixture, green test, Access AUD, GitHub login, hosted probe or signed-but-untrusted directory record.
- Stop on any provider/project mismatch, stale or unverifiable owner proof, MFA freshness uncertainty, unsigned/invalid directory evidence, permission widening, RLS gap, failed atomicity/idempotency, or PII exposure.
- No customer data ingestion until the exact receiving service and active owner/business binding are demonstrably authorized.

**Next owner action:** identify the sole proprietor's country and state/province (if applicable), so we can determine the correct legal/trade-name and independent owner-verification route. Until actual owner evidence and fresh MFA are verified, registration remains **BLOCKED, NOT ATTEMPTED**; incorporation is not itself the gating technical requirement.
