# DEVELOPMENT acquisition: authenticated runtime and tenant-binding readiness v1

**Status: read-only verified planning artifact. No provider authorization or deployment.**
**Evidence snapshot:** 2026-10-12. Repository: `AnonymousKoo/avuhz-infra`;
baseline `main` commit `be485436ea153f089e8e1522abc283f266b5cd80`.
**Fixed provider boundaries:** Supabase DEVELOPMENT AUTH `pwlhruwutoitnieactol`;
Supabase DEVELOPMENT DATA `gnuqaefotwgkwurjpyik` (PostgreSQL 17).
**Runtime target to investigate:** Render `avuhz-command-dev`
(`srv-dab9n4qd0e5s73dq37mg`), **auto-deploy off**.
The existing command service must not silently become an acquisition service or gain acquisition DATA privileges.

## Decision

The existing shared acquisition path is **not ready for hosted customer traffic**.
The immediate work is **separate trusted identities and one independently verified
owner/organization binding**, followed by a synthetic-only proof. Do **not** create
a Sekinfra-specific authentication, tenant directory, billing, or n8n implementation.

No AUTH identity, credential, password, tenant/owner row, hosted route, Render
environment binding or n8n receiver is authorized by this plan. All stages below
are distinct resource boundaries; do not batch provider mutations.

## Read-only verified starting state

| Resource or control | Observed state | Source |
| --- | --- | --- |
| DEVELOPMENT DATA acquisition login `avuhz_acquisition_runtime_service_dev` | Exists, LOGIN/NOINHERIT/NOBYPASSRLS, connection limit 1, password NULL | Hosted DATA catalog read |
| SET-only membership into `avuhz_acquisition_service_dev` | Installed, `ADMIN FALSE, INHERIT FALSE, SET TRUE`, grantor `postgres`; not a member of broad command or migration role | DATA migration `20261012195017`; hosted catalog read |
| Acquisition registry RLS | 3 registry tables FORCE RLS; 7 acquisition policies | Hosted DATA catalog read; `development_data_shared_acquisition_registry_role_v1.sql` |
| Lifecycle-event/outbox RLS | 3 additional restricted acquisition policies; overall 10 acquisition policies | Hosted DATA catalog read |
| DEVELOPMENT DATA organizations | 0 total; 0 ACTIVE | Hosted aggregate-only DATA read |
| Verified owner memberships | 0 ACTIVE/OWNER/verified; 0 active organizations with such owners | Hosted aggregate-only DATA read |
| Intake records | 0 | Hosted aggregate-only DATA read |
| Shared acquisition counter table | Exists, FORCE RLS; **0 acquisition-role policies and no acquisition-role INSERT/UPDATE/SELECT privileges** | Hosted DATA catalog read |
| Hosted acquisition HTTP route | Not mounted | `src/avuhz_service/development.py`, `composition.py`, `development_acquisition_http.py` |
| Hosted acquisition service identity | Not enrolled/composed; offline verifier candidate only | `development_acquisition_service_identity_candidate.py`, `development_supabase_identity.py` |
| n8n receiver | LOCAL/TEST spec and synthetic round-trip only; actual receiver not verified or activated | `docs/shared-n8n-authenticated-receiver-local-v1.md`; `tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py` |

A passing CI test, database role membership, user JWT, arbitrary `avuhz.tenant_id`
session setting, or successful TLS connection **does not prove** a verified owner
or authorize another tenant. The grant is deliberately unusable for a hosted
password-based connection until a separate credential lifecycle is approved.

## Exact authentication and authorization chain to prove

1. **AUTH service identity:** Use the existing DEVELOPMENT Supabase AUTH ES256
   JWKS verifier and shared audience `audience.avuhz.command-service.development`.
   `DevelopmentAcquisitionServiceIdentityCandidate` expects a **distinct**
   service subject whose signed `sub` digest matches a **server-owned** policy,
   canonical `avuhz_tenant_id` matching provider-managed `app_metadata`,
   `avuhz_workload=acquisition_intake`, and the sole capability
   `acquisition_intake:receive`. Never relabel an existing human or
   provider-adapter identity. The current historical allowlist is
   checksum-bound and must not be casually rewritten.
2. **Trusted context:** Existing `DevelopmentTrustedIdentityResolver` converts
   independently verified identity evidence to `TrustedExecutionContext`.
   Browser forms, client headers and request JSON cannot select a tenant,
   organization, capability, owner, or service role.
3. **Organization authority:** `DevelopmentAuthenticatedAcquisitionIngress`
   queries DATA through tenant-scoped RLS for **exactly one ACTIVE organization
   with an ACTIVE, verified OWNER**. Multiple/zero matches deny. The shared
   `ReceiveAcquisitionIntakeCandidate` rechecks under locks within the
   transaction. An AUTH service subject is **not** itself proof of a business
   owner's verified identity.
4. **DATA session:** A separate private PostgreSQL login
   `avuhz_acquisition_runtime_service_dev`, never the generic command login,
   must pass host/port/TLS, exact session-role flags, one SET-only membership,
   zero direct Avuhz table ACLs, and restricted RLS/column-grant checks in
   `HostedDevelopmentAcquisitionConnectionFactory`. Only then does it
   `SET ROLE avuhz_acquisition_service_dev`; the transaction binds the
   *verified* tenant locally. No `service_role`, superuser, or RLS bypass.
5. **Shared rate limiting:** `DevelopmentPostgresAcquisitionRateLimiter`
   needs separate, exact acquisition-role counter-table policies and column
   grants plus retention/pruning proof. The presently missing access must
   **not** be bypassed by a permissive callback or privileged runtime.
6. **Shared event path:** Intake transaction creates sanitized
   `acquisition.intake.received` lifecycle event/outbox. Approved Avuhz worker
   may send a bounded envelope to one authenticated **shared** n8n receiver,
   with durable, tenant-scoped idempotent receipt. n8n cannot write
   authoritative Avuhz tables.

## Separate gates, in dependency order

| Gate | Exact boundary, required evidence | No-go/stop condition |
| --- | --- | --- |
| **G0. Prepare owner proof** | Determine a legitimate business reference and consenting real owner for the first internal DEVELOPMENT organization; identify separately authenticated AUTH owner subject and current MFA ceremony; independent server-owned signed business-owner-directory decision. Reuse dormant `development_owner_authentication.py`, `development_owner_mfa_freshness.py`, `development_business_owner_directory.py`, `development_tenant_registration.py` and `development_company_activation.py`. | Do not invent an owner, take self-attestation as proof, or treat signed JWT `aal2` alone as recent MFA. Directory is a dormant verification adapter, not a deployed authority. |
| **G1. Enroll one verified DATA organization** | Separate approved AUTH owner proof, bounded DATA writer rights and atomic pending registration; separate transition to ACTIVE only when matching verified owner and live AUTH evidence is satisfied. Read back just counts and safe state; no raw PII. | Current organizations/owners = 0; no owner writer role/service has been verified live. No direct admin insertion to speed onboarding. |
| **G2. Enroll acquisition AUTH workload** | Design and approve one **new** service subject under DEVELOPMENT AUTH, server-managed `app_metadata`, exact issuer/audience/JWKS, service-principal allowlist or injection, negative signed-token tests and session/credential retirement. | No reuse of HUMAN, PROVIDER_ADAPTER, user_metadata, unsigned JWT, cross-project keys, or old expired/consumed approvals. |
| **G3. Authorize private DATA login credential** | Separate approval for an environment-scoped login credential bound to the exact acquisition role, private Render/Vault storage, hostname/TLS, rotation/revocation and negative access checks. Verify with the adapter; never expose DSN values. | NULL-password installed today; current SET-only grant alone is **not** a successful connection test. No secret in Git, logs, or workflow JSON. |
| **G4. Enable acquisition counter access** | Review and test **only** rate-counter column privileges/RLS for `avuhz_acquisition_service_dev`, deny cross-tenant operations and ensure retained-safe record pruning. Apply as a separately approved DATA resource. | Existing table has forced RLS but zero acquisition-specific policy/ACL; do not use a dummy rate limiter. |
| **G5. Offline-to-hosted *synthetic* connection proof** | Under separately approved hosted composition, verify actual signed AUTH workload -> trusted tenant -> unique active verified owner -> restricted DATA session -> in-transaction scoped intake/event/outbox. Test absent owner, ambiguous owner, forged tenant, replay, cross-tenant, expired/invalid token, rate-limit, rollback and safe no-PII logs. | No real prospect payload or public route until proof. Render auto-deploy remains off. |
| **G6. Connect real n8n receiver** | Inventory actual n8n instance/version/ingress and credential manager; separately approve receiver, trusted HTTPS endpoint, event allowlist, durable receipt store, retry/idempotency. Exercise one synthetic event and verify exactly one receipt. | Existing LOCAL/TEST fake receiver is **not** a live receiver. No direct n8n access to DATA tables, no unauthenticated webhook. |
| **G7. First Sekinfra pilot** | Only after above gates, obtain prospect consent, bound tenant/owner authorization, support/rollback ownership and permission for **one** live pilot intake. Confirm successful intake, event, receiver receipt and governed follow-up. | No production, open public traffic, customer billing, or second tenant under DEVELOPMENT-only approvals. |

**Each G0–G7 provider action requires its own exact project, resource, source and
approval, and read-only postconditions.** The table is a roadmap, not a blanket
authorization. Do not modify the protected historical allowlist or use a
vertical-specific workaround.

## Business lane / smallest path to value

While the hosted route is disabled, pursue **one consenting Sekinfra pilot
agreement and a clear service offering** without collecting prospect contact
data into unapproved Avuhz intake. The engineering critical path is verified
owner/organization authority and safe service identity, not another general
platform rewrite. Expanding to a second pilot must wait for the first verified
end-to-end shared-core transaction.

## Known gaps and stop conditions

- The existing owner-registration, recent-MFA, signed-directory and activation
  modules are not hosted authority integrations; they cannot create an ACTIVE
  verified owner safely without separate real provider evidence and DATA writer.
- The acquisition service JWT verifier is injection-only; no enrolled AUTH
  workload or hosted acquisition capability is proven.
- The DATA SET-only login has no password or hosted credential and no approved
  `AVUHZ_ACQUISITION_POSTGRES_DSN` binding.
- The current restricted acquisition role cannot operate the existing persistent
  rate-counter table. This is a **fail-closed integration gap**, not an RLS
  exposure or reason to broaden to command/service_role.
- n8n is only represented by local/spec assets, not a verified active receiver.
- The hosted `/v1/acquisition/intakes` route is absent; no first customer
  onboarding has been proven.
- Existing docs and some code docstrings predate the installed rate-counter
  migration/SET grant. This plan records live readbacks and does **not**
  claim stale docstrings are current provider state.

**Next action:** Independently verify one business owner's AUTH subject,
fresh MFA/owner-directory source and proposed DEVELOPMENT organization
registration authority **read-only**, and prepare exactly one bounded
repository-local G0/G1 implementation plan. Do not create owner/tenant records
or request secrets before the owner evidence and role boundary are reviewed.
