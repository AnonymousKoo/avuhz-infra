# System #001 — DEVELOPMENT DATA fictional QA tenant readiness

**Decision:** Keep SekInfra out of the first-client role. Use fictional **Avuhz QA Tenant 001** for testing. The full LOCAL n8n → receipt → PostgreSQL Work Item and follow-up certification is merged as PR #697; it is not hosted customer readiness.

## Verified resource boundary (read-only, 2026-10-15)

- **Source:** `AnonymousKoo/avuhz-infra`.
- **Target for a future, separately approved DATA-only action:** Supabase DEVELOPMENT DATA project `gnuqaefotwgkwurjpyik`, `public.avuhz_tenant_organizations` only.
- **NEVER target:** DEVELOPMENT AUTH `pwlhruwutoitnieactol`, production, billing, n8n, or a SekInfra client table.
- **Live read-only counts:** 0 tenant organizations, 0 owner memberships, 0 acquisition intakes, 0 Work Items.
- `avuhz_tenant_organizations`, `avuhz_tenant_owner_memberships`, and `avuhz_acquisition_intake_requests` are owned by `postgres`, have RLS **enabled and forced**, with tenant-scoped shared-core policies. No anonymous/authenticated insert grant was identified.
- Existing `avuhz_command_service` and `avuhz_acquisition_service_dev` runtime roles are NOLOGIN, NOBYPASSRLS, and **do not have INSERT permission** on `avuhz_tenant_organizations`. A normal application writer cannot create a tenant today.
- Required constraints: unique tenant UUID, unique organization UUID, unique `business_reference`; organization state defaults to `PENDING_VERIFICATION`; verified owner membership cannot be faked as ACTIVE without `verified_at`; intake and membership tables use exact-tenant/organization FKs; additional vertical-owned FK dependencies exist, so cleanup must never CASCADE.
- The existing acquisition ingress source checks the **organization ACTIVE** plus **OWNER ACTIVE**, `verified_at IS NOT NULL`. A fictional pending record cannot, and MUST NOT, pass this gate.

## Narrow hypothetical future seed (NOT AUTHORIZED / NOT APPLIED)

One row and one resource ONLY in the shared organization registry:

| Field | Fictional fixture |
| --- | --- |
| `tenant_id` | `a4730000-0000-4000-8000-000000000001` |
| `organization_id` | `a4730000-0000-4000-8000-000000000011` |
| `business_reference` | `avuhz.qa.tenant001` |
| `lifecycle_state` | `PENDING_VERIFICATION` |
| `record_version` | `1` (existing default) |

No synthetic membership digest, `verified_at`, ACTIVE organization, acquisition intake, Work Item, AUTH user or credential should be written as part of this first seed. Never loosen policies or add broad runtime writer grants merely to make a QA row insert.

**Important limitation:** The approved shared registration candidate normally requires independent AUTH MFA and business ownership proof **before even creating pending records**. A provider-admin QA seed would be a conspicuous DEVELOPMENT-only exception to that workflow, not normal enrollment or customer authority. It must receive its own exact provider authorization and explain the privileged migration boundary.

## Required verification and cleanup before any provider write

1. Review an **exact, source-bound, transaction-scoped** SQL candidate using existing canonical migrations and current live DATA policies. Its SQL digest, source commit, project, one-row intent and retry prohibition must be explicit. No reusable role or credential creation.
2. Confirm the reserved UUIDs and business reference remain unused; fail closed on collision, owner/intake dependency, schema/RLS/role drift or unexpected records. Reject attempts to mark fictional business/owner as verified.
3. Validate an **independent exact-row rollback** against disposable PostgreSQL 17 and all known FK dependencies, with no CASCADE or cross-tenant deletion. Rollback is a separately authorized provider resource change if ever needed.
4. The executable rollback candidate could not be completed under the current safety boundary. An incomplete draft was **discarded**; no executable SQL was committed or sent to DATA.
5. Only after seed + rollback candidates have both passed independent review and tests, seek explicit approval for a **single DEVELOPMENT DATA organization-row insert**. Verify postconditions with read-only source-bound queries. Do not authorize AUTH, production, credential, runtime role or tenant ACTIVE changes.
6. Keep System #001's hosted acquisition gate **closed** until independent, actual owner proof and a server-owned workload authority exist. A seeded PENDING QA org is only for tenancy/RLS inspection, not an end-to-end hosted business workflow.

## Four-lane priority tradeoff

**Security:** forced RLS, no forged owner, no elevated runtime GRANT. **Infrastructure:** DEVELOPMENT DATA single-row fixture remains blocked pending safe rollback. **Automation:** LOCAL System #001 is certified; hosted automation is not authorized by a synthetic organization. **Business:** prioritize making client onboarding/use-case deliverable rather than polishing Command Center UI or adding unnecessary platform features.

**Next action:** prepare/review an exact seed + independent rollback implementation under proper approval, then request authorization for one DATA-only pending organization seed. Alternatively, if immediate hosted workflow proof is more valuable, prioritize a verified owner/authorized service boundary instead; do not fake it with this fixture.
