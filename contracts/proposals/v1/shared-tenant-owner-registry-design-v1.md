# Shared Tenant + Owner Registry — DEVELOPMENT DATA implementation design v1

**Status:** REPOSITORY PROPOSAL ONLY. This document is NOT a migration, command, approval, credential, activation, or permission to apply SQL. Its SQL fragments are review shapes, not executable provider instructions.

## Exact boundary

- Repository: `AnonymousKoo/avuhz-infra`, shared core only; no code in `AnonymousKoo/sekinfra`.
- Target for a later, *separately authorized* migration: Supabase **DEVELOPMENT DATA** `gnuqaefotwgkwurjpyik`.
- Identity provider stays Supabase **DEVELOPMENT AUTH** `pwlhruwutoitnieactol`. They are never interchangeable. No AUTH or DATA project was contacted or modified by this document.
- One resource at a time: first register a tenant/organization table under one reviewed DATA migration, independently verify RLS/ACL, then separately register the owner membership table under its own reviewed migration. Do not bundle provider mutations without an exact new approval.
- First intended business: SekInfra, as the owner-operated Avuhz pilot. **Do not use the existing passwordless synthetic DEVELOPMENT user or its tenant as ownership proof or as SekInfra's real tenant.** No SekInfra tenant or owner has been provisioned.

## Why these resources are needed

The frozen Phase 5 DATA baseline defines 16 tenant-scoped `avuhz_*` authority tables, but **no canonical tenant, organization, or membership registry**. The existing `TrustedExecutionContext` has `tenant_id` and `organization_id` fields, yet DEVELOPMENT Supabase identity resolution currently maps only bounded synthetic/provider-adapter allowlist entries and does not provide business-owner membership authority. PR #600 added an **inactive** onboarding-intent proposal, and PR #601 added a **dormant**, read-only owner preflight; neither is a registration mechanism.

## Resource 1 — tenant/organization directory (new table, proposed)

Proposed table: `public.avuhz_tenant_organizations`.

- `tenant_id uuid primary key` — minted by Avuhz trusted server, never accepted from a public onboarding form.
- `organization_id uuid not null unique` — canonical Avuhz organization, distinct from `tenant_id`; one org per tenant for the first pilot only.
- `business_reference text not null unique` — validated opaque source reference; do not store names, contacts, emails, phones, or provider payloads.
- `lifecycle_state` closed to `PENDING_VERIFICATION`, `ACTIVE`, `SUSPENDED`; the default is `PENDING_VERIFICATION`. An onboarding-intent does not imply `ACTIVE`.
- Server timestamps and constrained record version; no service plan, billing authority, or workflow credentials.
- `UNIQUE (tenant_id, organization_id)` to support exact composite ownership membership binding.

**RLS and ACL must exist in the same resource's migration transaction**: enable and FORCE RLS; use a command-service policy comparing exact row `tenant_id` to transaction-local `nullif(current_setting('avuhz.tenant_id', true), '')::uuid` in both `USING` and `WITH CHECK`; revoke table privileges from `PUBLIC`, `anon`, `authenticated`, and `service_role`. Do not grant runtime INSERT/UPDATE/DELETE during directory creation, and never grant `BYPASSRLS`, DDL, ownership, or migration role membership. Any future SELECT grant must be independently reviewed and scoped.

**Verification before completion**: existence/constraint/catalog digest, RLS enabled/forced, exact policy/grants, absent tenant context denial, cross-tenant denial, no direct anon/service-role access, no indirect write route, no PII in serialized rows, and disposable PostgreSQL 17 migration/rollback tests. Update the current fixed 16-table readiness inventory **only through a separately reviewed baseline change**; never loosen the old 16 table checks.

## Resource 2 — owner membership (separate future resource, proposed)

Proposed table: `public.avuhz_tenant_owner_memberships`.

- Composite foreign key `(tenant_id, organization_id)` to the exact verified directory record; no free-floating owner/membership row.
- `principal_subject_digest` constrained to `sha256:[0-9a-f]{64}`; digest is calculated only from a cryptographically verified AUTH subject by a trusted server, never from browser JSON or a caller-supplied hash.
- `member_role` is initially exactly `OWNER`, with closed state `PENDING_VERIFICATION`, `ACTIVE`, `REVOKED`; record/version and verification timestamps. No raw AUTH subject, login token, email, phone or credential.
- Unique `(tenant_id, principal_subject_digest)` plus the composite organization binding. No automated owner transfer, escalation, self-registration or cross-tenant discovery.
- Enable and FORCE tenant RLS, use the existing `avuhz_command_service_tenant_isolation` comparison pattern, and revoke all direct PUBLIC/anon/authenticated/service_role privileges. **No runtime writer grants** until a separate trusted, idempotent, atomic registration command has been reviewed and independently tested.

**Verification before completion**: deny claimed/unverified owner, wrong business, wrong organization, wrong tenant, changed digest, stale/revoked evidence, duplicate/conflicting idempotency, expired session, privileged role spoofing, missing step-up, and direct SQL/anon access. A failed insert must never leave an orphaned tenant; the eventual registration command must use a separately authorized atomic transaction across these resources and an independently verified AUTH-derived owner identity.

## Bootstrap authority and first pilot acceptance

1. Establish an independent **trusted** proof-of-business-ownership source and a hosted human identity. A plain `VerifiedOwnerEvidence` dataclass, a string such as `AUTHORITATIVE_OWNER_DIRECTORY`, a GitHub owner login, a synthetic DEVELOPMENT JWT, or a matching business reference is not proof by itself.
2. Add the shared, closed command/identity capability only after verified ownership and per-tenant membership mapping are available. The current DEVELOPMENT allowlist must not be broadened as a shortcut.
3. Create one development pilot tenant and verified owner membership with a fresh, exact, owner-approved provider mutation after SQL/RLS/grant verification. Check idempotency, absence of partial writes, and cross-tenant isolation.
4. Grant service entitlements **only** for implemented shared services. n8n, communications, and Stripe are not ready merely because onboarding intent lists them. Client data intake, real OIA handoff, or Phase 6 must not run automatically.
5. Validate a synthetic SekInfra → Avuhz governed handoff against the new tenant before accepting real client data. SekInfra's OIA and public website logic remain in its separate repository.

## Completion boundary

**Proposal complete != registered business.** No tables, migration, SQL dispatch, AUTH identity/metadata, credential, environment secret, API route, workflow, billing path, or hosted resource is created by this file.

**Next single-resource implementation:** prepare the `public.avuhz_tenant_organizations` DEVELOPMENT DATA migration and its disposable-Postgres RLS/ACL regression test, subject to exact migration allowlist and resource authorization; verify before proposing the separate membership resource.
