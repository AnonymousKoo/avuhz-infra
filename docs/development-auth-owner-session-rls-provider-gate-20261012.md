# DEVELOPMENT AUTH owner-session RLS provider gate — October 12, 2026

**REPOSITORY-ONLY design and evidence. No Supabase operation is approved.**

**Validated boundary:** `AnonymousKoo/avuhz-infra`, DEVELOPMENT
**AUTH** `pwlhruwutoitnieactol` (PostgreSQL 17.6);
**DATA** `gnuqaefotwgkwurjpyik` is an entirely separate project and
**never** a fallback. No STAGING or PRODUCTION access.

## Read-only provider evidence, not assumed grants

| AUTH provider resource | Verified on October 12, 2026 |
| --- | --- |
| `auth` schema | Owner `supabase_admin`; `postgres` has USAGE but **not CREATE** |
| `auth.sessions` | Owner `supabase_auth_admin`; RLS enabled, not FORCE |
| `auth.mfa_factors` | Owner `supabase_auth_admin`; RLS enabled, not FORCE |
| Current policies on those two tables | **0** |
| `avuhz_owner_session_reader_dev` role | **Absent** |
| `postgres` -> `supabase_auth_admin` | No role membership or SET permission |
| `postgres` authority | It has BYPASSRLS and table grants with grant option; **unsuitable as a runtime identity** |
| Sessions; verified MFA factors | **0; 0** |
| Existing pre-tenant human subjects | **0** (two AUTH users are already DEVELOPMENT-tenant-bound) |

`postgres` **does not own** the two AUTH tables and cannot issue an ordinary
`CREATE POLICY` for them using its present membership. A provider
`apply_migration` running as `postgres` cannot be assumed to succeed.
Do **not** temporarily elevate it to the AUTH owner, create AUTH policies,
or change core GoTrue-owned RLS under an unreviewed approval. The provider
owner/administration path and blast radius must first be expressly approved.

## Repository-only shared-core implementation

- `src/avuhz_service/development_owner_mfa_freshness.py` verifies exact
  AUTH issuer, ES256 JWT, native pretenant audience, human subject, fresh
  signed TOTP AMR and `GET /auth/v1/user`; that endpoint **alone is not
  session-revocation proof**.
- `src/avuhz_service/development_auth_owner_session_record.py` remains
  uncomposed/dormant; it requires direct AUTH host, verified TLS, non-elevated
  exact login, only the expected column grants, table RLS, and **exactly
  two** owner-subject RLS SELECT policies. A missing or different policy
  denies before any session lookup.
- The upstream **cryptographically verified** owner subject is transactionally
  bound using `set_config('avuhz.owner_subject', subject, true)`; its
  read-only, parameterized proof looks up the exact signed subject/session,
  unexpired AAL2 session, and currently verified TOTP factor. It returns
  only a boolean and always closes/rolls back.
- Exact expected policy name for each table:
  `avuhz_owner_session_reader_dev_scope`. Intended predicate:
  `user_id = NULLIF(current_setting('avuhz.owner_subject', true), '')::uuid`,
  SELECT-only to the dedicated reader. Expected PG17 normalized predicate
  is checked byte-for-byte by the runtime; extra AUTH policies cause denial.
- `tests/migrations/test_development_auth_owner_session_rls_v1.py`
  tests a **disposable** synthetic version of these grants/policies on PG17,
  not actual Supabase AUTH ownership or approved grants.

**Critical security distinction:** A PostgreSQL connection can set its own
custom GUC. The subject setting **cannot prove who is logged in or who owns
a business**. Only the separate signed AUTH user/session/MFA checks and
independent business-ownership directory decide whether this subject is
authorized. Never export the session-record SQL checker as a caller-controlled
API or use `service_role`/postgres to work around an RLS denial.

## Required provider approvals, one resource boundary at a time

1. **AUTH role preparation:** Audit the intended login's exact role flags,
   no password, no inherited roles, and no default table/schema access.
   Prepare a separate DEVELOPMENT AUTH role-creation source, CI and
   single-resource provider approval. No DATA permissions.
2. **AUTH schema owner policy feasibility:** Obtain a specific
   `supabase_auth_admin`-owned authorization method approved by the
   operator/provider. Check it does not disturb GoTrue's own management
   of `auth.sessions` or `auth.mfa_factors`. Each protected table's
   SELECT policy is a **separately approved resource change**, never a
   generic open policy or AUTH-table-wide grant.
3. **Minimal column privileges:** Separate exact grant authority and
   check the actual columns. Reader may select
   `sessions(id,user_id,aal,not_after,factor_id)` and
   `mfa_factors(id,user_id,status,factor_type)` only, with `auth` USAGE
   but **no CREATE**. Absolutely no raw factor `secret`, email,
   refresh tokens, INSERT/UPDATE/DELETE/TRUNCATE, table-wide ACL,
   BYPASSRLS, grants to `anon`/`authenticated`, or cross-project key.
4. **Private reader credential:** Only after the isolated role/RLS/ACL
   is independently verified, approve a secret lifecycle in a designated
   server-side vault/secret manager and pin TLS `verify-full` to the
   actual AUTH host. Do not commit DSNs or issue passwords as part of a PR.
5. **Real owner and synthetic proof:** One new legitimate pre-tenant
   DEVELOPMENT AUTH human must personally enroll current TOTP MFA.
   Verify the exact session, logout/revocation denial, wrong subject,
   missing factor, expired session, and no PII leakage. A successful
   synthetic database row is **not** live provider evidence.
6. **Business owner authority and DATA registration:** Independent
   real-world authorized-person/business verification must precede the
   separate DATA `PENDING_VERIFICATION` registration and `ACTIVE`
   transition. AUTH and DATA stay distinct; no live Sekinfra intake
   until the shared service, n8n receiver and full development chain pass.

## Four-lane next action

**Security:** Keep AUTH-owned tables and role privileges untouched until
their owner authority is verified. **Infrastructure:** Review the exact
one-role and column-grant resources independently. **Automation:** Keep
n8n receiver and website intake disabled; no synthetic trust is promoted
to hosted authority. **Business:** Identify the consenting first operator
and actual business evidence in a private enrollment process, so the next
engineering gate leads to a real first Sekinfra pilot instead of another
general platform expansion.

**Next action:** Run full CI on this *repository-only* RLS-bind candidate.
After merge, resolve the protected AUTH policy-owner boundary read-only
and prepare the **single**, individually approved AUTH role-creation
candidate; do not issue a provider mutation until the policy authority
and approved human enrollment sequence are verified.
