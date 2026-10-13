# DEVELOPMENT AUTH `auth.sessions` policy-owner authorization gate

**Status: REVIEW-ONLY / PROVIDER MUTATION BLOCKED.** This document records a
single-resource feasibility and authorization plan, **not** an executable SQL
artifact, provider credential request, migration, or change approval. It does not
authorize a retry, owner-role impersonation, policy creation, or access grant.

## Confirmed target and authority boundary

| Field | Exact scope |
| --- | --- |
| Source | `AnonymousKoo/avuhz-infra`, this repository-only review |
| Source baseline | `main` at `6d6340fe71cfb6c6484f96dc5d73ea456315fecf` |
| Environment | DEVELOPMENT only; no staging or production |
| Provider | Supabase **AUTH** project `pwlhruwutoitnieactol`, PostgreSQL 17.6 |
| Explicitly excluded | Supabase **DATA** project `gnuqaefotwgkwurjpyik` |
| Proposed future resource | **Only** one SELECT RLS policy on `auth.sessions` |
| Provider operation authorized now | **None** |
| Authority classification | Repository document R0; proposed eventual RLS provider mutation **R2**, requiring fresh exact approval |

This is shared Avuhz identity infrastructure. Sekinfra must not get direct AUTH
database access, independent login infrastructure, or owner-registration
authority from this plan. The separate `auth.mfa_factors` policy, column grants,
schema USAGE, reader credential, hosted composition, and business owner proof
are **not** in this resource change.

## Current read-only provider proof (2026-10-13 UTC)

Observed on **DEVELOPMENT AUTH**, using read-only catalog checks (aggregates
and role/permission flags; no passwords, JWTs, factor secrets, raw identity or
session records were returned):

- `auth.sessions`: table owner `supabase_auth_admin`; RLS enabled; FORCE RLS
  not enabled; **zero** policies. `auth.mfa_factors` also has the same owner
  and RLS mode. These are Supabase-managed AUTH tables.
- `avuhz_owner_session_reader_dev` **already exists**. It is a login role
  with `NOSUPERUSER`, `NOBYPASSRLS`, `NOINHERIT`,
  `NOCREATEDB`, `NOCREATEROLE`, and connection limit 1.
  **Do not recreate this role.**
- The reader has no `auth` schema USAGE/CREATE, no table SELECT, and no
  `auth.sessions` column SELECT grant. This is an intentional dormant state.
- The available SQL executor is `postgres`, which has **no** AUTH schema
  CREATE permission and **no** membership or SET privilege in
  `supabase_auth_admin`.
- The separate real-owner enrollment has an independently verified TOTP factor
  and a single MFA-backed AAL2 session. This verifies authentication state,
  **not** business ownership or the reader's ability to access these tables.

Older `docs/development-auth-owner-session-rls-provider-gate-20261012.md`
records a historical role-**absent** state; the live role now exists. Current
provider state supersedes that snapshot. Do not treat the existence of the role
as proof the next policy may be created.

## Exact future policy *contract* — not deployable SQL

The dormant shared-core session verifier in
`src/avuhz_service/development_auth_owner_session_record.py` requires:

| Field | Required value |
| --- | --- |
| Relation | `auth.sessions` **only** |
| Policy name | `avuhz_owner_session_reader_dev_scope` |
| Command | `SELECT` **only** |
| Target role | `avuhz_owner_session_reader_dev` **only** |
| Permissiveness | `PERMISSIVE` with exact role/predicate and no other policy |
| Predicate | `user_id = NULLIF(current_setting('avuhz.owner_subject', true), '')::uuid` |
| `WITH CHECK` | NULL / absent |
| Extra policies | None on `auth.sessions` |
| AUTH provider ownership / GoTrue | Must remain unchanged and operational |
| Independent subject authentication | Required upstream; PostgreSQL GUC alone is NOT proof of identity |

PostgreSQL 17's normalized predicate string and exactly two final policies
(one per table) are already checked by `_ROLE_PREFLIGHT_SQL`. The existing
disposable PostgreSQL 17 tests in
`tests/migrations/test_development_auth_owner_session_rls_v1.py`
validate only the *synthetic* expected design, not Supabase's table-owner
authorization or compatibility. Even a valid `auth.sessions` policy **alone
will not** activate the session reader: the separate `auth.mfa_factors` policy,
narrow grants, protected credential and hosted wiring remain absent.

## Feasibility decision required *before* any migration or policy draft

**HARD STOP: the current `postgres` SQL executor cannot legitimately CREATE
a policy on a table owned by `supabase_auth_admin`.** The available direct
migration API does not convert an unprivileged role into the table owner.
Creating speculative `CREATE POLICY` SQL and repeatedly attempting it is not
a valid progress step.

A security reviewer and an authorized Supabase project owner/provider
representative must establish and record, without sharing any credentials:

1. **Supported execution mechanism.** Is modifying RLS on the provider-managed
   `auth.sessions` table supported by Supabase for this project/version?
   Identify the actual provider-supported, audited table-owner action and
   explicit principal that would apply exactly **one** policy, *if supported*.
   Do not assume a dashboard admin session, regular SQL editor, broad
   `postgres` grants, `SET ROLE supabase_auth_admin`, temporary owner
   membership, `SECURITY DEFINER`, `service_role`, or a superuser bypass
   is acceptable. Do not issue or request a token/password in chat.
2. **Blast-radius review.** Prove the operation preserves GoTrue's provider
   management, internal privileges and RLS behavior; confirm that a
   role-targeted `SELECT` policy cannot broaden `anon`, `authenticated`,
   `PUBLIC`, `postgres`, or other actors. Identify expected failure and
   recovery behavior if the provider manages or replaces its AUTH policies.
3. **Independent authority.** Name the responsible reviewer and approved
   execution boundary. Specify the exact provider ID, role, table, intended
   predicate, preflight, transaction, postcondition and rollback. Obtain
   *fresh*, **resource-specific** DEVELOPMENT AUTH approval. Do not reuse
   prior role-creation, DATA, owner-enrollment or credential approvals.
4. **Unsupported path.** If no legitimate table-owner mechanism exists, STOP.
   Propose a separately reviewed, least-privilege shared-core design that
   uses supported GoTrue surfaces. Do not quietly loosen the session freshness
   invariant or substitute JWT signature alone for session revocation proof.

This decision is the **next** gate. No provider DDL is approved by this file.

## Proposed single-resource execution gate (only after feasibility is proven)

A separately authored, reviewed, source-and-digest-bound artifact may be
prepared *later* for `auth.sessions` alone. Before an explicitly approved
one-shot operation, independently re-check:

- exact DEVELOPMENT AUTH project and PostgreSQL 17 version;
- legitimate `supabase_auth_admin` owner authority and supported execution
  mechanism, not a guessed elevated credential;
- `auth.sessions` still owned by `supabase_auth_admin`, RLS enabled,
  existing policy count **0**, and no unexpected grants/role memberships;
- reader role still least-privileged and cannot bypass RLS;
- no change to GoTrue-managed schema, user/session/factor records or DATA.

The later owner-authorized operation, if allowed, must create **exactly one**
named reader-only policy on `auth.sessions`, in one transaction, with
independent catalog readback matching the full contract above. Stop on drift
or ambiguous outcome; no blind retry. Postcondition must also prove that
no other policy, table grant, role membership, user record or credential was
introduced. Record sanitized, non-PII outcomes only.

**Rollback** must be independently approved under the *same legitimate
table-owner mechanism*: remove **only** the newly introduced named
`auth.sessions` policy, and verify pre-change policy/ACL counts and GoTrue
behavior. Never disable RLS, rewrite AUTH tables, revoke GoTrue privileges,
or touch `auth.mfa_factors` as part of this rollback. Define the operator
responsible for rollback *before* scheduling a mutation.

Only after verified policy completion may a distinct boundary be proposed
for `auth.mfa_factors` and, later, grants/secret binding. A green local
test or success on this one table does not make the dormant verifier usable.

## Four-lane impact and next action

- **Security:** do not privilege-escalate against Supabase-managed AUTH tables;
  do not expose MFA secrets/PII; preserve fail-closed session verification.
- **Infrastructure:** verify a provider-sanctioned AUTH table-owner policy
  mechanism; the existing reader role does not need recreation.
- **Automation:** no n8n integration, customer handoff, session checker
  deployment, or workflow activation is authorized.
- **Business:** the real owner now has MFA, but paying-client onboarding
  still requires independent business-owner proof and approved Avuhz
  capability; account security is not client readiness.

**Next action:** obtain a read-only, provider-supported table-owner
feasibility decision for **`auth.sessions` only**. If supported, prepare a
fresh exact approval and a new narrowly scoped implementation artifact.
If unsupported, stop and design a safe supported shared-core alternative.
