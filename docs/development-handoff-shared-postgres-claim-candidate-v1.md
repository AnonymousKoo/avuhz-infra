# Shared PostgreSQL handoff approval-consumption candidate (DEVELOPMENT ONLY)

**Status: repository-only design, disconnected adapter and disposable-database
security tests. NOT A DEPLOYED SCHEMA, APPROVAL OR EXECUTABLE HANDOFF.**

## Confirmed repository boundary and provider distinction

- Repository: `AnonymousKoo/avuhz-infra`, source `main`
  `5bb9e091af27a3986252917ada08b4eb60be2d42` at preparation.
  Exact SHA must be rediscovered after this PR merges.
- Future shared store target, subject to distinct approval: Supabase
  **DEVELOPMENT DATA** `gnuqaefotwgkwurjpyik`.
- Existing identity project: Supabase **DEVELOPMENT AUTH**
  `pwlhruwutoitnieactol` — absolutely NOT the place for the DATA
  claim table; no permission, session, user, or recovery-token changes.
- Existing shared business tables are in `public` on DATA. The baseline
  migration creates `avuhz_command_service` as NOLOGIN, NOINHERIT,
  NOBYPASSRLS and grants it narrowly scoped direct table access. All 16
  authoritative `avuhz_*` tables have tenant-scoped RLS based on
  transaction-local `avuhz.tenant_id`. The existing SQL schema grants
  **zero direct table authority** to `PUBLIC`, `anon`,
  `authenticated`, and `service_role`.
- The existing `public.avuhz_idempotency_records` is BUSINESS-command
  idempotency. It is NOT a shared approval-consumption ledger. Its schema,
  tenant policy and grants must NOT be repurposed.
- Current `development_handoff_single_use_claim.py` and
  `development_handoff_trusted_one_shot_executor.py` consume stage
  approvals in an owner-private SQLite file, atomic only for contenders
  sharing that one file. GitHub ephemeral runners do not share that ledger.
- The read-only GitHub environment public-key check
  [37861471138](https://github.com/AnonymousKoo/avuhz-infra/actions/runs/37861471138)
  passed key/fingerprint and GitHub source context, but it did not
  independently establish human owner attribution, durable approval
  consumption, signed authorization stages or live execution authority.

## Candidate prepared in this PR

`src/avuhz_engineering/development_handoff_durable_claim_candidate.py` is
a **disconnected persistence adapter**, NOT the handoff executor and NOT a
credential provider. Its invocation needs an injected connection factory to
an already provisioned PostgreSQL store with the exact least-privilege role,
forced tenant RLS and approved environment. It does not create its schema or
role, fetch credentials, verify approval signatures, issue tokens, contact
Supabase by itself, or send commands.

Its four-stage atomic `INSERT` transaction is independent of caller retries.
A unique `approval_digest` prohibits using the same signed approval again;
unique `(tenant_id, authorization_set_digest, stage)` and
`(tenant_id, command_digest, stage)` prohibit reissuing a stage under
rebound plans or SHA. The four stage plan identifiers and stage-to-project
assignments are validated against existing shared handoff constants. On
conflict, all attempted inserts roll back; on uncertain commit, it fails
closed and never declares the claim reusable. A successful candidate receipt
sets `live_execution_authorized=false`, `retry_authorized=false`,
`human_owner_binding_verified=false`,
`signed_approval_authority_verified=false`, and
`provider_environment_installed=false`.

`tests/integration/test_postgres_development_handoff_durable_claim_candidate.py`
creates a disposable **local-only** `avuhz_handoff_control` schema and
`avuhz_handoff_claim_writer` NOLOGIN/NOBYPASSRLS/NOINHERIT role using its
own fixture DDL; **this DDL is not in `supabase/migrations` and cannot be
applied by a deploy path**. The fixture enables and **FORCES** RLS and
limits the writer to schema USAGE and table INSERT with tenant `WITH CHECK`.
No SELECT, UPDATE or DELETE for the writer, no direct access for
`avuhz_command_service` or exposed roles. It tears down both schema and
role. It certifies contention across separate connections to the same
disposable PostgreSQL instance, one-success-only, transaction rollback when
one stage was already used, source rebound denial, tenant mismatch denial,
invalid project refusal and ambiguous-store failure codes.

## Future exact installation gate (NOT approved by this PR)

Before ANY remote DATA change, require a separate source-bound R2 migration
proposal and owner authorization for exactly one DEVELOPMENT DATA resource.
Do not copy the disposable test DDL into remote SQL without migration-specific
review. Require, in this order:

1. Independently confirm the correct **DEVELOPMENT DATA** project reference,
   connected database, current protected `main` SHA, migration identity,
   effective role and absence of conflicting `avuhz_handoff_control`
   resources. Do not touch AUTH, production or other tenants.
2. Review a single atomic candidate migration creating a shared dedicated
   control schema, a **nonlogin** least-privilege claim role, a separate table,
   immutable unique constraints, **enabled and forced tenant RLS**, narrowly
   scoped INSERT policy, and default-deny grants. Avoid SECURITY DEFINER
   shortcuts, `service_role`, public schema APIs and blanket grants.
3. Certify on disposable PostgreSQL and preflight the *actual* provider
   version, role inheritance/membership, policy and grants. Prove no direct
   `PUBLIC/anon/authenticated/service_role/avuhz_command_service` access
   and negative cross-tenant behavior. Do not infer safe RLS from a table
   name or existing business-idempotency policy.
4. Provision a reviewed trusted runner/database connection path whose
   effective DB role really is the isolated writer and whose **tenant scope
   is derived from authenticated owner-approved source**, not caller-supplied
   SQL or an API payload. Keep the connection and secret in an approved
   environment secret manager; no private signing PEM on a runner.
5. Bind the adapter ONLY after the executor verifies trusted GitHub source,
   independently confirmed human owner, the exact owner signing key,
   four fresh valid signed stage approvals, approval-set/command digest and
   the explicit one-transaction claim. Do not use a caller Boolean or
   a successful local test as proof of provider installation.
6. Treat all commit/timeout uncertainty as **CONSUMED/UNKNOWN**, never
   auto-retry. Independently observe the durable claim across distinct
   connections/runners without leaking approval contents.
7. Separately approve the narrow short-lived AUTH identity lifecycle, the
   one synthetic `AcceptImplementationHandoff` HTTP request, and tenant-RLS
   DEVELOPMENT DATA readback plus AUTH credential/session retirement.

## Current hard stop conditions

- **Not installed**: The claim schema/role exists only inside disposable
  local test fixtures. No DEVELOPMENT DATA migration or provider change.
- **Not wired**: The first-handoff GitHub workflow remains OFFLINE ONLY;
  the injection-only executor still uses local SQLite and does not import
  or call the PostgreSQL candidate. Its first-run guard is not consumed.
- **Not verified**: No independently attested human owner binding to the
  signing key, fresh four-stage approvals, production-grade runner/DB
  credential binding, cross-run hosted claim, short-lived AUTH session,
  live command or postcondition readback.
- **Not approved**: No remote schema, workflow dispatch, Supabase, Render,
  n8n, billing, credential or customer operation is authorized here.

**Next action:** Review the scoped PR, require full Main PR Gate PASS,
and merge only after accountable R2 owner review. Then **separately**
prepare a precisely reviewed DEVELOPMENT DATA migration/role binding
and explicit execution authorization. The immediate business milestone
remains one fictional DEVELOPMENT handoff followed by Sekinfra integration;
do not over-engineer a second authorization service.
