# R2 DEVELOPMENT DATA handoff-claim migration proposal v1 (REVIEW ONLY)

**Status:** repository-only proposal. **DO NOT APPLY.** This is not a Supabase migration, provider artifact, workflow, credential binding, signed approval, or authority to dispatch. The draft transaction below ends in `ROLLBACK` intentionally. It has not been certified against hosted DATA.

## Exact source and target boundary

- Repository: `AnonymousKoo/avuhz-infra`; protected main at proposal start: `70bb258957f34a30df3f8aedf49a8b99e28cf402` (PR #582 merge). Rediscover and bind the exact main SHA before any future action.
- **Future** provider target only: Supabase **DEVELOPMENT DATA** project `gnuqaefotwgkwurjpyik`. Its hosted database, current migration history and privileges have **not** been inspected for this proposal.
- Distinct and excluded: Supabase **DEVELOPMENT AUTH** `pwlhruwutoitnieactol`; no Auth changes, users, JWTs, sessions, or credentials.
- Excluded: staging, production, customer tenants, Render, n8n, billing, one-shot GitHub workflow dispatch, private signing material, and any remote mutation.
- Repo boundary: one **documentation file only**. There is no new `supabase/migrations/*.sql` or provider-artifact SQL. `scripts/check-baseline.sh` allowlists SQL surfaces; bypassing this guard is prohibited.

## Why this exists

PR #582 added the **disconnected** adapter `src/avuhz_engineering/development_handoff_durable_claim_candidate.py`, a disposable-PostgreSQL fixture/test suite, and `docs/development-handoff-shared-postgres-claim-candidate-v1.md`. Six concurrent connections, atomic four-stage collision rollback, replay denial, role isolation, and tenant RLS were exercised in disposable PostgreSQL. These tests **do not** prove hosted provider privileges, a trusted runner, owner attribution, signed approvals, or a live cross-run claim.

The existing `public.avuhz_idempotency_records` is for **business commands** under `avuhz_command_service`; it must not be repurposed as a security approval ledger. The existing SQLite stage claims are file-local, not cross-runner durable.

## Proposed single atomic installation unit — not approved

One separately authorized DEVELOPMENT DATA migration would create:

1. Private schema `avuhz_handoff_control` and separate table `avuhz_handoff_approval_claims` (no `public` API exposure).
2. Dedicated `avuhz_handoff_claim_writer` **NOLOGIN, NOINHERIT, NOBYPASSRLS** role with no role membership or DDL/table ownership.
3. Database-enforced stage, digest, SHA, project-reference constraints and immutable uniqueness for per-approval, per-authorization-stage, and per-command-stage consumption. Four inserts occur in **one** transaction in the existing adapter; one collision must roll back all four.
4. **Enabled and FORCED tenant RLS**, insert-only writer `WITH CHECK` policy, schema USAGE/table INSERT only, no SELECT/UPDATE/DELETE, and explicit denials of exposed/business roles.
5. No grant to a runner/login role in this installation unit. A future trust-bound runner credential and narrowly reviewed membership/`SET ROLE` flow are a **different** resource/approval.

### Candidate SQL for disposable review — deliberately rolled back

The following is **not** in an executable migration path. It mirrors the existing adapter's column contract but is a **new proposed provider migration**, not a copy/paste authorization of the PR #582 fixture. It must be reviewed, adapted for real provider privilege behavior, tested on disposable PostgreSQL, then translated into a separately source-bound artifact. Its final `ROLLBACK` is intentional.

```sql
BEGIN;

DO $preflight$
BEGIN
  IF to_regnamespace('avuhz_handoff_control') IS NOT NULL
     OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='avuhz_handoff_claim_writer') THEN
    RAISE EXCEPTION 'HANDOFF_CLAIM_PREEXISTING_RESOURCE_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname = current_user AND (rolsuper OR rolcreaterole)
  ) OR NOT has_database_privilege(current_user, current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'HANDOFF_CLAIM_MIGRATION_IDENTITY_UNVERIFIED';
  END IF;
END
$preflight$;

CREATE ROLE avuhz_handoff_claim_writer
  NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE SCHEMA avuhz_handoff_control;
REVOKE ALL ON SCHEMA avuhz_handoff_control FROM PUBLIC;

CREATE TABLE avuhz_handoff_control.avuhz_handoff_approval_claims (
  tenant_id uuid NOT NULL,
  stage text NOT NULL CHECK (stage IN (
    'AUTH_GLOBAL_LOGOUT','AUTH_GENERATE','AUTH_VERIFY','DATA_COMMAND')),
  plan_id text NOT NULL CHECK (plan_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  step_id text NOT NULL CHECK (step_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
  approval_digest text NOT NULL CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
  project_reference text NOT NULL,
  authorization_set_digest text NOT NULL
    CHECK (authorization_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  command_digest text NOT NULL CHECK (command_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_sha text NOT NULL CHECK (source_sha ~ '^[0-9a-f]{40}$'),
  claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,plan_id,step_id),
  UNIQUE (approval_digest),
  UNIQUE (tenant_id,authorization_set_digest,stage),
  UNIQUE (tenant_id,command_digest,stage),
  CONSTRAINT stage_project_bound CHECK (
    (stage='DATA_COMMAND' AND project_reference='gnuqaefotwgkwurjpyik')
    OR
    (stage<>'DATA_COMMAND' AND project_reference='pwlhruwutoitnieactol')
  )
);

ALTER TABLE avuhz_handoff_control.avuhz_handoff_approval_claims
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE avuhz_handoff_control.avuhz_handoff_approval_claims
  FORCE ROW LEVEL SECURITY;

CREATE POLICY avuhz_handoff_claim_writer_tenant
  ON avuhz_handoff_control.avuhz_handoff_approval_claims
  FOR INSERT TO avuhz_handoff_claim_writer
  WITH CHECK (
    tenant_id = NULLIF(
      current_setting('avuhz.handoff_claim_tenant', true), ''
    )::uuid
  );

REVOKE ALL ON avuhz_handoff_control.avuhz_handoff_approval_claims FROM PUBLIC;

DO $deny_exposed_roles$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['anon','authenticated','service_role',
                              'avuhz_command_service']
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=name) THEN
      EXECUTE format('REVOKE ALL ON SCHEMA avuhz_handoff_control FROM %I',name);
      EXECUTE format(
        'REVOKE ALL ON TABLE avuhz_handoff_control.avuhz_handoff_approval_claims FROM %I',
        name
      );
    END IF;
  END LOOP;
END
$deny_exposed_roles$;

GRANT USAGE ON SCHEMA avuhz_handoff_control TO avuhz_handoff_claim_writer;
GRANT INSERT ON avuhz_handoff_control.avuhz_handoff_approval_claims
  TO avuhz_handoff_claim_writer;

-- REVIEW ONLY: no durable provider object must be created from this document.
ROLLBACK;
```

## Required preflight and acceptance checks before any future remote installation

- **Source/project:** independently confirm exact protected-main SHA, DEVELOPMENT DATA project ref and actual database endpoint; compare with known DEVELOPMENT AUTH ref. Verify provider SQL version, migration identity, `CREATE ROLE` and `CREATE SCHEMA` authority, and existing migration history. Stop if ambiguous.
- **Absence and conflicts:** confirm `avuhz_handoff_control`, table, role, policies, grants, memberships and any related resource are absent; never silently adopt or overwrite unknown state. Do not change the canonical 16 `public.avuhz_*` tables or the business-command idempotency table.
- **Role/ACL:** independently prove writer flags: `rolcanlogin=false`, `rolinherit=false`, `rolbypassrls=false`, `rolsuper=false`, no create/replication privileges, no implicit membership. Enumerate effective `USAGE`, `INSERT`, `SELECT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, ownership, and `GRANT OPTION` for writer, provider roles and any inherited roles. Check default ACLs and memberships; deny any unreviewed access.
- **Tenant RLS:** assert `relrowsecurity=true`, `relforcerowsecurity=true`, exactly one insert-only writer policy, correct `WITH CHECK`, and negative cross-tenant, missing-tenant and malformed-tenant tests. SQL session variables are **caller-settable**: RLS using `avuhz.handoff_claim_tenant` does not independently authenticate the owner or tenant. Trust must come from the separately reviewed source-bound runner/owner authority chain.
- **Cross-run durable claim:** exercise fresh distinct PostgreSQL sessions and runner-equivalent connections, six simultaneous attempts with exactly one success, per-stage replay denial across source SHA changes, four-stage rollback on conflict, and ambiguous-commit **terminal** refusal without retry.
- **Least privilege:** no direct claim-table access for `PUBLIC`, `anon`, `authenticated`, `service_role`, or `avuhz_command_service`. Reject API schema exposure, SECURITY DEFINER shortcuts, owner privileges for runtime identities, broad grants, and live `service_role` writer use. Explicitly verify future LOGIN → `SET ROLE` eligibility only in its own approved step.
- **Provider-specific hazards:** hosted DATA may restrict role creation or schema privileges and may have default grants that differ from disposable PostgreSQL. Do not infer provider readiness from local tests. If installation is impossible under least privilege, stop and prepare a revised proposal, not a privileged workaround.
- **Reconciliation:** after separately approved installation, independently read back the actual table, policies, roles, grants and migration identity. Sanitize evidence; capture no user PII, secret, private PEM, database DSN, or raw signed authorization.

## Exact sequence after this proposal

1. Accountable owner reviews this *repository-only* scope and separately approves preparing an **actual migration artifact plus disposable SQL tests**; do not treat a passing repository documentation PR as migration certification.
2. Review and certify the resulting SQL against disposable PostgreSQL and independently preflight DEVELOPMENT DATA. Then request **fresh, time-bounded, source-bound approval for exactly one DATA installation transaction**; no bundled runner credential operation.
3. Independently verify provider postconditions. Only in separate subsequent boundaries review trusted runner DB/login binding, human owner attribution and fresh four signed stage authorizations; then one fictional DEVELOPMENT `AcceptImplementationHandoff`, DATA readback and AUTH session/key cleanup.
4. After that successful synthetic end-to-end result, proceed to the Sekinfra integration path. Keep customer onboarding on hold until the required security gates pass; do not build another authorization service.

## Stop conditions / known gaps

- The SQL is a **proposal**, not an executed or integration-tested migration. GitHub Main PR Gate on a documentation-only PR does not certify the SQL.
- No hosted DATA schema, writer role, migration identity or role membership was inspected or mutated here.
- No trusted cross-run database connection, independently attested human-owner binding, fresh four signed approvals, runtime wiring, or live handoff exists as a result of this proposal.
- The `avuhz.handoff_claim_tenant` setting is not itself an identity or signature check; untrusted callers must never receive the writer connection.
- Any conflict, privilege escalation, RLS gap, project mismatch, credential/PII exposure, or unknown commit outcome is a hard **STOP**.

**Next action:** owner reviews this documentation-only candidate; prepare a separately authorized real migration and disposable test PR, not a remote apply.
