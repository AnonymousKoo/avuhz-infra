# System #001 — DEVELOPMENT DATA Work Item deadline owner wrapper

**Status:** REVIEW-ONLY repository source candidate. NOT APPROVED for hosted
execution. GitHub merge, passing tests and this file do not grant Supabase
execution authority.

## Exact target and verified prerequisite

- Repository: `AnonymousKoo/avuhz-infra`, source base
  `a8da7ab8cada51f0902c7b632fa2730ff3870e42`.
- Only future target: Supabase **DEVELOPMENT DATA**
  `gnuqaefotwgkwurjpyik`; exclude DEVELOPMENT AUTH
  `pwlhruwutoitnieactol`, production, and every other project.
- Read-only provider checks show `avuhz_work_items` exists,
  FORCE RLS enabled, exactly one command-service tenant policy,
  zero Work Item rows, and no `next_action_due_at` column.
- Both Work Item idempotency CHECK updates are already installed from
  the independently verified owner-wrapper migration
  `development_data_work_item_command_idempotency_owner_wrapper_v1`
  (version `20261015000332`). No new ledger or table is needed.
- Current `postgres` has **no** persistent SET grant to
  `avuhz_data_migration_service_dev`. Command role has no
  parent memberships. Existing Work Item permissions are 9 table ACL
  entries and 13 column ACL entries; RLS policy and idempotency CHECK
  definitions are pinned by source-bound SHA-256 digests.

## Scope and source integrity

The single provider wrapper is
`supabase/provider-artifacts/development-data/current/development_data_work_item_deadline_owner_wrapper_v1.sql`.

Its verbatim embedded canonical SQL body (except standalone outer
BEGIN/COMMIT) is
`supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql`
with SHA-256:
`8511708bce3e2236772d41775ab5fd1fd255cf4097141f621cb604b203bbc9d2`.

One atomic transaction performs preflight owner/role/tenant-policy/ACL
checks, introduces one temporary non-inheriting SET membership for the
migration owner, selects that role transaction-locally, runs the
canonical migration, resets the role, revokes the temporary membership,
and verifies final owner/role/ACL/postconditions before COMMIT.

The only lasting intended change is **one nullable timestamptz column**
`public.avuhz_work_items.next_action_due_at` and **two non-grantable,
column-scoped** INSERT/UPDATE privileges for `avuhz_command_service`.
No table-wide writes, bypass grants, policy replacement, user creation,
tenant/company records, credentials, billing, n8n activation,
communication sending or customer data operations are permitted.

## LOCAL/TEST evidence and limitations

The static contract checks prove exact canonical body reuse, one
transaction, one temporary owner grant/revoke, and no extra DDL.
Five no-network PostgreSQL 17.6 cases ran in an isolated Docker
container without a published port, covering a successful forward
migration, replay denial, permissive RLS drift rejection, unexpected
PUBLIC ACL denial, and full rollback on injected post-DDL failure.
All five passed; the container was destroyed. These tests do not
attest a hosted provider execution or tenant enrollment.

## Required next action

1. Review the source-only PR, run the full Avuhz repository gate and
   confirm immutable wrapper SHA-256 and exact current `main` commit.
2. Perform **fresh**, read-only DEVELOPMENT DATA role/ACL/RLS/column
   preflight. If a required invariant changed, stop and re-review.
3. Obtain a new **separate exact owner approval** for precisely one
   DEVELOPMENT DATA `development_data_work_item_deadline_owner_wrapper_v1`
   execution, its temporary SET membership and revocation, and this
   sole column/grant scope. No automatic retry.
4. Only after approval apply it once, then independently verify the
   migration-history entry, nullable column type, two column grants,
   unchanged tenant RLS, temporary membership revocation, zero
   unintended schema/role changes, and absence of new customer rows.
5. Keep the System #001 read-only due-work reader PR #687 monitored
   independently. Do not mount it as a hosted API or activate n8n
   without distinct owner identity and workload readiness gates.
