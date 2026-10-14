# System #001 DEVELOPMENT DATA — Work Item Idempotency Preflight

**Status:** Repository-only readiness evidence, captured October 14, 2026.
**Not an approval, execution plan, migration result or authorization to retry.**

## Exact resource boundary

- Repository: `AnonymousKoo/avuhz-infra` at `main`
  `fdd7fb566f9e401f2a12ada5c56449d14d000c38`.
- Environment: **DEVELOPMENT DATA** Supabase project
  `gnuqaefotwgkwurjpyik` only.
- Excluded: DEVELOPMENT AUTH `pwlhruwutoitnieactol`,
  production, tenant/customer records, secret lifecycle, n8n, Render,
  hosted ingress, and any other SQL or permission change.
- Single next resource: existing
  `public.avuhz_idempotency_records` CHECK constraints for
  `TransitionWorkItem` and `WORK_ITEM` support; temporary migration
  owner role access is needed only within the reviewed transaction.

## Fresh read-only provider evidence

A project-scoped Supabase read-only inspection on October 14 returned:

- Projects remain distinct and ACTIVE_HEALTHY. This inspection used
  `gnuqaefotwgkwurjpyik`, not AUTH.
- Migration history includes the shared Work Item table install
  `development_data_work_item_table_owner_install_v1`
  (`20261014152105`), and the Work Intake event owner wrapper
  (`20261014095828`).
- Migration history does **not** include a Work Item
  command-idempotency migration or the next-action deadline migration.
- `public.avuhz_work_items`: zero recorded rows at inspection,
  owner `avuhz_data_migration_service_dev`, RLS enabled,
  FORCE RLS enabled, exactly one tenant-scoped policy,
  and **no** `next_action_due_at` column.
- `public.avuhz_idempotency_records`: zero recorded rows,
  same owner, RLS enabled, FORCE RLS disabled as in canonical
  baseline, and one tenant-scoped policy. The existing two named
  CHECK constraints exclude `TransitionWorkItem` and `WORK_ITEM`.
- Both policies are `ALL`, `PERMISSIVE`, restricted to
  `avuhz_command_service`. Their read-only predicate digest is
  `ef79710e5f4248ea201af9151b0908370a99ab8964741bcbcf0f8965980748e6`.
  The combined predicate/with-check digest is
  `1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88`.
  These match the digest expectations in the existing review-only
  owner wrapper, but **do not replace** its fresh full preflight.

No provider mutation or customer row insertion occurred in this inspection.

## Existing canonical SQL and exact source hashes

| File | SHA-256 |
| --- | --- |
| `supabase/migrations/20261014041000_enable_shared_work_item_command_idempotency.sql` | `e3b4fc664b95fe4395b1b885a727f25a92cd4d941492bd324c51d54939b77d33` |
| `supabase/provider-artifacts/development-data/current/development_data_work_item_command_idempotency_owner_wrapper_v1.sql` | `ddb64f6268c347aeef48ce86e641a14b3e38420d6c886f7b54a45fd4b6167bfc` |
| `supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql` | `8511708bce3e2236772d41775ab5fd1fd255cf4097141f621cb604b203bbc9d2` |

These are source file SHA-256 hashes from the inspected Git checkout.
They are NOT approval digests or proof of provider application.
The approved single-transaction idempotency wrapper must perform
fresh owner-role/ACL/RLS/constraint preflight, constrain its temporary
SET membership, apply only the two authorized CHECK replacements,
revoke the temporary membership before COMMIT, and independently
verify exact postconditions.

## One-resource execution sequence — not yet authorized

1. Freeze reviewed source and exact target; confirm current branch
   and immutable SHA-256 for the SQL and wrapper.
2. Obtain **new, explicit** owner approval for exactly one
   DEVELOPMENT DATA idempotency owner-wrapper migration,
   its temporary role membership and revocation, one attempt
   without automatic retry. Do not reuse earlier approvals.
3. Run a fresh independent preflight. If drift exists,
   **stop** and prepare a new reviewed candidate.
4. Only within that new authorization window, execute exactly
   the approved transaction. Check postconditions read-only
   and record sanitized evidence, with no customer records.
5. Separately review and authorize the nullable
   `next_action_due_at` migration. It is NOT part of Step 2's
   approval or execution boundary.
6. Only after both migrations are independently verified may
   the source-only System #001 atomic OPEN deadline writer be
   considered for a strictly bounded synthetic hosted proof.
   No live client intake, n8n activation or production.

**Next action:** Obtain exact one-resource owner authorization for
the idempotency wrapper *after* independent source/role review.
Until then, leave DATA untouched and continue source-only work
on trusted due-time reads and Infrastructure V1.
