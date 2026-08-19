# Existing Supabase project inventory (A0)

## 1. Scope

This is a read-only inventory of the approved existing Supabase project. It records CLI link and migration-history observations only. It does not approve the remote schema as an Avuhz target, apply a migration, inspect application rows, or alter any remote resource.

## 2. Confirmed target and access state

- Approved and linked project ref: `gnuqaefotwgkwurjpyik`.
- Authentication was usable through the operator's existing local CLI login.
- The project-local Supabase CLI was `2.115.0`.
- Local link data is stored only under ignored `supabase/.temp/`; it is not a committed source of truth.

## 3. Migration history

`migration list --linked` reported no local migration versions and one remote migration version:

| Local version | Remote version | Status |
| --- | --- | --- |
| none | `20260816120000` | remote-only; histories are not aligned |

No migration repair, application, reversion, or remote history update was performed.

## 4. Baseline pull status

Docker was available locally. `db pull` connected for a schema-only operation but stopped with `LegacyDbPullMigrationConflictError` before producing a local baseline because remote migration history does not match the empty local `supabase/migrations/` directory. The CLI suggested migration repair; that suggestion was deliberately not followed.

There is no pulled baseline migration file. No alternative schema dump or remote SQL operation was attempted, because this inventory is not authorized to bypass or repair migration history.

## 5. Public schema inventory

**Deferred.** Without a successful schema-only baseline, public table definitions, keys, indexes, RLS state, policies, grants, triggers, functions, and RPC definitions cannot be asserted safely. No table rows or customer data were inspected.

## 6. Slice 1 collision matrix

The following statuses are `UNKNOWN`, not `ABSENT`: no schema baseline exists from which to make a safe assertion.

| Planned durable resource | Remote status | Reason | Provisional future action |
| --- | --- | --- | --- |
| `acquisition_handoffs` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `engagements` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `diagnostic_scopes` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `human_approvals` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `idempotency_records` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `lifecycle_events` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |
| `outbox_deliveries` | UNKNOWN | schema pull blocked | NEEDS_OWNER_REVIEW |

The target table ownership and invariants remain those in [Phase 4 persistence design](phase4-persistence-design.md); this document does not change them.

## 7. Legacy-overlap classification

Objects resembling engagements, OIA submissions, events, incidents, infrastructure monitoring, payment, agreements, credential/access tracking, deployment, or workflow state are **UNKNOWN** until a schema-only baseline can be captured. The legacy filesystem tree was not inspected or used as migration input.

## 8. RLS, auth, storage, functions, and privileges

- **RLS/policies:** deferred; no safe schema baseline was available.
- **Auth customization:** deferred; no auth users, credentials, or authentication data were read.
- **Storage:** not required for Slice 1 inventory and not inspected.
- **Functions/triggers/RPC:** deferred; none were invoked.
- **Grants/privileges:** deferred; no grants were changed.

## 9. Phase 4 design gap and data-preservation risk

Every existing-object compatibility decision is **UNKNOWN**. Consequently, data-preservation risk for all potentially overlapping durable resources is **UNKNOWN**. Do not infer absence, compatibility, or safe replacement from the lack of a local migration file.

The planned migration strategy remains additive by default: after a reviewed schema baseline is available, classify each discovered object as `REUSE_AS_IS`, `ALTER_IN_PLACE`, `ADD_PARALLEL_NEW_TABLE`, `BACKFILL_THEN_SWITCH`, `DEPRECATE_LATER`, `DO_NOT_TOUCH`, or `NEEDS_OWNER_REVIEW`. Prefer parallel/additive tables when compatibility or data risk is uncertain.

## 10. Objects explicitly not touched

- Remote migration history and migration repair state.
- All remote tables, rows, constraints, RLS policies, grants, functions, triggers, auth settings, storage settings, and project configuration.
- Local ignored CLI linkage and credential-bearing temporary state.

## 11. Owner decision required

| Question | Recommended default | Consequence |
| --- | --- | --- |
| Who is authorized to reconcile the existing remote migration history with the clean repository baseline? | Assign a migration owner to review the remote-only version and approve an explicit baseline/reconciliation procedure. | Blocks reliable `db pull` and any subsequent migration work. |
| Must the remote-only migration and its dependent application schema/data be preserved? | Treat it as preserved until a reviewed schema baseline and application-dependency assessment prove otherwise. | Determines whether later work is additive, backfill-and-switch, or a separate target. |

## 12. Exact recommended next batch

**Migration-history reconciliation decision, no schema change:** an authorized owner reviews the remote-only migration `20260816120000`, confirms the intended source of truth and data-preservation requirements, and explicitly approves a non-destructive baseline/reconciliation path. Only after that approval should a new read-only schema baseline be captured and inventoried. No Avuhz migration, RLS change, or remote SQL is authorized by this document.
