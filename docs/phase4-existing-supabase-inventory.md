# Existing Supabase project inventory (A0)

## 1. Scope and safety boundary

This is a schema-only, read-only inventory of the approved existing Supabase project. It records local migration-history reconciliation and a blocked schema-pull attempt. It does not apply migrations, inspect application rows, alter remote configuration, or approve the remote schema as the Avuhz target.

## 2. Confirmed target and local link state

- Approved linked project ref: `gnuqaefotwgkwurjpyik`.
- Operator-provided local CLI authentication was usable.
- Project-local Supabase CLI: `2.115.0`.
- CLI linkage is confined to ignored `supabase/.temp/`; it is not committed.

## 3. Migration-history reconciliation

Before fetch, migration history contained no local versions and one remote-only version, `20260816120000`. The authorized local-only fetch created:

| File | Local version | Remote version | Post-fetch status |
| --- | --- | --- | --- |
| `supabase/migrations/20260816120000_create_onboarding_engagements.sql` | `20260816120000` | `20260816120000` | aligned |

`migration list --linked` confirmed the version on both sides after fetch. No migration repair, migration apply/revert, or remote migration-history update occurred.

## 4. Fetched migration review

The fetched file is **SCHEMA_ONLY_BASELINE historical evidence**, not a new Avuhz migration and not a complete current-schema baseline.

- 156 lines; two `CREATE TABLE` statements, three enum types, three indexes, one composite foreign key, one trigger function, one trigger, two RLS enablements, and five policies.
- No `DROP`, `GRANT`, extension, or `SECURITY DEFINER` statement.
- No executable row-data `INSERT`, `UPDATE`, or `DELETE` statement.
- No secret, token, API key, password, connection string, auth-user data, or client row data was present.
- It contains schema fields for contact details and legacy lifecycle/payment/credential concepts, but no values from any customer record.

The migration creates the legacy `public.engagements` and `public.engagement_events` tables plus `engagement_urgency`, `engagement_status`, and `engagement_event_type` enums. It references `public.tenant_users` in policies but does not define that dependency.

## 5. Schema-pull result

Docker was available. Port inspection found no current listener or Docker owner for `54320`; the earlier collision was transient Supabase shadow-startup state, so no container was stopped and no local config was changed. The retry created its local shadow database, then stopped while applying the fetched migration because `public.tenant_users` does not exist in the historical migration set.

Classification: **E — BLOCKED_BY_REMOTE_HISTORY_OR_SCHEMA_ISSUE**. No additional migration/diff file exists. No prompt to update remote migration history was presented; therefore no update was accepted or performed.

## 6. Historical public-schema inventory (limited)

This table inventory is evidence from the fetched historical migration only. Current remote state remains unverified until a successful schema-only pull is possible.

| Object | Historical shape and access evidence | Avuhz relevance | Classification | Data risk | Future strategy |
| --- | --- | --- | --- | --- | --- |
| `public.engagements` | UUID PK; tenant ID; company/contact PII fields; broad legacy status enum; urgency; timestamps; authenticated tenant-scoped SELECT/INSERT/UPDATE policies; update timestamp trigger | Conflicts with Slice 1’s narrow Avuhz Engagement ownership and lifecycle | REPLACE | HIGH | ADD_PARALLEL_NEW_TABLE |
| `public.engagement_events` | UUID PK; tenant and engagement IDs; JSONB event body; globally unique idempotency key; composite tenant-aware FK with cascade; authenticated SELECT/INSERT policies | Historical event overlap, but not the bounded LifecycleEvent/Outbox model | REPLACE | HIGH | ADD_PARALLEL_NEW_TABLE |
| `public.tenant_users` | Referenced by RLS predicates only; definition unavailable | Tenant/identity bridge dependency | UNKNOWN | UNKNOWN | DO_NOT_TOUCH / NEEDS_OWNER_REVIEW |
| legacy enum types | Include payment, credentials, conversion, ongoing-service, and other future-slice lifecycle terms | Outside Slice 1 | DEPRECATE (later) | HIGH | DO_NOT_TOUCH until dependency review |

## 7. Slice 1 collision matrix

The current remote schema cannot be asserted without a completed pull. `engagements` is historical evidence only; all exact current-name checks remain `UNKNOWN` unless shown below.

| Planned durable resource | Remote status | Evidence / implication |
| --- | --- | --- |
| `acquisition_handoffs` | UNKNOWN | not created by fetched history; current schema unverified |
| `engagements` | EXISTS_INCOMPATIBLE (historical evidence) | legacy PII and lifecycle/payment/credential model conflicts with Slice 1 |
| `diagnostic_scopes` | UNKNOWN | current schema unverified |
| `human_approvals` | UNKNOWN | current schema unverified |
| `idempotency_records` | UNKNOWN | legacy event key is global and not the required tenant/principal/subject model |
| `lifecycle_events` | UNKNOWN | historical `engagement_events` is semantic overlap, not a confirmed exact table collision |
| `outbox_deliveries` | UNKNOWN | current schema unverified |

## 8. RLS, functions, storage, and privileges

- **RLS:** historical migration enables RLS on both legacy tables. Five policies derive tenant access by joining `public.tenant_users` with `auth.uid()`. They are tenant-shaped, but give authenticated clients direct authoritative engagement writes; that conflicts with the Phase 4 command-service write model. Events have SELECT/INSERT only in the fetched policy set.
- **Function/trigger:** `set_engagements_updated_at` is a non-SECURITY-DEFINER timestamp trigger function with an empty `search_path`; it does not evidence a lifecycle/RLS bypass.
- **Auth:** no custom auth schema baseline was pulled; auth bridge details remain unknown beyond the historical `tenant_users` reference.
- **Storage:** not required for Slice 1 and not inspected.
- **Grants:** no grant statements appear in fetched history; current privilege state is unverified.

## 9. Design gap and preservation strategy

The planned Phase 4 tables and invariants remain those in [Phase 4 persistence design](phase4-persistence-design.md). The historical tables should not be altered or reused as authoritative Slice 1 tables without a current schema baseline and owner dependency review. The preferred future approach is additive: introduce the seven tenant-scoped Slice 1 tables in parallel, then consider backfill/switch/deprecation only with explicit data and application dependency approval.

## 10. Objects not to touch

- Remote migration history, schema, data, RLS, grants, functions/triggers, auth, storage, and project settings.
- Local Docker containers and host processes; no container was stopped or reconfigured.
- `public.engagements`, `public.engagement_events`, `public.tenant_users`, and related legacy enum types until owner review.
- Ignored local CLI linkage state.

## 11. Owner input required

| Question | Recommended default | Consequence |
| --- | --- | --- |
| What is the authoritative historical source of `public.tenant_users` required by the fetched migration? | Identify and review its historical migration or approved schema provenance; do not create a local stub or repair remote history. | Blocks reproducible shadow migration application and current schema baseline capture. |
| Must legacy engagements/events and their dependencies be preserved for an active application? | Treat all legacy records and dependencies as preserved pending explicit application-owner review. | Determines later parallel/backfill/deprecation work. |
| What is the authoritative `tenant_users`/human identity bridge and its RLS ownership? | Keep it untouched until its full schema and claim model are reviewed. | Blocks durable RLS design and connected authorization tests. |

## 12. Exact recommended next batch

**Historical tenant-membership provenance only:** identify the reviewed historical source for `public.tenant_users`, add it only as faithful local migration continuity evidence if approved, then retry the same schema-only `db pull` without repair or remote history update. Do not create a replacement tenant table, Avuhz durable table, RLS change, or data backfill in that batch.

## 13. Local migration-file disposition

The fetched historical migration is schema-only, secret-free, row-data-free, matches aligned remote history, and is necessary for migration continuity. It is eligible for commit. The baseline policy now permits only conventionally named `supabase/migrations/*.sql` files, continues rejecting SQL elsewhere, and rejects direct row-data DML in approved baseline migrations. No fetched migration is to be applied or edited casually.
