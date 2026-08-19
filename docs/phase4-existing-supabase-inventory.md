# Existing Supabase project inventory (A0)

## 1. Scope and evidence status

This is a read-only inventory of the approved linked project. Current public-schema evidence comes from the schema-only artifact [current_public_schema.sql](../supabase/inventory/current_public_schema.sql), captured with `db dump --linked --schema public` and without `--data-only`. No customer rows, auth users, storage objects, credentials, or remote changes were read or made.

- Approved linked project ref: `gnuqaefotwgkwurjpyik`.
- Project-local CLI: `2.115.0`; existing operator authentication was usable.
- **CURRENT SCHEMA KNOWN:** YES, for `public` as captured by the dump.
- **HISTORICAL MIGRATION CHAIN COMPLETE:** NO. The local shadow database cannot replay the committed historical migration because its `public.tenant_users` dependency has no recovered historical provenance.

## 2. Migration continuity and schema capture

Local and remote migration history are aligned at `20260816120000`. The committed historical file, `supabase/migrations/20260816120000_create_onboarding_engagements.sql`, is schema-only continuity evidence; it is not a new Avuhz migration.

A prior `db pull` shadow retry cleared the transient local port collision but stopped on the missing historical `tenant_users` dependency. This does not invalidate the current schema dump. No migration repair, apply/revert, history update, or remote mutation occurred.

The current dump is a 973-line, schema-only inventory artifact. It contains 16 public tables, three custom enums, two trigger functions, two triggers, eleven indexes, four foreign keys, 31 policies, and grants/default privileges. It contains no `COPY`, direct row-data DML, secret-bearing literal, or client row export.

## 3. Current public-table inventory

| Table | Current schema role and key evidence | RLS/access evidence | Slice 1 / preservation classification |
| --- | --- | --- | --- |
| `alerts` | UUID PK; lead/client/tenant IDs; severity, resolution, JSONB metadata, timestamp | RLS; authenticated full access; broad anon/auth/service grants | Legacy monitoring; KEEP / DO_NOT_TOUCH; HIGH |
| `automation_logs` | UUID PK; lead/client/tenant IDs; severity/message/timestamp | RLS; authenticated `USING/WITH CHECK true`; duplicate service-role log policies; broad grants | Legacy operational logging; KEEP; MEDIUM |
| `client_config` | UUID PK; client/contact/configuration URLs and operational settings | RLS; authenticated full access; broad grants | Legacy configuration; DO_NOT_TOUCH; HIGH |
| `demo_assets` | UUID PK; optional `sekinfra` client FK; tenant ID; multiple JSONB demo/finding fields; unique demo slug | RLS; anon/authenticated read policy; select grants | Legacy/demo assets; KEEP; MEDIUM |
| `engagement_events` | UUID PK; tenant + engagement ID; legacy enum; JSONB event data; global idempotency-key unique; composite FK to engagements | RLS; tenant_users-based authenticated SELECT/INSERT; broad table grants | Legacy event stream; PARALLELIZE; HIGH |
| `engagements` | UUID PK; tenant ID; company/contact PII; legacy urgency/status enums; timestamps; `(id, tenant_id)` unique | RLS; tenant_users-based authenticated SELECT/INSERT/UPDATE; timestamp trigger; broad table grants | EXISTS_INCOMPATIBLE; DO_NOT_TOUCH / PARALLELIZE; HIGH |
| `event_logs` | UUID PK; lead/client/tenant IDs; JSONB metadata/timestamp | RLS; authenticated full access; broad grants | Legacy events; KEEP; MEDIUM |
| `events` | UUID PK; tenant FK to client_config; aggregate fields; JSONB payload; global idempotency-key unique | RLS; authenticated full access; service-role policy; broad grants | Generic legacy events; PARALLELIZE, not LifecycleEvent; HIGH |
| `incident_logs` | UUID PK; workflow/node/error/payload/metadata/status and tenant/client IDs | RLS; authenticated full access; broad grants | Legacy incidents; KEEP; MEDIUM |
| `infrastructure_events` | UUID PK; source/event/severity/host/service/metric fields; client ID | RLS; authenticated full access; broad grants | Legacy monitoring; KEEP; MEDIUM |
| `oia_submissions` | UUID PK; extensive intake/OIA/PII text fields; JSONB submission; tenant/client IDs; unique submission ID | RLS; authenticated full access; broad grants | Legacy OIA intake; DO_NOT_TOUCH; HIGH |
| `pipeline_stages` | UUID PK; name/order/timeout/timestamp | RLS; authenticated full access/read; service-role policy; broad grants | Legacy pipeline; KEEP; MEDIUM |
| `revenue_events` | UUID PK; lead ID, amount, status/timestamp | RLS; authenticated full access; service-role policy; broad grants | Payment/revenue legacy; DO_NOT_TOUCH; HIGH |
| `sekinfra` | UUID PK; extensive lead/contact, payment, agreement, OIA, deployment, monitoring, tenant/demo fields; unique email | RLS; authenticated full access; anon demo read; broad grants; timestamp trigger | Legacy aggregate; DO_NOT_TOUCH; HIGH |
| `sla_rules` | UUID PK; client/stage/severity/action/tenant fields | RLS; authenticated full access; service-role read; broad grants | Legacy operational policy; KEEP; MEDIUM |
| `tenant_users` | UUID PK; tenant UUID; nullable auth-user UUID FK to `auth.users`; role, full name, created timestamp; tenant index | RLS enabled, no table-specific policy in dump; broad grants | Current membership bridge; PARTIAL; HIGH |

No table-row data was inspected. Defaults, constraints, JSONB column presence, unique keys, foreign keys, indexes, triggers, policies, and grants above are schema evidence only.

## 4. Tenant-users assessment and dependencies

`public.tenant_users` exists in the current remote schema and is the bridge used by legacy engagement/event policies: `auth.uid() = tenant_users.auth_user_id` and tenant IDs must match the protected row.

It is **PARTIAL**, not reusable as-is for the Phase 4 target: it has an auth-user FK and tenant field but no visible uniqueness constraint on `(tenant_id, auth_user_id)`, nullable `auth_user_id`, unbounded text role, no current table-specific policy in the dump, and broad grants. It may remain untouched while future Slice 1 tables use a separately approved tenant/identity/RLS design.

Schema dependencies observed: `engagement_events(engagement_id, tenant_id)` has a cascading composite FK to `engagements`; `demo_assets.client_id` references `sekinfra`; `events.tenant_id` references `client_config`; `tenant_users.auth_user_id` references `auth.users`. The engagement and engagement-event policies depend on `tenant_users`. No views were present in the public dump.

## 5. Slice 1 collision matrix

| Planned resource | Current status | Evidence / recommendation |
| --- | --- | --- |
| `acquisition_handoffs` | ABSENT | use a new Avuhz-prefixed table |
| `engagements` | EXISTS_INCOMPATIBLE | legacy PII/lifecycle model, no handoff/account/opportunity/record-version semantics; keep and parallelize |
| `diagnostic_scopes` | ABSENT | use a new Avuhz-prefixed table |
| `human_approvals` | ABSENT | use a new Avuhz-prefixed table |
| `idempotency_records` | ABSENT | legacy global event keys are not the tenant/principal/subject model |
| `lifecycle_events` | ABSENT | `events` and `engagement_events` are unrelated legacy alternatives |
| `outbox_deliveries` | ABSENT | use a new Avuhz-prefixed table |

## 6. Engagement compatibility and parallel naming

Current `public.engagements` is not compatible with Slice 1: it lacks acquisition handoff/account/opportunity references, engagement and record versions, Slice 1 state vocabulary, and scoped authority semantics; it mixes legacy contact PII and future payment/credential/OIA/deployment lifecycle states. Its direct authenticated write policy and update trigger are legacy behavior, not an authority model for new records.

Use one clear ownership prefix consistently:

- `avuhz_acquisition_handoffs`
- `avuhz_engagements`
- `avuhz_diagnostic_scopes`
- `avuhz_human_approvals`
- `avuhz_idempotency_records`
- `avuhz_lifecycle_events`
- `avuhz_outbox_deliveries`

This avoids all current table-name collisions, clearly distinguishes Avuhz authoritative records from legacy data, and maps predictably to the existing repository ports.

## 7. RLS, command-service, functions, types, and grants

All 16 current public tables have RLS enabled, but the current model is not suitable to reuse for Slice 1 authority writes. Twelve legacy tables have `authenticated_full_access` policies using `true` predicates; automation logs also have broad authenticated/service-role policies. Legacy engagements/events have tenant-shaped policies but directly permit authenticated writes. The dump also shows broad grants, including `ALL` on many tables for `anon`, `authenticated`, and `service_role`, plus default privileges that grant maintenance capabilities. RLS may narrow some paths, but these grants/policies are material legacy direct-write risks.

The target remains: browser/session callers issue bounded commands and reads; command service is the authoritative write path; future n8n has no direct authoritative-table write access. Existing legacy policies are preservation concerns, not a reason to weaken the new-table model.

Two public trigger functions only maintain `updated_at` for legacy engagements and sekinfra. Neither is `SECURITY DEFINER`; no application RPC/view was found in this public-schema dump. The three custom enums are legacy engagement urgency/status/event vocabularies and include payment, credential, conversion, and ongoing-service values. New Slice 1 tables must use new narrow governed checks/enums rather than reuse them.

## 8. Data-preservation and additive strategy

Keep and do not alter legacy engagements, engagement_events, sekinfra, oia_submissions, client_config, revenue_events, and tenant_users pending owner review. High-risk data/identity/lifecycle tables should not be renamed, backfilled, or deprecated in the first durable Slice 1 batch.

A future additive migration should create only the seven `avuhz_*` tables, their tenant-aware foreign keys, narrow state/check constraints, idempotency uniqueness, append-only lifecycle-event constraints, and outbox linkage. It must not reference or mutate legacy tables. New-table RLS/grants must implement command-service-controlled writes from the start.

## 9. Migration provenance and implementation safety

Missing historical `tenant_users` provenance does **not** prevent designing a non-colliding additive migration, because the current schema is now known. It **does** block reproducible local shadow replay and durable adapter integration tests through the standard migration pipeline.

Therefore: **NEW Slice 1 additive migration is not yet safe to implement in this repository.** Prerequisite: owner-approved historical tenant-membership provenance/reconciliation or an explicitly approved durable-test strategy that proves new migrations and RLS without reconstructing legacy history. No remote repair is authorized.

## 10. Owner input and exact next batch

| Question | Recommended default | Consequence |
| --- | --- | --- |
| What is the authoritative historical source for `tenant_users`, and may it be committed as local continuity evidence? | Recover/review the original schema migration or owner-approved equivalent; do not create a synthetic replacement. | Enables reproducible shadow replay and migration testing. |
| Who confirms whether legacy public tables are active production dependencies? | Treat all as active and preserved until confirmed otherwise. | Controls later migration/backfill/deprecation only. |
| What trusted command-service identity and tenant/RLS claim model is approved for new tables? | Use separate command-service workload identity; browsers/n8n do not write authoritative tables. | Required before durable RLS/grant implementation. |

**Exact next batch:** historical tenant-membership provenance reconciliation only, followed by a local shadow replay check. It must not create new Avuhz tables, change legacy RLS, or mutate the remote project.

## 11. Inventory artifact policy

The current schema dump is an inventory artifact, not a migration. The narrow baseline policy permits only this exact inventory file and conventionally named migration files, while continuing to reject SQL elsewhere, dump-like content, direct row-data DML, and credential-shaped material.
