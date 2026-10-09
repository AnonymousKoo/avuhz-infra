# DEVELOPMENT DATA durable handoff-claim hosted preflight v1 — READ ONLY

**Status:** source-bound, repository-only R2 inspection record. **NO installation or workflow authority.** This document is not a migration, credential operation, approval-consumption receipt, or authorization to contact or mutate any production resource.

## Confirmed source, project, and operation

- Repository: `AnonymousKoo/avuhz-infra`; protected `main` at inspection: `d0002c94fabbff901b40575428b918c14833cb1d` (PR #584 merged). Rediscover canonical main before any future change.
- Provider read target only: Supabase **DEVELOPMENT DATA** project `gnuqaefotwgkwurjpyik`, reported name `DEVELOPMENT DATA`, database host `db.gnuqaefotwgkwurjpyik.supabase.co`, PostgreSQL engine 17. Project reported `ACTIVE_HEALTHY`.
- Distinct/excluded provider: **DEVELOPMENT AUTH** `pwlhruwutoitnieactol`, independently confirmed name `DEVELOPMENT AUTH` and `ACTIVE_HEALTHY`. No AUTH SQL, identity, session, key, or setting changes.
- Inspection class: read-only metadata/project and migration-list calls plus two **SELECT-only**, aggregate/catalog SQL queries scoped to DEVELOPMENT DATA. No payload rows, tenant identifiers, PII, credential contents, database connection strings, or private signing material were retrieved for this record.
- No Supabase mutation, migration, object creation, role grant, workflow dispatch, repository runtime change, Render, n8n, billing, production, customer or synthetic HTTP command operation was performed.

## Observed hosted DEVELOPMENT DATA state

| Inspection | Live finding |
| --- | --- |
| Database/current SQL role | `postgres` / `postgres` |
| PostgreSQL SQL-reported version number | `170006` |
| Recorded provider migrations | `20260914005437 rebaseline_provider_neutral_avuhz`; `20261002215206 enable_implementation_handoff_command_intake` |
| Existing `avuhz_handoff_control` schema | **ABSENT** |
| Existing `avuhz_handoff_approval_claims` table | **ABSENT** |
| Existing `avuhz_handoff_claim_writer` role | **ABSENT** |
| Existing canonical business `avuhz_command_service` role | Present; NOLOGIN / NOINHERIT / NOBYPASSRLS / no superuser / no create-role |
| Existing `public.avuhz_idempotency_records` | Present; **business-command**, not security authorization |
| Existing `public.avuhz_implementation_handoffs` | Present |
| Existing canonical `public.avuhz_*` tables | 16; RLS enabled 16/16; 16/16 with policy targeting `avuhz_command_service`; no table without a policy |
| Forced RLS on existing authoritative 16 tables | 0/16 — existing baseline is enabled-RLS, not forced-RLS; **new security ledger requires forced RLS** |
| SQL role `postgres` | CREATEROLE / CREATEDB / BYPASSRLS; not superuser; `CREATE` allowed on current database. **Migration/admin-only authority** |
| PostgreSQL default privilege entries | Several schema-scoped ACL entries; inspected `public` table defaults include grants to `anon`, `authenticated`, and `service_role`. Other defaults exist on managed schemas. No claim schema exists yet, so these do not prove claim access. |
| Existing command-role membership records | 2 membership edges for `avuhz_command_service`, which require separate review if reused; the **new isolated claim role must have zero unapproved memberships**. |

**Interpretation:** the expected new security objects are absent and the DATA baseline is present. This is a favorable read-only precondition, **not** certification that a live migration is safe. An elevated migration role does not satisfy the restricted writer role contract. Default ACLs and managed provider behavior must be independently verified during a separate installation/post-installation gate.

## Candidate code already merged and tested — not deployed

- PR #582: `src/avuhz_engineering/development_handoff_durable_claim_candidate.py` is disconnected from runtime and requires an injected trusted PostgreSQL connection; tests covered atomic four-stage claims using disposable PostgreSQL.
- PR #583: `docs/development-handoff-data-claim-migration-r2-proposal-v1.md` documents the proposed private schema, writer role, grant restrictions and stop conditions.
- PR #584: `tests/integration/development_handoff_claim_installation_candidate.py` contains **test-only** SQL, with `test_postgres_development_handoff_claim_installation_candidate.py`. Exact-head Main PR Gate `37925142036` passed 10 new installation tests and 127 total integration tests, no skips, against disposable PostgreSQL.
- The candidate SQL is **not** in `supabase/migrations/` or `supabase/provider-artifacts/`. Its successful disposable commit is not an installation on hosted DATA.

## Required bound proposal before ANY migration

**Do not apply SQL from this document.** A future separate, accountable owner authorization must enumerate the **one tightly coupled, atomic installation bundle**, because it changes more than one PostgreSQL object:

1. Exactly one new private schema `avuhz_handoff_control`, one `avuhz_handoff_approval_claims` table with constraints, and one isolated `avuhz_handoff_claim_writer` NOLOGIN/NOINHERIT/NOBYPASSRLS role, plus its required forced RLS policy, default-deny revocations and scoped INSERT/USAGE grants. No unrelated changes.
2. Confirm exact branch/main source SHA and canonical reviewed SQL content digest, migration identity/version, provider project reference and hostname immediately before applying; recompute after any merge or rebasing.
3. Check again that the schema/table/role are absent; conflict means STOP, not adoption. Verify the effective role's creation privileges without using a runtime/service-role key. Establish which exact migration tool/write path is authorized and whether it writes migration history.
4. Verify all inherited/default ACL effects on **the new private schema** after creation. Fail if `PUBLIC`, `anon`, `authenticated`, `service_role`, `avuhz_command_service`, or any unexpected role can access the ledger directly. The new writer must have only INSERT and schema USAGE, no SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, ownership, role membership, login, privilege escalation or grant option.
5. Prove both `relrowsecurity=true` and `relforcerowsecurity=true` on the ledger and exactly the tenant-scoped writer INSERT policy. A caller-supplied `avuhz.handoff_claim_tenant` PostgreSQL setting is **not** independent proof of tenant identity, signed human-owner consent, or trusted GitHub source.
6. Treat any failed or ambiguous transaction outcome as terminal **UNKNOWN / no retry**; independent readback must establish installation postconditions and migration history without leaking secrets or user data.
7. No runner/login role provisioning, `SET ROLE` membership grant, secret creation, GitHub workflow dispatch, signed approval consumption, synthetic AUTH session, command HTTP request, customer handoff or production activity in this installation bundle. Each remains a separately authorized future resource.

## Known security limits and stop criteria

- `postgres` has BYPASSRLS as an admin identity. That does **not** mean the intended claim writer has BYPASSRLS; the writer does not yet exist. It is a hard STOP if a future runtime writer inherits that ability.
- Hosted default ACLs can provide broad access in managed schemas, including `public`. The proposed private schema requires **independent negative privilege proof**, not an assumption based on the disposable fixture.
- Existing 16 Avuhz authority tables use enabled tenant-RLS policies but not forced RLS. This is pre-existing baseline state; no missing RLS policies were observed. Do not modify those tables as part of this claim ledger task.
- No hardcoded private credential or sensitive data was observed in this scoped metadata inspection. This is **not** an exhaustive secret scan or security audit of all DATA objects.
- No verified live claim store, trusted runner/login route, human owner attribution, fresh four signed stage approvals, single fictional DEVELOPMENT command, postcondition readback, or AUTH cleanup is established by this preflight.
- Stop on project mismatch, source drift, an unexpected preexisting object, role/membership or default grant widening, deficient forced RLS, missing owner authority, ambiguous commit, or any credential/PII exposure.

**Next action:** accountable owner review/merge this read-only preflight record. Then prepare an exact source-bound, time-bounded owner authorization for the **DEVELOPMENT DATA claim installation bundle only**. Do not run a migration merely because the preflight or GitHub PR gate passes.
