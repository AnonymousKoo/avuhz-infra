# System #001 — Shared Work Item next-action deadline, source candidate

**Scope:** Avuhz shared Revenue Engine, repository-only schema change.
It is **not** a hosted Supabase migration approval, connected n8n workflow,
live deadline scheduler, delivery obligation, or customer-communications
capability.

## What the change supplies

The single forward-only candidate
supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql
adds one nullable timestamptz column, next_action_due_at, to the **existing**
public.avuhz_work_items table. A stored deadline can later support generic
Revenue Engine follow-up rules for Mid State, Yaadbody, Sekinfra, or any
approved tenant **without separate domain infrastructure**.

- No new table, user, service identity, tenant, membership, key, role, RLS
  policy, queue, ledger, API, webhook, or billing implementation is created.
- The existing table has FORCE RLS and one tenant-scoped command-service
  policy. The migration checks these explicitly before changing anything.
- Only the existing avuhz_command_service receives narrowly scoped INSERT
  and UPDATE column privileges for the added field; no table-wide UPDATE
  grant, privilege for anon/authenticated/service_role, tenant_id update,
  or DELETE permission. The preflight also rejects PUBLIC/named-API-role privileges,
  unexpected role memberships, table-wide runtime writes, policy-expression
  drift and existing-column/ownership drift.
- The column is nullable and has no default: old rows remain usable, but a
  null deadline must NOT be treated as scheduled or followed up.
- The data migration must be executed by the verified table owner.
  Supabase DEVELOPMENT DATA requires a **separately reviewed owner-session
  role selection and exact named approval**. This SQL has its own BEGIN/COMMIT
  and cannot be nested in a DO/function wrapper. The future provider executor
  must obtain independently approved SET permission, choose the verified
  owning migration role **before** the BEGIN, execute this single complete
  transaction, and revoke any temporary permission separately as approved.
  A disposable PG17 test certifies this owner-session shape, not the hosted
  owner grant mechanics. This source neither grants ownership nor authorizes
  generic Supabase SQL execution.
- The candidate is designed to fail closed if replayed or if exact RLS,
  role, owner, column or policy preconditions have changed. It runs as
  one transaction; injected post-DDL error rolls the column and grants
  back entirely.

## Evidence and deployment boundary

One static source test and 13 no-network disposable PostgreSQL 17.6 cases verify
one column/no unexpected grants, tenant isolation under the bounded
command role, no-tenant denial, replay denial and post-DDL rollback. Adversarial
cases reject a permissive same-name RLS policy, PUBLIC access, table-wide
INSERT, role inheritance to owner/BYPASSRLS, missing table and wrong owner;
correct pre-BEGIN owner role selection is also tested. The synthetic test database and container are destroyed.

**Target if separately approved:** DEVELOPMENT DATA
gnuqaefotwgkwurjpyik ONLY. DEVELOPMENT AUTH pwlhruwutoitnieactol and
all production projects are excluded. Live DATA is currently empty,
and no real receiving tenant has been verified. Fictional test tenants
are not a reason to create real tenant/owner rows.

## What remains

The shared Work Item writer/reducer must be extended through a **separate
reviewed change** so an authenticated, eligible owner can atomically
commit a bounded next-action deadline, versioned Work Item transition,
idempotency receipt, event and shared outbox. The source-only
follow-up reviewer in PR #681 expects an independently trusted persisted
deadline. Neither the reviewer nor a bare nullable column ensures a lead
gets contacted. An escalation worker, notification consent and reliable
dispatch also remain to be implemented.

**Next action:** verify full Avuhz baseline and independent Codex security
review, publish one source-only PR. After it merges, prepare a strict
DEVELOPMENT DATA migration-owner wrapper and obtain exactly one
resource/project-specific approval before any database mutation.
Do not activate local or hosted n8n, or use real client PII under this PR.
