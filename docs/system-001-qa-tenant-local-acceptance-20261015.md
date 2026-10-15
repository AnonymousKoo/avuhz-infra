# System #001 LOCAL-first QA tenant — acceptance evidence and remaining gates

**Confirmed on 2026-10-15:**
- Repository/resource: `AnonymousKoo/avuhz-infra`, isolated LOCAL/TEST source worktree.
- Local n8n: private `127.0.0.1:5678`; separate disposable PostgreSQL 17 test database bound only to `127.0.0.1:65447`. Neither is a hosted tenant database.
- DEVELOPMENT Supabase AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are distinct and **untouched**.
- No production, Render, Cloudflare, GitHub secret, billing, SMS, email, n8n activation, real customer or credential changes in this PR.

## Client selection

The local synthetic client is **Avuhz QA Tenant 001**, intentionally NOT SekInfra. Its canonical test fixture is `tests/fixtures/system001_qa_tenant_local_v1.json`.

The fixture uses a reserved synthetic test tenant/organization UUID, fictitious personal name, `example.invalid` email, no telephone, fictional work ID, and fixed future due timestamp. A source system of `avuhz.qa` means the intake is Avuhz shared-core test data, NOT a SekInfra intake. No fixture field proves business identity, ownership, membership, verified registration or authority over hosted DATA.

The fixture and any client-generated IDs are test inputs only; **never** promote them as verified tenancy, put them into production, or reuse the same static ID across real tenants.

## What is exercised end-to-end in local TEST

`tests/integration/test_system_001_fictional_qa_local_acceptance.py` follows the real Avuhz shared intake HTTP adapter, command candidate, lifecycle event and outbox worker through a synthetic n8n relay to the **actual local loopback HTTP receipt server and on-disk SQLite receipt store**, then explicitly passes the **separate synthetic authenticated owner** boundary to the shared Work Intake candidate:

1. Valid fictional HTTP intake → accepted receipt, committed fake acquisition-UoW event + outbox.
2. Actual outbox adapter → simulated native n8n authentication relay → actual receipt HTTP 202 and on-disk digest receipt.
3. First acknowledgment is deliberately lost; the actual outbox worker retries without creating a second durable receipt.
4. Explicitly separate TEST-only owner evidence opens a work item with persisted-by-candidate due timestamp; replay creates no new work event.
5. Pure follow-up review returns not due, due, and escalation-review candidates at fixed times (no timer, SMS, email or scheduler).
6. Owner offers handoff, recipient accepts, former owner loses access, new owner resolves; resolved items have no due candidate.
7. A forged tenant value and incorrect relay credential fail before any saved receipt.

**Important limitations:** the intake SQL UoW in this composite test is a controlled TEST double. n8n relay is a controlled TEST double, NOT the actual installed n8n service. The Work Item writer in this composite test is in-memory, and the owner evidence is a TEST-only resolver. A durable HTTP receipt is not business authorization or a work command.

Separately, existing `scripts/certify_system_001_due_journey_local.py` certifies the **real shared Work Item Postgres writer and RLS** in disposable PostgreSQL 17 using the isolated, pinned `psycopg[binary]==3.3.4` dependency. This test proves atomic Work Item/idempotency/lifecycle/outbox writes, current owner / tenant RLS, persisted follow-up deadline, due query, handoff and revoked-owner denial. It does NOT run through the live n8n instance or hosted AUTH/DATA projects.

## Clear remaining System #001 LOCAL completion gates

These are NOT satisfied by passing repository tests:

- **Actual local n8n** currently has three inactive workflows, zero executions, one uncertified System #001 candidate. The v2 child workflow is in repository source, not installed. Establish the exact local inactive import and verify workflow topology, credentials and allowed entrypoint; do not expose port 5678 or make it public.
- **Approved LOCAL receipt service:** inspect and authorize `local_n8n_receipt_dev_runner.py` `--serve` against the exact local Docker bridge, known trusted QA tenant, approved encrypted secret and private on-disk receipt store. The launcher deliberately defaults to preflight and requires separate serve approval. A committed HTTP receipt is only transport evidence.
- **Governed owner/Work Item command:** wire receipt to a separate Avuhz-owned authoritative member resolver and shared Work Item writer. The n8n child stops at `OWNER_LOOKUP_REQUIRED` by design; it must not infer owner, tenant, Work Item or notification authority from an event.
- **Real one-event LOCAL proof:** initiate one synthetic request through the complete installed LOCAL n8n workflow, confirm exact receipt-once, persisted work item/due event, authorized owner handoff/follow-up, rejects bad auth, missing receipt, wrong tenant, retry and restart. No customer/PII data or messages until separately authorized.
- **No premature 'fully operational' claim:** no production n8n, hosted credential, owner login or customer-ready launch is covered.

## Future DEVELOPMENT DATA test-client seed — not yet applied

The user wants a test client in DEVELOPMENT DATA. Keep `Avuhz QA Tenant 001` as the reference identity, but first prepare an **explicitly reviewable, reversible synthetic seed plan** for DATA project `gnuqaefotwgkwurjpyik` only. Verify the actual `avuhz_tenant_organizations`, `avuhz_tenant_owner_memberships`, `avuhz_work_items` RLS policies, required columns, unique constraints and lifecycle state machine before suggesting any SQL.

Never create a fake `ACTIVE` or `VERIFIED` owner; fake identity cannot satisfy actual proof. Prefer PENDING_VERIFICATION or a data-only seed path validated against current code. Seed must be distinguishable from real customer data, allow deterministic cleanup without cross-tenant DELETE or altered RLS, and never be accessible to unverified tenants. If current schema cannot support such a disposable synthetic fixture safely, DO NOT insert it; propose a scoped DEVELOPMENT-only fixture boundary instead.

The local acceptance test intentionally does not write to hosted DEVELOPMENT DATA.

**Next action:** review the fictional-client local acceptance source PR and pass the complete local suite. Then separately approve one LOCAL n8n v2 import (inactive) and an explicit receipt-server preflight; build the Avuhz owner command adapter and only then authorize a one-event local system execution. Later, review a DATA-only synthetic QA seed plan as a separate provider action.
