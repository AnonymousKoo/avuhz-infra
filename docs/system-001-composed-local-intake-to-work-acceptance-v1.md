# System #001 — composed local intake-to-persisted-work acceptance

**Scope confirmed:** `AnonymousKoo/avuhz-infra` source-only LOCAL/TEST on the authorized DefNet machine. No hosted credential, Supabase, production, Render, customer records, billing, communications, n8n workflow activation or public tunnel is created or changed.

The SOURCE of the fictional client remains `tests/fixtures/system001_qa_tenant_local_v1.json` (`Avuhz QA Tenant 001`). Its test Work Item UUID has been corrected to **differ from the synthetic acquisition intake UUID**. Neither UUID proves real ownership, verification or an authorized hosted client.

## One joined LOCAL test

New `test_fictional_qa_http_to_durable_work_item_full_local_composition` in the existing LOCAL disposable-PostgreSQL-17 integration test suite joins previously separate proofs into a single bounded test:

1. Avuhz existing shared acquisition HTTP adapter receives fictional intake and returns sanitized HTTP 202. The acquisition DATA transaction remains an existing TEST double (not hosted or actual SQL).
2. The real shared Avuhz outbox worker projects one PII-free lifecycle event and sends through a deliberately **simulated n8n relay**. This test does NOT invoke the installed local n8n workflow.
3. The relay calls the **actual loopback HTTP receipt server**, committing one receipt into real local private SQLite storage. First acknowledgment deliberately disappears; the worker retries and returns PUBLISHED. Both delivery envelopes are identical.
4. The existing **LOCAL/TEST-only** `LocalSystem001GovernedHandoff` rejects a synthetically authenticated owner from a different tenant. It checks a committed receipt, then calls a test-only *independent acquisition lookup* and existing shared human identity resolver callback.
5. With matching fictional owner evidence, it opens **one real Work Item via the existing PostgreSQL writer and existing `avuhz_command_service` bounded tenant RLS**.
6. Exact replay produces **one** Work Item, idempotency row, lifecycle event and outbox row. The persisted due timestamp is read back from PostgreSQL, and the existing guarded due reader sees the item only for the authorized current owner.
7. PII and private synthetic receipt secret never enter the n8n envelope or Work Item fields.

The test uses the already established source modules and SQL migrations. It adds **no** table, role, grant, authentication provider, worker transport, HTTP handler, deployment path or tenant infrastructure. The named disposable PG17 container uses loopback `127.0.0.1:65447`, independently of existing PostgreSQL on 5432 and n8n on 5678, and is stopped and removed after testing.

## Certainty boundaries — not yet complete

- **Real n8n execution: NOT certified.** The actual System #001 v2 child is installed in local n8n **inactive**, its child input is unbound and the receipt backend URL is deliberately unreachable. This test uses a synthetic relay to protect the live service from premature automation/credentials.
- **AUTH/business ownership: NOT certified.** Fictional QA identity evidence and the independent acquisition lookup are controlled LOCAL test doubles, not a provider-authenticated owner or remote RLS tenant registry.
- **Acquisition SQL transaction: NOT certified by this composed test.** The existing HTTP acquisition adapter is real, but its authorized acquisition DATA connection and transaction are synthetic here. The Work Item writer and RLS are real disposable PostgreSQL tests.
- **Hosted DATA QA tenant: NOT inserted.** DATA `gnuqaefotwgkwurjpyik` and AUTH `pwlhruwutoitnieactol` remain separate; no provider operations are authorized by this source change.
- **Scheduled follow-up, human approvals, notifications and production deployment: NOT completed or active.** Due review is a read-only candidate, not a delivered task or notification.

## Operational next milestone

Before the installed local n8n child can safely execute one QA event, Avuhz must configure a **server-owned acquisition/owner authorization source** for the local fictional QA environment, an approved encrypted credential to the strictly private receipt server, a verified n8n child input binding and receipt endpoint, and a single-event controlled run. Never let n8n create its own authoritative Work Item, forge HUMAN auth or bypass tenant isolation. Check receipt once, ledger once, Work Item once, and fail-closed negative tests and rollback.

**Next action:** review this source-only PR and CI; then plan the exact LOCAL-only input/receipt credential binding for one synthetically authorized n8n execution. No real client or production setup is required to continue.
