# System #001 — REAL LOCAL n8n to PostgreSQL QA certification

**Environment and scope confirmed on 2026-10-15**

- Avuhz source: `AnonymousKoo/avuhz-infra`; LOCAL/TEST DefNet machine only.
- Existing n8n: Docker `n8n` on `127.0.0.1:5678`; five-node System #001 v2 child installed **inactive**.
- One disposable PostgreSQL 17 container `avuhz-system001-due-journey-local-20261015` bound only to `127.0.0.1:65447`. It is started separately after exact local-only approval and stopped and removed after the QA test. Never use the existing `ditl-postgres-1` or any hosted database.
- DEVELOPMENT Supabase AUTH project `pwlhruwutoitnieactol` and DATA project `gnuqaefotwgkwurjpyik` remain **distinct and untouched**. Render, n8n production, Cloudflare, billing, communication providers and real customer data are untouched.
- QA is the fictional `Avuhz QA Tenant 001` source fixture, **not SekInfra**. There is no verified real business or owner.

## Actual certification command

Run only after approving and confirming the exact LOCAL disposable PostgreSQL and n8n scope:

```sh
export PYTHONPATH=src:.
export AVUHZ_LOCAL_POSTGRES_CONTAINER=avuhz-system001-due-journey-local-20261015
export AVUHZ_WORK_ITEM_TEST_LOCAL_DSN='host=127.0.0.1 port=65447 dbname=avuhz_system001_durable_writer_test user=postgres'
# Run through the isolated Python env that installs requirements.txt and pinned psycopg[binary].
python scripts/certify_system001_live_local_n8n_to_work.py
```

**No automatic provider deployment or container creation occurs in this script.** It is strictly opt-in. The script requires the existing approved n8n Docker identity, one personal project, inactive source-matching child, strictly fictional QA fixture, zero stored executions and no unrelated active workflows. It runs one CLI invocation with an isolated task broker on port 5687 instead of colliding with the running n8n broker on 5679.

The script uses n8n's supported credential import to **encrypt a temporary header credential**. It supplies the secret over a private process pipe, never CLI args, source, JSON exports, GitHub, a browser, or chat. Any CLI diagnostic is classified into static safe categories; raw output is never displayed. It reuses an existing exact-name QA credential or creates exactly one and reuses/creates one **inactive manual QA parent** with a native 16-character n8n workflow ID. The previous 36-character QA parent may remain inactive but is never run. No public webhook, schedule, SMS, email, tenant-facing API, or payment is configured.

## Verified LOCAL execution (two passing executions)

1. One manual-only synthetic event enters the **installed real n8n v2 child**, traverses validation and the private HTTP node, and commits **exactly one durable receipt** to a temporary private SQLite ledger. CLI returns success, the `OWNER_LOOKUP_REQUIRED` marker is observed, and all workflows stay inactive.
2. The receipt is validated independently against the full committed envelope digest. An independent **fictional local acquisition registry** in private SQLite is created strictly from the source QA fixture, not from n8n-supplied owner/tenant claims.
3. The existing `LocalSystem001GovernedHandoff` independently resolves QA acquisition and a synthetic strong HUMAN identity. An otherwise-valid identity belonging to **another tenant** is explicitly rejected before a Work Item write.
4. A matching QA identity invokes the **real existing shared PostgreSQL writer**, with `avuhz_command_service`, scoped RLS, current member checks and canonical lifecycle/outbox transaction: exactly **one Work Item, one idempotency record, one lifecycle event and one outbox row**. Exact replay creates zero duplicates.
5. Persisted deadline, due review, escalation review and denial to unrelated tenant pass. The shared writer executes authorized owner offer/accept handoff and resolution, and denies the former owner's attempted mutation after handoff. No real communications are delivered.
6. In a `finally` cleanup, the existing child is restored to its **original unbound, inactive source**, the receipt listener is stopped, and the temporary SQLite ledger is removed. QA's manual parents and an encrypted credential may remain **inactive artifacts** until removed through a supported n8n admin interface. Do not mutate the n8n database directly.

**Evidence:** This was independently executed twice with exit code 0, including a repeat after hardening the source inspection and CLI return/owner marker checks. Local n8n's stored execution ledger remains zero by its explicit `saveManualExecutions:false` setting; certification relied instead on exact private durable receipt verification **while the service was running**, plus PostgreSQL transaction/readback checks.

## Honest limits — what is NOT certified

- No real, provider-authenticated human owner: the synthetic identity and acquisition registry exist only in a private disposable LOCAL/TEST environment. This certifier is not production authorization or a process for enrolling real tenants.
- The live n8n event in this proof originates from a manually invoked fictional QA parent, **not** the hosted acquisition SQL/outbox worker. The separate source tests cover that earlier segment; a fully unattended running ingestion pipeline is not installed.
- The test Work Item database is disposable. There is no operational hosted DATA QA tenant, no enduring live work queue, no real business-service agreements or real customer notifications.
- Follow-up review is tested as a guarded read; an automatic durable scheduler and human approval/notification delivery are not activated.
- A real autonomous System #001 service requires the existing Avuhz shared acquisition and identity boundaries to be implemented, staffed and authorized; n8n receipts cannot choose owners or issue Work Item commands.

## Remaining LOCAL and DEVELOPMENT actions

1. **Source**: keep this audited certifier and tests under GitHub review, with no credential committed. Merge only after repository CI.
2. **LOCAL n8n cleanup**: delete the two inactive QA parents and the expired local QA encrypted credential through a supported n8n owner/admin interface after their evidence is reviewed. Do not delete original System #001 v2 child.
3. **DEVELOPMENT DATA**: separately review the isolated, reversible fictional QA tenant seed plan for DATA project `gnuqaefotwgkwurjpyik`. Do not fabricate real owner verification, disable RLS, or conflate it with AUTH.
4. **Business feature**: connect a real authority-backed acquisition read boundary and human membership to the shared Work Item command under explicit DEVELOPMENT approvals; then separately authorize durable follow-up scheduling.

**Next action:** review the source PR and the LOCAL cleanup plan. Then prioritize a safe synthetic DEVELOPMENT DATA tenant and authorized owner identity boundary instead of more Command Center features.
