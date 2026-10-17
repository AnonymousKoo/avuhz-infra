# LOCAL shared n8n v2 — sanitized first-event HTTP diagnostics

**Confirmed change boundary:** `AnonymousKoo/avuhz-infra`, DefNet **LOCAL** Docker n8n 1.103.2 at `127.0.0.1:5678`, existing inactive shared receiver `0068feb4c96bdb5f`, fictional QA tenant `a4730000-0000-4000-8000-000000000001`. This is a **source/tests/runbook-only** change to the existing shared QA sender. It does not change n8n, secrets, running services, the private receipt database, workflows, auth, tenants, DNS, billing, or production. Supabase DEVELOPMENT **AUTH** `pwlhruwutoitnieactol` and **DATA** `gnuqaefotwgkwurjpyik` remain separate and untouched.

## Evidence of failed first LOCAL test

A separately approved single fictional test POST was attempted from the owner terminal and printed only `BLOCKED`; **the exact HTTP response status was not captured in the prior sender**. Subsequent **read-only** checks confirmed the one stored native n8n *manual* execution metadata row `#13` for the exact shared receiver, `status=running` and `stoppedAt=null`, without any serialized node-run entries or recorded last node executed. The protected LOCAL SQLite receipt table contains **zero** rows. The receiver remains inactive with exactly its two existing encrypted credential references and the original private receipt listener `172.17.0.1:37891`. The workflow's `saveManualExecutions=false` and `saveDataErrorExecution=none` explain why its editor Executions list may be empty. The editor diagram showed all five nodes connected but did **not** identify a failing node.

**No validated root cause yet.** An unregistered/expired native test listener, native n8n Header Auth denial, or another request-entry problem are possible, not proven. The previous one-event authorization is consumed. **Never re-run that POST under the old authorization**, manually resend it, restart the service, inspect private execution payload/header contents, or activate the workflow to diagnose it.

## Strict source-only diagnostic change

The existing `scripts/prepare_shared_n8n_v2_local_test_webhook_sender.py` still runs **read-only by default** and, only under a **fresh exact approval**, can perform at most one native loopback POST to `http://127.0.0.1:5678/webhook-test/avuhz-events` with the existing private inbound Header Auth and the previously reviewed fictional eight-field event. Its double runtime and source preflights, current receipt-service and zero-receipt checks, pinning, private token FD handoff, exact HTTP 202 success contract, separate SQLite commit verification and no-retry behavior are unchanged.

If the **next separately authorized** POST receives a non-202 HTTP response, this version emits an **allowlisted status category only**, e.g. `BLOCKED LOCAL test webhook outcome=HTTP_401; no retry` or `HTTP_404`; allowed categories are 400, 401, 403, 404, 405, 409, 415, 422, 429, 500, 502, 503, 504, and `HTTP_OTHER_NON_202`. A `202` with an unexpected, oversized, malformed, or nonexact `{"accepted":true}` response emits `HTTP_202_INVALID_RESPONSE`. A socket/HTTP timeout or transport exception emits `TRANSPORT_AMBIGUOUS`. The private 1Password wrapper may subsequently print its generic `BLOCKED` marker; the preceding sanitized category is the useful diagnosis.

**Never read or print rejected response bodies, response headers, request headers, private token values, credential payloads, untrusted server errors, or raw Python exceptions.** Status categories alone cannot conclusively attribute an error to native auth or an expired listener. In particular, a timeout may have delivered and committed an event: **no automatic or manual retry without fresh read-only reconciliation and new exact authority**. A `202` alone does not certify a real Work Item or tenant authorization.

## Read-only preflight available now

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_op_test_webhook_sender.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

This does not read 1Password, register a test webhook, issue HTTP requests, mutate state, or create receipts. Tests use synthetic in-memory secrets, HTTP response stubs, forced rejections and ambiguous transports only.

**Next action:** exact-head CI review and merge the source-only PR. After merge, prepare a separate, **fresh** one-resource approval for the native n8n temporary test-listener registration (two-minute window), verify the original approved inbound 1Password field in the owner's terminal without exposing it, and only then request **another** separately authorized single fictional POST. Gather the sanitized status and independent receipt evidence, and stop without retry on any ambiguity. A passing transport test must subsequently be followed by distinct authorized duplicate/negative and shared Work Item handoff tests before System #001 LOCAL V1 certification.

**Four lanes:** Security forbids secret/PII logging; Infrastructure stays on the existing LOCAL shared private service; Automation gains bounded status evidence without a second orchestrator; Business prospect/OIA outreach remains independently important. No vertical implements its own auth, billing or automation.
