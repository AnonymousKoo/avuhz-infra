# Gate B candidate — in-place encrypted LOCAL n8n inbound-token replacement

**Security incident OPEN until Gate B is independently executed and verified.** The owner reported that **Gate A was saved** in the existing 1Password item `Avuhz Infrastructure / Avuhz Shared Receiver v2 LOCAL inbound header`, existing `password` field. A replacement value has **not been read or checked** by this repository work. The older inbound token was shown in a screenshot of n8n's Webhook OUTPUT → headers and must be treated as exposed. The original value remains in n8n's encrypted credential until Gate B. Do **not** show Webhook input/output headers again or resend/test with the old credential.

## Exact source-only preparation and target

- Repo: `AnonymousKoo/avuhz-infra`; environment: DefNet **LOCAL**, Docker n8n **1.103.2** bound to `127.0.0.1:5678`; namespace: **shared Avuhz n8n receiver**, **not** a vertical.
- Existing **inactive** receiver: `0068feb4c96bdb5f`; canonical receiver source `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`.
- **Only eventual mutation:** in-place replacement of **the existing** encrypted `httpHeaderAuth` credential `6ece28c3-f72d-4021-942d-8d0eb072b711`, name `Avuhz Shared Receiver v2 LOCAL inbound header`, header key `X-Avuhz-Webhook-Token`, within its current **single personal n8n project**. The credential and receiver binding IDs, name, type and project ownership must remain unchanged.
- **Outside scope:** existing separate outbound receipt credential `154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2`, private service `172.17.0.1:37891`, owner-only QA receipts SQLite, event delivery, receiver activation, credentials export, tenant/customer data, hosted or production n8n, and both distinct Supabase DEVELOPMENT projects (**AUTH** `pwlhruwutoitnieactol`; **DATA** `gnuqaefotwgkwurjpyik`).
- This source-only correction updates only the existing rotation-specific guard, its synthetic tests and this runbook. **Merging does not authorize `--rotate-one`.**

## Current execution evidence changed; don't erase the discrepancy

At the time of PR #731's incident plan, n8n's read-only SQLite metadata contained manual executions **#13 and #14**, each `running`. At PR #732 preparation, **#13 was absent** and **#14 remained**. On 2026-10-17, the authorized Gate B read-only preflight stopped when **#14 also disappeared**. A separate fresh read-only inspection confirmed **both #13 and #14 are now ABSENT**. The cause is **unknown**; the agent did not delete, restore or alter either execution, nor inspect execution payloads. Do not describe either record as preserved, intentionally pruned or resolved. The receipt table still contains **zero rows**, and n8n still has six non-archived plus one archived workflow with all inactive. This discrepancy is a known evidence-retention gap and must be explicitly accepted by the owner before Gate B; do not weaken the check without documented approval.

The corrected read-only gate requires **exactly zero saved execution rows**, and refuses any new/reappearing execution, including #13 or #14. A future Gate B mutation requires a **new exact approval** acknowledging BOTH missing records and the new flag `--approved-execution-13-14-absence EXACT_13_AND_14_ABSENT`. The old `--approved-execution-13-absence EXACT_13_ABSENT_14_PRESERVED` is invalid and must not be reused. Before/after metadata must remain identically empty. Any drift requires STOP and read-only reconciliation; no retry, restore or cleanup.

## Implementation grounded in installed n8n

Installed n8n `dist/commands/import/credentials.js` in version 1.103.2 uses transaction-scoped `upsert(CredentialsEntity, credential, ['id'])`, checks owner/project constraints and encrypts incoming `credential.data` objects. That is suitable as a *candidate* for one existing-ID update (source-reviewed, not yet exercised in live Gate B). **Never** use the repo's older first-import scripts: those generate a new ID and require zero existing credential/executions.

`scripts/prepare_shared_n8n_v2_local_inbound_rotation.py` defaults to **read-only**:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_local_inbound_rotation.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

Its default inspects exact canonical bound receiver, current private listener and empty protected receipt store, same inbound/outbound encrypted IDs, single n8n personal-project ownership shares, workflow counts and inactivity, and the exact absence of all saved execution records, including #13 and #14. **No secret, ciphertext, HTTP header, execution payload, or user data is selected or displayed.** It makes no event requests, imports, workflow mutations or provider writes.

Only after a **new explicit, exact Gate B approval** naming the merged Git commit SHA-1, LOCAL target, existing receiver ID, **existing** credential ID, current personal n8n project ID, canonical source SHA-256, distinct receipt credential ID, observed private endpoint, stable ID-based approved inbound 1Password secret reference (field suffix `password` only), and separately acknowledged absence of BOTH executions #13 and #14, may `--rotate-one` be considered. The owner operates from their **own approved signed-in DefNet 1Password terminal**, never a remote unauthenticated process. The required CLI approval flags are `--approved-receiver-id`, `--approved-credential-id`, `--approved-receipt-credential-id`, `--approved-project-id`, `--approved-receiver-sha256`, `--approved-receipt-endpoint`, `--approved-source-commit`, `--approved-secret-reference`, and `--approved-execution-13-14-absence`. Flags alone are **not authorization**.

Under such authority, the tool: (1) checks the exact LOCAL source commit and clean tracked tree; (2) compares two full non-secret LOCAL readbacks before reading any field; (3) reads **one** exact approved 1Password field through existing `LocalN8nOnePasswordCredential` (length 48–64 ASCII alphanumeric, no shell, clipboard, logging or display); (4) sends exactly **one** JSON credential record for the **same ID** via `docker exec -i n8n n8n import:credentials --input=/dev/stdin --projectId=<same-project>`, with secret bytes only through subprocess stdin in memory, stdout/stderr suppressed; (5) checks that `updatedAt` changed on that credential while `createdAt`, managed flag, identity/name/type, total counts and owners remained unchanged; that other credentials, all workflow nodes/settings, project shares, empty execution state and store count remain unchanged. A successful CLI return code **alone is insufficient**, since the installed n8n CLI can catch/log an import error without propagating a failure code. No secret/ciphertext is queried, hashed, compared or printed by the postcheck. Metadata cannot prove old-token revocation in an active n8n process.

**No retries or automatic rollback**, even on timeouts, nonzero return, or ambiguous postcondition. If an in-place update partially applied, request a new read-only incident reconciliation; never reuse this approval, generate another token, or call a second importer automatically.

## Post-rotation gates (separately authorized)

A Gate B metadata PASS **does not certify** that the exposed old token is revoked in running n8n memory, an active test-webhook listener has ended, a valid new-authenticated event processes through all five nodes, a durable receipt is committed, or any real business owner or Work Item has been authorized. Only after the incident has been reviewed may a **new** temporary LOCAL test listener and a **distinct** one-POST QA execution be approved; avoid n8n INPUT/OUTPUT screenshots with sensitive headers. Current previous test status includes `HTTP_OTHER_NON_202`, no receipts and both #13 and #14 missing for reasons not yet determined. Diagnosing the failed receipt node, replays and tenant isolation is subsequent work. Never send real customer events before explicit tenant/owner and shared-command/RLS gates.

**Four lanes:** Security closes the specific exposed-secret path; Infrastructure preserves the existing LOCAL private gateway and n8n project; Automation keeps shared receiver and durable receipt boundaries; Business/OIA progress should continue separately and must not be conflated with a credential rotation or a paying client.

**Next action:** review/merge this source-only PR after exact-head CI; then provide a new **specific Gate B authorization acknowledging BOTH #13 and #14 absences and the exact same existing inbound n8n credential update**. No live rotation until then.
