# Shared n8n Receiver v2 — guarded LOCAL private receipt HTTP node binding

**Source-only scope:** `AnonymousKoo/avuhz-infra`, DefNet LOCAL runtime, existing Docker n8n bound to `127.0.0.1:5678`. Resource is exactly one node of installed **inactive** shared receiver workflow `0068feb4c96bdb5f`. The repo PR does **not** mutate n8n, restart the receipt service, read secret values, create a credential, activate/execute a workflow, touch Supabase or production, or onboard a real customer.

## Grounded current state

The existing shared receiver is installed with one inbound n8n encrypted Header Auth credential. The third node, `Private Durable Receipt UNBOUND`, has a deliberate unreachable URL `http://127.0.0.1:1/v1/avuhz/local-n8n-receipts`, method `POST`, generic `httpHeaderAuth` configuration, and a distinct `X-Avuhz-Delivery-Key` header, but no assigned receipt credential. The separately encrypted `Avuhz Shared Receiver v2 LOCAL receipt bridge` credential exists in the owner project under ID `154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2`.

The prior, separately approved QA-only receipt service is currently running under the approved foreground launcher on the Docker-private gateway at `172.17.0.1:37891`, with protected SQLite store at `/home/network-p/.local/share/avuhz-qa-receipts.sqlite` (owned by operator, `0600` mode, zero receipts at inspection). It is bound to the **fictional, LOCAL-only** tenant `a4730000-0000-4000-8000-000000000001`. This service is *not* the authoritative Avuhz DATA command service and does not prove real owner or tenant authority. Source path, service parent-child process identity, private listener, storage, tenant fixture, receiver template and credential project shares are reverified before any action.

The LOCAL n8n inventory is **6 non-archived workflow records, 1 archived record, 0 active workflows and 0 recorded executions**. The full number of database workflow rows is seven, not seven user-visible workflows. The listener port is ephemeral: a future change must approve the **current observed exact** private endpoint; do not assume that it survives service restart.

## Read-only preparation

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_local_receipt_node_binding.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

Default execution performs strict metadata-only readback. It never fetches credentials, sends network requests or delivery events, writes to SQLite, imports workflows, or starts services. It prints the exact discovered private endpoint if all security checks pass.

## Future single-resource operation — requires separate approval

Approve an exact owner-authorized LOCAL-only operation naming the reviewed and merged source commit, target, receiver ID, template digest `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`, the existing receipt credential ID, fictional QA-only tenant, and **the currently observed complete private endpoint** (presently `http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts`). The operation must allow exactly one native n8n `import:workflow` updating *only* the inactive receiver receipt HTTP node URL and its `httpHeaderAuth` credential reference. No other credential creation/decryption, events, activation, provider changes, or retry. Authorization expires on any service/endpoint/source drift.

The already-implemented approved-flag interface is `--bind-one --approved-receiver-id <exact-id> --approved-receipt-credential-id <exact-id> --approved-source-sha256 <canonical-sha256> --approved-endpoint <exact-http-private-url>` plus the standard target. Approval IDs and URL contain **no secret value**.

The tool obtains two independent preflights before a single native n8n workflow import. It never includes a credential value in the JSON import: only n8n encrypted credential metadata `{id,name}` is referenced. All nodes other than receipt node index 2 remain unchanged; inbound webhook auth, receipt delivery-key header, timeout, response behavior, workflow connections, sharing, active flags, and existing credentials must remain unchanged. A separate read-only postcondition checks entire workflow inventory and selected metadata-only credentials/shares; service PID and endpoint must still match; the private QA store must still have zero receipts. On failed/ambiguous import **STOP with no retry or automatic rollback**. Do not run the importer outside the approved exact LOCAL environment.

## Known limitations and remaining gates

Binding an inactive node alone does not certify a durable event. The service must remain alive for future LOCAL testing, and its ephemeral port can change on restart. Next separate authorizations: any receiver activation or controlled event execution, synthetic tenant-scoped end-to-end proof, negative auth/duplicate/delivery tests, and eventual authoritative Work Item handoff. No hosted AUTH (`pwlhruwutoitnieactol`) or DATA (`gnuqaefotwgkwurjpyik`) changes are within this scope. Never conflate these two DEVELOPMENT projects or treat the QA tenant as a real business.

**Four lanes:** Security is an exact credential-reference and LOCAL-only boundary; Infrastructure reuses the existing shared n8n and private receipt server; Automation stays inactive; Business can independently progress real prospect OIA discovery. No vertical-specific infrastructure is added.

**Next action:** Review this source-only PR and require the exact-head Main PR Gate pass before merging. After merge, separately approve one **LOCAL inactive receipt-node binding** using the freshly observed private endpoint.
