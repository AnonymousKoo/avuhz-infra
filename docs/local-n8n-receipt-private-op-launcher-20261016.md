# DefNet LOCAL — guarded 1Password-backed receipt-service launcher

**Change classification:** R2 source-only preparation for a future sensitive runtime operation. Repository: `AnonymousKoo/avuhz-infra`, shared Avuhz worker and automation, DefNet LOCAL/TEST only. No change to DEVELOPMENT AUTH `pwlhruwutoitnieactol` or DEVELOPMENT DATA `gnuqaefotwgkwurjpyik` (different projects), hosted n8n, production, billing, communications, or actual customers. This source PR does **not** launch a service, create a database, read a secret, bind a workflow, or activate any n8n workflow.

## Source and current resource evidence

The existing shared worker owns `src/avuhz_worker/local_n8n_receipt_dev_runner.py`, `local_n8n_receipt_http.py` and `local_n8n_receipt_store.py`. No replacement server or vertical-specific infrastructure is introduced. The existing `LocalN8nOnePasswordCredential` handles one approved private `op read --no-newline` field. The active LOCAL Docker n8n is bound to loopback `127.0.0.1:5678`; the shared receiver workflow `0068feb4c96bdb5f` is inactive with inbound Header Auth credential bound. The separate encrypted receipt-service `httpHeaderAuth` credential `154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2` exists in the same owner project but is **not bound** to the receipt HTTP node. Its URL remains an unreachable `127.0.0.1:1` placeholder.

The LOCAL n8n currently has **six non-archived workflows plus one archived record**, all inactive, with **zero saved executions**. Counting stored rows as seven visible workflows would be incorrect. This is a read-only observation, rechecked before any permitted serve action.

The only accepted QA tenant is **fictional** `Avuhz QA Tenant 001`, UUID `a4730000-0000-4000-8000-000000000001`, pinned to `tests/fixtures/system001_qa_tenant_local_v1.json`. This is NOT a verified legal business, hosted owner, active DATA tenant, or proof of membership. The private receipt store is transport evidence only, not Work Item or owner authority.

## Preflight-only command (allowed without runtime permission)

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_local_n8n_receipt_op_service_launcher.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

The script checks the pinned source SHA-256 of the existing receipt runner (`97f2f4bbda81bc6f382484ec8c2d351ea016d0e615fad2cf2d1343cf046ce421`) and fictional fixture (`217da325ebd1740211934e4d515db2f8a0d67b7b565f383fbd2a7c348ed16fea`), the Docker-private gateway and pinned source address, the exact inactive shared receiver, the existing two distinct encrypted n8n credentials and sharing, and zero workflow activity. Storage is fixed to `~/.local/share/avuhz-qa-receipts.sqlite`; its existing `~/.local/share` parent must be owned by the operator with permissions `0700`. An existing database must be a regular owned file with permissions no broader than `0600`. Neither a directory nor the SQLite file is created during default mode.

## Future separately approved one-resource service start

A future exact authorization must name DefNet LOCAL `127.0.0.1:5678`; immutable approved source commit; the same runner SHA-256; fictional QA tenant UUID; fixed LOCAL private SQLite path; receipt credential ID `154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2`; exact existing dedicated receipt-bridge 1Password stable field reference; **one service start** with its private on-start SQLite initialization; and explicitly no retry, remote/provider mutation, secret display, n8n binding, workflow activation or execution, real customer or production operation. The approved secret reference is NOT committed to this repo.

Only under that separate approval, the operator may use `--serve-one --approved-qa-tenant-id <exact-qa-id> --approved-receipt-credential-id <exact-id> --approved-runner-sha256 sha256:<pinned-digest> --approved-secret-reference <approved-op-ref>`. Flags specify approval metadata, never secret values.

This uses the existing private 1Password provider exactly once, verifies the entire LOCAL state again after the read, and passes the secret via inherited anonymous OS pipe (not argv, environment, disk, Git, logging or n8n execution data) to the existing shared-worker receipt runner. The child receives a minimal explicit non-secret environment, verifies private Docker gateway and client IP again and binds on the Docker-private gateway's ephemeral port. The launcher reports only a tightly validated private gateway URL, never raw child output, secrets, or tenant payload. It stays in the **foreground**, supervises this single child, and makes no attempt to restart after errors; SIGTERM/keyboard stop triggers child termination. Unexpected status/output fails closed.

**Known limitations:** A real durable SQLite receipt does not authorize a tenant or work command. Only synthetic QA data may be submitted under later separate authorization. The service is not continuously supervised across host/parent hard-kill or power failure; operator must read-only reconcile its listener and SQLite state after an unexpected loss. A future ephemeral port must be reconciled and separately approved for the still-unbound n8n receipt HTTP node. The outbox publisher, Work Item owner resolver, HTTPS transport and end-to-end installed n8n certification are separate milestones. This preparation does not establish System #001 V1 or a production client.

**Four lanes:** Security preserves the credential boundary; Infrastructure reuses the existing Docker network, n8n and SQLite test adapter; Automation remains inactive until independent receipt-node binding and synthetic test authorization; Business may continue real prospect/OIA discovery without treating this source-only milestone as customer onboarding.

**Next action:** Review and merge this source-only PR after exact-head CI success. Then separately authorize one LOCAL foreground QA receipt-service start (including its one private SQLite receipt store). No startup on merge.
