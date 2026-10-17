# Shared n8n v2 — LOCAL private receipt Header Auth credential importer

**Source-only scope:** `AnonymousKoo/avuhz-infra` on DefNet, LOCAL/TEST shared automation; existing Docker n8n `127.0.0.1:5678`. This change does not access Supabase DEVELOPMENT AUTH `pwlhruwutoitnieactol`, separate DATA `gnuqaefotwgkwurjpyik`, production, hosted n8n, real clients or communications/billing providers. The PR creates no credentials and performs no workflow or provider mutations.

## Verified starting state

At inspection, the LOCAL n8n database has seven stored workflows, **zero active** and **zero executions**. Shared Receiver v2 has ID `0068feb4c96bdb5f`; its inbound `httpHeaderAuth` credential is already bound while its **outbound receipt HTTP node remains unbound** and points to `http://127.0.0.1:1/v1/avuhz/local-n8n-receipts`, deliberately unreachable inside the n8n container. No n8n credential named `Avuhz Shared Receiver v2 LOCAL receipt bridge` is present. These are observations, not permanent invariants: the tool re-verifies immediately before each proposed action.

1Password metadata inspection previously confirmed one separate, newly generated Password item `Avuhz Shared Receiver v2 LOCAL receipt bridge` in the existing `Avuhz Infrastructure` vault. Its stable **metadata-only** field reference was independently verified privately, but the exact vault/item locator is deliberately **not committed** to this repository. The owner must separately authorize the exact private `op://<vault-id>/<item-id>/password` field before an import. The token value must never enter Git, logs, command arguments, environment variables, or ChatGPT conversation text.

The canonical shared receiver template source digest is `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`.

## Default read-only operator preflight

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_shared_n8n_v2_op_receipt_credential_local.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

Default mode checks exact LOCAL Docker-private n8n network, canonical receiver source and installed node shape, existing encrypted inbound credential and project sharing, inactive workflow state, zero executions, separate receipt credential name absence, and receipt HTTP placeholder/unbound state. It does **not** run `op read`, install a credential, write SQLite, start services, bind or activate workflows.

## Separately authorized one-credential import (NOT authorized by this PR)

A later *new* exact approval must identify DefNet `127.0.0.1:5678`, one new encrypted `httpHeaderAuth` credential, existing inactive receiver ID `0068feb4c96bdb5f`, the canonical receiver source digest, and the exact privately verified 1Password reference (not stored in Git). It must explicitly prohibit retry, receiver edits, workflow activation or execution, service start, DATA/AUTH and production operations. Operator write flags after that approval: `--import-one --approved-source-sha256 <canonical-sha256> --approved-receiver-id <exact-id> --approved-secret-reference <stable-op-ref>`.

The importer uses the shared `LocalN8nOnePasswordCredential` provider to read the **one approved** secret privately in memory. It then performs a fresh full LOCAL read-only preflight and invokes **one** supported `docker exec -i n8n n8n import:credentials --input=/dev/stdin --projectId=<verified-personal-project>`, delivering the credential document only over process stdin. The new encrypted credential has header name `X-Avuhz-Receipt-Bridge-Token`. The existing inbound header `X-Avuhz-Webhook-Token` remains separate; secrets and credentials MUST NOT be reused across these boundaries.

Strict independent metadata-only postcondition requires one additional encrypted `httpHeaderAuth` credential of the exact name, one project share, unchanged previously existing credential metadata, all workflow node/configuration/connection records unchanged, unchanged workflow sharing, unchanged webhook count, all workflows inactive, zero executions. Credential ciphertext is never selected or decrypted by verification. A secret cannot be proven equivalent to its 1Password source by this metadata-only check; that assurance depends on the approved private import boundary and later protected positive/negative tests.

If the n8n importer fails, times out, or postcondition is ambiguous, **STOP and reconcile read-only**. There is no retry or automatic compensating import/rollback; never infer that a failed CLI means the resource was not created.

## Why this is the next shared-core step

- **Security:** dedicated private token with least privilege, no plaintext secret exposure, CI/PRODUCTION fail-closed, and separate receipt authentication.
- **Infrastructure:** reuse the existing DefNet Docker n8n and shared worker; do not create a second auth or orchestration system.
- **Automation:** prerequisite only. This import does not bind a receipt node or start the private receipt server; the receipt gateway and QA tenant verification are separate resource changes.
- **Business:** does not deliver a Work Item or a customer-ready onboarding flow. A consented prospect OIA can proceed independently; do not mistake an encrypted credential for business-system completion.

**Next action:** Review source/test gates and merge only after exact-head CI. Separately authorize exactly one LOCAL encrypted receipt-credential import; after that, approve the private receipt-service and binding steps one resource at a time.
