# Shared n8n receiver v2 — prepared LOCAL Header Auth binding

**Scope (October 16, 2026):** `AnonymousKoo/avuhz-infra`, LOCAL/TEST automation on DefNet, existing Docker n8n on `127.0.0.1:5678`. No hosted AUTH `pwlhruwutoitnieactol`, DATA `gnuqaefotwgkwurjpyik`, production, customer, billing, or communications operation. This change creates repository source and offline tests only; it does **not** bind or activate the receiver.

## Verified installed preconditions

- Merged PR #722 registered exactly one dedicated, encrypted, LOCAL `httpHeaderAuth` credential named `Avuhz Shared Receiver v2 LOCAL inbound header`, using the approved 1Password private reference. **Never** copy or export the token.
- The durable v2 shared receiver is installed exactly once and remains **inactive, unbound**, with no saved executions. The native webhook node is configured for `headerAuth` but has no `credentials` reference.
- The existing System #001 child and the shared receipt endpoint are still inactive/unbound. An independent receipt credential and durable private receipt service remain future, separately authorized boundaries.
- The canonical receiver source digest is `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`.

## Safe read-only check (available now)

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_shared_n8n_receiver_v2_header_binding_local.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

This validates the exact Docker-private LOCAL boundary, canonical receiver source, inactive System #001 child, one dedicated n8n-encrypted and correctly project-shared credential, existing receiver and zero executions. It never reads or decrypts the secret and never imports or edits a workflow.

## Separately authorized provider action (NOT included in this PR)

A later owner approval must explicitly identify the **exact LOCAL receiver workflow ID**, **exact encrypted credential ID**, receiver source checksum above, one existing workflow binding, and no retries. After that approval, an operator may invoke `--bind-one --approved-source-sha256 sha256:... --approved-receiver-id <exact-id> --approved-credential-id <exact-id>`.

The guarded importer uses the existing supported `docker exec -i n8n n8n import:workflow --input=/dev/stdin --projectId=<verified-personal-project>` command for **one** existing workflow ID. It updates only the webhook node's `credentials.httpHeaderAuth` reference (ID plus metadata name) in an otherwise exact v2 source document and forcibly keeps `active=false`. No password, bearer token, credential plaintext, runtime environment variable, direct n8n database mutation, workflow activation, receipt request, provider sign-in, or new credential is involved.

The tool performs a second exact preflight immediately before the one import and independently reads the LOCAL SQLite database in query-only mode afterward. It requires unchanged other workflows, receiver connections/settings and other nodes, same project shares, no new webhook registration, no new credential records, no new executions, and all workflows inactive. Only the bound webhook node may differ.

**Failure handling:** If the n8n importer exits unsuccessfully, times out, or the postcondition is ambiguous, **STOP**. The import might have partially completed. No retries or automatic rollback under the consumed approval. Inspect the target read-only and seek fresh exact remediation authority.

## Current limits and next steps

This binding alone does not establish operational V1: n8n remains inactive and the receipt URL is a fail-closed placeholder. Next distinct approvals cover (1) actual inactive receiver binding; (2) dedicated private receipt service and independent receipt credential; (3) independently verified HTTPS ingress; and (4) one fictional tenant-scoped acquisition-to-durable-Work-Item end-to-end test with negative paths. Production, hosted Supabase, real customers and billing remain outside scope.

**Four lanes:** Security receives a bounded, no-secret binding interface; Infrastructure preserves isolated LOCAL n8n; Automation gains only a potential authenticated receiver; Business still requires consenting prospect/OIA and genuine customer onboarding, not infrastructure work alone.

**Next action:** Run focused and full gates; review and merge source-only changes. Then request new approval identifying the exact LOCAL installed receiver and dedicated encrypted credential before any provider binding.
