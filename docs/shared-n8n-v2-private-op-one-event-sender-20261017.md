# Shared Receiver v2 — privately reuse the existing inbound 1Password field for one LOCAL QA webhook test

**Confirmed scope:** `AnonymousKoo/avuhz-infra`, DefNet LOCAL shared automation (n8n 1.103.2 at `127.0.0.1:5678`), receiver `0068feb4c96bdb5f`, canonical template SHA-256 `fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`. The source addition does not touch the hosted Supabase **AUTH** `pwlhruwutoitnieactol` or distinct **DATA** `gnuqaefotwgkwurjpyik`, hosted n8n, production, customers, credentials, or billing.

## Why this small composition exists

PR #722 installed a LOCAL-only private `LocalN8nOnePasswordCredential` provider and an encrypted n8n importer; later approved operations registered the inbound encrypted Header Auth credential. Merged PR #728 supplies a guarded **one-POST** test-webhook sender, but it requires the same existing inbound secret through an approved anonymous file descriptor. The owner must **not** copy/paste the secret or export/decrypt n8n encrypted credential data to satisfy this input.

The new `scripts/prepare_shared_n8n_v2_op_test_webhook_sender.py` composes these two already-reviewed components. **There is no new secret store, token, token rotation, external integration, or n8n workflow.** It reads the one exact, independently approved LOCAL 1Password field once (after prechecks) using the existing `op read --no-newline` provider, moves the value via a private `os.pipe()` file descriptor, then invokes the canonical one-event sender **in the same trusted LOCAL process**. The secret is never a command argument, environment variable, on-disk file, application log, terminal output, ChatGPT message, or Git source. On failure, no fallback, auto-retry, import, activation, secret creation, or workflow repair is attempted.

## Safe read-only preflight

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_op_test_webhook_sender.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

The default verifies the unchanged **bound but inactive** receiver, separate encrypted inbound/receipt references, correct project sharing, original owned foreground private receipt listener, empty `0600` QA SQLite receipt store, and pinned PII-free fictional eight-field event digest. It **never** accesses 1Password, starts a test listener, posts an event or changes n8n. At last inspection LOCAL n8n held six non-archived workflows and one archived, no active workflows and no saved executions. The private receipt endpoint `http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts` is an **observed ephemeral port**, not a hardcoded permanent deployment destination. Gate checks the live endpoint before any future send.

## Three separate operator decisions remain

1. **Verify existing inbound 1Password field reference, metadata-only.** Repo history confirms inbound registration used an approved 1Password reference, but its exact stable-ID `op://vault-id/item-id/field-id` **is not stored in Git and has not been recovered in the remote tool session**. The remotely invoked `op whoami` currently fails; the owner's own interactive terminal may be authenticated separately. A reference is metadata, never the secret value. Do **not** use the separate *outbound receipt-bridge token field* as the inbound secret. Owner may privately locate the approved inbound field through 1Password without revealing its value to chat. Never enumerate unrelated items or export/decrypt n8n credentials.
2. **Separately authorize a temporary native n8n test-webhook registration.** In the LOCAL n8n editor, use **Listen for test event** on the *existing* shared receiver's inbound webhook. Only the ephemeral `/webhook-test/avuhz-events` URL may be used, not the production webhook endpoint or workflow activation. Installed n8n 1.103.2 test-webhook registrations are short-lived (approximately two minutes), so register immediately before an authorized send. Test-listener registration is one separate n8n resource change, *not* implied by this repo merge.
3. **Separately authorize exactly one fictional test event delivery**, naming reviewed source commit, exact LOCAL receiver ID, canonical source checksum, exact local test URL `http://127.0.0.1:5678/webhook-test/avuhz-events`, freshly observed receipt endpoint, fixed QA event digest, and **exact approved inbound 1Password field reference**. The sender must be launched from the owner's signed-in approved LOCAL session, not an unauthenticated remote subprocess. Only then may its write flags include `--send-one --ui-listener-ready` plus `--approved-receiver-id`, `--approved-test-url`, `--approved-receipt-endpoint`, `--approved-source-sha256`, `--approved-source-commit`, `--approved-event-digest`, and `--approved-secret-reference`. These flags by themselves are **not** approval.

The wrapper rechecks source, runtime, exact event and endpoint twice before any approved field read; then reads the field *once* and transfers the token via an anonymous FD to the guarded one-event sender. That sender does **one** loopback POST, requires HTTP 202 with exact `{"accepted":true}` response and independently verifies one matching tenant/event/delivery key/canonical digest row in the private durable SQLite store. If any postcondition is ambiguous, **STOP without retry**; a timeout may already have committed.

This first transport-only proof does **not** demonstrate authentic business/tenant ownership, a true committed acquisition/outbox, replay/negative cases, or governed Work Item creation. Those need distinct approved evidence before LOCAL System #001 V1 certification or real-customer onboarding. No vertical-specific auth, automation or billing is introduced.

**Four lanes:** Security protects existing inbound field and separate receipt token; Infrastructure reuses the current shared core; Automation can prove actual n8n transport without activation; Business should continue real prospect/OIA outreach independently of this QA plumbing. Do not let source tests masquerade as a paying-customer outcome.

**Next action:** merge source-only PR after exact-head GitHub CI. Then privately verify the original inbound `op://` field reference and owner sign-in. Separately authorize the brief native test listener registration; afterward separately approve exactly one genuine LOCAL synthetic POST. Never trigger a listener or event from source merge alone.
