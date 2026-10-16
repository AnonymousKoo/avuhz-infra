# Avuhz shared receiver v2: single-resource LOCAL inactive installation

**Confirmed target:** `AnonymousKoo/avuhz-infra` LOCAL/TEST source; installed n8n v1.103.2 container `n8n`, bound to loopback `127.0.0.1:5678` on the owner's machine. This runbook does not authorize production, the hosted AUTH project `pwlhruwutoitnieactol` or hosted DATA project `gnuqaefotwgkwurjpyik`. These projects are never interchangeable. Preserve unrelated local uncommitted work.

## Current implementation vs remaining gap

The installed five-node System #001 child remains **inactive/unbound** and the October 16 connected manual fictional QA execution already proved local n8n, durable receipt and real disposable PostgreSQL work lifecycle. PRs #715–#717 introduced the shared unattended polling loop, validated HTTPS outbound transport, and one **inactive repository-source** shared receiver v2 with 202-after-commit semantics.

The new source receiver is **not installed or activated** merely by merging PR #717. No n8n native Header Auth credential, independently approved TLS ingress, private receipt service, source tenant identity or continuously supervised workload is in place. Its current source includes an unreachable `127.0.0.1:1` receipt target and deliberately lacks credentials. Accidental activation cannot accept work. Do not bypass this by using plaintext `http://127.0.0.1:5678` as the external ingress.

## One-command read-only inspection

`scripts/prepare_shared_n8n_receiver_v2_local.py` defaults to a read-only preflight:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_shared_n8n_receiver_v2_local.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

It checks the exact Docker bridge identity, the already-installed v2 child and fictional fixture, SHA-256 of the approved **inactive** v2 template, one personal n8n project, zero active workflows, zero execution records, no existing shared receiver with the same name or webhook path, and that the source has no credentials and only its original unbound receipt placeholder. The SQLite database is opened with `mode=ro` and `query_only`. Preflight prints only fixed status lines, not workflow data, tokens, paths or project identifiers.

Read-only inspection passed against installed local n8n on October 16, 2026. There were **no resource changes**.

## Restricted, separately authorized inactive import

**Do not invoke installation mode merely because CI passes or the PR merges.** First obtain one specific owner approval that names:

- The exact LOCAL `n8n` Docker container at loopback :5678.
- The canonical inactive v2 template, SHA-256 `fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`, and the reviewed main commit.
- **Exactly one new inactive workflow import**, with no event execution, activation, credentials, config edits, n8n cleanup, hosted Supabase/Render, customer data or retry.

After approval, the option `--install-inactive` with the exact `--approved-source-sha256 sha256:...` can execute **one** supported n8n `import:workflow` CLI call with a locally generated 16-hex workflow ID and the already-installed personal project; workflow JSON enters via stdin only. The script does not use direct SQLite mutations, secrets or provider tokens. Immediately afterward it checks read-only that exactly one workflow was added, remains inactive and unbound, matches the precise five-node source and graph, has one project share, no active workflows or execution records, and the expected one webhook path. It does not enable a receiver. If n8n import or validation fails, it **does not retry** or delete anything; owner intervention is required, because a partial CLI import may have happened.

No component of this step can deliver a customer request. Native receiver credential binding, private independently authenticated durable receipt service, and verified HTTPS route are **separate named resource changes requiring their own verification and approval**. Only then can a separately approved LOCAL fictional continuous event test run.

## Security and operating separation

- **Security:** n8n may shape-check and receive a durable acknowledgment, but has no tenant-owner authority, direct work write, service-role DATA access, or access to production. The independent private receipt store enforces its own trusted tenant and source boundary. Never log PII or tokens.
- **Infrastructure:** existing LOCAL Docker n8n and source; no new platform or scheduler.
- **Automation:** import inactive first, then bind and test the shared receiver; after that demonstrate fully unattended Work Item creation using the shared dispatcher and existing PostgreSQL writer.
- **Business:** continue OIA and prospects in parallel. The codebase can work with Yaadbody or any other real business, but independent owner/legal-operator verification and consented onboarding precede any real customer data.

**Next action:** Merge source-only installer after GitHub exact-head CI. Independently approve one inactive LOCAL receiver import, verify postconditions; then separately scope receipt/auth/TLS binding. No production or real customer traffic.
