# Second unique fictional LOCAL receipt: source-only preparation

This change adds only the preparation script, its offline tests and this document.
Baseline: local `origin/main` at `24e941207974931d14f940945b39d4bbdf2b2d9d`,
archived from `AnonymousKoo/avuhz-infra` at `/home/network-p/avuhz-infra-clean`
on DefNet. The stale dirty checkout and all refs remain untouched. Candidate
source is under `/tmp`; an archive is not a clean, approved canonical source HEAD.

The responsibility is shared automation, LOCAL/TEST ONLY, personal project
`axT3GLERZRiPXxnj`, installed receiver `0068feb4c96bdb5f`. No live readback,
credential operation, listener registration, webhook POST, receipt write,
activation, service change or provider action is performed in this preparation.
Tests use fictional in-memory SQL fixtures and mocked runtime observations.
AUTH and DATA remain separate; nginx, Tailscale, n8n and production remain untouched.

The event is a copy of `qa.fictional_event()` with exactly three replacements:

| Field | Pinned fictional value |
| --- | --- |
| event_id | `822db2e6-fd66-4b17-a85f-f3d4c5221921` |
| correlation_id | `8ada11c9-bebe-4935-b4ec-a46deba50a0d` |
| delivery_idempotency_key | `avuhz.qa.system001.fresh-receipt-002` |

Tenant stays `a4730000-0000-4000-8000-000000000001`. The fixed eight-field
allowlist contains no personal information. Canonical JSON SHA-256 is
`0dd4988ba6f3c365d63c4ca933d02ed21190a1a3c008d3fc06008ebeeee39b70`.
No fixture or existing sender is changed; never invoke the first-send sender
with its old event/key to deliver this candidate.

For a later separately authorized read-only inspection:

```bash
PYTHONDONTWRITEBYTECODE=1 AVUHZ_ENVIRONMENT=LOCAL python3 \
  scripts/prepare_shared_n8n_v2_op_fresh_event_test_webhook_sender.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

The default checks the pinned receiver source and unchanged helper hashes,
exact installed identity/project, five-node graph, connections and settings,
zero active workflows and persistent webhook registrations, two exact n8n
credential references and exclusive owner project shares. It selects only
credential ID/name/type and share metadata, never the encrypted `data` column,
its length/prefix, secret references, execution bodies or credential values.
Metadata proves references to n8n-managed credentials; it does not independently
certify their ciphertext or validity.

The private bridge checks reuse the existing bounded Docker metadata inspection
and listener/owned-parent checks, verify runner/launcher source paths and hashes,
and require the protected, owner-0600 receipt store. Missing bridge listeners,
source drift, changed owners, widened shares and unexpected counts fail closed.
Read-only SQLite connections use `mode=ro`, `query_only`, and a consistent read
transaction. Aggregate-only receipt queries require exactly one historical
QA tenant/ID/key/digest match and zero fresh event-ID or key collisions across
all tenants. No stored receipt fields are returned or printed. This replaces
only the incompatible first-send zero-count gate and payload-column credential
inspection; it never calls or monkeypatches `qa.preflight()`.

The native temporary test listener is deliberately unverified. Absence is allowed
for read-only inspection, but the result always says **NOT READY FOR SEND**.
Zero persistent webhook registrations cannot prove temporary listener readiness.
The runtime checks have not been executed in this source-only task, so uniqueness,
current bridge state and installed metadata remain unverified live facts.

`--send-one` is unconditionally **BLOCKED**, before any runtime inspection.
Approval/issuer/token flags are unsupported. Existing sender helpers accept
asserted CLI approval values and first-event receipt counts; composing them here
would not independently verify the new authority boundary. Missing components are:

- An independently verified, exact owner approval record binding the reviewed
  canonical source HEAD, new fixture digest, installed receiver/project, gateway,
  current bridge endpoint and native test-only URL, with one-attempt consumption.
- Separately approved and freshly verified native two-minute test-webhook
  registration; a CLI boolean or old observation is insufficient.
- Approved inbound 1Password field metadata and a matching user-authenticated
  private issuer. No secret field reference is discovered or retained here.
- A reviewed bridge from that issuer through an anonymous pipe to exactly one
  test-only POST, with no redirects/retries and authorization consumed even on
  timeout, plus aggregate postchecks: total two, exact historical one, exact new one.

These require a later bounded implementation/approval; no flag enables them now.
A future clean-head check must use the actual integrated commit, not this archive's
baseline label. Source hashes and green offline tests do not grant send authority.

Security: metadata and aggregate reads, no secrets or authority widening.
Infrastructure: preserve existing LOCAL services and both Supabase boundaries.
Automation: prepare the second distinct transport QA event only.
Business: no acquisition, owner verification, Work Item or customer outcome is
established; this does not replace client delivery work.

Next action: review the three-file patch and offline validation evidence, then
separately authorize integration or an exact read-only runtime inspection.
Listener registration, issuer access and one POST remain separate later approvals.
