# Second unique fictional LOCAL receipt: dormant governed sender

This follow-up changes only the PR751 sender script, its offline tests and this
document. It implements a dormant one-attempt core; live sending stays BLOCKED.
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

The native temporary test listener remains unverified. Absence is allowed
for read-only inspection, but the result always says **NOT READY FOR SEND**.
Zero persistent webhook registrations cannot prove temporary listener readiness.
The runtime checks have not been executed in this source-only task, so uniqueness,
current bridge state and installed metadata remain unverified live facts.

`--send-one` remains unconditionally **BLOCKED**, before runtime inspection.
Approval/issuer/token flags are unsupported. Even a direct call to the dormant
core stops at the unavailable independent owner verifier before runtime or secret
access. There is no enable flag, artifact-file argument, injectable CLI verifier,
owner trust root, or default credential reference. The current source-only task
is not execution authority. Do not remove this block merely because tests pass.

The existing `avuhz_engineering.authorization_plan` framework was inspected:
`validate_approval` and `authorize_step` validate exact plan/approval/progress
bindings. They do not authenticate an artifact's issuer, independently observe a
native listener or owner 1Password session, or atomically persist consumption.
Its returned progress is not a durable single-winner claim. The first-event and
replay senders accept asserted CLI approvals and incompatible receipt counts;
they cannot supply the missing trust boundary. No alternative governance store,
signing system or authorization schema is introduced here.

Three intentionally unavailable internal adapters block real execution:

1. `_verified_owner_authorization`: independently authenticate a fresh exact
   owner-issued artifact, reject revoked/stopped/superseded authority, and return
   its immutable identity, digest, two-minute-or-shorter window and exact binding.
   A Python record, JSON file or matching checksum is not independent proof.
2. `_listener_and_issuer_observation`: freshly verify separately approved native
   registration identity/window, exact project/workflow/test URL and inbound
   credential, plus the signed-in owner's 1Password account/user/session and
   approved existing private inbound field metadata. Service-account identity,
   a CLI readiness flag, a listening socket or zero persistent registrations
   cannot satisfy this requirement. This adapter never reads a secret value.
3. `_consume_owner_authorization`: revalidate authority and atomically persist a
   single-winner consumption across processes/restarts before returning True.
   It must never refund an attempt after issuer failure, rejection or timeout.
   An in-memory boolean or local caller-owned marker is not sufficient.

These must be integrated with the existing bounded authorization framework in a
separately reviewed scope before wiring the CLI. No authentic owner artifact,
trusted listener/issuer observer or durable consumer was supplied or verified in
this task. The three functions always deny; mocks replace only these explicit
boundaries in offline tests. Tests validate sequencing and binding checks, not
real artifact provenance, live sessions, cross-process persistence or delivery.

Behind those gates, the dormant core:

- Requires DefNet/LOCAL, no CI; checks the actual clean integrated commit rather
  than the cached baseline label, exact sender hash and pinned helper/receiver
  hashes. Binds project/workflow, tenant, event ID/correlation/key/digest, gateway,
  bridge PID/endpoint, store, historical digest and before/after receipt counts.
- Matches all observed listener and issuer metadata to the verified artifact;
  requires observation age at most five seconds, listener lifetime at most 120
  seconds, and an authorization window within the listener expiration.
- Rechecks runtime/bindings, durably consumes authority, then invokes the existing
  `LocalN8nOnePasswordCredential` once for exactly the approved inbound field.
  The value stays in memory and passes through an anonymous pipe FD to the
  existing bounded FD reader. No subprocess or shell is used for FD handoff;
  the descriptor is private to this process and is closed on read. The provider's
  private child stdout PIPE remains its existing implementation. This does not
  implement a child-process inherited-FD handoff; that requested variant remains
  a limitation of this disabled preparation and needs separate review before
  any live enablement. No token is
  copied into argv, environment, a named file, output or diagnostic text.
- Rechecks source/runtime/listener/session after the private read, then sends one
  fixed POST to `http://127.0.0.1:5678/webhook-test/avuhz-events`. No redirect,
  retry, fallback issuer or second delivery occurs. Exactly HTTP 202 with a
  single JSON member `{"accepted":true}` is required; numeric `1`, duplicates,
  extra members, oversized or malformed bodies fail closed. A timeout means
  ambiguous delivery with consumed authority; reconciliation must be read-only.
- Performs aggregate-only postchecks requiring total=2, historical exact=1,
  fresh ID/key collision count=1 and fresh exact tenant/ID/key/digest=1. Both
  pre/post checks deny ownership drift and cross-tenant or partial collisions.
  No stored receipt payload is returned. The old first-event zero-count guard
  and every baseline tracked source remain unchanged.

The fresh acknowledgment parser is local to this sender because the older helper
uses Python equality that accepts numeric `1` as boolean true. That helper is
hash-pinned and left untouched in this bounded patch; the fresh path does not
call its HTTP sender. Its private FD reader and clean-head reader are reused.

Source provenance: the input snapshot is cached #749 (`24e9412`) plus the exact
three PR751 additions, verified against published Git blobs
`b52bebf91d4a03027e6bd732fa010acac8e743b0` (script),
`aa66cb6de7fd5b52438b9febc46e583ee9453ab1` (tests), and
`6d194f4ae8ae479094a10549b144197d6923a8cc` (this document).
The owner reported remote main #751 at
`d17abac5986c965a8620c13a45233d30aef86afa`; it was not fetched or independently
re-read here. Possible #750 changes are absent from the snapshot. Validation
uses an independent temporary Git checkout with real cached #749 HEAD and the
three PR751 additions indexed, not a fabricated PR751 commit. The resulting
three-file patch must be reviewed against the actual integrated tree; no test
result here certifies unobserved #750 changes or authorizes a live send.

The native test route proves only fictional transport/receipt behavior if later
separately authorized and observed. It is not Gate D's TLS1.3 production
`/webhook/avuhz-events` route, acquisition ownership or business Work Item proof.

Security: metadata and aggregate reads, no secrets or authority widening.
Infrastructure: preserve existing LOCAL services and both Supabase boundaries.
Automation: prepare the second distinct transport QA event only.
Business: no acquisition, owner verification, Work Item or customer outcome is
established; this does not replace client delivery work.

Next action: owner reviews the three-file patch and validation evidence against
actual integrated main. A later reviewed trust-adapter integration and exact
owner approval are required before sending can be enabled. Listener registration,
issuer access and one POST remain separately governed operations.
