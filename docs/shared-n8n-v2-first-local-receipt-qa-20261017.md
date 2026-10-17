# Shared Receiver v2 — first fictional LOCAL receipt QA gate

**Repository:** `AnonymousKoo/avuhz-infra`. **Target:** DefNet **LOCAL** Docker n8n on loopback `127.0.0.1:5678`, *not* hosted or production n8n. **Runtime responsibility:** shared Avuhz automation and its existing LOCAL-only private receipt store. **Repository action:** source/tests/documentation only. No secret read, workflow mutation, service restart, HTTP delivery, receipt insertion, customer data, or hosted provider operation is authorized by this change.

DEVELOPMENT Supabase AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are **different** projects and are both outside this task. This QA fixture never registers an owner or tenant with either provider. Reusing the shared receiver does not create vertical-specific authentication, billing, or orchestration.

## What is implemented and verified

The installed shared receiver ID `0068feb4c96bdb5f` (source template SHA-256 `fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`) has its *inbound* encrypted n8n `httpHeaderAuth` credential bound and its *outbound receipt* encrypted `httpHeaderAuth` reference `154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2` bound to the existing private `http://172.17.0.1:37891/v1/avuhz/local-n8n-receipts` endpoint, checked at the time of inspection. This private port is **ephemeral**; never treat the observed port as a permanent endpoint. The receipt service is held open by its separately approved foreground parent launcher and stores only tenant-bound delivery key, event ID, envelope digest and receipt time in owner-only SQLite at `/home/network-p/.local/share/avuhz-qa-receipts.sqlite`.

At the time of inspection, LOCAL n8n holds **6 non-archived workflows and 1 archived workflow record**, with **none active** and **zero saved executions**. The private receipt store has **zero receipt rows**. The two separately scoped credentials are n8n-encrypted and shared to the existing personal project, but their values are never read by this tool. No other workflows or provider projects are modified. The correct count of visible workflows is **6**, not 7.

## Read-only gate: exact installed receiver

Run from the reviewed checkout in DefNet:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_local_first_event_qa.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

The default mode verifies the pinned canonical five-node receiver, its exact two encrypted credential references and project shares, unchanged connected Code/HTTP/response nodes and settings, the verified private listener/foreground parent identity, private `0600` SQLite receipt database, and the exact **fictional** QA tenant. It also verifies a deterministic PII-free eight-field *transport-only* event fixture. It performs **no n8n execution or network request**, does not read any secret, creates no files, and does not import or activate workflows. No public ingress is opened.

The generated synthetic event has fictional tenant `a4730000-0000-4000-8000-000000000001`, static event/correlation identifiers in reserved `a473...` QA space, event type `acquisition.intake.received`, a fixed future QA timestamp, version 1, a stable QA delivery key, and an `ACQUISITION_INTAKE` reference to the fictional fixture's external request. **It is not a real committed authoritative acquisition event.** A successful transport-only receipt must not be treated as a legitimate customer inquiry, independently approved owner, Work Item creation or business outcome. The fixture contains no name, email, phone or diagnostic notes in its eight-field transport projection.

A later separately authorized test may use the exact synthetic event. Only after that test, the following **read-only** check can verify a single matching SQLite receipt by full canonical SHA-256 envelope digest, delivery key, event ID and tenant (not just row count):

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. AVUHZ_ENVIRONMENT=LOCAL \
python3 scripts/prepare_shared_n8n_v2_local_first_event_qa.py \
  --target LOCAL_DEVELOPMENT_N8N_5678 --expect-one-receipt
```

**Important proof limit:** even an exact SQLite receipt could have been inserted by another permitted LOCAL authenticated client. It is not proof that n8n ran, that the webhook returned HTTP 202, that replay/negative tests passed, or that an authorized Work Item exists. Those must be separately observed in the actual execution and shared command service. The current n8n workflow settings disable saving manual execution contents, so a zero saved-execution row count is not evidence that an execution did or did not occur.

## Next bounded test sequence and gates

1. **Approve and prepare a supported test-input method for this exact installed inactive receiver.** The existing `n8n execute --id` CLI exposes no flag for sending webhook request data; `scripts/certify_system001_live_local_n8n_to_work.py` and `scripts/run_system001_local_contiguous_qa.py` target a **different, unbound System #001 child** and may import/revert QA workflow resources and create a disposable PostgreSQL container. **Do not run either existing certifier on the bound shared receiver or silently import another workflow.** Inspect/review native test-webhook lifecycle or an isolated manual-only QA harness first. Activation or a temporary test-webhook registration is a separate approved n8n resource change, not implied by this source PR.
2. Separately authorize **one** exact fictional event delivery through the actually installed receiver, with privately sourced inbound n8n authentication, matching `X-Avuhz-Delivery-Key`, strict PII-free body, verified LOCAL loopback ingress, a bounded execution window, a checked one-time invocation, and sanitized HTTP status/receipt evidence. Never put credentials into logs, Git, terminal history, CLI flags or ChatGPT conversation. No retry if result is ambiguous.
3. Verify an actual sender HTTP 202 **after** a single durable SQLite receipt and a matched sanitized n8n response; distinguish a duplicate replay (HTTP 202, unchanged row count), same-key tampering (409), wrong credential (401), cross-tenant (403), extra fields (400) and backend failure (not 202). Each additional send is a separately authorized test event within an explicitly approved bounded batch; do not imply this PR authorizes any of them. Keep all n8n workflows inactive after the test and never expose hosted endpoints.
4. Separately validate the **authoritative** local Work Item handoff using the shared command service, independently owned acquisition lookup and strong authenticated HUMAN membership with tenant RLS. The existing disposable PostgreSQL integration tests provide a synthetic writer proof, **not a hosted owner/tenant onboarding or an operational System #001 outcome**. No DATA/AUTH provider writes are in scope.

**Security / Infrastructure / Automation / Business lanes:** the gate protects credentials and isolation; reuses existing private Docker/n8n/SQLite infrastructure; prepares evidence for a real n8n event instead of substituting a mock for that event; and does not block supervised real-client OIA discovery or pretend that plumbing alone wins a paying client.

**Next action:** Merge this source-only gate after exact-head CI. Then investigate/prepare the native, **inactive-first** QA input method and seek an explicit new authorization for the *one* corresponding LOCAL n8n resource change. Do not activate or send on merge.
