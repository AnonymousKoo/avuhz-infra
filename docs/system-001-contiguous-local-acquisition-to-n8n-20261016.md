# System #001 — contiguous LOCAL acquisition → shared outbox → real n8n QA input

**Scope:** Avuhz LOCAL/TEST source only, on `AnonymousKoo/avuhz-infra`. Existing local n8n at `127.0.0.1:5678` is not modified or activated by this source change. Supabase DEVELOPMENT AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are separate and untouched. No hosted DATA, production, customer information, provisioned credential, workflow import or new n8n service is part of this PR.

## The previous discontinuity

The existing [October 15 real local n8n certification](system-001-real-local-n8n-postgres-qa-certification-20261015.md) executed the inactive five-node n8n child and created one real PostgreSQL Work Item with a durable n8n receipt. But its QA parent **invented the eight-field lifecycle event in Python** instead of obtaining it from the previously certified shared acquisition intake and outbox. The prior independent HTTP/outbox unit test used an in-memory n8n receiver, not installed n8n.

A second discrepancy became visible as soon as these stages were joined: a fictional public request's `external_request_id` is *not* the authoritative `intake_id` returned by the intake writer. Treating those IDs as interchangeable can orphan a receipt or bind work to the wrong intake. The old hand-built event used the external ID.

## What this source change does

The existing opt-in real-n8n certifier `scripts/certify_system001_live_local_n8n_to_work.py` now generates its one fictional QA event through this exact sequence:

1. Create the **existing** fictional shared acquisition WSGI adapter and independent fake DEVELOPMENT JWT verifier. Send the exact repository `LOCAL_TEST_ONLY_FICTIONAL_CLIENT` fixture to the existing `/v1/acquisition/intakes` route **without an external network call**.
2. Require the 202 reply and one committed synthetic acquisition transaction. Verify event and outbox inserts were staged by the shared writer. The acquisition DB connection remains a TEST double, **not** actual PostgreSQL or hosted AUTH.
3. Verify the lifecycle event's authoritative intake reference matches the **server-generated ID returned by the intake writer**, *not* the public external request ID. Keep the committed intake ID as independent source evidence outside the n8n envelope.
4. Run the **existing shared** `OutboxWorker` and `N8nOutboxSink` to project the committed event to the eight-field, PII-free n8n envelope. The injected temporary `.invalid` HTTPS transport captures the exact bytes in memory and acknowledges them. No n8n or external server is called at this staging point.
5. Give the captured envelope to the existing, inactive real n8n QA parent/child execution in the certifier. The existing receipt ledger still commits before acknowledgment.
6. Only after checking the actual committed n8n receipt, require the envelope's authoritative intake reference to match the **independently retained committed writer intake ID**. The private LOCAL-only acquisition lookup is populated from that independently retained source ID, never from an n8n claim, client tenant header or fabricated owner.
7. Existing synthetic strong HUMAN identity check, cross-tenant denial, real restricted PostgreSQL Work Item writer, exact replay, due/escalation review, handoff, resolution and revoked-owner denial are unchanged.

This is a **one-command, opt-in QA scenario**, not a running autonomous hosted pipeline. The n8n QA parent still uses one CLI manual execution and must remain inactive. The certifier still imports/reuses and restores exactly bounded inactive local QA workflows and an encrypted local credential, and requires the explicitly authorized disposable PostgreSQL test container and checked local n8n state. A live end-to-end connected QA run after this source change requires **separate exact LOCAL target authorization**. Do not run the certifier merely because GitHub CI is green.

## Current test evidence and honest gaps

`tests/integration/test_system001_committed_acquisition_to_n8n_projection.py` exercises the now joined **offline** WSGI → committed synthetic acquisition event/outbox → real shared worker projection, with no n8n changes. Negative tests cover fabricated owner flags, real-contact substitution, cross-tenant/source changes, inactive organization, forged intake response, and wrong-tenant committed event. They also assert the external request ID differs from the authoritative intake ID and none of the eight forwarded fields contains contact, business, diagnostic or token data.

The same module includes an **opt-in disposable PostgreSQL 17** integration test that uses a deliberately simulated private durable receipt (not installed n8n) before invoking the existing restricted Work Item writer and verifying idempotent replay, due/escalation, handoff, resolution and former-owner denial. It explicitly rejects the external request ID as committed intake authority even with a valid durable receipt. The PostgreSQL test skips when the exact local test container and DSN are absent; a skipped test is not counted as executed database proof. The joined path has also passed a separately run isolated LOCAL PostgreSQL 17 certification; its Docker container was removed afterward.

The **actual installed n8n stage** and disposable PostgreSQL handoff ran successfully in the historical October 15 certifier, but those old runs did not execute this new contiguous source input. Until the explicitly authorized local QA run passes, **do not claim the complete new contiguous path has been executed in real n8n**.

Other blockers are unchanged: acquisition data writes remain a test double, local owner evidence is fictional, no legitimate hosted owner is enrolled, no durable autonomous scheduler or approved communications/billing adapter is operating, and future privileged acquisition version/state writers must honor a separately reviewed serialization protocol.

**Next action:** review/merge exact-head source CI, then run one *separately authorized* LOCAL-only n8n/disposable PostgreSQL one-shot certification. Once that is proven, implement the durable, unattended source-outbox-to-n8n trigger and customer follow-up actions without granting n8n owner or tenant authority.
