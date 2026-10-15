# Shared Avuhz → n8n receiver: real-instance inventory and DEVELOPMENT cutover gate

**Status: READ-ONLY INVENTORY + REPOSITORY-ONLY PLAN. NOT DEPLOYED.**
Evidence collected October 13, 2026. This document grants no n8n, AUTH, DATA, Render, Sekinfra website, DNS, credential, billing, or production mutation authority.

## Confirmed namespace and source

- Repository: `AnonymousKoo/avuhz-infra`, protected `main` baseline `55b907e7c40bda2c07ffb6d9e975ccae0095b57e`, shared `Automation` lane. This is **not** the Sekinfra consulting/OIA vertical.
- DEVELOPMENT Supabase **AUTH** `pwlhruwutoitnieactol` is distinct from **DATA** `gnuqaefotwgkwurjpyik`. No database contact was needed for this inventory.
- DefNet Ubuntu device read-only Docker inventory: container named `n8n`, image configured as `n8nio/n8n:latest`, running n8n **1.103.2**, localhost port **5678**, bind-mounted `/home/network-p/.n8n` to `/home/node/.n8n`. Its read-only workflow list contains just **`AI Auto Marketing Check`**; SQLite metadata reports that workflow inactive. The image tag `latest` does not establish automatic upgrades and does not justify upgrading/restarting it.
- `https://n8n.sekinfra.com` answers **HTTPS 200** and `/rest/settings` answers **200**, but its public settings response differs significantly from the local Docker settings response. Its n8n version, provider account, project namespace, underlying host, actual workflow list, and environment classification are **not independently established** by anonymous HTTP inspection. The earlier owner-supplied screenshot displayed 15 published workflows, including `Secure Dashboard API` and `OIA Intake`; **no credential-free evidence proves this is DefNet's local container or identifies the exact hosted project**. Do not conflate the two instances.
- Do not use the local `~/.n8n` workflow count to declare the owner-shown hosted workflows deleted or migrated. Do not import legacy exported workflows: the historical exports contained credential-shaped material and unsafe direct provider access.
- No new subscription or paid identity/KYB verification is necessary for this **synthetic** receiver readiness step.

## Implemented sender and exact first event

- `src/avuhz_worker/n8n_event_sink.py`: `N8nOutboxSink` validates HTTPS host/path, same trusted tenant, schema, and eight-field JSON envelope (maximum 4096 bytes); delegates token retrieval and non-redirecting HTTPS POST to injected collaborators. It is **LOCAL/TEST-only**, rejects DEVELOPMENT/PRODUCTION, and implements **neither** transport nor credential provisioning.
- `src/avuhz_service/acquisition_intake_command.py` appends `acquisition.intake.received` and a transactional outbox delivery in the shared acquisition writer. `tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py` verifies the fictional intake → fake event/outbox → fake authenticated receiver, correct replay, wrong token denial and PII-free eight-field delivery. This supersedes the older assertion in `docs/shared-n8n-authenticated-receiver-local-v1.md` that acquisition events are not emitted; the newer code is authoritative. A test fake does not certify hosted DATA persistence, a deployed endpoint, or a real organization.
- Exact envelope fields: `event_id`, `event_type`, `tenant_id`, `correlation_id`, `occurred_at`, `authoritative_subject_reference`, `authoritative_subject_version`, `delivery_idempotency_key`. Only the explicitly permitted `acquisition.intake.received` event and `ACQUISITION_INTAKE` reference type are candidates for the first synthetic scenario; a trusted server-owned allowed tenant ID must be configured separately.
- `docs/first-client-operational-cutover-20261012.md` still blocks live intake on independent verified owner/ACTIVE company, scoped acquisition DATA role, trusted AUTH service identity, durable rate limiting, and approved hosted command path. No n8n test bypasses these gates.

## First provider preflight — strictly read-only

Before any n8n workflow creation, unpublishing, import, or activation, the operator and agent must independently record:

1. **Instance:** exact logged-in origin and n8n account/project namespace for the **intended DEVELOPMENT** recipient, with n8n version and hosting owner; do not use workflow names, an anonymous 200 response, or a Docker container on another host as proof.
2. **Environment and workload:** confirm whether `n8n.sekinfra.com` is handling production traffic; if so, **do not** install a DEVELOPMENT experiment there under a generic `proceed`. Prefer a separately approved LOCAL/DEVELOPMENT n8n boundary using existing resources and only fake events; confirm it cannot access existing live customer workflows or credentials.
3. **Native encryption/auth:** verify n8n's native Webhook node supports Header Auth with an encrypted n8n credential at that exact version; no token literals, query parameters, node code, static fixtures, exports or screenshots.
4. **Durable receipt option:** inspect actual instance features and its database permissions, but do not assume n8n Data Tables, a PostgreSQL store, or Redis support atomic unique insert. Choose one already available **shared** receipt store with an enforced unique `(trusted_tenant_id, delivery_idempotency_key)` constraint, digest-collision rejection, and bounded PII-free columns. New DB grants/policies or a hosted store require distinct review and exact approval. n8n must not write authoritative Avuhz tables.
5. **Isolated network and permissions:** authenticate outbound Avuhz calls through an approved least-privileged secret boundary, verify HTTPS/TLS and redirects, and ensure receiver and test tenant cannot reach real customer actions or unrelated n8n workflows. Never use Supabase `service_role` or a legacy JWT shortcut.
6. **Production freeze:** do not change published legacy workflows, customer data, public Sekinfra `/api/diagnostic-intake` (still `503 INTAKE_NOT_CONNECTED`), command-center services, or the current production website.

## Shared receiver implementation acceptance contract

Once the above instance and one exact provider change are approved:

- Use **one shared** Avuhz inbound workflow, not a Sekinfra-specific automation platform. Native n8n Header Auth on POST `/webhook/avuhz-events` enforces `X-Avuhz-Webhook-Token`; provisioning is exclusively via n8n encrypted credentials and the approved Avuhz secret store. Test webhooks and production endpoints must not be silently interchanged.
- After native auth, validate a bounded 4096-byte JSON object with **exactly** the eight keys above; validate canonical UUIDs, schema types, subject reference, bounded event and delivery key; require `X-Avuhz-Delivery-Key` to match the body. Reject extra keys, arbitrary instructions, identity assertions, raw PII, unknown event types, or unauthorised tenant IDs. The tenant allowlist originates in the trusted configuration, never the webhook body alone.
- **Before any 2xx**, durably record a PII-free receipt using the trusted tenant and delivery key. Same key + same canonical event must return the accepted result with **no second effect**; same key + different payload is a **409 conflict**, even under concurrent submissions. All writes must be transactional/uniquely constrained rather than check-then-insert.
- A persisted first receipt or an identical replay may return **202**. Missing/invalid authentication must fail; invalid/unauthorized/conflicting envelopes must return bounded **400/403/409**; unavailable receipt storage must return **503** and never ACK. Apply abuse/rate guards and sanitized response bodies. n8n workflow error/execution logs must not retain raw request headers, PII, or secret values.
- Do not let receiver receipts become authoritative acquisition, OIA, payment, deployment or customer-communication authority. Any downstream action requires the separate approved Avuhz command/API policy and confirmed client consent. No outbound messages or payments are included in the synthetic test.

## Synthetic acceptance sequence, no real data

1. **LOCAL/TEST:** rerun `tests/integration/test_n8n_authenticated_receiver_round_trip.py`, `tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py`, and `tests/worker/test_n8n_event_sink.py` against fake identities and fake receivers. These are useful regression gates but not provider evidence.
2. **After distinct DEVELOPMENT approval only:** provision native encrypted header credential and exactly one inactive/isolated recipient; prove allowlist, atomic unique receipt, bad-auth denial, unknown tenant denial, malformed/PII payload denial and durable storage failure with synthetic events. This step must never contact a real customer workflow or reuse historical credentials.
3. Demonstrate **first delivery**, **identical retry after simulated lost ACK** (one stored receipt, no repeat effect), and **semantic collision** (409, no second effect); check independent stored receipt evidence, not only HTTP success.
4. Separately authorize the Avuhz DEVELOPMENT sender transport/role upgrade when provider evidence is complete; the current LOCAL/TEST-only sink must not be relabeled deployable.
5. Separately complete ACTIVE verified Sekinfra tenancy, scoped acquisition ingress, consent and rate limits before production onboarding. Only a later exact production approval may switch the Sekinfra website from fail-closed 503 to real intake.

## Known gaps and next action

**Known gaps:** hosted n8n project/production classification unknown; hosted n8n version not verified; encrypted header credential not bound; no approved durable receiver receipt store; no installed shared receiver; no authorised DEVELOPMENT sender transport or company; existing 15-workflow browser inventory not established as the local Docker installation. The fake tests and a 200 home page do not prove a receiver exists.

**Next action:** collect one nonsecret, read-only n8n operator evidence set for the logged-in hosted project's **instance/version, project namespace, and production/development classification**. Then select one isolated DEVELOPMENT destination and the actual available receipt-store feature before requesting approval for **one** receiver workflow mutation. Do not purchase a new service or activate production to accomplish discovery.
