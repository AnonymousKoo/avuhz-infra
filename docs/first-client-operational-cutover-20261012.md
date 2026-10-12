# First-client Avuhz → Sekinfra cutover — evidence-bound gate

**As of Avuhz main `121924415c7378f67a78e0272109ccbbf556de00`.** This is a
repository-only operational readiness plan. It is not an approval to change
DEVELOPMENT DATA `gnuqaefotwgkwurjpyik`, DEVELOPMENT AUTH
`pwlhruwutoitnieactol`, n8n, Sekinfra hosting, credentials or production.
No new billing, authentication or automation infrastructure may be created in
the Sekinfra vertical.

## What is implemented and what remains disconnected

The dormant DEVELOPMENT acquisition WSGI adapter parses bounded JSON and requires
server-verified AUTH evidence. The shared intake writer validates consent,
ACTIVE receiving organization and independently verified OWNER membership,
limits requests, inserts an intake, and appends one sanitized
`acquisition.intake.received` event plus one outbox delivery in the same
transaction. The DEVELOPMENT DATA event-vocabulary migration is installed.
The LOCAL/TEST `N8nOutboxSink` projects an eight-field, PII-free envelope.

The end-to-end synthetic test
`tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py`
exercises WSGI intake → verified fake identity and fake organization →
existing writer's captured atomic writes → local outbox worker → authenticated
fake n8n receiver, including simulated lost ACK retry and wrong-header denial.
It **does not** verify real PostgreSQL grants, deployed n8n, a real AUTH
service account, a durable receiver store or a public website integration.

## Operational cutover conditions, in dependency order

1. **DATA access design, one reviewed boundary.** A previously proposed
   shared `avuhz_command_service` contact-column grant path was closed in
   [PR #638](https://github.com/AnonymousKoo/avuhz-infra/pull/638) after
   discovering it would expand same-tenant PII access. The writer's row
   locking uses `FOR SHARE`, which **requires UPDATE privilege** in
   PostgreSQL 17 even when reading. Do not grant broad UPDATE or PII SELECT
   to the general shared command role to work around this. Design a
   separately scoped **shared-core acquisition execution identity**, with
   only necessary table access and tenant-bound RLS, and test denied owner
   modifications, denied same-tenant access by unrelated workload roles,
   cross-tenant access, rollback and idempotent replay on disposable PG17.
   Any hosted role/grant/policy change needs fresh, exact DEVELOPMENT DATA
   approval. The previous event-vocabulary migration approval grants
   no authority to create or alter roles.
2. **Receiving business and AUTH identity.** DEVELOPMENT DATA presently has
   zero active registered receiving organizations and zero verified owners.
   Register and verify the intended business and owner through the governed
   Avuhz authority process without fabricating records or treating Florida
   business-registration paperwork as an engineering prerequisite. Separately
   enroll a scoped DEVELOPMENT AUTH `acquisition_intake:receive`
   **service identity** using the existing AUTH verification mechanism.
   Never let a browser choose a trusted tenant/organization ID.
3. **Rate limits and hosting.** Require durable tenant/service rate-limit
   access plus public-edge abuse controls, with tested retry and negative
   cases; the current LOCAL/TEST lambda is not deployable. Confirm HTTPS
   trusted ingress, security headers, redacted logs and the DEVELOPMENT
   Avuhz command-service route before mounting the existing WSGI adapter.
   This is a separate, explicit runtime authorization.
4. **One n8n receiver, centrally shared.** Confirm the actual n8n instance,
   version, ingress host and project namespace. Use encrypted native header
   credentials. The receiver must validate tenant/event allowlist and
   delivery key and write a **durable, uniquely keyed receipt before 202**
   (including lost-ACK replay). Do not import unsafe legacy n8n templates,
   use service_role credentials, enable unauthenticated webhooks, or write
   authoritative Avuhz tables directly. The current n8n adapter and
   outbox worker are restricted to LOCAL/TEST; hosted activation requires
   separately reviewed transport, runtime binding and permissions.
5. **Sekinfra website and synthetic cutover.** Keep
   `/api/diagnostic-intake` returning `503 INTAKE_NOT_CONNECTED` until
   the verified backend is connected. With explicit DEVELOPMENT runtime
   authorization, test synthetic POST → authenticated Avuhz intake →
   persisted event/outbox → n8n durable receipt → consent-based notification,
   then test denial and lost ACK. Verify across the boundary that no client
   contact fields are present in the n8n notification or logs. Only then
   authorize real prospect intake and introduce a monitored fail-closed
   rollback switch.

## Client #1 business lane

Real prospects can attend discovery meetings and receive separately agreed
consulting work before the whole automation is operational; do not claim
Avuhz is handling onboarding until the five gates pass. Pricing, agreements,
and payments require independently authorized shared billing/communications
capabilities or an explicitly out-of-band founder-operated process. No
vertical-specific billing path is permitted.

**Next action:** Review the synthetic integration PR, then implement and
disposable-test the distinct acquisition-only DATA execution boundary,
not a broader command-role grant. The first live provider change remains
approval-gated; do not ask for authority unrelated to the next gate.
