# System #001 — verified LOCAL n8n execution preflight and safe activation boundary

**Verified 2026-10-15:** `AnonymousKoo/avuhz-infra` source-only LOCAL/TEST; authorized DefNet Docker container `n8n`, bound only to `127.0.0.1:5678`. The canonical workflow source is `contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json`; the fictional QA fixture is `tests/fixtures/system001_qa_tenant_local_v1.json`.

No hosted, remote provider, Supabase AUTH (`pwlhruwutoitnieactol`), Supabase DATA (`gnuqaefotwgkwurjpyik`), n8n workflow, credential, paid API, tenant or production resource is mutated by this PR.

## Executed read-only preflight

`PYTHONPATH=src:. python3 scripts/preflight_system001_installed_n8n.py`

The command verifies the Docker container identity/loopback port/private bridge, reads ONLY its mounted n8n SQLite database in `mode=ro`, and compares the installed workflow exactly against canonical source nodes/parameters/wiring. It also checks project assignment, inactive workflow status, zero executions, and the strictly fictional QA fixture. It reads no n8n credential row, customer data, execution payload or token; it prints only safe booleans/counts and no workflow ID, local filesystem path or private Docker address.

As currently observed:
- **PASS**: exact System #001 v2 child, five source-matching nodes, installed once in the existing owner project.
- **PASS**: zero active workflows, zero recorded executions, no bound header credential and no alternate receipt endpoint.
- **EXPECTED BLOCKERS**: child input unbound, HTTP request still targets unreachable `127.0.0.1:1`, private receipt server not running, no independently resolved QA owner integration mounted. This is not a real executed workflow or an authorized customer Work Item path.

The new preflight fails closed on credential drift, activation, unknown topology, a published/changed URL, prior executions, duplicated/missing workflow, non-fictional fixture, or missing project assignment. Five negative-focused tests and the existing seven JS contract tests pass.

## Required one-resource-at-a-time LOCAL execution sequence

The user wants to finish System #001 **locally** with fictional Avuhz QA Tenant 001 (not SekInfra). No real business or hosted tenant registration is required for this phase. Execution must still respect Avuhz's shared AUTH/command boundary and n8n secret-storage rules.

**DO NOT automatically perform any of the following merely because the preflight passes.** Each is a separate LOCAL provider/resource change with confirmed scope and explicit approval:

1. **Receipt service:** approve a single LOCAL/TEST temporary start of the existing private `local_n8n_receipt_dev_runner.py --serve` against the explicitly inspected Docker bridge and fictional QA tenant. Pass a generated ephemeral token through the required secret FD, never an argument, environment variable, GitHub artifact, workflow JSON or chat. Use private temporary storage with mode 0700/0600; receipt process exits after controlled test.
2. **n8n encrypted credential:** register one dedicated, ephemeral **httpHeaderAuth** credential in the existing LOCAL `n8n` project, sharing the same token through an approved private channel only. No unrelated credential edits, no plaintext credential commit or log. Its value must be encrypted by n8n at rest.
3. **Inactive child workflow:** update only the installed LOCAL v2 child's HTTP node to the verified private Docker gateway and private receiver port, reference ONLY that new encrypted n8n credential, and keep its **active=false** flag. Retain exact source validation, response gate, disabled redirects and marker.
4. **One-event QA entrypoint:** add a separate manual-only, non-public, explicitly test-labelled parent workflow to supply exactly one allowlisted fictional sanitized event to the v2 child; no public webhook, schedule, email, billing, customer PII, real owner enrollment or platform-specific auth alternative.
5. **Controlled local execution:** independently verify the QA-only acquisition source/owner evidence, start one operator-invoked LOCAL run, and verify a single durable receipt and a single governed Work Item in a disposable local PostgreSQL schema with tenant-scoped RLS. Test duplicate, wrong-tenant, missing credential, disabled server, retry and idempotency. A committed n8n transport receipt does **not** confer owner authority. No send/notify/scheduler is permitted.
6. **Clean up:** stop receipt service, retire test credential, leave existing v2 inactive/unbound, archive only PII-free counts and outcomes, and verify no unexpected workflow activation/executions.

If credential import or child update cannot be verified without exposing a secret, **stop** and report the exact blocker. Do not use `service_role` or add an HTTP endpoint to the public Internet.

## Current scope outside the plan

- The joined QA intake-to-durable Work Item local test is now merged as PR #695. Its relay is **simulated**, while private receipt HTTP+SQLite and Work Item Postgres+RLS are real.
- Neither n8n execution success nor hosted DEVELOPMENT tenant authority has been certified.
- Read-only Docker metadata also showed an **unrelated** existing `ditl-postgres-1` container published on `0.0.0.0:5432` (and IPv6 `::`). Exposure beyond the host depends on firewall/network policy and was **not verified**. Flag for a separate authorized security audit; do not modify that service in System #001.

**Next action:** obtain exact permission for the first LOCAL-only receipt service start and test credential boundary. Proceed sequentially; do not conflate source validation with an installed n8n run.
