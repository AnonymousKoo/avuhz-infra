# System #001 — bounded synthetic deadline and due-work certification

**Scope:** Avuhz shared Work Intake / Revenue Engine, LOCAL/TEST only.
This proves repository code composition; it is **not** a hosted
Supabase Auth login, client onboarding, production workflow, real
notification, booking confirmation, or permission to activate n8n.

## Why this exists

The shared Work Item writer, lifecycle event, idempotency ledger,
outbox, nullable `next_action_due_at` column, and owner-scoped due-work
reader already exist in the same Avuhz control plane. The DEVELOPMENT
DATA migration `development_data_work_item_deadline_owner_wrapper_v1`
was applied and independently verified, but real hosted principals and
an authorized HTTP/worker integration are separate deployment gates.

This test proves one **reproducible, bounded synthetic sequence** using
the actual canonical SQL on disposable PostgreSQL 17:

- Reject an unauthenticated synthetic owner before writes.
- Inject a strong but **synthetic** HUMAN authorization context through
  the established shared identity resolver and tenant membership hook.
- Create one OPEN Work Item with a deadline five minutes later, and
  persist the Work Item, idempotency receipt, lifecycle event and outbox
  in one transaction.
- Replay the same idempotency key without additional records.
- Verify no due review before deadline, one review exactly at deadline,
  and an overdue escalation review after the policy threshold.
- Deny unauthorized current owner / foreign tenant reads.
- Transfer ownership through the existing shared handoff commands,
  verify due-work visibility moves to the current owner, then deny
  a revoked member.
- Assert due-work reads did not produce outbox messages, additional
  lifecycle events or idempotency receipts.

## Run only in disposable LOCAL/TEST

The standalone runner intentionally **requires** an explicit
localhost-only DSN with a fixed disposable database and pinned local
port. It fails if `psycopg` is missing or if the test skips;
a skipped test never counts as certification.

From the repository root, using a local PostgreSQL 17.6 Docker image:

```bash
set -euo pipefail
name=avuhz-system001-due-journey-local-20261014
docker run --rm -d --name "$name" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:65447:5432 postgres:17.6-alpine >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 35); do
  if docker exec "$name" pg_isready -U postgres -q; then break; fi
  sleep 1
done
export AVUHZ_LOCAL_POSTGRES_CONTAINER="$name"
export AVUHZ_WORK_ITEM_TEST_LOCAL_DSN='host=127.0.0.1 port=65447 user=postgres dbname=avuhz_system001_durable_writer_test'
python3 scripts/certify_system_001_due_journey_local.py
```

Use an isolated test Python environment with pinned project dependencies
including psycopg 3; do not reuse hosted secrets or cloud DSNs.
The fixture creates/destroys only its disposable local database.
The container is removed at exit.

The runner emits one small JSON attestation with no customer PII,
provider secrets or real access tokens. It explicitly reports that
hosted authentication and n8n have **not** been certified.

## Authority and remaining gates

This harness has no authenticated access to DEVELOPMENT AUTH project
`pwlhruwutoitnieactol`, DEVELOPMENT DATA
`gnuqaefotwgkwurjpyik`, production, or any hosted n8n instance.
Passing does **not** enroll or authenticate a real owner.
Do not change providers, create tenants, send notifications or
activate webhooks to run this proof.

**Next action:** after independent review and green CI, merge this
source-only certification. Separately plan a fully authenticated,
one-tenant hosted synthetic ingress test with documented enrollment,
least-privilege runtime binding, and explicit environment-specific
approval. Keep Infrastructure V1 source observation and business
readiness moving in parallel.
