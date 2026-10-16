# System #001: bounded one-command LOCAL n8n + disposable PostgreSQL certifier

**Resource / environment:** Avuhz LOCAL/TEST source only. This wrapper **does not run autonomously**, start or install persistent services, deploy, register an owner or authorize a hosted environment. It exists to replace error-prone *manual disposable Postgres setup* around the existing guarded LOCAL installed-n8n QA script. AUTHORITATIVE hosted Supabase AUTH (`pwlhruwutoitnieactol`) and DATA (`gnuqaefotwgkwurjpyik`) remain separate and are never touched by either script.

## Current state

The existing System #001 v2 child is installed **inactive** on loopback local n8n port 5678. The October 16 preflight passed, showing exactly one five-node child, no bound receipt credential, no active workflows, no execution rows, and only fictional QA fixtures. Prior **offline** acquisition → outbox → synthetic receipt → disposable PostgreSQL work lifecycle tests pass; the *new joined path has not been executed through real installed n8n* yet.

## Safely inspect, with no mutations

Run from the Avuhz repository with the Python environment containing the required source dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
python3 scripts/run_system001_local_contiguous_qa.py
```

Default behavior: read local n8n state without altering it, check that the pinned local PostgreSQL 17 image is already present (no pull), check fictional source fixtures; print a safe fixed status. NO database, credential, workflow or container is created.

## Operator-approved execution, strictly LOCAL

**STOP until there is separately confirmed approval for exactly one LOCAL QA run.** Confirm the exact device, n8n Docker container and inactive source-matching child, fictional QA tenant, and a disposable pinned PostgreSQL container. Source code/PR approval alone is not permission to import a local encrypted credential or execute n8n.

Once that separate approval is recorded, use an **isolated QA Python environment** with exact package versions `psycopg==3.3.4`, `jsonschema==4.10.3`, `PyJWT==2.14.0` and `cryptography==50.0.1` and invoke the wrapper with `--execute-local-qa`. It does not create or install a Python environment and refuses unpinned dependencies *before* starting Docker. It is blocked under CI/GitHub Actions or any non-LOCAL/TEST `AVUHZ_ENVIRONMENT`.

The wrapper:

1. Checks n8n safe inactive state and pinned test dependencies.
2. Starts exactly one **locally available** digest-pinned PostgreSQL 17 image, with a random unique disposable name, loopback-only dynamically allocated port (`127.0.0.1::5432`), `--pull=never`, and no persistent volume. This disposable test DB uses trust authentication strictly on localhost; never expose it externally.
3. Waits for readiness and verifies one loopback-only port mapping. Sets **child-process only** `AVUHZ_LOCAL_POSTGRES_CONTAINER` and `AVUHZ_WORK_ITEM_TEST_LOCAL_DSN` for the existing guarded certifier; these refer only to the ephemeral container, not hosted/local Supabase data.
4. Executes exactly once the existing `scripts/certify_system001_live_local_n8n_to_work.py` with the already-approved source-bound LOCAL n8n test child. That script temporarily binds the inactive child to a private receipt server using an encrypted n8n header credential, executes one fictional manual QA parent, tests the real Work Item database and owner guards, then restores the original inactive child. The envelope is now derived from the committed **fictional** acquisition event and shared outbox, not invented. No public route, actual customer, billing or outbound communication is enabled.
5. Requires all exact fixed successful certification markers, **not merely exit code 0** (the older certifier returns 0 even for an internally reported QA denial). Only sanitized messages are exposed; CLI execution JSON, token and raw output are never printed. Requires the n8n preflight to pass again.
6. In a `finally`, removes and verifies absence of the unique disposable database container. An inactive QA parent and an encrypted credential can remain in local n8n as documented in the original certifier; removal requires separate scoped approval via the supported n8n interface. In case of a failure during QA, the original certifier attempts child restoration; a failed restoration requires owner intervention rather than activation.

This one-shot operator-approved test does **not** establish an unattended continuously polling local outbox service, a real business-owner issuer, hosted acquisition authorization, working communications/booking/billing, or production-readiness.

## Proof and next action

Read-only preflight succeeded on October 16, 2026. The new wrapper's mocked safety tests cover default read-only behavior, CI/hosted denial, source drift, pinned image and Python gates, loopback network mapping, exact success markers despite old script exit-0 semantics, one source-bound execution, and cleanup even on a failed child certification. They have **not** executed n8n or created a container.

**Next action:** merge exact-head tested source, then obtain **separate exact LOCAL scope approval** and perform one contiguous n8n + disposable PostgreSQL certifier run. Only after positive evidence, implement the persistent unattended shared outbox trigger and due/escalation execution without giving n8n access to authoritative tenant or owner tables.
