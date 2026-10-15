# LOCAL n8n read-only activity evidence — source-only v1

**Scope:** Existing Avuhz source; LOCAL/TEST only. No production API,
n8n workflow mutation, credential read, network listener, outbound call,
Supabase access, customer data or Command Center configuration changed.

## Why this exists

The private Sekinfra Command Center currently displays **GitHub engineering
activity** but not actual local n8n executions. A Command Center deployment
cannot access `127.0.0.1:5678` on the operator's machine. Never make n8n
public or embed local database/API credentials in the dashboard.

This first stage makes the minimum useful **local-only aggregate evidence**
available through a read-only CLI. It is NOT yet a transport connection.

## Actual existing LOCAL resource

- Owner's machine: `DefNet`, existing `n8n` Docker container bound to
  `127.0.0.1:5678` and answering `/healthz`.
- n8n uses a mounted local SQLite database (do not copy it or commit it).
- Read-only tables: `workflow_entity` and `execution_entity`. The CLI
  does **not** SELECT nodes, connection settings, execution data, contacts,
  workflow names, IDs, credentials, users or execution payloads.
- Rows are summarized by workflow/active counts and tightly allowlisted
  execution statuses, plus a **name-prefix-derived candidate count** for
  System #001. A name match is neither authorization nor proof of a correctly
  installed, wired, or certified workflow. No raw workflow names are emitted.

## Explicit manual use

Run from the Avuhz repo on the LOCAL owner's machine:

```bash
mount=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/home/node/.n8n"}}{{.Source}}{{end}}{{end}}' n8n)
test -n "$mount"
python3 scripts/local_n8n_activity_snapshot.py --database "$mount/database.sqlite"
```

The output is **only** sanitized, bounded JSON for an operator to inspect
locally. It includes `connection_to_command_center:false` and
`system_001.runtime_certified:false` to prohibit mistaken interpretations.

No cron, daemon, HTTP server, external push, file artifact or periodic task
is created. You must not export an underlying SQLite file, WAL, credentials
or workflow definitions.

## Recovery and failure

- The database argument must be an existing, absolute, non-symlink path.
- SQLite is opened `mode=ro` and `PRAGMA query_only=ON`.
- Missing/malformed tables, unavailable database, filesystem errors and
  invalid inputs return only a static `state:"unavailable"` marker and exit
  code 2; exception messages and database paths are not emitted.
- Any unknown execution status goes into the aggregate `other` count;
  arbitrary string statuses are not echoed.
- Direct LOCAL-to-PRODUCTION data movement is forbidden without an
  authorized transport/repository design, scoped credential and receiving
  server read model. In particular, no browser calls to localhost.

## Integration steps after source review

1. Verify the operator owns the exact local Docker/n8n environment and
   inspect aggregate-only output; unit tests run against synthetic SQLite.
2. Decide an explicit, authenticated outbound-only bridge with a bounded,
   versioned snapshot contract, tamper/replay protection and secret storage
   outside Git or workflow JSON. Reuse Avuhz shared identity/communications
   policy; DO NOT invent a second auth backend.
3. Create the least-privilege **server-side** Avuhz activity ingestion/read
   boundary, with operator authorization and environment-scoped status. No
   tenant claims based on untrusted local n8n names. Deploy only after
   separately approved environment/namespace confirmation.
4. Show freshness, data source, LOCAL vs PRODUCTION and failure explicitly
   in the Command Center. Read-only local status cannot be treated as
   approval to activate a workflow, modify data or contact customers.
5. Repeat separately for production n8n after diagnosing the observed
   `n8n.sekinfra.com` nginx 502. The public host reported 502 while LOCAL
   `127.0.0.1:5678/healthz` reported 200; they are separate environments.

This is a **local visibility primitive**, not an automation, command API,
tenant RLS exemption, or production monitoring endpoint.

**Next action:** review and merge the source-only collector PR, then design
the exact secure outbound-only LOCAL telemetry bridge and receiving Avuhz
read model for separately authorized implementation. No hosted changes or
live n8n activation are approved here.
