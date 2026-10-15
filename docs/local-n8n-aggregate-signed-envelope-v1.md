# LOCAL n8n signed telemetry envelope — source-only v1

**Verified target:** `AnonymousKoo/avuhz-infra`, LOCAL/TEST
`127.0.0.1:5678` on the authorized DefNet machine.
DEVELOPMENT Supabase AUTH `pwlhruwutoitnieactol` and DATA
`gnuqaefotwgkwurjpyik` stay separate. No hosted, production,
provider or tenant resource is touched.

## Grounded starting point

`scripts/local_n8n_activity_snapshot.py` already produces a bounded,
PII-minimized aggregate from the existing n8n SQLite database in
read-only mode. It contains only workflow counts, allowlisted execution
status counts and a System #001 name-matching candidate count. It
explicitly says `connection_to_command_center:false` and
`system_001.runtime_certified:false`. It never exports workflow names,
IDs, nodes, customer information, execution content or credentials.

The private SekInfra Command Center is hosted in Vercel and cannot
connect to the local-only address. This change adds only a **pure in-memory
HMAC-SHA256 envelope protocol** in
`src/avuhz_worker/local_n8n_telemetry_envelope.py`:
- exact v1 schema with ONLY count and source fields (no tenant ID or PII),
- version, 32-hex random nonce and integer observed-at timestamp,
- canonical signed payload, constant-time signature comparison,
- maximum five-minute freshness window and bounded 2500-byte message,
- reject-by-default malformed/tampered inputs and count discrepancies,
- a receiver-supplied `replay_seen` checker (fail closed when missing).

This is **transport integrity, not authentication or authorization**:
an HMAC by itself does NOT prove the sender belongs to a tenant, has an
Avuhz identity, may initiate commands or owns workflow state. It does not
replace the shared Avuhz authentication/authorization service.

## Absent until separately approved

- No transport key has been created, read, exported or configured.
- No local agent/daemon/cron, outbound HTTP client, Vercel endpoint,
  private API connection, n8n API token, listener, external notification,
  public tunnel, workflow mutation or Supabase migration is added.
- The producer does not emit or publish an envelope by default.
- The verifier's `replay_seen` callback is **not** an atomic durable
  reservation. A real Avuhz receiver must atomically reserve nonce
  and freshness after independent authorized identity and tenant proof,
  then persist only bounded sanitized aggregate state under scoped RLS.
  Until implemented, no remote delivery must occur.
- Never attach a public GitHub artifact as substitute transport.

## Next authorized implementation sequence

1. Implement an **Avuhz-core** restricted ingest/read boundary with
   authenticated source capability, durable replay reservation and RLS,
   reusing existing shared AUTH and DATA projects (not a second
   per-vertical authentication service).
2. Verify the exact DEVELOPMENT AUTH subject and intended DATA tenant
   membership via the owner's approved enrollment process. Current DATA
   organization, owner membership and Work Item tables are empty;
   an unauthenticated sender must not populate tenant rows.
3. Register the transport secret only in approved LOCAL secret storage
   and the approved receiving backend's secret boundary, separately and
   with exact resource confirmation. Never send the key to ChatGPT,
   GitHub, n8n workflow JSON, browser JS or public Vercel variables.
4. Deploy a locally installed read-only collector/egress agent that
   sends only signed aggregates to the Avuhz ingest boundary over TLS.
   Remain outbound-only; port 5678 stays loopback.
5. Expose a separate server-side, authenticated tenant-/owner-scoped
   read view to the private SekInfra Command Center. Show freshness and
   source, and downgrade the UI to stale/unavailable if no receipt
   is verified. No workflow activation is implied.
6. Test negative replay, tamper, delivery retry, network loss, outage,
   provider limits and independent AUTH/DATA project isolation.

**Verification:** `PYTHONPATH=src:. python3 -m unittest -v
tests.worker.test_local_n8n_telemetry_envelope
tests.worker.test_local_n8n_activity_snapshot`.

**Next action:** review and merge this source-only PR. Then approve
the exact shared Avuhz DEVELOPMENT read/ingest plan as one resource
at a time, before configuring a transport key or starting a sender.
