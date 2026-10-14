# Local DEVELOPMENT n8n receipt service — source-only launch gate

**Source scope:** Avuhz shared automation, LOCAL/TEST repository source only.
No service started, n8n credential created, workflow imported, or production
resource changed by this source change.

## Reuse the existing core

- Reuses LocalN8nReceiptStore (private LOCAL/TEST SQLite, trusted tenant,
  event allowlist, atomic duplicate/conflict receipts) and
  LocalN8nReceiptHTTPServer (private gateway and exact source-IP pinning,
  independently injected token, bounded request, protected error responses).
- New src/avuhz_worker/local_n8n_receipt_dev_runner.py is a **fail-closed
  operator entry point**, not a daemon or new tenant/billing/auth stack.
- Accepts only exact target LOCAL_DEVELOPMENT_N8N_5678 and confirms the
  local container /n8n is running on localhost port 5678, Docker's
  private default bridge, trusted n8n source address and private gateway.
  Reads selected Docker identity/network metadata only; no container
  environment, keys, user credentials or workflow content is read.
  Any network/identity drift denies startup.
- Requires a preexisting owner-controlled private receipt directory (0700),
  an absolute non-symlink database path, and a canonical trusted tenant UUID.
  The source does **not** verify that a supplied tenant belongs to an
  authorized real business; this must be proven separately before serving.
- Running without --serve is **preflight only**: no secret read, listener
  binding, database creation or credential provisioning.
- Running with --serve additionally requires --token-fd >= 3 containing
  32–512 printable ASCII bytes supplied by an approved secret boundary.
  No default token is generated and the secret is never passed in arguments,
  written to Git, read from environment, or logged. An n8n encrypted Header
  Auth credential needs separate approval and must use the matching token.
- The existing server binds to the verified private Docker gateway on an
  **ephemeral port** and prints its private address without a secret.
  A restart requires reconciliation of the address. The existing n8n
  receipt child intentionally points at unreachable 127.0.0.1:1 and
  has no credential; this launcher does **not** edit the child.
- Receipt acknowledgment of 202 means an authorized durable LOCAL/TEST
  dedup record exists. It is NOT proof of downstream owner assignment,
  notification delivery, customer onboarding, or billing.

## Environment and release gate

The owner must separately authorize **one resource change at a time**:
the exact local service runtime, the local n8n encrypted credential, then
any inactive child import/configuration and shared receiver wiring.
Before a run, confirm the trusted tenant in Avuhz's authority system,
verify private Docker source IP and gateway, approve secret provenance
and persistence, and run synthetic rejection/replay/recovery cases.

The existing synthetic test suite includes real private Docker-container
reachability to the temporary receipt server, durable receipt/replay,
lost ACK, denied source/tenant and malformed payload, conflicts and
storage failure. The launcher test suite separately tests preflight-only
defaults, drifted/public Docker boundaries, strict storage permissions,
FD-only secrets and no implicit service launch.

**LOCAL DEVELOPMENT** is n8n on 127.0.0.1:5678; hosted
n8n.sekinfra.com is **PRODUCTION**, excluded entirely. DEVELOPMENT
AUTH pwlhruwutoitnieactol and DATA gnuqaefotwgkwurjpyik are
different Supabase projects; neither is read or mutated here.
Cal.com webhook and Sekinfra production rollout remain on hold.

**Known gaps:** no authenticated live receiver, reachable n8n bridge
child, bound n8n encrypted credential, persistent receipt-service
process, verified real tenant binding or durable downstream business
effect. Never rely on a receipt alone to prevent missed client follow-up.

**Next action:** finish synthetic preflight and full source gates, submit
one source-only PR, then request separate exact authorization to start
one restricted DEVELOPMENT local receipt-service process once its
tenant and credential boundaries are confirmed.
