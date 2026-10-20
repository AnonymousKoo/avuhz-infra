# LOCAL/TEST reconciliation-only recovery v1

Status: source-only R2 simulation candidate. Only the recovery module, recovery
tests and this proposal change. No provider, network, deployment, hosted runtime,
scheduler, communications, billing or business-domain authority is introduced.

`LocalTestInfrastructureRecovery` records one immutable terminal disposition for
an existing consumed fictional attempt. It cannot execute, compensate, retry,
issue execution tokens, reset consumption, clear revocation or change physical
state. All results have `retry_authorized=False` and `authority_effect=NONE`.

Historical validation and current recovery authority are separate:

- Original policy, approval, manifest, observation, ownership, execution,
  verification and audit sources must be independently provisioned by the trusted
  harness. Missing evidence or noncanonical schemas fail closed. Complete source
  inputs are digest-bound, including source clocks, grants and all bindings.
- Original observation and approval times are checked against original windows;
  verification and audit are checked at their persisted historical timestamps.
  The existing audit validator receives the persisted audit time, never the
  recovery time. An expired original approval can remain a historical fact. Its
  window is never extended, its status never changed, and it grants no recovery
  permission. Revoked supplied grants and durable execution revocation still deny.
- A separate current trusted clock, independent recovery observer grant, human
  grant and exact human consent must all be active and fresh. Reconciliation
  rechecks the durable consumed/nonrevoked execution reservation under its lock.

The trusted harness calls `open_recovery_case` to persist a `RecoveryCase`, with
immutable `opened_at`, unique case/challenge, exact original scope/execution,
audit digest and complete original-source digest. This occurs strictly after the
original audit, before evidence collection. Full scope pins principal, tenant,
LOCAL/TEST environment, fictional namespace, resource class, resource ID and
owner; policy, approval, versions and evidence sources are also pinned.

A separately invoked `collect_recovery_observation` runs as the independent
observer, in its own FULL synchronous transaction. It reads the actual simulated
state and persists a separate immutable `local_recovery_observations` row, with
actual state digest/version, observation timestamp, case/challenge, case digest,
observer grant digest and evidence digest. It accepts no caller-supplied state.
The observer differs from the original principal, source observer, human,
executor, verifier and auditor, and from the recovery human. Collection must
occur strictly after persisted case opening. One observation is allowed per case.

Only after that observation may the harness register `RecoveryConsent`. Its
domain-separated intent pins the exact persisted observation digest, observation,
case/challenge, original audit digest, observer grant, human grant and computed
terminal disposition. Consent must be strictly later than observation. Evidence
must be at most 60 seconds old at reconciliation; current grants must cover both
observation and reconciliation. Changed human pins, invented or pre-case evidence,
source tamper, cross-tenant inputs and revoked reviewers deny.

Reconciliation accepts only instance-local opaque handles. Its SQLite authorizer
allows INSERT only into `local_recovery_decisions` and reads only the bounded
source/evidence tables. It denies physical-state reads, observer/case writes,
predecessor mutations, DDL and attachment. The observer writer separately permits
physical-state reads and INSERT only into observation storage; it cannot write a
recovery decision or physical state. Trusted harness provisioning alone creates
schemas and case rows. These Python APIs and constructor inputs must never be
exposed as requester enrollment or hosted endpoints.

| Consumed attempt / separately observed state | Terminal decision |
| --- | --- |
| UNCERTAIN, including a matching state | REVIEW_REQUIRED |
| ATTEMPTED and desired digest/version | NO_RETRY_AUTHORIZED |
| ATTEMPTED and expected prestate digest/version | HOLD |
| ATTEMPTED and any other state | REVIEW_REQUIRED |

These dispositions do not establish causality, completion, ongoing state or
provider recovery. **A delayed original effect remains possible after observation
and after a terminal record**, including HOLD. Reconciliation deliberately does
not resample physical state. None of these decisions authorizes a retry.

All three recovery tables have immutable update/delete/replacement defenses and
256-row bounds. Exact schema checks reject altered tables, views, indexes or
triggers. One serialized decision transaction revalidates the persisted sources,
case and observation, checks terminal history and inserts a hash-bound sanitized
record. Success returns only after commit. Storage/insert/commit failures return
CONFLICT without authority; a lost commit acknowledgment may leave a durable row
that an unchanged authorized replay can read. Concurrent calls produce at most
one record. Replays retain timestamps/digests and fail after freshness expires;
new consent or evidence cannot overwrite terminal history.

Trust limits: independent identities, clocks, source inputs and human consent are
registered by the trusted LOCAL/TEST harness. Python, SQLite, filesystem ownership
and harness separation remain trusted; hashes are consistency pins, not signed
attestation. Privileged writers capable of replacing all independent pins, Python
reflection/monkeypatching or replacing the database remain outside this model.
There is no real identity verification or provider observation. Disposable `/tmp/`
storage is a simulation, not a live ledger; no secrets, PII or provider payloads
belong in fixtures. Revocation inputs are trusted snapshots plus the locked
execution registry, not a live identity/revocation service.

Validation: run the seven authority, trust, policy, execution, verification, audit
and recovery LOCAL suites, then the unchanged offline `scripts/check-baseline.sh`.
Use `PYTHONDONTWRITEBYTECODE=1`, `SEMGREP_ENABLE_VERSION_CHECK=0`,
`SEMGREP_SEND_METRICS=off`, and `SEMGREP_SETTINGS_FILE` and `SEMGREP_LOG_FILE` under
`/tmp/`. Tests include expired original authority with fresh recovery, pre-case,
stale/missing/fabricated evidence, changed consent, revoked reviewers, cross-tenant
bindings, coherent source/observation rehash, denied physical reads, separate writer
permissions, terminal immutability, concurrency and failed/lost commit responses.

Security and Infrastructure progress is limited to this LOCAL/TEST reconciliation
boundary. Automation cannot dispatch recovery. Business first-client gates and
all DEVELOPMENT/STAGING/PRODUCTION readiness remain unchanged. Next action:
independent read-only security review of these three files before integration.
Any real recovery remains a separately authorized provider boundary.
