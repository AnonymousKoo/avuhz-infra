# Avuhz Infrastructure Authority LOCAL v1 Completion

Specification revision: **2026-10-19**. Inspected source: cached `origin/main` at **`55ff37f2c70c31e9988340dacdb7577e43bbb5a9` (`55ff37f`)**.

The previous **2026-10-17** checklist described source at **`99130ed4c57eccd839076c46a82405eacc6b666a` (`99130ed`)**. Its 14 items are summarized below as historical shared-domain capability evidence. Their statuses and acceptance scope must not be projected onto the inspected ref or retroactively certified against this new release target.

This is a repository-local specification, not a provider inventory or execution authorization. **Current provider state is unverified.** Recorded observations in `docs/current-build-state.md`, `docs/development-first-client-readiness-20261013.md` and `contracts/plans/v1/` retain their exact observation time, resource, source commit and evidence class. Neither source ref proves current installation, activation, credentials, health or tenant ownership. No provider read, network call or live mutation is required or authorized by this specification.

## Release boundary and status

Avuhz LOCAL v1 certifies a **client-neutral infrastructure authority and governance control plane**, following `ARCHITECTURE.md`:

`AUTHENTICATE + SCOPE -> approved desired state + trusted observation -> policy -> bounded human authorization -> restricted execution -> independent verification -> audit`

A clean checkout must demonstrate that loop for one fictional tenant/resource change using deterministic local fake adapters, with durable local evidence and the denial/failure cases below. Trusted identity, resource ownership and exact approval are mandatory; business onboarding, OIA assessment, intake, n8n, communications and billing journeys are not release prerequisites. OIA owns diagnostics/methodology, Sekinfra owns the client-facing experience, and reusable systems own domain logic. They consume Avuhz authority without granting it. Terraform/Ansible/Helm artifacts or runners may participate only inside an authorized boundary; installing or invoking those tools is not required for LOCAL v1.

**Infrastructure LOCAL v1: NOT CERTIFIED. DEVELOPMENT: NOT_READY. Production: NOT_READY.** These are release-readiness conclusions, not claims that all recorded provider foundations failed. No existing test name, prior acceptance result, matching digest, historical approval or documentation revision certifies the new loop. A future pass certifies only the exact reviewed source and fictional local behavior; it grants no DEVELOPMENT, staging, production or client authority.

The original provider-neutral migration defines 16 authoritative `avuhz_*` tables. `supabase/migrations/20261014034000_create_shared_work_items.sql` defines an additional authoritative shared Work Item source candidate; DEVELOPMENT artifacts separately describe tenant organizations, owner memberships, acquisition intake and counters. Git presence does not prove provider application. Preserve the shared Executor/UoW path, least privilege, tenant RLS, and runtime/migration separation. Any future authoritative Supabase table requires correctly scoped RLS and negative tenant tests before completion; local fakes cannot waive that requirement.

DEVELOPMENT AUTH is `pwlhruwutoitnieactol`; DATA is `gnuqaefotwgkwurjpyik`. They are distinct responsibilities and neither is a LOCAL v1 fixture. Existing Phase 5 contracts, client-system deployment authorizations, bounded provider plans, consumed/expired/stopped approvals and historical evidence remain unaffected. This specification neither reinterprets their scope nor revives their authority.

## Required clean-checkout certification

All rows are normative acceptance requirements, **not recorded passes**. The implementation must supply one documented offline entrypoint at an exact reviewed ref. It must fail certification if a required assertion is skipped, its fixture is unavailable, or evidence cannot be persisted. Use only fictional principals, tenants, resource identifiers and artifacts; no provider credential resolution, provider SDK transport, hosted service, live infrastructure or customer data is allowed. A preconfigured fictional tenant/resource registry is sufficient; real enrollment and the OIA journey are unnecessary.

| Gate | Required demonstration and pass condition |
|---|---|
| 1. Authenticate and scope | Submit a fictional resource change request through the shared governed boundary. Derive principal, tenant, resource ownership, environment, namespace and operation capability from a trusted local identity/ownership adapter, independently of request fields. Deny unauthenticated/forged identities, revoked membership, missing capability, caller-supplied authority and wrong tenant/resource/environment with zero executor dispatch. |
| 2. Desired state and observation | Bind the exact immutable approved desired-state digest/version and resource set to approval provenance. Obtain a separately attested simulated pre-state observation from a trusted local observer. Verify observer identity, tenant/resource/environment, collection time, freshness and state digest. The requester/executor cannot mint accepted observation provenance. A fake adapter may simulate the resource; a caller's fabricated provenance claim must still be denied. |
| 3. Deterministic policy | Evaluate a versioned policy over trusted scope, approved desired state and attested observation; identical inputs yield the same allow/deny decision and safe reason codes. Demonstrate both outcomes. Deny missing/stale/future/unattested observations, fake provenance, conflicting evidence and scope/digest substitution. Record a desired-versus-observed mismatch explicitly: only an allowed, exactly approved transition may resolve it; mismatch alone never triggers dispatch. |
| 4. Exact human authorization | Verify a fictional human approver's trusted role and explicit bounded decision, separate from requester claims and executor output. Bind request, tenant, environment/namespace, exact resource/operation, desired and observation digests, policy version/decision, executor identity, validity window, one-attempt limit and recovery limits. Deny missing, forged, expired, revoked, consumed or mismatched approval. Approval of desired state or policy allow alone cannot authorize execution. |
| 5. Restricted fake execution | Revalidate the bound scope, policy, approval and fresh expected pre-state immediately before execution. Atomically claim the attempt/idempotency identity and perform **exactly one restricted fake executor dispatch** for the approved successful scenario. The adapter changes only the named fictional local resource. Prove zero dispatch on denial, no arbitrary command/target substitution, no broader credential/DDL authority and no live transport. n8n, if used, only orchestrates approved API work. |
| 6. Independent resulting-state verification | Re-observe the fake resource through a separately trusted observer/verifier, not the executor's return value or echoed desired input. Attest and compare actual resulting resource scope/state with approved postconditions. Demonstrate an executor reporting success with unchanged/wrong resulting state: verification must fail and the change must remain unverified. Only independent successful verification may mark the change verified. |
| 7. Durable sanitized audit | Persist authoritative change/attempt state and sanitized linked audit evidence across process restart. Retain opaque request/tenant/resource references, desired-state digest, pre/post observation attestations, policy version/decision, bounded approval identity/window, consumed attempt, outcome, verification and recovery references with safe codes. Prove tenant isolation, tamper/substitution rejection and failure preservation. Use a reviewed local persistence boundary; no raw payloads, credentials, unnecessary PII or secret-derived material. Audit/events/receipts do not grant authority. |
| 8. Idempotency and replay | Repeating the same request returns its recorded outcome without a second dispatch; conflicting reuse of its idempotency identity is denied. Duplicate/concurrent delivery and restart cannot consume approval twice. An expired or consumed approval cannot authorize a new attempt even if a historical successful result can be read. Demonstrate stale approval/input substitution and cross-tenant replay denial. |
| 9. Failure and recovery | Inject executor failure, partial/ambiguous effect, lost acknowledgment, verifier failure/unavailability and durable evidence-write failure. Preserve consumed-attempt and unsuccessful/unverified states; never convert uncertainty to success or blindly retry. Reconcile through independent observation before any further mutation. A recovery mutation needs exact recovery authority (already explicitly bounded or freshly approved), its own attempt and independent verification. Demonstrate safe bounded recovery and denial when recovery authority is absent/expired; retain the original failure. |
| 10. Reproducible release evidence | Run every required positive and negative case from a clean checkout with deterministic local fixtures and controlled clock. Record exact source ref, command, dependencies, assertions, skips and sanitized artifact references. Run focused checks and the full applicable repository baseline offline. A missing fixture, skipped required case, failed check or absent durable proof means NOT CERTIFIED. Documentation-only checks are not this certification. |

Within the simulated trust model, “independent” requires distinct authenticated roles and separate observation/verification paths: the request and executor must not control accepted attestation or verification results. These roles may run locally in a deterministic harness; they need not call a real provider. Constructor flags, well-shaped reference strings and copies of executor output are insufficient trust evidence. Approval and observation fixtures must explicitly test forgery/substitution and bounded expiry, not merely inject `True` and count a happy path.

The release must distinguish denied, authorized, attempted, failed/ambiguous and verified outcomes. Durable attempt reservation must precede dispatch; failure to reserve or persist required pre-execution evidence prevents dispatch. If evidence persistence fails after a possible effect, block further execution and retain/reconcile the attempt as unverified. Audit integrity and replay safety must survive restart, rather than depending only on an in-memory list.

## What inspected source proves and what remains open

The following identifies source behavior and existing test surfaces at `55ff37f`; it does not claim those tests were executed for this specification or that the new acceptance requirements pass.

| Existing source/test surface | Narrow evidence and remaining gap |
|---|---|
| `src/avuhz_runtime/infrastructure_state_review.py`; `tests/architecture/test_infrastructure_state_review_v1.py` | Pure shape/supplied-scope validation, claimed timestamp checks and digest comparison. Missing/stale/future claims produce `BLOCKED`; fresh digest equality/difference produces `MATCHED`/`MISMATCHED`. Provenance/fingerprint syntax is checked, authenticity is not. The module does not authenticate, discover, attest, authorize, execute, remediate, persist audit or verify deployments. It accepts targets labeled DEVELOPMENT; an explicit LOCAL/TEST composition remains to be designed, without implying live DEVELOPMENT scope. |
| `src/avuhz_runtime/guards.py`; `tests/runtime/test_guard_pipeline.py`; `tests/runtime/test_trusted_human_authority.py` | Existing trusted-context and human-authority guard foundations. These do not supply the new fictional infrastructure resource-ownership registry or attest its inputs. |
| `src/avuhz_runtime/runtime.py`; `src/avuhz_runtime/postgres.py`; `tests/runtime/test_executor_repository_usage.py` | Governed command/UoW and tenant-scoped persistence foundations to reuse. The infrastructure request/attempt/observation/audit composition and restart-safe single-dispatch proof remain open. No parallel authority database/path should be introduced. |
| `tests/runtime/test_phase5d_deployment_authorization_runtime.py`; `tests/runtime/test_phase5d_deployment_execution_runtime.py`; `tests/runtime/test_phase5d_deployment_verification_runtime.py`; `docs/phase5d-deployment-execution-verification-architecture.md` | Separately bounded Phase 5D records and transitions provide reusable conventions, not discovered resources or independent attestation. Preserve their existing contracts; do not reinterpret client deployment authority as platform authority. Exact infrastructure approval, fake execution, independent resulting-state verification and recovery still need composed proof. |
| `docs/infrastructure-authority-v1-state-review-source.md`; `docs/infrastructure-authority-v1-render-observation-candidate.md` | Historical source design and separately gated DEVELOPMENT observation proposals. They are not executed provider evidence or mandatory provider prerequisites for this local release. |
| `src/avuhz_worker/shared_communications_local.py`; `src/avuhz_worker/shared_usage_billing_local.py`; `tests/worker/test_shared_communications_local.py`; `tests/worker/test_shared_usage_billing_local.py` | Present source-only protocols and deterministic in-memory fakes, not absent capabilities. Receipts/usage are non-authoritative; sink protocols cannot attest their caller or committed event origin. No external send, invoice, money movement or live Stripe integration. Outside infrastructure LOCAL v1's critical path. |
| `tests/integration/test_avuhz_local_v1_unified_acceptance.py` | Existing shared-domain acceptance covers onboarding and acquisition/Work Item/event/receipt/fake composition. Its PostgreSQL cases require explicit fixtures/opt-in; ordinary discovery may skip them. Its historical name is not infrastructure certification, and no run is retroactively credited to Gates 1–10. |

No complete certification entrypoint for Gates 1–10 is established by these sources. The critical gaps are trusted resource/observation provenance, immutable approval/input binding, deterministic policy composition, restricted fake dispatch, independent post-state verification, durable attempt/audit integrity and failure/recovery proof as one infrastructure journey. Component tests remain useful within their actual scope.

## Historical 14-item shared-domain capability record

This summary preserves the former tracker IDs, `99130ed` statuses and relevant pointers. “SOURCE-VERIFIED” below is the old checklist's source-evidence label, **not a new test result or current certification**. Former dependencies and journey criteria belong to that historical domain release model, not the infrastructure gates above. The original full checklist, which describes the `99130ed` source snapshot, remains in Git at `55ff37f2c70c31e9988340dacdb7577e43bbb5a9:AVUHZ_V1_COMPLETION.md`; the checklist file itself was not present at `99130ed`.

| Former item / lane | Historical scope and status at `99130ed` | Evidence pointers and treatment at `55ff37f` |
|---|---|---|
| 1 / Security | Authority separation, least privilege, RLS — SOURCE-VERIFIED | `SECURITY.md`; `supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql`; `supabase/migrations/20261014034000_create_shared_work_items.sql`. These principles remain mandatory; a domain table checklist does not certify the infrastructure loop. |
| 2 / Business | Client-neutral tenant/organization/owner onboarding — PARTIAL | `src/avuhz_service/development_owner_authentication.py`; `development_business_owner_directory.py`, `development_tenant_registration.py`, `development_company_activation.py` in the same directory; `tests/service/test_development_tenant_registration.py`; `tests/service/test_development_company_activation.py`. Later local composition exists in `src/avuhz_service/shared_client_onboarding_local_proof.py` and `tests/service/test_shared_client_onboarding_local_proof.py`. No live owner/enrollment is inferred. Business onboarding is outside the infrastructure gate; trusted fictional scope is still mandatory. |
| 3 / Security | Server-derived identity/membership/command authority — SOURCE-VERIFIED | `src/avuhz_runtime/guards.py`; `src/avuhz_service/development_owner_mfa_freshness.py`; `src/avuhz_service/shared_acquisition_commit_admission.py`; `tests/service/test_shared_acquisition_commit_admission.py`. Reuse applicable denials without treating acquisition admission as resource-change authority. |
| 4 / Infrastructure | Command/query runtime and single transaction boundary — SOURCE-VERIFIED | `src/avuhz_service/application.py`; `src/avuhz_runtime/runtime.py`; `src/avuhz_runtime/postgres.py`; `tests/service/test_service.py`; `tests/runtime/test_executor_repository_usage.py`. Shared foundation, not a completed infrastructure journey. |
| 5 / Business | OIA to client-neutral lifecycle — PARTIAL | `docs/oia/universal-oia-methodology.md`; `docs/oia/assessment-planning-architecture.md`; `docs/phase5b-oia-architecture.md`; `contracts/schemas/v1/`; `tests/runtime/test_phase5_end_to_end_freeze.py`. **The OIA-specific discovery/findings/handoff journey is not an infrastructure LOCAL v1 gate.** Methodology and Phase 5 contracts remain preserved; no OIA runtime access or client state is inferred. |
| 6 / Infrastructure | DEVELOPMENT source/provider evidence separation — PARTIAL | `docs/current-build-state.md`; `docs/development-first-client-readiness-20261013.md`. Keep exact recorded resource/ref/time; no extrapolation to either snapshot or current provider state. |
| 7 / Automation | Transactional outbox/safe worker — SOURCE-VERIFIED | `src/avuhz_worker/outbox.py`; `src/avuhz_runtime/outbox_delivery.py`; `contracts/schemas/v1/orchestration/outbox-delivery.schema.json`; `tests/worker/test_outbox_worker.py`; `tests/integration/test_postgres_outbox_worker_persistence.py`. Non-authoritative delivery remains distinct from execution approval and audit authority. |
| 8 / Automation | Shared LOCAL/TEST n8n boundary — PARTIAL | `contracts/templates/n8n/avuhz-shared-event-receiver-durable-inactive-v2.json`; `src/avuhz_worker/n8n_event_sink.py`; `src/avuhz_worker/local_n8n_receipt_http.py`; `src/avuhz_worker/local_unattended_n8n_dispatch.py`; `tests/integration/test_local_unattended_n8n_dispatch_postgres.py`; `tests/worker/test_shared_n8n_durable_receiver_source_v2.py`. Shared orchestration evidence, outside the infrastructure release critical path; no activation or direct authoritative writes. |
| 9 / Automation | Shared communications adapter/fake — NOT STARTED | That old absence status is historical. Current source/test paths are listed above; the local fake now exists, with no live delivery authority. |
| 10 / Business | Shared usage metering/billing fake — NOT STARTED | That old absence status is historical. Current source/test paths are listed above; the local usage/billing fake now exists, with no authoritative charges or live billing. |
| 11 / Business | Shared acquisition-to-Work-Item intake — PARTIAL | `src/avuhz_service/shared_acquisition_work_handoff.py`; `src/avuhz_service/shared_work_intake_postgres_candidate.py`; `supabase/migrations/20261014031000_enable_shared_work_intake_lifecycle_events.sql`; `tests/integration/test_shared_acquisition_work_handoff_postgres.py`; later `tests/integration/test_shared_governed_work_local_proof.py`. Domain capability evidence; System #001 private workflow, scheduling, deployment and acceptance remain separately owned. |
| 12 / Automation | Unified onboarding/intake/n8n/communications/usage local journey — PARTIAL | `tests/integration/test_acquisition_http_to_n8n_synthetic_journey.py`; `tests/integration/test_shared_work_intake_postgres_candidate.py`; later `tests/integration/test_avuhz_local_v1_unified_acceptance.py`. Preserved shared-domain journey; replaced as the release criterion by Gates 1–10, not renamed or retroactively certified. |
| 13 / Infrastructure | Staging/production operational controls — BLOCKED | `SECURITY.md`; `tests/architecture/test_platform_production_readiness.py`. Separate environment registries, secrets, observability, network controls, restore/rollback, SLO/capacity and artifact provenance remain required for promotion, outside local certification. |
| 14 / Business | Production launch authorization/certification — BLOCKED | `SECURITY.md`; `docs/roadmap.md`. Exact production resource authorization plus deployment/recovery/support/incident evidence remain separate; no local pass authorizes launch. |

## Next three actions

1. **Specify the shared infrastructure trust and state contracts locally.** Define a fictional resource ownership registry, authenticated principal/approver roles, approved desired-state binding, independently attested simulated observations, deterministic policy and durable change/attempt/audit records. Map reuse to existing guards, Executor/UoW and Phase 5D conventions without changing historical contracts or claiming existing attestation. Resolve the comparison module's DEVELOPMENT-only input constraint explicitly. This is the next implementation boundary; this documentation revision authorizes no code changes.
2. **Implement one bounded fake resource-change composition under separate repository authority.** Connect policy, exact one-attempt human approval, restricted fake executor and independent observer/verifier. Add durable idempotency, restart safety and bounded recovery. Prove zero dispatch for denied/mismatched authority, fake provenance, stale inputs and cross-tenant requests before expanding any adapters. No live Terraform/Ansible/Helm or provider operation is needed.
3. **Build and run the clean-checkout offline certification entrypoint.** Exercise every gate, including partial failure, lost acknowledgment, failed verification, audit-write failure and recovery denial. Record exact source-bound results and independently review them; only then consider infrastructure LOCAL v1 certification. Keep DEVELOPMENT and production NOT_READY pending their own fresh authority and evidence.

Four-lane responsibility is explicit: **Security** owns trust/tenant/approval denials; **Infrastructure** owns resource/change state and independent verification; **Automation** owns bounded dispatch, replay and recovery; **Business** owns the client-neutral release scope and consumer priorities. This prioritizes infrastructure certification over additional domain integration work. A supervised consented OIA/discovery meeting can still advance the Business lane independently; it grants no hosted intake, OIA table access, automatic invoice/payment or Avuhz tenant. Private client evidence stays outside Git and fixtures.

## Evidence and promotion rules

- Re-read the exact source ref and validate cited paths before changing a status. Record commands, pass/fail/skip results and narrow evidence; do not replace missing proof with a percentage or inferred completion.
- Preserve historical contracts, source tests and failed/stopped/superseded authority evidence. Existing acceptance tests retain their original meaning even when named “LOCAL V1.” No prior run is a pass of newly defined gates.
- Stop on credential exposure, RLS/ACL widening, AUTH/DATA confusion, unnecessary PII, elevated authority or direct n8n/vertical writes to authoritative state. Never weaken a check to achieve certification.
- Keep current DEVELOPMENT first-client gaps separate: independent owner proof, pending/active enrollment, distinct acquisition AUTH workload, private DATA credential, hosted ingress/receipt and synthetic proof remain gated. The October 13 G4 rate-counter migration is already recorded as applied; do not rerun it. Recorded OIA tables have FORCE RLS with no application runtime policies; preserve fail-closed access.
- Local source evidence cannot establish live health, resource discovery, owner verification, hosted observation provenance, deployment verification or credentials. Provider reads/mutations, secret operations, deployments and every production resource require fresh exact authority, preflight and independent postcondition evidence.
- Domain onboarding/OIA/System #001, hosted acquisition/n8n, live communications/Stripe, money movement, frontend/Edge Function work, staging/production operations and Phase 6 remain separate work. Removing their journeys from this release gate does not remove their security controls, shared ownership or future acceptance obligations.

**Explicit next action:** prepare the repository-local infrastructure trust/state contract design in Action 1 for independent review. Do not start a provider observation or treat this specification as certification or execution approval.

## R1 offline release evidence integration (2026-10-20)

Status remains **NOT CERTIFIED**. This section supersedes the earlier runner's
unconditional `RECOVERY_MUTATION_GATE_UNMET` interpretation; the literal Gates
7–10 above are unchanged. Historical source-gap tables above retain their
`55ff37f` scope. This integration starts at exact cached PR769 merge
`a6104c48511465c583f7f2de2fc7e38d9fa0991a`; it changes tooling/tests/docs only.

PR769 adds an R2 source-only fictional recovery action and fencing protocol,
separate from non-executing HOLD / REVIEW_REQUIRED / NO_RETRY_AUTHORIZED
reconciliation. The component's reported 336 tests and owner-reported Main PR
Gate `39427818355` PASS are historical component/CI evidence, not an independent
LOCAL release certificate. No GitHub result was fetched or authenticated here.
The action remains LOCAL/TEST SQLite with all writers running the reviewed
protocol; it does not make ambiguous effects recoverable or authorize legacy,
mixed-version, provider, DEVELOPMENT, staging or production execution. Its
limitations remain in `contracts/proposals/v1/local-infrastructure-recovery-action.md`.

The runner explicitly loads ten canonical modules: the seven authority, trust,
policy, execution, verification, audit and recovery suites, recovery-safety,
recovery-action and fencing. It does not discover filenames or execute its own
release contract suite recursively. Every module must run nonzero tests with
zero failures, errors and skips. Successful Gate 9 assertion IDs must include
fresh separate recovery authority, its one attempt and actual-state verification,
missing/forged/expired authority denials, wrong actual poststate, and the new
process fencing/replay test. Reports bind to the current exact source SHA;
missing/stale/unverified assertions deny. Tests use controlled fictional clocks.

The new subprocess test pauses an actual original executor after reservation,
using pipes rather than sockets, semaphores or sleeps. Recovery executes in the
parent; a fresh optimized Python process reconstructs deterministic trusted
fixture inputs, denies replay against the original database and independently
verifies actual state before any verifier result exists. The original then
resumes and must return UNCERTAIN without dispatch. A separate read-only physical
connection confirms the recovery desired state, one recovery reservation and
ATTEMPTED event, the original fence, zero original dispatch receipts and persisted
VERIFIED evidence after all children exit. Child start/timeout/failure is a test
error or failure, never a skip or an inferred pass. This is a simulated trust
boundary, not real identity or process isolation from a privileged database owner.

From a clean checkout of the exact independently reviewed commit, select a new
literal file directly under `/tmp` and use an uncredentialed local environment:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/certify-local-infrastructure-v1.py \
  --check <exact-40-character-HEAD-SHA> --output /tmp/selected-local-v1-evidence.json
```

The runner checks exact HEAD, repository identity and clean tracked/untracked
state before and after suites. It rejects provider/service configuration and Git
identity override variables, and denies sockets in the in-process suites.
Children execute only reviewed local fixture code; this is not an OS network
sandbox. It records positive assertion IDs and counts without dumping failures
or input payloads. Output paths must be literal direct `/tmp` children, outside
the checkout, without symlinks or traversal; no append or overwrite is permitted.
Evidence uses O_EXCL/O_NOFOLLOW, mode 0600, file and directory fsync, readback and
SHA256 of the exact persisted bytes. Persistence failure returns nonzero with no
successful digest. An incomplete file after a failure must never be treated as
accepted evidence, and cannot be overwritten by another run.

Optional **candidate** release input uses `--release-input
/tmp/selected-release-input.json --release-input-sha256 <actual-manifest-sha256>`.
This is a bounded schema enforced by the runner, not an attestation protocol:

- Exact top-level keys: `schema` = `avuhz-local-release-input-v1`, `source_sha`,
  `reviewed_sha`, and `records`. Both commits must equal `--check`.
- `records` has exactly `baseline`, `dependency`, `artifact`, `review`, and `ci`.
  Each record has exactly `source_sha`, `path`, `sha256`, and `result` = `PASS`.
  Every commit must match; every path is a literal existing regular direct
  `/tmp` child. Digest syntax is 64 lowercase hex characters.
- The runner hashes actual file bytes (including the purported built wheel),
  compares each supplied digest and the manifest digest, then repeats validation
  after suites. It never substitutes a claimed artifact digest for file bytes.
  Only digests and bounded classifications enter output, never payloads or paths.
- A complete manifest also checks that the baseline script is byte-identical to
  PR769 and records actual hashes of `requirements.txt`, `package-lock.json`,
  `pyproject.toml` and `.github/workflows/main-pr-gate.yml`. These are dependency
  evidence sources, **not a claim of a fully hash-locked Python dependency graph**.

Missing inputs are recorded as MISSING; malformed, mismatched or tampered inputs
are denied. Even well-formed matching files are only
`CANDIDATE_UNAUTHENTICATED`: anyone could fabricate a review/CI report or label
arbitrary bytes as a wheel. No offline trusted signing identity or attestation
verification policy exists in this integration. It cannot authenticate reviewer
independence, CI results, baseline execution, artifact build provenance or a
complete dependency lock/SBOM. It deliberately has **no CERTIFIED transition**.
Green required suites yield nonzero `GATE10_INDEPENDENT_PROOF_UNVERIFIED`, a
sanitized `EVIDENCE_CANDIDATE` file and its strong digest. Failed suites yield a
durable failed candidate where possible; preflight/input/persistence errors yield
only sanitized denial output. No success exit is possible from test green alone.

Run the unchanged baseline separately offline (inspect it before execution):

```sh
PYTHONDONTWRITEBYTECODE=1 SEMGREP_ENABLE_VERSION_CHECK=0 \
  SEMGREP_SEND_METRICS=off SEMGREP_SETTINGS_FILE=/tmp/selected-semgrep-settings.yml \
  SEMGREP_LOG_FILE=/tmp/selected-semgrep.log bash scripts/check-baseline.sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.architecture.test_local_infrastructure_release_v1
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover \
  -s tests/architecture -p 'test_*.py'
```

The Main PR Gate additionally installs dependencies, starts disposable PG17,
runs migration/integration gates and builds/checks a wheel. This invocation does
none of those operations: no installs, service sockets, database migrations or
provider access are authorized. Exact-commit authenticated CI/PG17 and built-wheel
provenance, independently reviewed unchanged baseline and dependency lock/SBOM,
and explicit human Gate 10 approval remain required. A prior commit's CI PASS or
this source review cannot satisfy those requirements for a new commit. Under an
appropriate separate approval, the wheel build command in the canonical CI is
`python3 -m pip wheel . --no-deps --no-build-isolation --disable-pip-version-check
-w <fresh-artifact-directory>`; this document does not authorize installs/builds
or service starts in the present invocation.

Security progress is stricter evidence denial; Infrastructure progress is bounded
Gate 9 test integration and candidate persistence. Automation has no new dispatch
path. Business delivery and customer readiness remain unchanged. No new executor
privilege, policy or runtime behavior is introduced, and no R2 component is
reclassified as production ready.

**Explicit next action:** independently review the exact committed candidate and
its locally generated evidence, then obtain authenticated same-commit baseline,
dependency/artifact and applicable CI/PG17 proof plus explicit human Gate 10
approval. Until that separate boundary is satisfied, LOCAL v1 remains NOT CERTIFIED.

## Gate 10 supply-chain R0 candidate (2026-10-20)

The repository-local four-file candidate based on exact source
`d508c96ce0025d16a8c59e50bace33b2ebda1bb6` adds an offline Python 3.12
inventory generator and denial tests. See
[`docs/local-v1-supply-chain-evidence.md`](docs/local-v1-supply-chain-evidence.md)
for its clean exact-commit invocation and limitations. This is unsigned
inventory/SBOM CANDIDATE evidence, always **NOT CERTIFIED**, with observed source
and schema SHA256 values, matching declared direct Python pins, separate npm
metadata and an optional internally checked wheel digest. An omitted wheel is
explicitly MISSING. No dependency or runtime changes are included.

Still unmet: complete Python hash-locked transitive/build dependency graph with
verified distribution archive hashes, approved SBOM, authenticated exact-merge
CI/PG17 results, signed provenance, immutable retention proof and explicit human
Gate10 approval. Structural wheel checks cannot authenticate origin or prove a
build corresponds to source. No candidate, green local suite or historical CI
result certifies the exact future merge. LOCAL v1 remains **NOT CERTIFIED**;
DEVELOPMENT and production remain **NOT_READY**.

Next action: independent review of the exact committed candidate, then separately
approved release-evidence work. Future main-push CI/PG17 and retention changes
require separate approval; this candidate grants no push, PR, merge or provider
authority.

The LOCAL corrective candidate verifies every tracked regular file and executable
mode against raw native Git blob hashes without status or worktree filters.
Wheel inspection bounds compressed input, member count and declared/consumed
uncompressed bytes before parsing and while streaming. These denial checks
close source-substitution and unbounded-archive inspection gaps; they do not
supply any missing release proof. Status remains **NOT CERTIFIED**.

## Gate10 Stage 1 Python wheel-lock candidate (2026-10-20)

The bounded LOCAL/TEST candidate based on cached main
`92bd1ab9f6395a7939c6f8c2191d0ee3d6a729e7` adds separate runtime,
build/bootstrap and verifier archive-hash locks, offline graph/archive denial
tests and deterministic unsigned candidate CycloneDX generation. See
[Python lock scope and reproduction](docs/local-v1-python-lock.md).
The exact target is CPython 3.12.3 Linux x86_64 glibc 2.39; this does not claim
glibc 2.17 compatibility or a reproducible full CI tool environment.

Actual install/build/smoke results belong to the private source-bound dossier,
not a certification assertion in this specification. No runtime or workflow
change, push, PR, merge, service or provider action is included. Security gains
archive/closure denial checks; Infrastructure gains isolated wheel evidence;
Automation dispatch and Business/customer readiness are unchanged.

Independent human lock/SBOM review, authenticated exact-merge CI/PG17, trusted
signed provenance, immutable retention and explicit human Gate10 approval remain
unmet. LOCAL v1 remains **NOT CERTIFIED**; DEVELOPMENT and production remain
**NOT_READY**. Next action: review the exact committed candidate and private
archive-bound evidence before authorizing the separate release-proof boundary.
