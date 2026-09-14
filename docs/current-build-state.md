# Current Build State

`CURRENT_PHASE`: Phase 5 remains frozen. Engineering/production-readiness milestone 9.5 is active.

`CURRENT_CANONICAL_STATE`: DEVELOPMENT AUTH v16 is complete and verified. DEVELOPMENT DATA v3 is complete and verified. DEVELOPMENT AUTH v17 and v18 remain immutable, unapproved, unexecuted, and unconsumed after their owner-approval timing windows became unusable. DEVELOPMENT AUTH v19 has an exact persisted owner approval but remains unexecuted and unconsumed; the owner-interactive dashboard path was stopped before mutation because Supabase's create-user form requires a password. AUTH v20 remains immutable `DRAFT_BLOCKED` and unexecutable. Authorization-plan v2 defines the narrowly scoped `SUPABASE_AUTH_ADMIN_EPHEMERAL` server-executor capability class and handling rules without exposing, hashing, persisting, or returning credential material. AUTH v21 now exists as a fresh forward-only `READY_FOR_APPROVAL` plan for exactly one passwordless synthetic DEVELOPMENT Auth identity; it has no approval, no provider execution, and no executor-capability preflight evidence yet. The hosted DEVELOPMENT Render service remains intentionally fail-closed for dependency readiness because real hosted identity and DATA adapters are not yet injected.

`PLATFORM_PRODUCTION_READINESS`: `NOT_READY`.

`READY_FOR_PHASE6`: `NO`.

## Completed foundation work

- Phase 5 execution/verification is frozen behind the provider-neutral governed runtime and contracts.
- DEVELOPMENT AUTH and DEVELOPMENT DATA are physically separated and must never be conflated:
  - AUTH: Supabase `pwlhruwutoitnieactol`
  - DATA: Supabase `gnuqaefotwgkwurjpyik`
- AUTH v15 successfully bootstrapped the restricted migration identity, applied the hardened custom access-token hook, and sealed the migration identity.
- AUTH v16 independently verified the sealed state: the hook owner/body/ACL match, the migration identity cannot be used through a SET path, and the hook remains disabled. AUTH v16 is `COMPLETED / CONSUMED / SUCCEEDED / PASS`.
- AUTH v17 defined exactly one synthetic-identity provider mutation but remained unapproved and unexecuted. Its immutable authorization window began before the owner instruction to approve arrived, and the authorization engine forbids backdating `approved_at`; v17 therefore remains historical `PENDING / NOT_STARTED / NOT_STARTED / unconsumed` evidence only.
- AUTH v18 preserved the exact same synthetic-identity scope but also remained unapproved and unexecuted because the owner authorization arrived 12 seconds after its immutable effective start. v18 therefore remains historical `PENDING / NOT_STARTED / NOT_STARTED / unconsumed` evidence only; backdating is prohibited.
- AUTH v19 preserved the exact synthetic-identity scope and received an exact owner approval with approval digest `sha256:3e31e523d03220c8301a76430dbd3d1c7a72538b711661b187ea063c3306e6d9`, approved at `2026-09-14T07:45:58Z`, effective at `2026-09-14T09:00:00Z`, and expiring at `2026-09-14T12:00:00Z`.
- The v19 provider preflight verified DEVELOPMENT AUTH project `pwlhruwutoitnieactol`, zero Auth users, zero Avuhz tenant-metadata rows, and unchanged hardened disabled-hook state. The owner-interactive dashboard create-user path was then stopped before mutation because its form requires a password; v19 progress therefore remains `PENDING / NOT_STARTED / NOT_STARTED / unconsumed`, with no success evidence and no synthetic user created.
- AUTH v20 records a forward-only correction toward the supported Supabase Admin `createUser` email-only confirmed route for `avuhz-development-synthetic@example.invalid`, while explicitly prohibiting password/password-hash creation, invitation, metadata, session/token issuance, credential persistence/exposure/logging, hook enablement, DATA, Render, staging, and production changes. v20 remains intentionally `DRAFT_BLOCKED`, has no authorization window, permits credential class `NONE`, and grants no provider authority. The introduction of authorization-plan v2 does not mutate or retroactively unblock v20.
- Authorization-plan v2 is backward-compatible with the historical plan surface and adds only `SUPABASE_AUTH_ADMIN_EPHEMERAL`. The class is valid only for `DEVELOPMENT` + `supabase` + `AUTH` + `PROVIDER_MUTATION` + `provider.auth-*`, must be the sole allowed class, and carries no secret value. Its handling contract requires approved environment-secret-boundary origin, server-executor-memory-only residency, class-label-only control-plane visibility, and prohibits material digest, persistence, logging, return, copying, export, creation, and rotation.
- Authorization of a step using that class requires a digest-only non-secret executor-capability attestation (`auth.admin-executor-capability.observed`). The digest represents the non-secret executor capability reference, never provider credential material. A concrete executor binding must still satisfy `SECURITY.md`; the class does not permit a shared service-role key or long-lived static credential shortcut.
- AUTH v21 is the fresh forward-only plan that uses the v2 class without editing v20. It binds DEVELOPMENT AUTH project `pwlhruwutoitnieactol`, the existing v16 disabled-hook evidence, the exact `provider.auth-identity.create-one` operation, the passwordless Supabase Admin `createUser` email-only confirmed path for `avuhz-development-synthetic@example.invalid`, and the exact no-password/no-metadata/no-invite/no-session/no-token/no-DATA/no-Render boundary. Its authorization window is `2026-09-14T14:00:00Z` through `2026-09-14T17:00:00Z`, but no v21 approval exists and no provider authority is granted merely because the plan is `READY_FOR_APPROVAL`.
- AUTH v21 requires two runtime preflights before execution authorization can succeed: the sanitized identity/provider-state preflight (`auth.synthetic-identity.create-preflight.observed`) and the digest-only non-secret executor-capability attestation (`auth.admin-executor-capability.observed`). Credential material is not a binding and must never appear in plan, approval, progress, evidence, request, log, or agent-visible surfaces.
- The canonical baseline certifies the credential model, the v21 plan package, and modern Supabase secret-key prefixes in addition to the existing credential-shaped-content and Semgrep gates.
- DATA v2 applied the canonical provider-neutral 16-table Avuhz baseline to DEVELOPMENT DATA.
- The DATA outbox function `search_path` warning was repaired through a separate bounded provider artifact and independently verified; Supabase Security Advisor returned zero findings afterward.
- DATA v3 sealed the migration identity and independently verified tenant isolation. DATA v3 is `COMPLETED`; both steps are `CONSUMED / SUCCEEDED / PASS`.
- Final DATA verification proved 16 Avuhz tables, RLS on all 16, one exact tenant policy per table, no direct Avuhz table authority for `PUBLIC`, `anon`, `authenticated`, or `service_role`, the canonical command-service ACL surface only, sealed migration-role membership, unchanged canonical migration history, and zero Security Advisor lints.
- The registered DEVELOPMENT Render service `avuhz-command-dev` exists at `https://avuhz-command-dev.onrender.com`; recorded bounded evidence includes `GET /health/live = 200` and intentional `GET /health/ready = 503`.
- Local DEVELOPMENT trusted-identity deterministic fake positive/negative identity tests are implemented and green.
- The disposable local PostgreSQL DEVELOPMENT DATA composition and UnitOfWork tests are green.
- The repository now has a root `ARCHITECTURE.md` that distinguishes implemented infrastructure from required future shared-core primitives.

## Current runtime truth

`src/avuhz_service/development.py` still instantiates `_UnavailableIdentityResolver` and `_UnavailableUnitOfWork`. The live hosted DEVELOPMENT composition still uses its unavailable real-provider resolver.

Therefore:

- startup/liveness can be healthy;
- `/health/ready` remains `503`;
- command/query requests fail closed at trusted identity resolution; and
- no hosted Supabase DATA connection is created by the current service composition.

This is intentional. AUTH/DATA provider-foundation completion and authorization-plan v2/v21 planning do not themselves authorize runtime credential creation, secret retrieval, hosted adapter wiring, or readiness promotion. The default Supabase `aud=authenticated` is rejected by Avuhz; the approved DEVELOPMENT command-service audience remains separate.

## Multi-tenant truth

The DEVELOPMENT DATA surface is deployed and verified:

- 16 Avuhz tables;
- RLS enabled on all 16;
- one `avuhz_command_service_tenant_isolation` policy per table;
- policy scoping through the transaction-local `avuhz.tenant_id` setting;
- zero direct Avuhz table grants to `PUBLIC`, `anon`, `authenticated`, or `service_role`;
- canonical command-service privileges only; and
- runtime authority separate from migration authority.

The hardened canonical-initial-migration lineage was certified at repository commit `5591dd6a99dd2d56dba6b682ab45198143d7539f`; at that historical certification point, clean disposable replay passes nine PostgreSQL tests. That lineage evidence remains historical proof even though the baseline has since been applied to DEVELOPMENT DATA and further sealed/verified through DATA v3.

## Preserved certification evidence

These facts are retained because they are part of the repository's production-readiness certification history. Historical snapshots are explicitly marked and do not override the current AUTH v16 / DATA v3 state.

### One-use DEVELOPMENT JWKS discovery

The bounded historical AUTH discovery used endpoint class `DEVELOPMENT_AUTH_JWKS` and observed HTTP `200`, key count `1`, supported metadata `ES256/EC/P-256`, private key material absent, and validation `PASS`. The discarded raw response was bound by SHA-256 `c13eec4a0c453116e035e0ff652a1e7395471422ec70f9aa1eb0c6391bfb73af`.

The discovery involved no credential, token, cookie, API key, DATA-provider access, redirect, retry, raw-response persistence, or remote mutation. The completed JWKS discovery grants no continuing AUTH/DATA access or provider authority.

### Local observability certification

Historical local-only observability evidence remains valid: Prometheus and node-exporter were locally certified, and the managed local Grafana path was separately validated. This is not hosted production telemetry, and no Grafana Cloud resource is claimed by that evidence.

### Superseded AUTH v9 snapshot

For certification lineage only, the older snapshot recorded: DEVELOPMENT AUTH v9 Step 1 is canonically `CONSUMED / SUCCEEDED / PASS`; Step 2 is canonically `AUTHORIZED / NOT_STARTED / unconsumed`; the owner approval/window that authorized v9 has expired. The same old snapshot said the hook `has not been remotely created or enabled`.

Those v9/hook statements are **historical and superseded**, not current instructions. AUTH v15 later created and hardened the hook and sealed its migration identity, and AUTH v16 verified the hook remains disabled. Agents must not revive v9 execution from this historical text.

## Production-readiness blockers still open

Production remains blocked by, at minimum:

- production outbox identity/provider sink;
- production AUTH/DATA registry;
- complete protected CI provenance/SBOM publication;
- hosted observability/alerting;
- backup/PITR RPO/RTO and restore proof;
- deployment/rollback rehearsal;
- environment-scoped secret boundaries and short-lived workload identities;
- capacity/SLO proof and production network enforcement.

These are blockers, not implied resources or authorizations.

## In progress

Engineering-readiness milestone 9.5 remains active. Provider foundations are complete through AUTH v16 and DATA v3. AUTH v17 and AUTH v18 remain immutable historical plan state only: each is `PENDING / NOT_STARTED / NOT_STARTED / unconsumed`, with no approval file and no provider execution.

AUTH v19 remains immutable with plan digest `sha256:4e6bb3a76b4d15b7993b2567c6743497b285bbecd03100f7ce73bbbc7a0cc72e`, initial progress digest `sha256:ef3d232916d7be0d4a65e94d0bbfaa635258c937ae58bfa038fd43a4bf185fa8`, and owner approval digest `sha256:3e31e523d03220c8301a76430dbd3d1c7a72538b711661b187ea063c3306e6d9`. Its provider mutation was not executed; its progress remains pending/unconsumed. The discovered dashboard password requirement means agents must not revive or reuse that owner-interactive execution route.

AUTH v20 remains immutable with plan digest `sha256:3870b6e83f4a7983e2a1fa668066790f4fd5ef77a70e4e801c081ae2459f509b` and initial progress digest `sha256:60c1818e6951a6493c08111a485ffdf3820b3ec9cc7c923b95a4ea5d3d79ec97`. It remains `DRAFT_BLOCKED`, not `READY_FOR_APPROVAL`; its authorization window is `UNRESOLVED_BLOCKER`, its credential policy permits only `NONE`, and its historical unresolved binding remains `binding.development.auth.v20.server-admin-credential-class`. There is no v20 approval, execution-progress file, provider-preflight evidence, or success evidence.

AUTH v21 is the current forward-only plan with plan digest `sha256:e7410c35e9de2e8c4e60d538e9f1e7fd79bc49e58f51788b2a1e5d931467ab0c` and initial progress digest `sha256:4fe494c84a052e5c5d6e6e6cb54eb4a5ffb7c6b24d71fb03ba1472e3518e5982`. It is `READY_FOR_APPROVAL`, targets only DEVELOPMENT AUTH `pwlhruwutoitnieactol`, and binds the exact window `2026-09-14T14:00:00Z` through `2026-09-14T17:00:00Z`. Its sole permitted credential class is `SUPABASE_AUTH_ADMIN_EPHEMERAL`, its progress remains `PENDING / NOT_STARTED / NOT_STARTED / unconsumed`, and there is no v21 approval, execution-progress file, provider-preflight evidence, success evidence, or synthetic identity.

## Next task

Create a separate exact owner approval for AUTH v21 while its immutable window remains usable. That approval must bind only plan id `e818f636-5470-4f39-a040-12f7e723b6c3`, plan version `21`, plan digest `sha256:e7410c35e9de2e8c4e60d538e9f1e7fd79bc49e58f51788b2a1e5d931467ab0c`, environment `DEVELOPMENT`, and the existing `2026-09-14T14:00:00Z` through `2026-09-14T17:00:00Z` window.

Approval persistence remains repository-only and must not retrieve or test any provider credential. Provider execution is a later separate boundary: immediately before any mutation, re-confirm canonical main, exact approval/window, DEVELOPMENT AUTH project `pwlhruwutoitnieactol`, the v16 disabled-hook prerequisite, the clean identity preflight, and the non-secret `auth.admin-executor-capability.observed` attestation. If the capability cannot be proven without exposing credential material, stop.

After a separately authorized future provider execution eventually creates and verifies the identity, the intended sequence remains:

1. bind only provider-controlled DEVELOPMENT tenant metadata;
2. bind the exact server-owned allowlist tuple with read-only `engagement:read` and no authority roles;
3. separately authorize hook enablement;
4. issue one short-lived synthetic token under its own boundary;
5. validate issuer/audience/signature/tenant/subject/policy locally; and only then
6. plan hosted identity and DATA adapter wiring for the Render DEVELOPMENT service.

Each item remains a separate bounded resource/action boundary.

## Do not start yet

- Do not execute or reuse AUTH v19's owner-interactive synthetic-user path; the dashboard requires a password and that path was stopped before mutation.
- Do not create a v20 approval or edit v20 to use the new credential class; v20 is immutable historical `DRAFT_BLOCKED` state.
- Do not retrieve, display, hash, fingerprint, log, copy, export, create, rotate, or persist a Supabase credential merely because authorization-plan v2 recognizes `SUPABASE_AUTH_ADMIN_EPHEMERAL` or v21 is `READY_FOR_APPROVAL`.
- Do not treat the new class as `service_role`, as permission to use a shared service-role key, or as an exception to the workload-identity/secret-boundary requirements in `SECURITY.md`.
- Do not treat v21 plan creation as owner approval or provider-execution authorization.
- Do not perform the provider mutation in the same resource change as v21 approval persistence.
- Do not create tenant metadata in the same action as the synthetic Auth identity.
- Do not enable the custom access-token hook yet.
- Do not issue or retain a synthetic access token yet.
- Do not wire Render to hosted AUTH or DATA yet.
- Do not alter RLS, tenant policy, command-service grants, migration ownership, or sealed role membership without a new exact plan.
- Do not create staging or production resources.
- Do not begin Phase 6.
- Do not treat n8n, communications, or billing as implemented merely because they are required architectural primitives.

## Known gaps

- No dedicated synthetic DEVELOPMENT Auth identity has been created for the next end-to-end identity proof.
- AUTH v21 exists and is `READY_FOR_APPROVAL`, but no v21 owner approval or provider-execution authorization exists yet.
- No concrete server executor has yet produced the required non-secret `auth.admin-executor-capability.observed` preflight attestation under the new class, and no credential material has been retrieved or validated.
- The custom access-token hook exists but remains disabled.
- Hosted DEVELOPMENT identity and DATA adapters are not wired.
- No canonical n8n workflow exports are present in this repository.
- No shared communications provider adapter is implemented here yet.
- No shared Stripe billing/usage-metering engine is implemented here yet.
- No dashboard application code or Supabase Edge Functions are present in the canonical tree.
- Hosted observability, environment-scoped secret bindings, concrete network enforcement, staging, backup/restore proof, capacity/SLO proof, and production configuration remain incomplete.
- `docs/architecture.md` contains detailed historical material and older readiness snapshots. When it conflicts with `ARCHITECTURE.md`, current code/provider evidence, or this file, the newer canonical evidence wins.

## Remote authorization

`REMOTE_AUTHORIZATION`: AUTH v21 is `READY_FOR_APPROVAL` but has no approval file and grants no remote authority. AUTH v20 remains immutable `DRAFT_BLOCKED`. AUTH v19's earlier exact approval artifact remains part of immutable history, but its owner-interactive provider path was stopped before mutation and must not be reused.

No provider mutation is currently authorized. No secret retrieval, executor binding, DATA operation, Render change, staging action, production action, hook enablement, metadata mutation, token issuance, or hosted adapter wiring is authorized by the v21 repository-only plan package.

## Recovery rule

`RECOVERY_RULE`: `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`.

Never destroy valid interrupted work. Never force push.

## Future agent workflow

1. Read `AGENTS.md`.
2. Read `ARCHITECTURE.md`, `SECURITY.md`, and this file.
3. Inspect the latest canonical plan/progress/approval artifacts relevant to the exact next boundary.
4. Confirm repository/environment/project/responsibility/resource before any change.
5. Complete one bounded resource change only.
6. Run focused validation and the full applicable gate.
7. Record sanitized evidence.
8. Stop at the next authority boundary.
9. End with one explicit next action.
