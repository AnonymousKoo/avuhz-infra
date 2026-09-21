# Current Build State

`CURRENT_PHASE`: Phase 5 remains frozen. Engineering/production-readiness milestone 9.5 is active.

`CURRENT_CANONICAL_STATE`: DEVELOPMENT AUTH v16 and DEVELOPMENT DATA v3 remain complete and verified provider foundations. AUTH v21 successfully created and verified exactly one passwordless synthetic DEVELOPMENT Auth identity with zero sessions or refresh tokens. AUTH v22 has an expired historical approval but no execution; AUTH v23 is unapproved and unexecuted historical state. AUTH v24 tenant metadata binding is complete and verified: the same synthetic identity now carries the exact canonical DEVELOPMENT tenant in provider-controlled `app_metadata`, while user metadata, email, role, sessions, refresh tokens, and hook state remained unchanged. AUTH v25 received an exact owner approval but expired unexecuted; its immutable audit records pristine/unconsumed progress, no allowlist bind, no provider contact, and no credential use. AUTH v26 completed the exact server-owned read-only allowlist bind: one entry is now persisted in the DEVELOPMENT identity policy, the authorization was consumed exactly once, execution/verification are `SUCCEEDED / PASS`, credential class was `NONE`, and no provider contact occurred. The DEVELOPMENT Auth-admin bootstrap credential is retired: provider deletion is owner-confirmed, the GitHub `development` environment binding is independently verified absent, and ignored local `supabase/.temp` secret material is independently verified absent. The retirement audit is canonical and retains no credential material. AUTH v27 received exact owner approval but remains pristine/unconsumed: the fresh provider preflight passed, then the owner-interactive Supabase dashboard revealed that its Create hook action also reconciles function/schema permissions, which exceeded v27’s narrower `function-acl.modify` prohibition, so the action was canceled before mutation. AUTH v28 completed the exact observed dashboard Create hook bundle during its approved window using `OWNER_INTERACTIVE_SESSION`; the hosted Custom Access Token hook now points to `public.avuhz_development_custom_access_token_hook_v1`, authorization is consumed, execution/verification are `SUCCEEDED / PASS`, the function body/owner/ACL remain unchanged, the five permission effects produced zero net permission change, and sessions/refresh tokens remain zero. A local, unmerged AUTH v29 token-validation candidate was rejected before canonicalization or provider contact because its `magiclink` route could create a missing user despite `identity.create` being prohibited and because its Management API key enumeration could expose secret-key material to the runner. AUTH v30 remains historical, pristine, unapproved, and unexecuted. AUTH v31 received exact owner approval, but Step 1 stopped after exactly one provider mutation attempt with safe code `V31_RECOVERY_LINK_GENERATION_FAILED`; its provider mutation outcome is `AMBIGUOUS`, exact historical response classification is `UNKNOWN`, authorization is consumed, retry is unauthorized, and Steps 2-3 are blocked/unconsumed. PR #110 confirmed and corrected the direct-HTTP-versus-SDK-shape parser defect. AUTH v32 then ran exactly once from source SHA `1fa628abba14acef4b58a1a983c95edafeac44a4`: Step 1 generated and verified the existing-user recovery credential, Step 2 attempted consumption once and stopped with `V32_SESSION_RESPONSE_MISSING`, and Step 3 was blocked. No access token was captured, local logout and independent post-failure session/refresh-token readback were not performed, and `emergency_cleanup=NOT_NEEDED` does not prove zero sessions. Provider session state remains `AMBIGUOUS / UNVERIFIED`; v32 is consumed and non-retryable. PR #115 canonically corrected the reusable future lifecycle to direct recovery verification with independent readback, without executing another token attempt. The separate `development-auth-v32-session-inspection-v1` boundary executed exactly once from canonical SHA `005e3d97dd31feb53a1314880a77c1fae96d569c` in workflow run `35370969272`: authority validation passed, the first project-read operation failed with `SESSION_INSPECTION_PROJECT_READ_FAILED`, execution stopped before SQL, and session/refresh state remains `SESSION_STATE_UNVERIFIED`. The unapproved diagnostic v1 window began before owner approval could be canonically recorded, so v1 remains pristine and cannot be backdated. The forward-only `development-auth-provider-read-diagnostic-v2` continuation is prepared with identical provider-read scope under the future September 20 window; it is pristine, unapproved, unexecuted, and grants no current provider authority.

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
- AUTH v21 completed the passwordless Supabase Admin `createUser` email-only confirmed path for the dedicated synthetic DEVELOPMENT identity. Its execution-progress is `COMPLETED / CONSUMED / SUCCEEDED / PASS`; exactly one synthetic Auth user exists, with zero sessions and zero refresh tokens, and the raw provider subject is retained only as a digest-bound reference.
- AUTH v22 prepared the first tenant-metadata continuation and received an exact owner approval, but it was not executed before its window expired. AUTH v23 was a fresh forward-only continuation but remained unapproved and unexecuted. Both are immutable historical state and must not be revived.
- AUTH v24 completed the exact provider-controlled tenant metadata bind. The verified identity count remains one; the exact canonical tenant is present in `app_metadata`; user metadata, email, role, session/token state, hook body/owner/ACL/configuration, DATA, and Render remained unchanged. AUTH v24 execution-progress is `COMPLETED / CONSUMED / SUCCEEDED / PASS`.
- AUTH v28 completed the exact Custom Access Token dashboard bundle after a fresh preflight. The hook is enabled on `public.avuhz_development_custom_access_token_hook_v1`; the pre/post permission state is unchanged, the certified function body/owner/search path remain exact, the single synthetic tenant binding remains present, and session/refresh-token counts remain zero. AUTH v28 execution-progress is `COMPLETED / CONSUMED / SUCCEEDED / PASS`.
- AUTH v29 never became canonical. Its local pre-canonical candidate is recorded only by `development-auth-v29-precanonical-review.evidence.json` with outcome `REJECTED_PRECANONICAL_UNEXECUTED`; no provider contact, mutation, identity creation, token/session issuance, or credential use occurred.
- AUTH v30 remains immutable historical preparation. AUTH v31 is stopped/consumed and non-retryable. AUTH v32 is also stopped/consumed and non-retryable: Step 1 is `CONSUMED / SUCCEEDED / PASS`, Step 2 is `CONSUMED / FAILED / FAIL` with `V32_SESSION_RESPONSE_MISSING` and unresolved provider session state, and Step 3 is blocked/unconsumed.
- PR #115 replaced the browser-fragment dependency in the reusable future lifecycle with direct recovery verification and explicit independent session-state reconciliation. It did not inspect or mutate provider state and did not authorize another token attempt.
- `development-auth-v32-session-inspection-v1` is stopped and consumed after one `PROVIDER_READ` attempt over the exact DEVELOPMENT AUTH project. Plan `8a1300d3-4bfb-461c-90c4-a22a53a11647`, plan digest `sha256:c397fc40fe5622047ab38d435ebad57f119a2b7882103ef0d175e39ee0d5bdf1`, exact approval `bf911bca-3187-4fef-a828-24728a844a05` with digest `sha256:81f5e22a86183e95067bd55e93706aa7dbab2bf58af3db8ce3f57f972e245b5c`, pristine progress digest `sha256:2d64cadde4b6b3686b13e00fd3d2fe2e92066d53ce2c51c0c27d56b0cb253d60`, failure evidence digest `sha256:c48c892c69a447eefcc499cc1f3f19d27a5f659a6ca2e52a5152a34487c303d1`, and stopped execution-progress digest `sha256:ed7312e7a29f192a5f6f84c8f838c857391282af08c177e8011993e8d2a165d9` are canonical. The project read failed before either Auth table query; no counts or subject binding were established, no cleanup or provider mutation occurred, and retry is unauthorized.
- AUTH v25 prepared the exact local-only server capability policy entry and received exact owner approval, but its immutable window expired without execution. The canonical expiry audit records `EXPIRED_UNEXECUTED`, pristine/unconsumed progress, no allowlist bind, no provider contact or mutation, and no credential use. AUTH v26 preserves the exact same subject digest, tenant UUID, provider-neutral principal reference `subject.development-synthetic-user`, DEVELOPMENT issuer/audience, `HUMAN` caller type, `engagement:read` only, empty authority roles, and provider-free local-only boundary under a fresh forward-only plan.
- The focused AUTH validators and the canonical credential/path/Semgrep gates continue to enforce secret-free plan/evidence surfaces; credential material must never appear in plan, approval, progress, evidence, request, logs, or agent-visible output.
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

This is intentional. AUTH v21/v24/v26/v28 completion, AUTH v31 and v32 failure recording, and DATA v3 completion do not themselves authorize runtime credential creation, secret retrieval, another synthetic-token attempt, hosted adapter wiring, or readiness promotion. AUTH v32 and v32 session-inspection-v1 authority are consumed and cannot be reused. The failed inspection grants no retry, cleanup, mutation, or token authority. The default Supabase `aud=authenticated` is rejected by Avuhz; the approved DEVELOPMENT command-service audience remains separate.

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

These facts are retained because they are part of the repository's production-readiness certification history. Historical snapshots are explicitly marked and do not override the current AUTH-through-v24 / DATA v3 state.

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

Engineering-readiness milestone 9.5 remains active. AUTH v21 synthetic identity creation and AUTH v24 tenant metadata binding are complete and verified. AUTH v22 remains expired/unexecuted historical state and AUTH v23 remains unapproved/unexecuted historical state. Neither may be reused or revived.

AUTH v25 is immutable historical state with plan id `b9532651-b0a2-420f-a3fb-bde9c5c3d396`, plan digest `sha256:70f57ac94af8906388dc07fe21284d46182c3efb9c8c5eb2cc3d303e723aa5b8`, exact owner approval, and expired window `2026-09-15T04:00:00Z` through `2026-09-15T10:00:00Z`. Its canonical audit outcome is `EXPIRED_UNEXECUTED`; progress remains pristine `PENDING / NOT_STARTED / NOT_STARTED / unconsumed`, and no allowlist, provider, or credential effect occurred. AUTH v26 is the current forward-only plan with plan id `f6c223d0-5e3e-43e1-b90c-190367840bec`, plan digest `sha256:e43e7a01dd79686bbb5efa744444126800e0d5b488461253fa7281fdd227a2c4`, pristine progress digest `sha256:ed6c3afa8aaed2f5f62431c0b6d0976ab35bde08dc7d9a0651725d33e15d7241`, the unchanged policy digest `sha256:864019b6d904f790fab298f0142989e067af65fa735094edc28ffa756de406f6`, and fresh immutable window `2026-09-15T15:00:00Z` through `2026-09-15T21:00:00Z`. Its exact owner approval was recorded at `2026-09-15T13:01:38Z`; the local bind executed at `2026-09-15T16:06:53Z` and verified at `2026-09-15T16:06:54Z`. Execution progress is `COMPLETED / CONSUMED / SUCCEEDED / PASS` with digest `sha256:57c9ddc55f2327712f161b4544125ba632c80dd6cca3da727d834ebb999db37a`; success evidence digest is `sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba`. Credential class was `NONE`; no provider contact or mutation occurred.

The canonical DEVELOPMENT Auth-admin bootstrap retirement audit is `contracts/plans/v1/development-auth-admin-bootstrap-retirement.evidence.json`, observed at `2026-09-15T16:48:52Z`, with raw file digest `sha256:9e310b6b114b4b4a2b71f35a6f9b6324231f3f071a2fdecc5d589d7b91e635ef`. It records provider deletion as owner-confirmed rather than independently provider-verified, while the GitHub `development` environment secret binding and local ignored `supabase/.temp` secret material are independently verified absent. No credential material is retained in the audit.

The hosted DEVELOPMENT runtime remains deliberately unwired: `src/avuhz_service/development.py` still uses `_UnavailableIdentityResolver` and `_UnavailableUnitOfWork`. The exact v26 server-owned allowlist entry is now persisted and verified, but hosted identity resolution is intentionally not yet injected into runtime composition.

AUTH v27 has plan id `cf30c352-08f2-4d17-98e5-9dbc5edc103e`, plan digest `sha256:9d2ab111c08ed6455b847c578eb6aa949cee12707ccb104e666e5fbe7b08c1c6`, exact owner approval `671bb3cb-3555-44a2-b7e3-17bcb04eeb03`, and immutable window `2026-09-15T18:30:00Z` through `2026-09-16T00:30:00Z`. A fresh provider preflight verified the exact function/body/owner/ACL and that no Auth hook was configured. The owner-interactive dashboard then disclosed an additional five-effect permission reconciliation bundle. Because v27 prohibited `function-acl.modify`, the Create hook action was canceled before mutation; v27 progress therefore remains pristine `PENDING / NOT_STARTED / NOT_STARTED / unconsumed` and no v27 success evidence exists.

AUTH v28 is complete. Plan `d65f18e6-ef65-42a9-96c3-d50a037c4866`, plan digest `sha256:dd5414b753903501a4a7998d854288611ac9195f3199c405c29eb865dbd2d3db`, exact dashboard-bundle digest `sha256:f3c5463a0a443e4290da202d47184cf65f8174cda05de5e7c7dd1b1717924025`, unchanged permission-state digest `sha256:974b40e7f289136e3a309017ba0205917dd6fb179d4479b148a14e806e1d244c`, approval `e0d2c051-50c5-4306-91ac-6ef5b81a062e`, and window `2026-09-15T20:30:00Z` through `2026-09-16T02:30:00Z` remain the immutable authority boundary. Fresh preflight evidence digest is `sha256:877d7568c2c59996e0cabb793ea7611e55dcbdeadb7d413985f75613fdc5586c`; verified success evidence raw digest is `sha256:d756b6baa3fbd4fc743b80d436e6578e66806658855b3c669690eb95dc79814c`; completed execution-progress digest is `sha256:1aa545222c50b3931834f9e76b6d58143d93896a2202d5cecd3b718e89c9c9af`. The exact hook is enabled, the function body/owner/ACL stayed exact, the permission state did not widen, one tenant-bound synthetic identity remains, and sessions/refresh tokens remain zero.

AUTH v29 is not a canonical authorization version. A local candidate with plan id `604a861b-32af-4f7e-a977-ff233f86ceba` was reviewed before merge and rejected fail-closed. Its review evidence raw digest is `sha256:9177fddb267c8e7735e19813a1f9c53f60403450c2c90d62fbb5ae75cf3f1f6d`; all recorded effects are false. The candidate files/approval/workflow were not merged and must not be reconstructed or executed.

AUTH v30 remains immutable historical preparation with no approval or execution evidence. AUTH v31 plan `c2a83103-7177-4bf4-855f-c3428b2d5b73` and approval are immutable; Step 1 is `CONSUMED / FAILED / FAIL`, provider outcome is `AMBIGUOUS`, exact historical response classification is `UNKNOWN`, retry is unauthorized, and Steps 2-3 are blocked/unconsumed. Failure evidence digest is `sha256:1ed8a2fcbdb7d168e48387a42096be23bee05c3eb8732735b4502374b0dbb034`; stopped progress digest is `sha256:88d8021f785120d91d4314d7c14028ca5bd8467db2f38b4ac7dea866d6399190`.

AUTH v32 plan `e8cd574a-a532-4c95-ab5d-5c069c1bbb96`, plan digest `sha256:c43b0b906bfb0c03e763d6cc5a13d47a900b40eb4db8fd904c799c524ec6c37c`, approval `22afae15-0eb0-4d29-927d-ed2d6405eb02`, and immutable window `2026-09-17T15:00:00Z` through `2026-09-17T21:00:00Z` remain historical authority. Workflow run `35240314854` invoked the executor exactly once from SHA `1fa628abba14acef4b58a1a983c95edafeac44a4`. Step 1 success evidence digest is `sha256:dfa0583adc85bddb3a40d60da1708f9e8591b07d203ed90f4ce08b43be57a30d`; Step 2 failure evidence digest is `sha256:e56af517533e0b6f4f05d7c7dbb33f1b39a8cc09669180b9874d506a5f0850e9`; stopped execution-progress digest is `sha256:d40704265985889923e8dbd013274ff151717ea1f5880e9269e4107b96e022f7`. The safe failure code is `V32_SESSION_RESPONSE_MISSING`. Access-token capture, local logout, and independent post-failure `auth.sessions`/`auth.refresh_tokens` readback did not occur, so cleanup is unverified and provider session/refresh-token state is ambiguous/unverified. v32 authority is consumed and retry is unauthorized.

The recovery-inspection boundary `development-auth-v32-session-inspection-v1` has plan id `8a1300d3-4bfb-461c-90c4-a22a53a11647`, plan digest `sha256:c397fc40fe5622047ab38d435ebad57f119a2b7882103ef0d175e39ee0d5bdf1`, exact owner approval `bf911bca-3187-4fef-a828-24728a844a05` with digest `sha256:81f5e22a86183e95067bd55e93706aa7dbab2bf58af3db8ce3f57f972e245b5c`, and immutable authorization window `2026-09-18T15:00:00Z` through `2026-09-18T21:00:00Z`. Workflow run `35370969272` invoked it exactly once from SHA `005e3d97dd31feb53a1314880a77c1fae96d569c`. Authority validation and credential-presence checks passed, then `GET https://api.supabase.com/v1/projects/pwlhruwutoitnieactol` failed under the executor's deliberately collapsed safe code `SESSION_INSPECTION_PROJECT_READ_FAILED`. The historical record cannot determine the underlying project-read failure cause. The SQL session-state inspection, `auth.sessions` query, `auth.refresh_tokens` query, count establishment, and expected-subject binding were never reached. Failure evidence digest is `sha256:c48c892c69a447eefcc499cc1f3f19d27a5f659a6ca2e52a5152a34487c303d1`; stopped execution-progress digest is `sha256:ed7312e7a29f192a5f6f84c8f838c857391282af08c177e8011993e8d2a165d9`. The step is `CONSUMED / FAILED / FAIL`, overall state is `STOPPED`, retry is unauthorized, provider session/refresh state remains unresolved, and no cleanup or provider mutation occurred.

`development-auth-provider-read-diagnostic-v1` is a separate preparation-only boundary with plan `205c2cef-1b90-4346-b4eb-d19ded202d6a`, plan digest `sha256:e38f0eac3128511f3e3c2d3bd45278276a69fe1ce86801e93c2417264e411f1d`, pristine progress digest `sha256:5f956df6a861088645ef7bb5831020683a03697ca87e93fbf631431951662e37`, and immutable window `2026-09-19T15:00:00Z` through `2026-09-19T21:00:00Z`. It is `READY_FOR_APPROVAL / NOT_STARTED / PENDING / unconsumed`, has no approval, execution progress, or evidence, and grants `NONE_UNTIL_SEPARATELY_APPROVED`. Its only possible future provider action is one `GET https://api.supabase.com/v1/projects/pwlhruwutoitnieactol` using credential class `SUPABASE_PROVIDER_READ` and runtime reference `AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN` by name only. It has no SQL/session-inspection or mutation path. Exact id/ref/name match yields `PROJECT_READ_OK`; safe failures are `PROJECT_READ_AUTHENTICATION_REJECTED`, `PROJECT_READ_FORBIDDEN`, `PROJECT_READ_NOT_FOUND`, `PROJECT_READ_RATE_LIMITED`, `PROJECT_READ_PROVIDER_FAILURE`, `PROJECT_READ_UNEXPECTED_STATUS`, `PROJECT_READ_REQUEST_FAILED`, `PROJECT_READ_RESPONSE_INVALID`, or `PROJECT_READ_MISMATCH`. This preparation does not reinterpret run `35370969272`.

The v1 window began before an approval artifact could be created. The authorization engine requires truthful `approved_at <= effective_at`; a post-start v1 approval fails closed with `PLAN_AUTHORIZATION_EXPIRED`, and backdating is prohibited. v1 therefore remains immutable historical `READY_FOR_APPROVAL / NOT_STARTED / PENDING / unconsumed`, with no approval, execution progress, evidence, or workflow run.

`development-auth-provider-read-diagnostic-v2` is the forward-only continuation with plan `b6d86aea-a009-4080-a82c-8ace44b91f45`, plan digest `sha256:e461550ca90b8ffbb38c8f8be0b73e767c57ead19aec23e3a8b4eaeccc938bba`, pristine progress digest `sha256:7e2c5396e878deb90988d39f46596b886de98bd7b98bec6ea49961bcd0c71ab0`, and immutable window `2026-09-20T15:00:00Z` through `2026-09-20T21:00:00Z`. Its target, operation, exact resource contract, required evidence, postcondition, execution class, credential class/reference, and provider prohibitions are identical to v1; it additionally prohibits backdating or executing v1. It is `READY_FOR_APPROVAL / NOT_STARTED / PENDING / unconsumed`, with no approval, execution progress, evidence, or workflow run, and grants `NONE_UNTIL_SEPARATELY_APPROVED`.

`development-auth-v32-session-inspection-owner-interactive-v1` is the fresh shortest forward-only recovery boundary. Plan `4bb906a5-1210-4564-aae2-81530f33661a`, plan digest `sha256:406b8f09b668bd32c0ac94715b317680c1d530344fe07c195bb7530403603e5e`, pristine progress digest `sha256:0c8a41220b72367495046ab6dd0f1782858016bae586423556ca47d3de618e2b`, and immutable window `2026-09-22T15:00:00Z` through `2026-09-22T21:00:00Z` bind one owner-interactive `PROVIDER_READ` step in the Supabase Dashboard SQL Editor for DEVELOPMENT AUTH only. The exact ordered SQL contract permits only aggregate `count(*)` reads of `auth.sessions` and then, only when the first count is zero, `auth.refresh_tokens`. Exact 0/0 establishes `SESSION_STATE_ZERO_CONFIRMED`; any nonzero count stops further SQL and records only `SESSION_STATE_NONZERO_OWNER_REVIEW_REQUIRED`. Raw rows, identifiers, PII, `auth.users`, additional SQL after a nonzero count, cleanup, issuance, and provider mutation are prohibited. The boundary is `READY_FOR_APPROVAL / NOT_STARTED / PENDING / unconsumed`, has no approval, execution progress, evidence, workflow, or executor, and grants `NONE_UNTIL_SEPARATELY_APPROVED`.

## Next task

AUTH v26 and AUTH v28 are complete and consumed, and the DEVELOPMENT Auth-admin bootstrap credential is retired. AUTH v27 remains intentionally unconsumed, AUTH v29 was rejected before canonicalization, AUTH v30 remains unapproved/unexecuted, and AUTH v31 and v32 are stopped/consumed with retry unauthorized. The hosted identity resolver remains deliberately unwired.

The intended sequence is now:

1. obtain owner review and, if desired, separately create the exact approval for pristine `development-auth-v32-session-inspection-owner-interactive-v1` before its effective time; do not approve or execute either provider-read diagnostic or retry the consumed inspection under preparation authority;
2. preserve the unresolved session/refresh state unless the separately approved owner-interactive aggregate inspection establishes a canonical sanitized result;
3. review the corrected lifecycle before preparing any new token-validation version; and only after a future validation succeeds,
4. separately plan hosted DEVELOPMENT AUTH wiring, followed by hosted DEVELOPMENT DATA wiring and readiness promotion after both dependencies verify independently.

Each item remains a separate bounded resource/action boundary.

## Do not start yet

- Do not reuse AUTH v22, v23, or v24 approval/credential authority for any later step.
- Do not recreate or reuse the retired DEVELOPMENT Auth-admin bootstrap credential. Any future provider mutation requires a fresh exact authorization and a fresh credential lifecycle.
- Do not reuse AUTH v27 or consumed AUTH v28 authority for any further provider action. Any later AUTH provider mutation requires a new exact boundary. DATA, Render, n8n, staging, and production remain separate boundaries.
- Do not persist or reconstruct the raw provider subject; only the verified digest may participate in the server-owned allowlist.
- Do not widen the allowlist beyond exactly one entry, `HUMAN`, `engagement:read` only, and empty authority roles.
- Do not disable, retarget, duplicate, or otherwise modify the enabled custom access-token hook without a new exact plan.
- Do not retry AUTH v31, AUTH v32, or consumed `development-auth-v32-session-inspection-v1`. Do not prepare v33, issue another synthetic token, clean provider session state, or reuse any consumed credential/authority.
- Do not wire Render to hosted AUTH or DATA yet.
- Do not alter RLS, tenant policy, command-service grants, migration ownership, or sealed role membership without a new exact plan.
- Do not create staging or production resources.
- Do not begin Phase 6.
- Do not treat n8n, communications, or billing as implemented merely because they are required architectural primitives.

## Known gaps

- The dedicated synthetic DEVELOPMENT Auth identity exists, tenant metadata is bound, and the exact server-owned read-only allowlist is applied; hosted runtime composition is still intentionally unwired.
- AUTH v25 is expired/unexecuted historical state and must not be reused; AUTH v26 completed the exact local-only allowlist bind and is consumed.
- The DEVELOPMENT Auth-admin bootstrap credential retirement is complete. Provider deletion is owner-confirmed; the GitHub `development` environment binding and local ignored temp secret material are independently verified absent. The retired credential must not be reused.
- The custom access-token hook function exists and the hosted Custom Access Token hook is enabled on the exact certified function. AUTH v27 remains unconsumed historical authority after the dashboard bundle mismatch; AUTH v28 completed and consumed the exact broader dashboard-bundle authority.
- AUTH v29 was rejected before canonicalization and has no provider effects or reusable authority. AUTH v30 remains pristine/unapproved/unexecuted. AUTH v31 and v32 are stopped/consumed and non-retryable. v32 exposed an access-token-gated emergency-cleanup weakness: `NOT_NEEDED` did not prove zero provider sessions. The forward-only lifecycle redesign is canonical. The one approved recovery inspection is also stopped/consumed and non-retryable after its project read failed before SQL, so provider session state remains unresolved. A fresh owner-interactive aggregate-only inspection is prepared but unapproved and unexecuted.
- No end-to-end short-lived synthetic token validation has been completed yet.
- Hosted DEVELOPMENT identity and DATA adapters are not wired.
- No canonical n8n workflow exports are present in this repository.
- No shared communications provider adapter is implemented here yet.
- No shared Stripe billing/usage-metering engine is implemented here yet.
- No dashboard application code or Supabase Edge Functions are present in the canonical tree.
- Hosted observability, environment-scoped secret bindings, concrete network enforcement, staging, backup/restore proof, capacity/SLO proof, and production configuration remain incomplete.
- `docs/architecture.md` contains detailed historical material and older readiness snapshots. When it conflicts with `ARCHITECTURE.md`, current code/provider evidence, or this file, the newer canonical evidence wins.

## Remote authorization

`REMOTE_AUTHORIZATION`: AUTH v21, v24, v26, and v28 are completed/consumed historical authority. AUTH v28 is consumed and grants no further execution authority. AUTH v22 is expired and unexecuted; AUTH v23 is unapproved and unexecuted; AUTH v25 expired unexecuted/unconsumed. AUTH v27 remains pristine/unconsumed, AUTH v29 never became canonical, and AUTH v30 remains unapproved/unexecuted. AUTH v31 and AUTH v32 are consumed/stopped and cannot be retried. v32 provider session/refresh-token state remains ambiguous/unverified; its historical approval grants no recovery, cleanup, redesign, or further execution authority. `development-auth-v32-session-inspection-v1` is also consumed/stopped and non-retryable after one failed project-read attempt; it established no session or refresh-token counts and grants no further provider-read, mutation, or cleanup authority. `development-auth-provider-read-diagnostic-v1` and `development-auth-provider-read-diagnostic-v2` remain pristine, unapproved, unexecuted historical preparations. `development-auth-v32-session-inspection-owner-interactive-v1` is pristine, unapproved, and unexecuted. Preparation grants no provider-read authority.

Any v32 recovery inspection, forward-only token-lifecycle correction, future synthetic-token execution, DATA access, Render change, staging or production action, and hosted adapter wiring remain separate boundaries and require their own exact authorization where applicable.

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
