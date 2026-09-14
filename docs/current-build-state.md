# Current Build State

`CURRENT_PHASE`: Phase 5 remains frozen. Engineering/production-readiness milestone 9.5 is active.

`CURRENT_CANONICAL_STATE`: DEVELOPMENT AUTH v16 is complete and verified. DEVELOPMENT DATA v3 is complete and verified. The hosted DEVELOPMENT Render service remains intentionally fail-closed for dependency readiness because real hosted identity and DATA adapters are not yet injected.

`PLATFORM_PRODUCTION_READINESS`: `NOT_READY`.

`READY_FOR_PHASE6`: `NO`.

## Completed foundation work

- Phase 5 execution/verification is frozen behind the provider-neutral governed runtime and contracts.
- DEVELOPMENT AUTH and DEVELOPMENT DATA are physically separated and must never be conflated:
  - AUTH: Supabase `pwlhruwutoitnieactol`
  - DATA: Supabase `gnuqaefotwgkwurjpyik`
- AUTH v15 successfully bootstrapped the restricted migration identity, applied the hardened custom access-token hook, and sealed the migration identity.
- AUTH v16 independently verified the sealed state: the hook owner/body/ACL match, the migration identity cannot be used through a SET path, and the hook remains disabled. AUTH v16 is `COMPLETED / CONSUMED / SUCCEEDED / PASS`.
- DATA v2 applied the canonical provider-neutral 16-table Avuhz baseline to DEVELOPMENT DATA.
- The DATA outbox function `search_path` warning was repaired through a separate bounded provider artifact and independently verified; Supabase Security Advisor returned zero findings afterward.
- DATA v3 sealed the migration identity and independently verified tenant isolation. DATA v3 is `COMPLETED`; both steps are `CONSUMED / SUCCEEDED / PASS`.
- Final DATA verification proved 16 Avuhz tables, RLS on all 16, one exact tenant policy per table, no direct Avuhz table authority for `PUBLIC`, `anon`, `authenticated`, or `service_role`, the canonical command-service ACL surface only, sealed migration-role membership, unchanged canonical migration history, and zero Security Advisor lints.
- The registered DEVELOPMENT Render service `avuhz-command-dev` exists and has demonstrated bounded liveness. Its readiness remains intentionally unavailable until hosted identity and DATA dependencies are connected.
- Local DEVELOPMENT identity and DATA composition boundaries are implemented and tested. The DATA composition is deliberately restricted to disposable loopback PostgreSQL; the hosted service does not yet use it as a remote provider connector.
- The repository now has a root `ARCHITECTURE.md` that distinguishes implemented infrastructure from required future shared-core primitives.

## Current runtime truth

`src/avuhz_service/development.py` still instantiates `_UnavailableIdentityResolver` and `_UnavailableUnitOfWork`.

Therefore:

- startup/liveness can be healthy;
- `/health/ready` remains `503`;
- command/query requests fail closed at trusted identity resolution; and
- no hosted Supabase DATA connection is created by the current service composition.

This is intentional. AUTH/DATA provider-foundation completion does not itself authorize runtime credential creation, hosted adapter wiring, or readiness promotion.

## Multi-tenant truth

The DEVELOPMENT DATA surface is not an aspirational design; it is deployed and verified:

- 16 Avuhz tables;
- RLS enabled on all 16;
- one `avuhz_command_service_tenant_isolation` policy per table;
- policy scoping through the transaction-local `avuhz.tenant_id` setting;
- zero direct Avuhz table grants to `PUBLIC`, `anon`, `authenticated`, or `service_role`;
- canonical command-service privileges only; and
- runtime authority separate from migration authority.

## In progress

Engineering-readiness milestone 9.5 remains active. Provider foundations are now ahead of the older narrative that previously described AUTH v9 and an unapplied DATA migration.

The immediate work is no longer schema bootstrap or AUTH hook creation. The next identity-validation chain must continue forward from the verified disabled-hook checkpoint.

## Next task

Create a fresh **repository-local forward-only DEVELOPMENT AUTH v17 plan** for exactly one dedicated synthetic DEVELOPMENT Auth identity in project `pwlhruwutoitnieactol`.

That repository plan is the next task; creating the plan does **not** authorize the provider mutation. Provider execution must remain a later separately authorized boundary with fresh exact preflight.

The intended sequence after that identity exists is:

1. bind only provider-controlled DEVELOPMENT tenant metadata;
2. bind the exact server-owned allowlist tuple with read-only `engagement:read` and no authority roles;
3. separately authorize hook enablement;
4. issue one short-lived synthetic token under its own boundary;
5. validate issuer/audience/signature/tenant/subject/policy locally; and only then
6. plan hosted identity and DATA adapter wiring for the Render DEVELOPMENT service.

Each item remains a separate bounded resource/action boundary.

## Do not start yet

- Do not create tenant metadata in the same action as the synthetic Auth identity.
- Do not enable the custom access-token hook yet.
- Do not issue or retain a synthetic access token yet.
- Do not wire Render to hosted AUTH or DATA yet.
- Do not create runtime credentials or use a service-role shortcut.
- Do not alter RLS, tenant policy, command-service grants, migration ownership, or sealed role membership without a new exact plan.
- Do not create staging or production resources.
- Do not begin Phase 6.
- Do not treat n8n, communications, or billing as implemented merely because they are required architectural primitives.

## Known gaps

- No dedicated synthetic DEVELOPMENT Auth identity has been created for the next end-to-end identity proof.
- The custom access-token hook exists but remains disabled.
- Hosted DEVELOPMENT identity and DATA adapters are not wired.
- No canonical n8n workflow exports are present in this repository.
- No shared communications provider adapter is implemented here yet.
- No shared Stripe billing/usage-metering engine is implemented here yet.
- No dashboard application code or Supabase Edge Functions are present in the canonical tree.
- Hosted observability, environment-scoped secret bindings, concrete network enforcement, staging, backup/restore proof, capacity/SLO proof, and production configuration remain incomplete.
- `docs/architecture.md` contains detailed historical material and older readiness snapshots. When it conflicts with `ARCHITECTURE.md`, current code/provider evidence, or this file, the newer canonical evidence wins.

## Remote authorization

`REMOTE_AUTHORIZATION`: none.

No further AUTH call, DATA operation, Render change, Supabase mutation, staging action, production action, hook enablement, synthetic-identity creation, metadata mutation, token issuance, or hosted adapter wiring is currently authorized by this document or by completion of earlier plans.

## Recovery rule

`RECOVERY_RULE`: `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`.

Never destroy valid interrupted work. Never force push.

## Future agent workflow

1. Read `AGENTS.md`.
2. Read `ARCHITECTURE.md`, `SECURITY.md`, and this file.
3. Inspect the latest canonical plan/progress artifacts relevant to the exact next boundary.
4. Confirm repository/environment/project/responsibility/resource before any change.
5. Complete one bounded resource change only.
6. Run focused validation and the full applicable gate.
7. Record sanitized evidence.
8. Stop at the next authority boundary.
9. End with one explicit next action.
