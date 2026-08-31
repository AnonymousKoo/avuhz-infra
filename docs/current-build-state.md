# Current Build State

`CURRENT_PHASE`: Architecture correction and Sekinfra extraction; provider-neutral persistence/migration rebaseline pending.

`CURRENT_HEAD`: `HEAD` (`refactor: remove sekinfra consulting domain from avuhz`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: Duplicated Sekinfra/OIA active runtime removed from Avuhz while preserving the governed foundation, reusable shared-system surface, provider-neutral ImplementationHandoff boundary, and Phase 5D execution governance.

`COMPLETED`:

- Avuhz Phase 1-5D-D2 execution infrastructure remains preserved.
- The canonical JSON Schema 2020-12 ImplementationHandoff contract remains byte-identical in Sekinfra and Avuhz.
- Avuhz active runtime and active contracts contain zero Sekinfra/OIA implementation dependencies.
- Generic acquisition, engagement, command execution, trusted context, UnitOfWork, idempotency, events, outbox, human approvals, and Phase 5D governance remain provider-neutral and green.
- ImplementationBrief and downstream Phase 5D execution governance remain bound to the exact handoff ID/version/digest without creating authority.
- Focused runtime, cross-repository handoff, contract, schema-representability, architecture-separation, Semgrep, credential, and baseline checks are green.

`IN_PROGRESS`: None. The active-runtime removal milestone is complete.

`NEXT_TASK`: Rebaseline Avuhz local persistence and migration artifacts for the provider-neutral current tree; do not certify full Avuhz/Sekinfra separation until migration replay and persistence isolation are green.

`DO_NOT_START_YET`: Phase 5D-D3 ClientAcceptance, DeploymentAuthorization runtime, deployment execution, production changes, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: None after the active-runtime milestone commit. Existing pre-separation migration lineage remains intact and is the next bounded milestone; do not rewrite history or contact remote infrastructure.

`REMOTE_AUTHORIZATION`: No Avuhz push. No remote Supabase or other infrastructure mutation. Any later Sekinfra feature-branch push requires explicit current authorization and green certification; never force push.

`RECOVERY_RULE`: `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`. Never destroy valid interrupted work.

## FUTURE_AGENT_WORKFLOW

1. Read the canonical agent rules.
2. Read `CURRENT_BUILD_STATE`.
3. Read architecture and security only when `NEXT_TASK` requires them.
4. Complete `NEXT_TASK` only.
5. Run focused tests.
6. Update `CURRENT_BUILD_STATE`.
7. Commit only the completed milestone if green.
8. Do not push unless explicitly authorized.
9. Stop after the milestone.
