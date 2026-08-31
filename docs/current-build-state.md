# Current Build State

`CURRENT_PHASE`: Architecture correction and Sekinfra extraction; active-runtime separation recovery.

`CURRENT_HEAD`: `HEAD` (`refactor: establish provider-neutral implementation handoff`)

`CURRENT_BRANCH`: `main`

`LAST_GREEN_MILESTONE`: Provider-neutral ImplementationHandoff boundary completed from Sekinfra producer through Avuhz acceptance and exact ImplementationBrief ID/version/digest binding.

`COMPLETED`:

- Avuhz Phase 1-5D-D2 committed execution infrastructure remains preserved.
- The canonical JSON Schema 2020-12 ImplementationHandoff contract is byte-identical in Sekinfra and Avuhz.
- Sekinfra produces deterministic, versioned, digest-bound handoffs from exact approved consulting sources without exposing OIA internals.
- Avuhz accepts only bounded, secret-free, exact tenant/version/digest/approval history and rejects stale or post-revocation rebinding.
- ImplementationBrief and downstream Phase 5D execution governance bind the exact handoff reference without creating new authority.
- Focused producer, consumer, Phase 5D source-binding, contract, and cross-repository tests are green.

`IN_PROGRESS`: Broader active-tree Sekinfra/OIA removal and persistence/migration separation remain preserved as dirty recovery work and were intentionally excluded from the completed handoff milestone.

`NEXT_TASK`: Remove duplicated Sekinfra/OIA active runtime from Avuhz while preserving Avuhz core, reusable shared systems, and Phase 5D execution governance.

`DO_NOT_START_YET`: Phase 5D-D3 ClientAcceptance, DeploymentAuthorization runtime, deployment execution, production changes, or later roadmap work.

`KNOWN_DIRTY/PARTIAL_WORK`: The Avuhz worktree intentionally retains uncommitted active-tree separation edits across contracts, runtime, persistence, migrations/validators, and tests. Inspect the exact diff against the handoff milestone, preserve valid work, and complete only the documented next task.

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
