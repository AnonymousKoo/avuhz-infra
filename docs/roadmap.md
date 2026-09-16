# Avuhz Roadmap

Ordered milestones from the separation checkpoint:

1. Complete the provider-neutral ImplementationHandoff boundary. — COMPLETE
2. Validate the Sekinfra-to-Avuhz cross-repository contract. — COMPLETE
3. Remove duplicated Sekinfra/OIA active runtime from Avuhz. — COMPLETE
4. Certify Avuhz/Sekinfra separation. — COMPLETE
5. Resume Phase 5D with ClientAcceptance. — COMPLETE
6. Implement DeploymentAuthorization. — COMPLETE
7. Implement DeploymentExecution, then DeploymentVerification, from the frozen D5 contracts. — COMPLETE
8. Reconcile and freeze Phase 5. — COMPLETE; BASELINE FROZEN
9. Complete engineering and production readiness.
   1. Define and certify platform architecture, security gates, environment registry, engineering-agent boundary, dry-run plan, and blockers. — COMPLETE
   2. Implement local production-shaped command/query service packaging and bounded health surfaces. — COMPLETE
   3. Implement the local transactional outbox delivery worker with a fake local sink. — COMPLETE
   4. Implement the local CI artifact/evidence pipeline and autonomous dry-run harness. — COMPLETE
   5. Establish owner-approved AUTH/DATA/environment registry values and certify DEVELOPMENT provider foundations. — FOUNDATION COMPLETE
      - DEVELOPMENT AUTH project separation and migration identity — COMPLETE
      - Hardened custom access-token hook creation and ACL — COMPLETE
      - AUTH migration-identity seal and disabled-hook verification — COMPLETE through AUTH v16
      - DEVELOPMENT DATA canonical 16-table baseline — COMPLETE
      - DATA migration-identity seal, tenant-RLS verification, and search-path repair — COMPLETE through DATA v3 and the separate repair track
   6. Complete DEVELOPMENT identity validation and hosted runtime integration. — NEXT
      - Build the forward-only v17 plan for one dedicated synthetic DEVELOPMENT Auth identity — COMPLETE; SUPERSEDED UNAPPROVED/UNEXECUTED DUE APPROVAL-TIMING CONSTRAINT
      - Build the forward-only v18 plan with the exact unchanged synthetic-identity scope — COMPLETE; SUPERSEDED UNAPPROVED/UNEXECUTED AFTER THE OWNER APPROVAL ARRIVED 12 SECONDS AFTER ITS EFFECTIVE START
      - Build the forward-only v19 plan with the exact unchanged synthetic-identity scope and a 60-minute-plus approval safety buffer — COMPLETE
      - Create the exact v19 owner approval before its `2026-09-14T09:00:00Z` effective time — COMPLETE
      - Attempt the v19 owner-interactive execution path without weakening credential controls — STOPPED BEFORE MUTATION; the Supabase dashboard create-user form requires a password, which is outside v19's no-credential-persistence intent. No synthetic identity was created and v19 progress remains unconsumed.
      - Define forward-only AUTH v20 for the supported Supabase Admin `createUser` email-only confirmed route — COMPLETE AS IMMUTABLE `DRAFT_BLOCKED`; v20 has no authorization window, permits credential class `NONE`, and cannot be approved or executed.
      - Design and certify the minimum server-side Auth-admin execution credential class/handling rule without retrieving, exposing, hashing, logging, returning, or persisting credential material — COMPLETE through backward-compatible authorization-plan v2 and `SUPABASE_AUTH_ADMIN_EPHEMERAL`; class use is DEVELOPMENT/Supabase/AUTH/provider-mutation only and requires a digest-only non-secret executor-capability attestation.
      - Create a new forward-only AUTH v21 plan for exactly one passwordless synthetic identity using the v2 credential class while preserving v20 unchanged — COMPLETE.
      - Separately create exact owner approval for v21 and prove clean identity state plus the non-secret executor capability — COMPLETE.
      - Execute exactly one passwordless Admin `createUser` operation with credential material outside Avuhz control-plane surfaces — COMPLETE through AUTH v21; exactly one synthetic identity verified with zero sessions/refresh tokens.
      - AUTH v22 tenant-metadata continuation — HISTORICAL; exact approval existed but expired without execution.
      - AUTH v23 tenant-metadata continuation — HISTORICAL; unapproved and unexecuted.
      - Bind provider-controlled tenant metadata — COMPLETE through AUTH v24; exact tenant metadata verified with identity/session/hook state unchanged.
      - Prepare forward-only AUTH v25 for the exact server-owned read-only allowlist tuple — COMPLETE AS HISTORICAL PLAN; exact owner approval expired unexecuted, progress remains pristine/unconsumed, and no allowlist/provider/credential effect occurred.
      - Prepare fresh forward-only AUTH v26 with the exact unchanged local-only allowlist scope — COMPLETE AS HISTORICAL PREPARATION; it entered `READY_FOR_APPROVAL` as `LOCAL_ONLY`, credential class `NONE`, with window `2026-09-15T15:00:00Z` through `2026-09-15T21:00:00Z` and no provider contact.
      - Create the exact AUTH v26 owner approval before its `2026-09-15T15:00:00Z` effective time — COMPLETE.
      - Bind the exact AUTH v26 server-owned read-only allowlist tuple during its active window — COMPLETE; exactly one entry, `HUMAN`, `engagement:read` only, empty authority roles, credential class `NONE`, no provider contact.
      - Retire the completed DEVELOPMENT Auth-admin bootstrap credential — COMPLETE; dedicated provider key deletion owner-confirmed, GitHub `development` environment binding independently verified absent, ignored local `supabase/.temp` secret material independently verified absent, no credential material retained.
      - Prepare forward-only AUTH v27 for the exact DEVELOPMENT custom access-token hook configuration — COMPLETE AS PREPARATION; plan `cf30c352-08f2-4d17-98e5-9dbc5edc103e`, credential class `OWNER_INTERACTIVE_SESSION`, window `2026-09-15T18:30:00Z` through `2026-09-16T00:30:00Z`.
      - Create the exact AUTH v27 owner approval — COMPLETE; approval `671bb3cb-3555-44a2-b7e3-17bcb04eeb03` is canonical.
      - Execute AUTH v27 hook enablement — STOPPED PRE-MUTATION; fresh provider preflight passed, but the Supabase dashboard disclosed a five-effect permission reconciliation bundle outside v27’s narrower ACL boundary, so Create hook was canceled and v27 remains pristine/unconsumed.
      - Prepare forward-only AUTH v28 for the exact observed dashboard Create hook bundle — COMPLETE AS PREPARATION; plan `d65f18e6-ef65-42a9-96c3-d50a037c4866` remains definition-status `READY_FOR_APPROVAL`, credential class `OWNER_INTERACTIVE_SESSION`, window `2026-09-15T20:30:00Z` through `2026-09-16T02:30:00Z`, exact bundle/permission-state evidence bound; at this historical preparation checkpoint execution was pristine/unconsumed.
      - Create the exact AUTH v28 owner approval — COMPLETE; approval `e0d2c051-50c5-4306-91ac-6ef5b81a062e` recorded at `2026-09-15T20:03:41Z` before the effective window; progress was pristine/unconsumed at approval time.
      - Execute only the exact DEVELOPMENT dashboard hook bundle during the active v28 window after a fresh matching preflight — COMPLETE; exact hook enabled once, permission state unchanged, authorization consumed, verification PASS, zero sessions/refresh tokens
      - Review the local AUTH v29 synthetic-token candidate before canonicalization — COMPLETE; REJECTED PRE-CANONICAL / UNEXECUTED because `magiclink` could create a missing user despite `identity.create` being prohibited and Management API key enumeration could expose secret-key material to the runner. No provider contact or credential use occurred.
      - Prepare forward-only AUTH v30 for one existing-user recovery-link token lifecycle — COMPLETE AS PREPARATION; plan `d89b1ba0-6a85-4897-8d40-33af4de45e4a`, digest `sha256:8b1d92022e192c73b856d5d399843a3ee4c9dac4d08e9c7778293f765f8ebd6f`, window `2026-09-15T23:00:00Z` through `2026-09-16T05:00:00Z`; existing-user recovery only, pre-bound publishable key, one session immediately locally revoked, then post-revocation ES256/issuer/audience/tenant/subject/read-only-policy validation; pristine/unapproved/unexecuted.
      - AUTH v30 remained unapproved and unexecuted — HISTORICAL; its authority was never activated.
      - Prepare and approve forward-only AUTH v31 — COMPLETE; exact approval became canonical.
      - Execute AUTH v31 Step 1 — STOPPED / CONSUMED; one provider mutation attempt ended with `V31_RECOVERY_LINK_GENERATION_FAILED`, provider outcome `AMBIGUOUS`, exact historical response classification `UNKNOWN`, Steps 2-3 blocked/unconsumed, retry unauthorized.
      - Correct the direct Auth HTTP response parser/classification defect — COMPLETE through PR #110; historical v31 outcome remains ambiguous.
      - Prepare forward-only AUTH v32 with the corrected parser and existing v32 secret referenced by name only — COMPLETE AS REPOSITORY-LOCAL PREPARATION; plan `e8cd574a-a532-4c95-ab5d-5c069c1bbb96`, digest `sha256:c43b0b906bfb0c03e763d6cc5a13d47a900b40eb4db8fd904c799c524ec6c37c`, window `2026-09-17T15:00:00Z` through `2026-09-17T21:00:00Z`; pristine/unapproved/unexecuted, no provider contact or secret use.
      - Create the separate exact AUTH v32 owner approval — NEXT; no v32 provider action is authorized by preparation.
      - Execute and record one short-lived synthetic token lifecycle under exact v32 authority — NOT STARTED
      - Wire the hosted DEVELOPMENT trusted-identity adapter — NOT STARTED
      - Wire the hosted DEVELOPMENT DATA adapter with least privilege — NOT STARTED
      - Promote hosted readiness only after both dependencies verify independently — NOT STARTED
   7. Complete environment-scoped secrets, hosted observability, network enforcement, backup/recovery evidence, and remaining DEVELOPMENT operational controls. — NOT STARTED
   8. Certify isolated staging, restore/rollback, capacity, security, and production-change gates. — NOT STARTED
10. Begin Phase 6 orchestration, intelligence, monitoring, incidents, remediation, managed operations, outcomes, and continuous improvement. — DO NOT START YET

Required shared-core primitives such as n8n orchestration, communications adapters, and the single Stripe billing/usage-metering engine must be implemented centrally in Avuhz rather than per vertical. Their architectural requirement does not mean they are currently implemented; see `ARCHITECTURE.md` and `docs/current-build-state.md` for current truth.

Detailed phase contracts remain in their existing phase-specific documents. This file records sequence only.
