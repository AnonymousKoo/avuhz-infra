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
      - Enable the exact DEVELOPMENT hook under a separate authorization — NOT STARTED
      - Issue and locally validate one short-lived synthetic token — NOT STARTED
      - Wire the hosted DEVELOPMENT trusted-identity adapter — NOT STARTED
      - Wire the hosted DEVELOPMENT DATA adapter with least privilege — NOT STARTED
      - Promote hosted readiness only after both dependencies verify independently — NOT STARTED
   7. Complete environment-scoped secrets, hosted observability, network enforcement, backup/recovery evidence, and remaining DEVELOPMENT operational controls. — NOT STARTED
   8. Certify isolated staging, restore/rollback, capacity, security, and production-change gates. — NOT STARTED
10. Begin Phase 6 orchestration, intelligence, monitoring, incidents, remediation, managed operations, outcomes, and continuous improvement. — DO NOT START YET

Required shared-core primitives such as n8n orchestration, communications adapters, and the single Stripe billing/usage-metering engine must be implemented centrally in Avuhz rather than per vertical. Their architectural requirement does not mean they are currently implemented; see `ARCHITECTURE.md` and `docs/current-build-state.md` for current truth.

Detailed phase contracts remain in their existing phase-specific documents. This file records sequence only.
