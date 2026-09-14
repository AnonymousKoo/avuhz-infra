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
   5. Establish and certify DEVELOPMENT provider foundations. — FOUNDATION COMPLETE
      - DEVELOPMENT AUTH project separation and migration identity — COMPLETE
      - Hardened custom access-token hook creation and ACL — COMPLETE
      - AUTH migration-identity seal and disabled-hook verification — COMPLETE through AUTH v16
      - DEVELOPMENT DATA canonical 16-table baseline — COMPLETE
      - DATA migration-identity seal, tenant-RLS verification, and search-path repair — COMPLETE through DATA v3 and the separate repair track
   6. Complete DEVELOPMENT identity validation and hosted runtime integration. — NEXT
      - Create one dedicated synthetic DEVELOPMENT Auth identity under a fresh forward-only plan — NEXT BOUNDARY
      - Bind provider-controlled tenant metadata — NOT STARTED
      - Bind the exact server-owned read-only allowlist tuple — NOT STARTED
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
