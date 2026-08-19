# Phase 3 persistence readiness

The runtime validates, guards, performs bounded Slice 1 domain changes in memory, records idempotency outcomes, and stages one event plus one pending outbox intent atomically. Future persistence must implement the repository ports, tenant-scoped lookups, optimistic version comparison plus mutation in one transaction, idempotency reservation uniqueness, and mutation/result/event/outbox atomicity. Human approvals must be loaded, active, tenant-bound, and scope/version/digest-bound.

Before Supabase work: confirm data/auth projects and environment, identity and tenant/RLS mapping, workload identities, migration ownership, credential remediation, and production keyed-fingerprint management. No connection details belong here.
