# Avuhz Architecture Source of Truth

## Foundation and ownership

Avuhz is the governed foundation for building, operating, monitoring, automating, and improving systems. It owns reusable execution governance and may own reusable cross-domain systems.

Systems are not domains. A system belongs in Avuhz when unrelated domains can use its core implementation through provider-neutral policies, configuration, and contracts. A domain-specific system belongs in its domain or company repository.

Company business meaning, methodology, policies, offers, ICP, pricing and commercial rules, and specialized lifecycle behavior do not belong in Avuhz core. Avuhz must not hard-code branches for particular companies.

The conceptual composition is:

`SYSTEM -> DOMAIN -> COMPANY INSTANCE`

## Public boundary and dependency law

Domain/company code may depend on Avuhz public contracts. Avuhz must never depend on company or domain implementation internals. Shared databases and circular imports are not public integration contracts.

- `domain/company -> Avuhz public contracts`: allowed
- `Avuhz -> domain/company internals`: prohibited

JSON Schema 2020-12 is the canonical provider-neutral contract source. Commands request changes, authoritative records determine truth, and events describe accepted changes. Exact tenant, identity, version, digest, authority, idempotency, concurrency, and transactional-outbox boundaries remain mandatory.

## Sekinfra boundary

Sekinfra owns business-architecture consulting and OIA. OIA is a system, but it is owned by the Sekinfra domain because its methodology and business meaning are specialized.

Sekinfra discovers and defines approved work; Avuhz governs execution of that approved work. Avuhz must not know Sekinfra or OIA internals. Sekinfra may produce a provider-neutral `ImplementationHandoff` through Avuhz's public contract. `ImplementationBrief` binds the exact handoff ID, version, and digest and creates no authority beyond its governed lifecycle.

## Avuhz platform production boundary

Avuhz platform production means operating Avuhz's own command/query services, workers, data stores, identity integration, and observability. It is distinct from deploying a client-system artifact. A Phase 5 `DeploymentAuthorization` governs only its exact client artifact and target; it neither approves an Avuhz platform release nor grants access to Avuhz production infrastructure. Avuhz platform changes use the engineering change policy in `SECURITY.md`.

The minimum production topology is:

- a stateless command/query API that constructs `TrustedExecutionContext`, validates canonical contracts, executes commands through the existing UnitOfWork, and exposes bounded health/read surfaces; read routes derive tenant from trusted context and require `engagement:read`;
- a separate idempotent outbox worker that publishes committed lifecycle events with retry, backoff, dead-letter handling, and no direct authority creation;
- isolated PostgreSQL DATA storage with encrypted transport/storage, tenant RLS, bounded service grants, connection pooling, migration ownership, backups, point-in-time recovery, and restore testing;
- an AUTH issuer that authenticates humans and workloads and maps issuer, subject, audience, tenant, environment, authentication strength, and approved role/capability facts into trusted context outside caller payloads;
- an approved secret manager and distinct short-lived identities for command service, read service, outbox worker, migration runner, observability exporter, and CI deployer;
- immutable versioned application artifacts built once and promoted by digest through development, staging, and production;
- structured sanitized logging, metrics, traces, alerts, audit retention, and health objectives for API, database, migrations, command failures, stale writes, idempotency conflicts, RLS denials, and outbox lag/failure; and
- environment-gated CI/CD with separately approved application, migration, rollback, and recovery procedures.

No production service may embed credentials, accept direct browser/n8n writes to authoritative tables, reuse a human identity as a workload, or treat an event/read model as authoritative truth.

## Environment model

Mutable data, identity issuers/clients, secrets, service identities, network policy, observability, and deployment authority are isolated by environment. The same immutable artifact digest is promoted; configuration is injected at runtime and never copied between environments.

| Environment | Purpose | Data and identity | Change boundary |
|---|---|---|---|
| `LOCAL` | Developer and disposable certification | Local/disposable PostgreSQL and fictional identities/data only | No remote access; reset/replay allowed only for the explicit local target |
| `DEVELOPMENT` | Shared integration of incomplete changes | Dedicated non-production AUTH/DATA targets and synthetic data | Automatic deployment may follow green CI; no production secrets or customer data |
| `STAGING` | Production-like release, migration, security, recovery, and load proof | Dedicated staging AUTH/DATA targets; synthetic or approved de-identified data | Protected deployment with human approval; production topology and policies must be represented |
| `PRODUCTION` | Avuhz platform service for real tenants | Dedicated production AUTH/DATA targets, identities, keys, logs, and backups | Exact artifact/environment approval, protected deploy identity, change window, verification, and rollback evidence required |

No environment may share mutable AUTH/DATA projects, service credentials, secret namespaces, tenant claims, or write-capable identities with another. Production data must never flow to lower environments unless separately approved, minimized, and irreversibly de-identified.

## Owner-authorized environment registry

Every connected environment requires one owner-approved registry record outside business state. Non-secret selection metadata may be recorded here; credentials, authenticated connection strings, and secret-bearing configuration remain outside Git. The minimum fields are:

- environment ID/class and owner;
- DATA project/database and migration-target references;
- AUTH project/issuer, allowed audience, and client references;
- tenant identity claim and exact `TrustedExecutionContext.tenant_id -> avuhz.tenant_id` bridge;
- RLS policy/version and trusted command-service identity;
- read-service, outbox-worker, migration-runner, observability-exporter, and CI-deployer identities;
- runtime/deployment target and artifact-registry references;
- secret-manager namespace/reference and key/fingerprint version policy;
- logging/metrics/tracing destination references and retention policy;
- backup policy, recovery-point objective, recovery-time objective, and restore-test owner;
- approved network boundaries/origins; and
- application, migration, security, production-change, and emergency-approval owners.

Missing, ambiguous, stale, or cross-environment registry values fail closed and block connected testing, migration, or deployment. Local Supabase link metadata is not an environment registry and is never proof of owner approval.

### Registered environment selections

This is the single canonical record of owner-approved, non-secret project selection. Registration does not authorize connection, migration, deployment, or mutation.

| Field | Development | Staging | Production |
|---|---|---|---|
| Environment | `development` | `staging` | `UNCONFIGURED` |
| Supabase project reference | `pwlhruwutoitnieactol` | `gnuqaefotwgkwurjpyik` | Project not created |
| Supabase base URL | `https://pwlhruwutoitnieactol.supabase.co` | `https://gnuqaefotwgkwurjpyik.supabase.co` | Unconfigured |
| AUTH project | `pwlhruwutoitnieactol` | `gnuqaefotwgkwurjpyik` | Unconfigured |
| DATA project | `pwlhruwutoitnieactol` | `gnuqaefotwgkwurjpyik` | Unconfigured |
| Tenant bridge | `TrustedExecutionContext.tenant_id -> avuhz.tenant_id` | `TrustedExecutionContext.tenant_id -> avuhz.tenant_id` | Unconfigured |
| Remote mutation | Not authorized | Not authorized | Not authorized |

Production is unconfigured and its project does not exist. No entry contains credentials or secret material, and no entry establishes that a project was contacted, validated, migrated, or made deployment-ready.

### Development and staging production-readiness references

`DEFINED_LOGICAL` means the stable provider-neutral reference and its separation semantics are defined, but it is not a provider binding or authority grant. `OWNER_VALUE_REQUIRED` means the stable reference slot is defined but its real provider resource, policy, or attributable human owner must still be supplied and approved. Both statuses fail closed for connected use until every required binding and separate connection authorization exists.

| Reference | Development | Status | Staging | Status |
|---|---|---|---|---|
| Command service identity | `avuhz_command_service_dev` | `DEFINED_LOGICAL` | `avuhz_command_service_staging` | `DEFINED_LOGICAL` |
| Outbox worker identity | `avuhz_outbox_worker_dev` | `DEFINED_LOGICAL` | `avuhz_outbox_worker_staging` | `DEFINED_LOGICAL` |
| Migration identity | `avuhz_migration_service_dev` | `DEFINED_LOGICAL` | `avuhz_migration_service_staging` | `DEFINED_LOGICAL` |
| CI identity | `avuhz_ci_service_dev` | `DEFINED_LOGICAL` | `avuhz_ci_service_staging` | `DEFINED_LOGICAL` |
| AUTH issuer reference | `auth-issuer.avuhz.development` | `OWNER_VALUE_REQUIRED` | `auth-issuer.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Command-service audience | `audience.avuhz.command-service.development` | `DEFINED_LOGICAL` | `audience.avuhz.command-service.staging` | `DEFINED_LOGICAL` |
| Outbox-worker audience | `audience.avuhz.outbox-worker.development` | `DEFINED_LOGICAL` | `audience.avuhz.outbox-worker.staging` | `DEFINED_LOGICAL` |
| Migration audience | `audience.avuhz.migration.development` | `DEFINED_LOGICAL` | `audience.avuhz.migration.staging` | `DEFINED_LOGICAL` |
| CI audience | `audience.avuhz.ci.development` | `DEFINED_LOGICAL` | `audience.avuhz.ci.staging` | `DEFINED_LOGICAL` |
| Tenant/RLS policy | `policy.avuhz.tenant-rls.development.v1` | `DEFINED_LOGICAL` | `policy.avuhz.tenant-rls.staging.v1` | `DEFINED_LOGICAL` |
| Secrets provider/reference boundary | `secrets.avuhz.development` | `OWNER_VALUE_REQUIRED` | `secrets.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Observability | `observability.avuhz.development` | `OWNER_VALUE_REQUIRED` | `observability.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Runtime/deployment target | `runtime-target.avuhz.development` | `OWNER_VALUE_REQUIRED` | `runtime-target.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Network boundary | `network-boundary.avuhz.development` | `OWNER_VALUE_REQUIRED` | `network-boundary.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Backup/recovery | `recovery.avuhz.development` | `OWNER_VALUE_REQUIRED` | `recovery.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Rollback | `rollback.avuhz.development` | `OWNER_VALUE_REQUIRED` | `rollback.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Platform-owner approval | `approval-owner.platform.avuhz.development` | `OWNER_VALUE_REQUIRED` | `approval-owner.platform.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Security-owner approval | `approval-owner.security.avuhz.development` | `OWNER_VALUE_REQUIRED` | `approval-owner.security.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Data/migration-owner approval | `approval-owner.data-migration.avuhz.development` | `OWNER_VALUE_REQUIRED` | `approval-owner.data-migration.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Deployment-owner approval | `approval-owner.deployment.avuhz.development` | `OWNER_VALUE_REQUIRED` | `approval-owner.deployment.avuhz.staging` | `OWNER_VALUE_REQUIRED` |

The tenant bridge remains exactly `TrustedExecutionContext.tenant_id -> avuhz.tenant_id`. Runtime identities receive tenant-scoped grants only and must never own authoritative tables or receive `BYPASSRLS`, universal tenant access, or migration authority. The outbox worker may claim and publish only tenant-bound committed outbox intents. The migration identity is separate from command, worker, and CI identities; schema/DDL authority cannot be exercised through an application runtime identity. CI identity and simulated approval never imply migration, deployment, or human authority.

Development and staging identities, audiences, targets, policies, secret namespaces, and approvals must resolve independently; no cross-environment reuse is allowed. Production has no logical or provider references, remains `UNCONFIGURED`, and has no connection, mutation, migration, deployment, or change authority.

## Engineering orchestration boundary

Codex, Claude, and other engineering agents are equivalent untrusted engineering workloads. They may inspect authorized repositories, create bounded branches/patches, run local or CI checks, prepare evidence, draft pull-request/change summaries, and propose remediation. They may not supply trusted human identity, approve or merge their own work, weaken tests/policy, access production secrets, select or alter a production registry target, apply a production migration, deploy, attest success without evidence, or create client/platform deployment authority.

An engineering orchestrator may sequence deterministic build/test/scan/evidence steps and resume failed work, but it remains a command client. GitHub protections, CI environment gates, secret-manager policy, trusted service identities, and attributable humans establish authority. This boundary introduces no Phase 6 AI, orchestration, monitoring, incident, or managed-operations product behavior.

## Autonomous engineering dry-run

The safe readiness rehearsal is:

1. Pin an exact source commit, change manifest, dependency lock, contract catalog, and target environment class.
2. Build one immutable artifact in an isolated runner and record its digest, dependency inventory/SBOM, build provenance, and tool versions.
3. Run contract, runtime, persistence, migration replay, RLS/tenant, atomicity, static analysis, secret, dependency, and artifact scans; retain bounded reports.
4. Generate a diff/risk summary and required application, data, identity, security, and rollback evidence; an agent may draft but not approve it.
5. Require the risk-class approvals defined in `SECURITY.md`; the artifact digest and environment registry version become immutable approval inputs.
6. Deploy only to a disposable local target or approved isolated staging target using the protected deploy identity and a no-client-mutation configuration.
7. Verify health, exact artifact digest, schema version, identity/tenant denial, command atomicity, outbox delivery, logs/alerts, and backup/restore evidence independently of deployment execution.
8. Rehearse application rollback to the preceding exact artifact and database recovery/forward correction without rewriting immutable business history.
9. Produce a sanitized evidence bundle and explicit pass/fail decision. Any missing evidence, failed gate, stale approval, target mismatch, or rollback failure blocks production promotion.

The local-only runner implements steps 1-5 and 9 for the service/worker wheel: it binds an exact source tree, runs fixed build/test/contract/migration/security checks, records bounded digest-bound evidence, and requires an explicit non-authoritative simulated decision. Steps 6-8 remain unimplemented. The runner cannot deploy a target, contact remote infrastructure, establish human approval, establish production readiness, or attest deployment success.
