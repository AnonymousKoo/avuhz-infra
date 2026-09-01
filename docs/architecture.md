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

The DEVELOPMENT deployment composition is separate from the unchanged LOCAL/TEST adapter. It may bind `0.0.0.0` and the platform-supplied `PORT`, but it must match the exact approved development registry and may never use a local/static trusted identity resolver. Startup/liveness do not imply dependency readiness; command/query access and readiness fail closed until separately authorized data and trusted-identity adapters are present. This composition creates no provider connection, deployment, or mutation authority and has no staging or production mode.

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

`DEFINED_LOGICAL` means the stable provider-neutral reference and its separation semantics are defined, but it is not a provider binding or authority grant. `OWNER_APPROVED_BINDING` means an exact non-secret value has been supplied; it is not connection or change authorization. `OWNER_APPROVED_POLICY` means the policy is frozen but no execution authority is granted. `OWNER_VALUE_REQUIRED` means the stable reference slot exists but a concrete resource or binding is still missing. Every status fails closed for connected use until all required bindings and separate connection authorization exist.

| Reference | Development | Status | Staging | Status |
|---|---|---|---|---|
| Environment owner | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` |
| Command service identity | `avuhz_command_service_dev` | `DEFINED_LOGICAL` | `avuhz_command_service_staging` | `DEFINED_LOGICAL` |
| Outbox worker identity | `avuhz_outbox_worker_dev` | `DEFINED_LOGICAL` | `avuhz_outbox_worker_staging` | `DEFINED_LOGICAL` |
| Migration identity | `avuhz_migration_service_dev` | `DEFINED_LOGICAL` | `avuhz_migration_service_staging` | `DEFINED_LOGICAL` |
| CI identity | `avuhz_ci_service_dev` | `DEFINED_LOGICAL` | `avuhz_ci_service_staging` | `DEFINED_LOGICAL` |
| AUTH issuer reference | `https://pwlhruwutoitnieactol.supabase.co/auth/v1` | `OWNER_APPROVED_BINDING` | `https://gnuqaefotwgkwurjpyik.supabase.co/auth/v1` | `OWNER_APPROVED_BINDING` |
| Command-service audience | `audience.avuhz.command-service.development` | `DEFINED_LOGICAL` | `audience.avuhz.command-service.staging` | `DEFINED_LOGICAL` |
| Outbox-worker audience | `audience.avuhz.outbox-worker.development` | `DEFINED_LOGICAL` | `audience.avuhz.outbox-worker.staging` | `DEFINED_LOGICAL` |
| Migration audience | `audience.avuhz.migration.development` | `DEFINED_LOGICAL` | `audience.avuhz.migration.staging` | `DEFINED_LOGICAL` |
| CI audience | `audience.avuhz.ci.development` | `DEFINED_LOGICAL` | `audience.avuhz.ci.staging` | `DEFINED_LOGICAL` |
| Tenant/RLS policy | `policy.avuhz.tenant-rls.development.v1` | `DEFINED_LOGICAL` | `policy.avuhz.tenant-rls.staging.v1` | `DEFINED_LOGICAL` |
| Secrets provider/reference boundary | Render runtime secrets plus GitHub CI/environment secrets; `secrets.avuhz.development` | `OWNER_VALUE_REQUIRED` | Render runtime secrets plus GitHub CI/environment secrets; `secrets.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Observability | Grafana Cloud via OpenTelemetry; `observability.avuhz.development` | `OWNER_VALUE_REQUIRED` | Grafana Cloud via OpenTelemetry; `observability.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Runtime/deployment target | Registered DEVELOPMENT Render service below; `runtime-target.avuhz.development` | `OWNER_APPROVED_BINDING` | Render; `runtime-target.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Network boundary | Approved policy below; `network-boundary.avuhz.development` | `OWNER_VALUE_REQUIRED` | Approved policy below; `network-boundary.avuhz.staging` | `OWNER_VALUE_REQUIRED` |
| Backup/recovery | Approved rebuild policy below; `recovery.avuhz.development` | `OWNER_APPROVED_POLICY` | Approved rebuild policy below; `recovery.avuhz.staging` | `OWNER_APPROVED_POLICY` |
| Rollback | Approved artifact/forward-correction policy below; `rollback.avuhz.development` | `OWNER_APPROVED_POLICY` | Approved artifact/forward-correction policy below; `rollback.avuhz.staging` | `OWNER_APPROVED_POLICY` |
| Platform-owner approval | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` |
| Security-owner approval | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` |
| Data/migration-owner approval | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` |
| Deployment-owner approval | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` | `github:AnonymousKoo` | `OWNER_APPROVED_BINDING` |

#### Development Render service binding and bounded health evidence

This owner-confirmed record identifies the existing DEVELOPMENT command/query web service and the exact deployed source. It records observed bounded health results; it grants no provider access, DATA/AUTH connection, migration, secret, staging, production, or further deployment authority.

| Field | Owner-confirmed value |
|---|---|
| Provider | Render |
| Project | `Avuhz` |
| Environment | `development` |
| Service name | `avuhz-command-dev` |
| Service identifier | `srv-dab9n4qd0e5s73dq37mg` |
| Public service URL | `https://avuhz-command-dev.onrender.com` |
| Region | Virginia (US East) |
| Source repository | `AnonymousKoo/avuhz-infra` |
| Source branch | `main` |
| Deployed source commit | `6bff57065151462fc74861c68a232454b2ef9a20` |
| Build command | `python -m pip install .` |
| Start command | `avuhz-service-development` |
| Health path | `/health/live` |
| Deployment evidence | `SUCCESS` |
| Liveness evidence | `GET /health/live` returned `200` |
| Readiness evidence | `GET /health/ready` returned `503`, intentionally fail-closed until DATA and trusted-identity adapters exist |
| Authority boundary | No connected DATA/AUTH validation or remote mutation is authorized |

The owner references identify the currently attributable owner for each approval class. They do not constitute approval of a connection, provider-resource creation, migration, deployment, or other change.

#### Approved providers and unresolved resources

- Render is the approved development/staging runtime provider, and the exact DEVELOPMENT command-service binding is recorded above. No Render service or deployment-target identifier is defined or claimed to exist for staging.
- Render runtime secrets and GitHub CI/environment secrets are the approved secret-delivery boundaries. No secret value, secret name, environment identifier, namespace identifier, or credential is recorded here.
- Grafana Cloud via OpenTelemetry is the approved observability path. No Grafana organization, stack, destination, endpoint, authentication, or collector resource is defined or claimed to exist.
- The recorded DEVELOPMENT service and provider choices grant no resource-change or connection authority. Staging runtime and all unresolved environment-scoped secret, observability, network-enforcement, DATA, and AUTH resources remain `OWNER_VALUE_REQUIRED`.

#### Non-production recovery policy

Development and staging are rebuildable non-production environments containing synthetic/non-production data only. Git migrations are canonical. Before a risky migration, an authorized operator must create a logical dump through a separately authorized procedure. Recovery is rebuild, replay canonical migrations, and seed approved synthetic data. No point-in-time-recovery capability is claimed. This policy grants no dump, migration, restoration, or provider access authority.

#### Rollback policy

Application rollback uses the preceding exact application artifact. Database changes use forward correction by default. Destructive migrations are prohibited until a later separately approved policy changes that boundary. Data-restoration rollback remains unauthorized.

#### Network policy

Public ingress is permitted only to the command/query service. The worker has no public inbound endpoint. Outbound access is restricted to the approved environment's Supabase and telemetry destinations. Development and staging resources and credentials remain isolated. Concrete Render, Supabase, Grafana/OpenTelemetry, DNS, firewall, routing, origin, and egress enforcement bindings are not defined by this policy and remain `OWNER_VALUE_REQUIRED`; no universal runtime or tenant bypass is permitted.

The tenant bridge remains exactly `TrustedExecutionContext.tenant_id -> avuhz.tenant_id`. Runtime identities receive tenant-scoped grants only and must never own authoritative tables or receive `BYPASSRLS`, universal tenant access, or migration authority. The outbox worker may claim and publish only tenant-bound committed outbox intents. The migration identity is separate from command, worker, and CI identities; schema/DDL authority cannot be exercised through an application runtime identity. CI identity and simulated approval never imply migration, deployment, or human authority.

Development and staging identities, audiences, targets, policies, secret namespaces, and approvals must resolve independently; no cross-environment reuse is allowed. Production has no logical or provider references, remains `UNCONFIGURED`, and has no connection, mutation, migration, deployment, or change authority.

### DEVELOPMENT AUTH/DATA adapter and connected-validation package

This package is a frozen plan, not provider access or runtime wiring. AUTH and DATA remain separate responsibilities even though both currently select Supabase project `pwlhruwutoitnieactol`. The hosted DEVELOPMENT service stays fail-closed until each real adapter is implemented, independently validated, explicitly wired, and approved.

| Boundary | Required composition | Fail-closed output | Explicit exclusions |
|---|---|---|---|
| Trusted DEVELOPMENT identity | A provider adapter implements only the existing `DevelopmentIdentityVerifier.verify` port. It validates an untrusted bearer token against the exact DEVELOPMENT issuer, audience, signature algorithm/key, lifetime, subject, tenant claim, and server-owned capability policy, then emits only `VerifiedDevelopmentIdentityEvidence`. The existing `DevelopmentTrustedIdentityResolver` alone constructs `TrustedExecutionContext`. | Invalid, stale, malformed, cross-issuer, cross-audience, missing-tenant, unknown-subject, unsupported-capability, or authority-bearing evidence raises the existing bounded denial and never reaches command/query execution. | No local/static resolver, admin-user lookup, raw provider payload persistence, caller-selected capabilities, human authority, alternate command path, or provider SDK authority path. |
| DEVELOPMENT DATA | A provider connection factory supplies a transaction-capable PostgreSQL connection to the existing `PostgresStore`; commands and reads continue through the existing `PostgresUnitOfWork`, repository ports, CommandExecutor, expected-version, idempotency, event, and outbox paths. UnitOfWork transaction-locally binds the verified `TrustedExecutionContext.tenant_id` to `avuhz.tenant_id`. | Missing/mismatched configuration, unavailable connection, wrong database role, superuser/`BYPASSRLS`, absent canonical schema/RLS, or missing trusted tenant keeps readiness unavailable and denies work. | No PostgREST/direct-table mutation path, no parallel repository, no universal tenant, no schema ownership, no DDL, no migration execution, and no fallback to a provider service-role credential. |

#### Least-privilege credential model

- AUTH signature verification uses the exact issuer public verification material and requires no provider credential when the issuer exposes asymmetric public keys. The runtime bearer token is request-scoped untrusted input, is never a server credential, and must never be logged, persisted, or included in evidence. If the approved issuer cannot be verified without symmetric secret material, an exact environment-scoped verification-secret reference becomes `OWNER_VALUE_REQUIRED` and validation stops; a Supabase service-role key is not an acceptable substitute.
- The first AUTH discovery check uses no credential, anon key, user session, admin API, or service-role key. A later end-to-end token check requires a separately approved short-lived synthetic DEVELOPMENT identity and token-delivery procedure; it is outside this package.
- The exact signed DEVELOPMENT tenant-claim name and the server-owned subject/caller/capability policy binding remain `OWNER_VALUE_REQUIRED`. The adapter must not default to caller-editable user metadata, accept token-provided authority roles, or infer these values from DATA.
- DATA runtime requires one environment-scoped database login credential resolved only at runtime from the approved Render secret boundary. Its login role may inherit only the canonical no-login `avuhz_command_service` role: database `CONNECT`, schema `USAGE`, and the exact table/column grants in the canonical migration. It receives no ownership, schema `CREATE`, DDL, `DELETE`, `TRUNCATE`, `TRIGGER`, `REFERENCES`, replication, superuser, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, migration, cross-tenant, or provider-admin authority.
- The concrete DEVELOPMENT database endpoint reference, runtime login binding, and secret-manager reference remain `OWNER_VALUE_REQUIRED`. Values stay outside Git, prompts, logs, evidence, and generated output. The separate `avuhz_migration_service_dev` authority is excluded from both connected-validation steps; the command identity cannot assume it and CI cannot substitute for it.

#### First connected validation

AUTH and DATA are separately reviewable and separately authorized. AUTH is first. Passing either step proves only that bounded dependency evidence; it does not make hosted readiness true, authorize adapter wiring, permit a command, or authorize migration/provider change.

1. **AUTH discovery:** perform exactly one credential-free `GET` to `https://pwlhruwutoitnieactol.supabase.co/auth/v1/.well-known/jwks.json`, with redirects disabled and a bounded response size/time. Record only UTC attempt time, exact target, HTTP status, content type, response SHA-256, key count, and boolean structural/algorithm checks. Do not retain the raw response. Stop on redirect, origin/path mismatch, credential request, non-`200`, invalid content type/JSON/JWKS, unsupported algorithm/key type, duplicate/missing key identity, oversized response, timeout, or any secret-shaped content. Do not test sign-in, users, sessions, claims, tokens, or DATA.
2. **DATA catalog/RLS validation:** only after separate authorization and owner binding of the exact non-secret database endpoint, runtime login identity, and secret-manager reference, open one connection as that runtime identity and immediately begin a read-only transaction. Inspect only current database/user role attributes, the 16 canonical `avuhz_*` table identities, canonical migration-compatible columns/constraints, RLS enablement/policy expressions, and effective grants. Compare locally to the committed migration; emit only counts, booleans, expected/actual digests, safe error codes, and timestamps; then roll back and close. Stop on endpoint/project mismatch, credential-resolution failure, unexpected role membership or grants, superuser/`BYPASSRLS`, missing/extra schema objects, RLS/policy mismatch, any non-synthetic row requirement, any attempted write/DDL, or any request for migration/service-role authority. Do not inspect business rows or AUTH data.

The AUTH evidence is reviewed before requesting DATA authorization. A failure stops that step and creates no authority to repair provider state. DATA failure stops without migration, grant, RLS, schema, credential, Render, or provider changes. Evidence is bounded and secret-free; command output, connection strings, tokens, raw provider responses, and tenant/business data are prohibited.

#### Exact owner-authorization text

The first provider call remains prohibited until the owner supplies this exact authorization in a new request:

> I, `github:AnonymousKoo`, authorize the bounded DEVELOPMENT AUTH discovery validation defined in `docs/architecture.md` against only `https://pwlhruwutoitnieactol.supabase.co/auth/v1/.well-known/jwks.json`: one credential-free GET, redirects disabled, bounded metadata evidence only, no token/user/session access, no DATA access, no mutation, no Render change, no staging/production, and stop on every documented condition. This authorization expires when that single validation completes or fails.

DATA remains unauthorized after that call. Before the DATA call, the owner must provide the exact non-secret database endpoint reference, runtime login identity binding, and secret-manager reference without revealing a secret value, then supply this separate authorization:

> I, `github:AnonymousKoo`, authorize the bounded DEVELOPMENT DATA catalog/RLS validation defined in `docs/architecture.md` against only Supabase project `pwlhruwutoitnieactol`, using the separately owner-bound runtime database endpoint, login identity, and secret-manager references: one read-only transaction, catalog/role/grant/RLS inspection only, rollback and close, bounded secret-free evidence, no business-row or AUTH-data access, no writes, no DDL, no migration, no service-role access, no grant/RLS/schema repair, no Render change, no staging/production, and stop on every documented condition. This authorization expires when that single validation completes or fails.

Neither authorization permits credential creation, provider configuration, adapter deployment/wiring, readiness changes, remediation, or a second call.

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
