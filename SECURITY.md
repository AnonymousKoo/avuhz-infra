# Security Baseline

## Non-negotiable rules

1. No raw credential material in this repository.
2. No legacy workflow export, migration, project-link metadata, environment file, provider payload, or forensic artifact may be copied into this tree.
3. No direct n8n authoritative database write surface is permitted.
4. Canonical internal identifiers are distinct from opaque external/provider references.
5. Contract fixtures use only explicit fictional test values.
6. Every commit must pass schema validation, fixture validation, secret scanning, and forbidden-file/path checks.
7. Trusted execution context and separate attributable human approval records determine authority; caller payloads do not.
8. Tenant-scoped repositories and RLS must fail closed for missing or cross-tenant identity.
9. No remote database or infrastructure mutation is permitted without explicit owner authorization for the exact target and environment.

## Local security gate

Run `./scripts/check-baseline.sh` before staging or committing. A failed check blocks the commit. Tool or rule exceptions require explicit security-owner review and must never disclose a suspected value.

## External systems

This baseline is unconnected. Owner-approved non-secret development/staging project selections are recorded only in the canonical environment registry in `docs/architecture.md`; registration grants no connection or mutation authority. The repository contains no n8n credential, provider integration, production secret, or deployment configuration. The provider-neutral baseline is the candidate canonical initial migration for a proven-empty Avuhz schema and starts an ordered Git lineage, but remote application remains unauthorized by default. Repository registration, local replay, or candidate status never authorizes a provider read, migration, history repair, or mutation.

## Production secrets and provider configuration

- Secrets exist only in an approved environment-scoped secret manager and are delivered at runtime through a short-lived workload identity. GitHub variables may hold non-secret opaque references only. The DEVELOPMENT-only Supabase Auth-admin bootstrap provider-secret exception below is the sole current exception and does not apply to STAGING or PRODUCTION.
- Environments use separate secret namespaces, keys, issuers, service identities, and rotation schedules. Production secrets are never available to pull requests, forks, developer shells, lower environments, AI agents, or general-purpose automation.
- Workloads receive least-privilege, audience-bound credentials only for their single role. Shared service-role keys, long-lived static credentials, authenticated URLs, and credential-bearing provider payloads are prohibited except for the exact DEVELOPMENT-only Supabase Auth-admin bootstrap provider-secret exception below. That exception may not be generalized, inherited, or reused by other workloads.
- Logs, traces, errors, evidence bundles, command/event records, and CI artifacts must redact secret values and minimize customer/business payloads. Secret scanning runs before artifact publication.
- Rotation, revocation, break-glass access, and suspected-exposure response require attributable human authorization and audit evidence. Break-glass access is time-bound and cannot bypass tenant or authority checks.
- Provider configuration is an allowlisted, schema-validated reference owned by the environment registry. Unknown endpoints, mutable-latest targets, and caller-selected provider credentials fail closed.
- The canonical logical reference names and resolution statuses exist only in `docs/architecture.md`. `DEFINED_LOGICAL` is not a provider binding; `OWNER_VALUE_REQUIRED` blocks connected use. Neither status grants access, approval, migration, deployment, or production truth.
- Command, outbox, migration, and CI workloads use distinct environment-scoped identities and audiences. Application/runtime identities never receive table ownership, `BYPASSRLS`, universal tenant access, or migration authority; the migration identity is separately gated and cannot be substituted by CI.

## DEVELOPMENT Supabase Auth-admin ephemeral execution class

`SUPABASE_AUTH_ADMIN_EPHEMERAL` is an authorization-engine **execution capability label**, not a credential value, key format, service-role alias, or permission to obtain a provider secret. Agents must actively enforce all of the following before a future plan may use this class:

- The plan environment must be exactly `DEVELOPMENT`, the provider must be `supabase`, the responsibility must be `AUTH`, the execution class must be `PROVIDER_MUTATION`, and the operation must be in the `provider.auth-*` namespace. Any other environment, provider, responsibility, execution class, or operation stops.
- The class must be the only allowed credential class for that step. It may not be mixed with `OWNER_INTERACTIVE_SESSION`, `MIGRATION_IDENTITY`, `SYNTHETIC_IDENTITY`, `EPHEMERAL_SYNTHETIC_ACCESS_TOKEN`, `SERVICE_ROLE`, or any fallback class.
- Credential material may originate only from an approved environment secret boundary and may exist only inside the approved server-side executor's memory for the bounded operation. The repository, agent, browser, plan engine, approval record, progress record, preflight request, evidence bundle, CI job output, logs, traces, or user-visible response may not retrieve or receive the material.
- The control plane may carry only the class label. The credential value, hash, digest, fingerprint, prefix-expanded value, connection string, provider payload, or derived reversible representation must not be stored, returned, logged, copied, exported, committed, or attached as evidence.
- Provider capability is proven only through a non-secret executor-capability attestation with evidence type `auth.admin-executor-capability.observed`. That assertion is `DIGEST_ONLY`; its digest represents the non-secret executor capability reference, **never** the credential material.
- Plans using the class must explicitly prohibit `credential.persist`, `credential.expose`, `credential.log`, `credential.return`, `credential.digest`, `credential.copy`, `credential.create`, `credential.rotate`, and `credential.export` at both plan and step scope.
- A plan using the class must not model the credential as an `EPHEMERAL_SENSITIVE` binding. The secret is outside the Avuhz control-plane model; only executor capability is modeled.
- The class does not itself waive the prohibition on shared service-role keys or long-lived static credentials. A concrete binding must satisfy the normal workload-identity rule unless it is covered by the exact DEVELOPMENT-only Supabase Auth-admin bootstrap provider-secret exception below. No other exception is implied.
- The canonical baseline must scan for modern Supabase secret-key prefixes in addition to the existing credential-shaped-content and Semgrep rules. A suspected match is treated as exposure: stop and remediate without printing the value.
- Existence of this class grants no provider authority. Secret retrieval, executor binding, plan approval, provider preflight, provider execution, outcome persistence, metadata binding, hook enablement, token issuance, DATA access, Render changes, STAGING, and PRODUCTION each remain separate authorization boundaries as applicable.
- AUTH v20 remains immutable and `DRAFT_BLOCKED`; do not rewrite it to consume this class. A new forward-only AUTH plan (v21 or later) is required before any synthetic-identity provider attempt.

## DEVELOPMENT Supabase Auth-admin bootstrap provider-secret exception

This exception exists only because the hosted Supabase Auth Admin API currently requires an elevated server-side API key and does not provide a short-lived, least-privilege workload-identity credential for the required Admin operation. It is a narrow bootstrap exception, not a replacement for Avuhz workload identity and not authority to create or use a provider credential by itself.

Agents must enforce every rule below before any credential is created, bound, tested, used, rotated, or revoked under this exception:

- Scope is exactly environment `DEVELOPMENT`, provider `supabase`, responsibility `AUTH`, project reference `pwlhruwutoitnieactol`. DEVELOPMENT DATA project `gnuqaefotwgkwurjpyik`, STAGING, PRODUCTION, Render, n8n, vertical-specific infrastructure, and all other provider resources are outside this exception.
- The provider credential must be a dedicated modern Supabase secret API key (`sb_secret_...`) created only for the shared Avuhz DEVELOPMENT Auth-admin bootstrap executor. The legacy JWT `service_role` key, a shared default secret, a key reused by another service, or a credential copied from another environment is prohibited.
- The credential may be stored only in Supabase's provider-side key store and the approved `development` GitHub Environment secret boundary. It may be injected only into the approved server-side Auth-admin executor for a separately authorized bounded operation.
- The raw credential value must never enter this repository, ChatGPT or any AI-agent context, browser-visible application code, PR text, issue text, plan/approval/progress records, evidence, logs, traces, command output, artifacts, user-visible responses, or shell history. The control plane may record only non-secret references and capability attestations.
- GitHub repository variables are not an allowed storage location. Pull-request jobs, forks, local developer shells, n8n workflows, dashboards, vertical services, and general-purpose automation must never receive the credential.
- Credential creation is a distinct provider mutation. GitHub Environment secret binding is a distinct secret-manager mutation. Capability certification is a distinct read-only executor action. Auth-user creation is a distinct provider mutation. Credential revocation/deletion is a distinct provider mutation. Each requires its own exact target confirmation and explicit owner authorization; none may be silently bundled into another boundary.
- The executor may use the credential only for the exact allowlisted Supabase Auth Admin operation authorized by the current bounded plan. It must not provide arbitrary pass-through access to Supabase, PostgREST, Storage, Realtime, SQL, Management API, or the DATA project.
- Before each use, the executor must confirm the exact environment, provider, AUTH project reference, bounded plan/version/digest, authorization window, operation, and credential class. Drift, expiry, unexpected remote state, missing capability evidence, or any request for broader privilege stops execution.
- The executor must not log HTTP request headers, provider response bodies containing user data, secret prefixes, hashes, fingerprints, or credential-derived identifiers. PII returned by a read-only capability probe must remain ephemeral and must not be persisted as evidence.
- The dedicated bootstrap key must be revoked or deleted immediately after the authorized bootstrap sequence completes, or immediately when the associated authorization expires, is stopped, becomes ambiguous, or is abandoned. A key created for one authorization window may not be carried forward into a later plan without fresh explicit authorization.
- This exception does not authorize weakening RLS, granting `BYPASSRLS` to Avuhz application identities, changing database ownership, modifying Auth hook state, creating sessions/tokens, binding tenant metadata, or touching the DATA project.
- This exception does not authorize a permanent runtime design. The future shared Avuhz Identity Admin Broker must receive its own architecture, threat model, credential lifecycle, authorization contract, implementation review, and provider authorization. It may not inherit or reuse the bootstrap key by default.
- Any suspected exposure, unexpected consumer, secret-manager misbinding, provider-project mismatch, inability to prove dedicated-key lifecycle, or inability to revoke the key is a stop condition. State the exposure or ambiguity clearly and do not proceed until resolved.

## GitHub and CI/CD controls

- Work occurs on bounded feature branches through pull requests. `main` and release tags are protected from direct/force pushes and deletion.
- Required checks include canonical schema/fixture validation, complete applicable runtime tests, PostgreSQL adapter and migration replay, RLS/tenant negatives, concurrency/idempotency/atomicity, separation tests, Semgrep/SAST, credential/path scanning, dependency review, artifact/SBOM scanning, compilation, and diff hygiene.
- CODEOWNERS or equivalent reviewers protect runtime/authority contracts, migrations/RLS, identity/security, CI workflows, and production configuration. Authors and engineering agents cannot satisfy required approval alone, except only under the narrowly scoped Solo-maintainer DEVELOPMENT bootstrap exception below.
- CI jobs default to read-only repository permissions. Write, package, attestation, and deployment permissions are separate jobs with minimal scopes. Untrusted/fork pull requests receive no secrets.
- Artifact builds are reproducible, versioned by exact commit, checksummed, provenance-attested, and promoted without rebuilding. Production accepts only an approved artifact digest from the protected registry.
- Deployment environments use GitHub environment protection (or an equivalent gate), short-lived OIDC identities, concurrency locking, explicit environment selection, and attributable human approval. CI may never infer a production target from branch names or local link metadata.
- Application deployment and migration execution are separate gated steps. A migration failure prevents application promotion; a rollback/recovery action requires its own exact plan and authority.

These controls are requirements, not current repository capabilities. Until branch protections, workflows, identities, environments, and evidence retention are configured and verified, production deployment is blocked.

## Solo-maintainer DEVELOPMENT bootstrap exception

This exception applies only when all of the following are true:

- The environment is explicitly `DEVELOPMENT`.
- The repository is still operating in bootstrap or pre-production mode.
- Exactly one eligible human repository maintainer exists.
- No independent eligible human reviewer is available.
- The repository/platform owner explicitly authorizes the exact bounded operation.

If any independent eligible human reviewer becomes available, this exception automatically stops applying to future changes.

For repository-local `DEVELOPMENT` work only, the sole human repository/platform owner may authorize a bounded `R0`, `R1`, or `R2` repository change to proceed without otherwise-required independent human approvals when independent review is impossible because no eligible independent human reviewer exists. This is a temporary bootstrap exception to the approval requirement only. It does not lower the risk classification; an `R2` change remains `R2`.

Every use of this exception requires all of the following substitute controls:

- Exact repository, environment, responsibility, and resource confirmation.
- One bounded resource change at a time.
- Exact expected branch and head, or immutable candidate identification.
- A clean pre-change state or explicit preservation of existing work.
- Focused validation and full applicable repository certification before merge.
- Canonical baseline and security checks, including secret and forbidden-path scanning.
- Tenant, RLS, and security tests when applicable.
- Successful natural CI when an applicable workflow exists.
- Exact diff and scope verification.
- Separate explicit repository/platform-owner authorization for each mutation, commit, push, and merge.
- No silent retry or self-repair after drift or failure.
- Evidence in the pull request or task output that identifies use of this exception.

CI success alone never constitutes merge authority.

The solo-maintainer `DEVELOPMENT` bootstrap exception never authorizes any of the following:

- `STAGING` or `PRODUCTION` execution.
- Production deployment or production migration.
- Production secret access.
- Provider credential creation, exposure, or rotation.
- Supabase or other provider mutation merely because repository code passed CI.
- Remote database migration execution.
- Destructive provider operations or break-glass access.
- Bypassing tenant isolation or RLS.
- Granting `BYPASSRLS`.
- Granting table ownership to runtime or application identities.
- Force pushing protected branches or disabling deletion protection.
- Direct unreviewed production changes.
- Treating AUTH and DATA projects as interchangeable.
- An AI agent approving risk or independently granting merge authority.

Any provider or remote infrastructure action still requires its own exact, separate owner authorization and provider preflight under the existing rules. The DEVELOPMENT Supabase Auth-admin bootstrap provider-secret exception above narrows what may be separately authorized; it does not make provider credential creation part of this repository-review exception.

Branch protection may reflect the actual number of eligible human maintainers during solo `DEVELOPMENT`, but `main` remains protected, force pushes remain prohibited, deletion remains prohibited, conversation resolution remains required, and automated certification must be required when technically available. Each branch-protection change requires its own explicit bounded authorization. Approval requirements must not be hardcoded to zero indefinitely, and protections must be strengthened when independent maintainers are added.

When at least one suitable independent human reviewer becomes available, repository governance must be reassessed before the next `R1` or `R2` merge. When sufficient qualified reviewers exist, independent-review enforcement must be restored according to the normal `R0`/`R1`/`R2`/`R3` policy.

Current repository controls remain requirements rather than proof of production readiness. This exception does not make `PLATFORM_PRODUCTION_READINESS=READY`; production remains blocked unless the full production evidence gate is satisfied.

## Engineering and production change policy

| Risk | Examples | Minimum authority and evidence |
|---|---|---|
| `R0` | Documentation/test clarification with no runtime, contract, security, or configuration effect | Green focused/baseline checks and one human engineering review |
| `R1` | Reversible application change that does not alter authority, identity, data shape, RLS, secrets, or external targets | Human engineering approval, full applicable CI, immutable artifact, staging verification, rollback plan |
| `R2` | Contract/runtime authority, authentication, tenant/RLS, schema/migration, dependency, secret, worker, observability, or infrastructure change | Independent engineering plus security/data/platform-owner approvals, migration/recovery proof, staging evidence, exact artifact/target approval |
| `R3` | Production application/migration execution, emergency access, destructive recovery, or change with customer impact | Explicit time-bound production-change authorization from platform owner and required security/data owner, protected deploy identity, change window, verification owner, rollback trigger, and incident path |

Prohibited changes always win. AI/workloads may classify and recommend but cannot approve risk, lower a classification, merge, authorize production, or establish success. Client-system `DeploymentAuthorization` is separate and cannot substitute for Avuhz platform change approval; platform approval cannot authorize a client-system deployment.

An owner may approve one immutable bounded provider-change plan version/digest, but that approval is not batched mutation authority. Every listed resource requires its own exact preflight, execution, verification, evidence gate, and authorization consumption before the next listed resource can start. Drift, missing evidence, expiry, failure, partial or ambiguous outcomes, extra privilege, scope expansion, skip/reorder, or replay stops without self-repair or silent retry. Unlisted resources/actions, other environments, and other responsibilities remain unauthorized.

## Platform deployment evidence gate

Before any Avuhz platform production deployment, the evidence bundle must prove:

1. exact reviewed commit, immutable artifact digest, build provenance, dependency lock/SBOM, and protected registry origin;
2. green contract, runtime, persistence-adapter, migration, concurrency, idempotency, atomicity, RLS/tenant, separation, and cross-repository suites;
3. green SAST/Semgrep, secret, dependency/vulnerability/license, artifact/container, and forbidden-path scans with reviewed exceptions;
4. exact owner-approved environment registry values, issuer/audience/tenant mapping, service identities, RLS version, and least-privilege grants;
5. clean migration replay on a production-like copy, backward/forward compatibility, lock/downtime assessment, backup checkpoint, and tested recovery/forward-correction plan;
6. API/worker health, capacity/load targets, outbox retry/dead-letter behavior, sanitized logs/metrics/traces, alert routing, audit retention, and incident ownership;
7. backup schedule, retention, encryption, point-in-time recovery, measured RPO/RTO, and successful restore rehearsal;
8. exact risk classification, independent required approvals, deployment/verification owner, change window, rollback triggers, and previous-artifact availability; and
9. post-deploy verification independent of the deploy step, including exact artifact/schema identity, tenant denial, command atomicity, outbox health, and security monitoring.

Missing, stale, unverifiable, or mismatched evidence blocks production. A successful build, CI run, migration, deployment command, or platform health check alone never establishes the next truth.
