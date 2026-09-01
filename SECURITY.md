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

This baseline is unconnected. Owner-approved non-secret development/staging project selections are recorded only in the canonical environment registry in `docs/architecture.md`; registration grants no connection or mutation authority. The repository contains no n8n credential, provider integration, production secret, or deployment configuration, and the current-tree migration baseline remains local/disposable only.

## Production secrets and provider configuration

- Secrets exist only in an approved environment-scoped secret manager and are delivered at runtime through a short-lived workload identity. GitHub variables may hold non-secret opaque references only.
- Environments use separate secret namespaces, keys, issuers, service identities, and rotation schedules. Production secrets are never available to pull requests, forks, developer shells, lower environments, AI agents, or general-purpose automation.
- Workloads receive least-privilege, audience-bound credentials only for their single role. Shared service-role keys, long-lived static credentials, authenticated URLs, and credential-bearing provider payloads are prohibited.
- Logs, traces, errors, evidence bundles, command/event records, and CI artifacts must redact secret values and minimize customer/business payloads. Secret scanning runs before artifact publication.
- Rotation, revocation, break-glass access, and suspected-exposure response require attributable human authorization and audit evidence. Break-glass access is time-bound and cannot bypass tenant or authority checks.
- Provider configuration is an allowlisted, schema-validated reference owned by the environment registry. Unknown endpoints, mutable-latest targets, and caller-selected provider credentials fail closed.

## GitHub and CI/CD controls

- Work occurs on bounded feature branches through pull requests. `main` and release tags are protected from direct/force pushes and deletion.
- Required checks include canonical schema/fixture validation, complete applicable runtime tests, PostgreSQL adapter and migration replay, RLS/tenant negatives, concurrency/idempotency/atomicity, separation tests, Semgrep/SAST, credential/path scanning, dependency review, artifact/SBOM scanning, compilation, and diff hygiene.
- CODEOWNERS or equivalent reviewers protect runtime/authority contracts, migrations/RLS, identity/security, CI workflows, and production configuration. Authors and engineering agents cannot satisfy required approval alone.
- CI jobs default to read-only repository permissions. Write, package, attestation, and deployment permissions are separate jobs with minimal scopes. Untrusted/fork pull requests receive no secrets.
- Artifact builds are reproducible, versioned by exact commit, checksummed, provenance-attested, and promoted without rebuilding. Production accepts only an approved artifact digest from the protected registry.
- Deployment environments use GitHub environment protection (or an equivalent gate), short-lived OIDC identities, concurrency locking, explicit environment selection, and attributable human approval. CI may never infer a production target from branch names or local link metadata.
- Application deployment and migration execution are separate gated steps. A migration failure prevents application promotion; a rollback/recovery action requires its own exact plan and authority.

These controls are requirements, not current repository capabilities. Until branch protections, workflows, identities, environments, and evidence retention are configured and verified, production deployment is blocked.

## Engineering and production change policy

| Risk | Examples | Minimum authority and evidence |
|---|---|---|
| `R0` | Documentation/test clarification with no runtime, contract, security, or configuration effect | Green focused/baseline checks and one human engineering review |
| `R1` | Reversible application change that does not alter authority, identity, data shape, RLS, secrets, or external targets | Human engineering approval, full applicable CI, immutable artifact, staging verification, rollback plan |
| `R2` | Contract/runtime authority, authentication, tenant/RLS, schema/migration, dependency, secret, worker, observability, or infrastructure change | Independent engineering plus security/data/platform-owner approvals, migration/recovery proof, staging evidence, exact artifact/target approval |
| `R3` | Production application/migration execution, emergency access, destructive recovery, or change with customer impact | Explicit time-bound production-change authorization from platform owner and required security/data owner, protected deploy identity, change window, verification owner, rollback trigger, and incident path |

Prohibited changes always win. AI/workloads may classify and recommend but cannot approve risk, lower a classification, merge, authorize production, or establish success. Client-system `DeploymentAuthorization` is separate and cannot substitute for Avuhz platform change approval; platform approval cannot authorize a client-system deployment.

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
