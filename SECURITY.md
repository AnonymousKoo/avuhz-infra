# Avuhz Security Rules

These are enforceable repository rules. An agent must actively check them before writing code, changing configuration, or applying a provider/infrastructure action. A failed check is a stop condition, not a warning.

## 1. Confirm the exact boundary before every change

Before modifying any resource, state and verify all of the following:

- repository or external provider;
- environment (`LOCAL`, `TEST`, `DEVELOPMENT`, `STAGING`, or `PRODUCTION`);
- provider project / namespace;
- responsibility boundary (`AUTH`, `DATA`, runtime, automation, communications, billing, observability, etc.);
- exact resource being changed; and
- action class: repository-local, provider read, or provider mutation.

For DEVELOPMENT Supabase, AUTH is project `pwlhruwutoitnieactol` and DATA is project `gnuqaefotwgkwurjpyik`. They must never be conflated. If the project, namespace, environment, or responsibility cannot be proven, stop before changing anything.

Production is never assumed safe to touch. A production action requires explicit production authorization for the exact resource and operation.

## 2. Change one resource at a time

Apply one bounded resource change at a time. Do not batch unrelated resource changes, provider mutations, credential operations, or environment changes without explicit approval for that batch.

A plan, PR approval, green CI run, provider login, or successful prior step does not silently authorize the next resource. Re-check the boundary before each mutation.

## 3. No hardcoded credentials or secret material

Never commit or persist passwords, API keys, access/refresh tokens, bearer tokens, authenticated connection strings, provider cookies, private keys, raw credential payloads, or reversible secret-derived material in code, workflow JSON, configs, docs, plans, evidence, logs, fixtures, or generated artifacts.

Repository evidence:

- `scripts/check-baseline.sh` rejects credential-shaped literals, `sb_secret_...` values, prohibited `.env`/linked-project paths, and unexpected SQL surfaces.
- `.semgrep.yml` runs as part of the baseline.
- `security/forbidden-path-patterns.txt` rejects `.env`, `supabase/.temp`, private-key files, `.n8n`, workflow-export paths, dumps, provider payloads, and execution logs from the canonical tree.
- `supabase/config.toml` uses `env(...)` placeholders for optional local/provider secrets rather than literal values.

Credentials belong in an approved secret boundary. n8n credentials must use n8n encrypted credentials when n8n is introduced; provider/server secrets belong in the approved environment-scoped secret manager or Supabase Vault where the design specifically calls for Vault. Never invent a Git-backed secret store.

The DEVELOPMENT Auth-admin bootstrap credential has been retired. Do not recreate, reuse, recover, hash, or copy that retired credential under historical authority; any future provider credential lifecycle requires a new exact boundary.

## 4. Enforce least privilege

Default to the least-privileged credential and identity that can perform the exact operation.

For provider client/API reads where a public client key is sufficient, use the publishable/anon-equivalent path. Use a service-role or other elevated server credential only when a server-side necessity is explicitly proven and separately authorized. Never use `service_role` as a convenience shortcut.

For authoritative Avuhz DATA access, the implemented pattern is stricter than generic Supabase client access: `PUBLIC`, `anon`, `authenticated`, and `service_role` are revoked from direct `avuhz_*` table access. The runtime path uses the bounded `avuhz_command_service` role, tenant RLS, and column-scoped grants. Do not weaken that model to satisfy an integration.

Runtime identities must not receive table ownership, `BYPASSRLS`, universal tenant authority, migration/DDL authority, or migration-role membership.

## 5. RLS is a completion gate

A Supabase table is not complete until RLS is enabled and its policies are proven to scope the exact intended identity and tenant. Before declaring a table ready, check RLS status, policy predicates, grants, and negative cross-tenant behavior.

The canonical `avuhz_*` migration currently enables RLS on all 16 authoritative tables and creates one `avuhz_command_service_tenant_isolation` policy per table using the transaction-local `avuhz.tenant_id` setting.

Treat any unauthenticated policy, `USING (true)`, `WITH CHECK (true)`, broad authenticated write policy, or service-role bypass as a security finding unless the exact resource is intentionally public and the exception is explicitly approved.

The preserved legacy inventory `supabase/inventory/current_public_schema.sql` contains broad `authenticated_full_access` policies and anon demo-read policies on non-Avuhz legacy tables. Those policies are legacy security debt. Do not copy them into new Avuhz tables, and do not describe them as the Avuhz tenant-isolation pattern.

## 6. Minimize PII in logs and events

Persist only operationally necessary information. Prefer opaque references, IDs, bounded status fields, sanitized metadata, and safe error codes over raw customer/provider payloads.

Current code establishes these conventions:

- lifecycle events are defined as sanitized, non-authoritative events and expose only `sanitized_metadata` rather than raw domain payloads;
- outbox delivery persists enumerated safe error codes; exception messages are explicitly not persisted;
- the local HTTP request handler suppresses access logging because request paths may contain authoritative IDs.

If a phone number or similar PII is operationally necessary in a future log, retain only the minimum useful representation (for example, last four digits) rather than the full value. This is a minimization rule, not a claim that a current canonical demo-line implementation already uses a last-four convention; no such current implementation was found in this repository.

Do not place full email addresses, phone numbers, names, provider response bodies, auth-user payloads, raw submission JSON, or credential material into operational logs unless a separately reviewed requirement proves the data is necessary and protected.

## 7. Stop on credential exposure, RLS gaps, or PII leaks

If a proposed or existing change would expose credential material, bypass tenant RLS, widen an ACL unexpectedly, mix AUTH and DATA responsibilities, or leak unnecessary PII: stop immediately, identify the exact exposure, and do not continue until it is resolved or separately authorized with an approved remediation plan.

## 8. Provider and authority changes are separately gated

Repository state is not provider authority. Before any remote mutation, require the exact bounded authorization, active time window if applicable, fresh preflight, exact target match, expected credential class, and explicit verification/evidence step.

Never reuse consumed or expired authority. In current AUTH history, v28 is completed and consumed; it grants no further provider authority. v27 remains historical/unconsumed after the dashboard-bundle mismatch and must not be repurposed for a different action.

Synthetic-token issuance, hosted AUTH wiring, hosted DATA wiring, Render changes, n8n integration, communications providers, billing providers, staging, and production are distinct resource boundaries.

## 9. Protect event and error surfaces

Lifecycle events are non-authoritative. Do not use events, outbox deliveries, read models, logs, or notification payloads as substitutes for authoritative Avuhz state.

Persist bounded error codes, not exception bodies or provider response payloads. Keep evidence sanitized and digest-bound where the contract requires it. Never attach screenshots, provider payloads, tokens, or secrets to committed evidence unless an explicit schema and security review permits that exact class of data.

## 10. Required repository gate

Before committing or merging, run the focused tests for the changed resource and the full applicable repository gate. At minimum, `./scripts/check-baseline.sh` must pass for repository changes unless the task explicitly changes that gate itself and the replacement has separate authorization.

A failed secret scan, forbidden-path check, schema/fixture validation, Semgrep rule, migration/provider-artifact allowlist, tenant/RLS test, or diff-hygiene check blocks the change. Do not weaken a guard merely to make CI green.

Preserve interrupted work. Do not reset, clean, stash, discard, force-push, delete branches, or rewrite valid evidence to escape a failure without explicit authorization for that destructive action.

## Production secrets and provider configuration

Environment registration is descriptive only: **registration grants no connection or mutation authority**. Provider selections, logical references, or repository configuration do not authorize secret retrieval, remote reads, migrations, deployment, or mutation.

Secrets must remain in approved environment-scoped secret boundaries and be delivered to workloads with the narrowest possible scope. Production secrets must not be exposed to pull requests, forks, lower environments, local shells, general-purpose automation, or AI-agent context. Application/runtime identities never receive table ownership, `BYPASSRLS`, universal tenant authority, or migration authority.

Client-system `DeploymentAuthorization` is separate from Avuhz platform change authority. A client deployment authorization cannot authorize an Avuhz platform deployment, and platform authorization cannot silently authorize a client-system deployment.

## GitHub and CI/CD controls

Keep `main` and release surfaces protected from direct/force pushes and deletion. Require the applicable automated gate and CODEOWNERS or equivalent human ownership for sensitive runtime, security, migration/RLS, CI, and production configuration surfaces.

CI defaults to read-only permissions. Untrusted/fork pull requests receive no secrets. Deployment credentials must use short-lived OIDC or an equivalent short-lived workload identity rather than static reusable credentials whenever the platform supports it.

Build/release evidence must identify the exact commit and immutable artifact and retain the dependency lock/SBOM and provenance needed for later verification. Repository CI success is evidence, not provider mutation authority.

## Engineering and production change policy

Classify changes before execution: `R0` documentation/test-only, `R1` reversible application behavior, `R2` auth/RLS/schema/secret/infrastructure or other authority-affecting change, and `R3` production execution, destructive recovery, emergency access, or customer-impacting change.

The higher-risk classification wins when a change spans classes. Required review, recovery evidence, staging evidence, exact target authorization, and rollback planning increase with risk; an agent may not lower the classification to make a change easier to execute.

## Platform deployment evidence gate

Before any Avuhz production deployment, verify the exact reviewed commit and artifact digest, full applicable test/security gates, tenant/RLS behavior, environment and identity bindings, dependency lock/SBOM, migration/recovery proof, observability/alerting, capacity/SLO evidence, and explicit production-change authority.

Production readiness also requires backups, point-in-time recovery where the approved platform design calls for it, measured restore/recovery evidence, and a tested rollback or forward-correction path. Missing or stale evidence blocks deployment.

post-deploy verification independent of the deploy step must confirm the exact artifact/schema identity, tenant denial behavior, command/outbox health, and security monitoring state. A successful deploy command alone never establishes production success.
