# Phase 4 persistence architecture

## 1. Scope

This design persists Slice 1 only: governed acquisition handoff, engagement, diagnostic scope, attributable human approvals, idempotency, lifecycle events, and outbox delivery. The JSON Schemas and Phase 3 repository ports remain canonical. It excludes payments, agreements, access, credentials, OIA, findings, implementation, deployment, and managed operations.

## 2. Relational model

| Table | Kind | Key and tenant boundary | Port |
| --- | --- | --- | --- |
| `acquisition_handoffs` | Authoritative immutable/versioned | `(tenant_id, handoff_id, handoff_version)` | AcquisitionHandoffRepository |
| `engagements` | Authoritative mutable/versioned | `(tenant_id, engagement_id)` | EngagementRepository |
| `diagnostic_scopes` | Authoritative mutable/versioned | `(tenant_id, diagnostic_scope_id)` | DiagnosticScopeRepository |
| `human_approvals` | Attributable authority evidence | `(tenant_id, approval_id)` | HumanApprovalRepository |
| `idempotency_records` | Operational/security-sensitive | tenant/principal/command/subject/key | IdempotencyRepository |
| `lifecycle_events` | Append-only evidence | `(tenant_id, event_id)` | LifecycleEventRepository |
| `outbox_deliveries` | Operational mutable delivery state | delivery ID plus event FK | OutboxRepository |

The canonical forward migration uses the parallel `public.avuhz_*` names:
`avuhz_acquisition_handoffs`, `avuhz_engagements`, `avuhz_diagnostic_scopes`,
`avuhz_human_approvals`, `avuhz_idempotency_records`,
`avuhz_lifecycle_events`, and `avuhz_outbox_deliveries`. These coexist with,
and do not alter, legacy `public.engagements`, `public.engagement_events`, or
`public.tenant_users`.

All authoritative tables carry `tenant_id` directly. Use composite tenant-aware foreign keys where a child references a tenant-owned parent, so cross-tenant references are structurally impossible. Provider/account/opportunity identities remain bounded external references, not canonical Avuhz IDs. Contract-shaped composite scope structures may use bounded JSONB after schema validation; core IDs, state, version, timestamps, approval references, and uniqueness-critical fields remain relational columns.

## 3. Table ownership and invariants

`acquisition_handoffs` stores only the immutable accepted acquisition snapshot, source/version, bounded constraints/evidence references, and acceptance evidence; never full acquisition history. `engagements` preserves immutable identity/source/type plus mutable state, `engagement_version`, and `record_version`. `diagnostic_scopes` preserves exact scope content, digest, state, version, and approval references; approved content is never silently overwritten. `human_approvals` has no joint-authority row: separate client and Sekinfra records bind exact scope ID/version/digest.

`lifecycle_events` are append-only and contain sanitized metadata only. `outbox_deliveries` track `PENDING` through terminal delivery state without changing event content. Retention categories remain contractual/audit history for handoffs, engagements, scopes, approvals, and events; security-sensitive for idempotency and approvals; operational for outbox. Actual durations require legal/accounting input.

## 4. Repository-port mapping

| Port | Tables | Reads/writes | Transaction/concurrency |
| --- | --- | --- | --- |
| AcquisitionHandoffRepository | acquisition_handoffs | tenant-scoped get, accepted transition | immutable version match |
| EngagementRepository | engagements | tenant-scoped get/exists/save | record-version update guard |
| DiagnosticScopeRepository | diagnostic_scopes | get/save/approve | record-version update guard |
| HumanApprovalRepository | human_approvals | tenant-scoped exact lookup | append/evidence immutable |
| IdempotencyRepository | idempotency_records | reserve, lookup, complete | unique reservation in command transaction |
| LifecycleEventRepository | lifecycle_events | append/list | append in command transaction |
| OutboxRepository | outbox_deliveries | append/update delivery | append intent in command transaction |
| UnitOfWork | all above | one command boundary | one database transaction |

## 4.1 Contract-to-schema traceability

| Contract resource | Durable table / primary key | Important constraints | Repository port |
| --- | --- | --- | --- |
| AcquisitionHandoff | `avuhz_acquisition_handoffs` / `(tenant_id, handoff_id, handoff_version)` | immutable accepted snapshot; bounded acquisition references | AcquisitionHandoffRepository |
| Engagement | `avuhz_engagements` / `engagement_id` | tenant-aware handoff FK; `DIAGNOSTIC_OIA`; `OPEN`/`ONBOARDING`; record version | EngagementRepository |
| DiagnosticScope | `avuhz_diagnostic_scopes` / `diagnostic_scope_id` | tenant-aware engagement FK; allowlisted actions; exact prohibited set; digest | DiagnosticScopeRepository |
| HumanApproval | `avuhz_human_approvals` / `approval_id` | tenant-aware scope/version FK; one attributable authority role per row | HumanApprovalRepository |
| IdempotencyRecord | `avuhz_idempotency_records` / `id` | tenant/principal/command/subject/key uniqueness; opaque fingerprint only | IdempotencyRepository |
| LifecycleEvent | `avuhz_lifecycle_events` / `lifecycle_event_id` | append-only evidence; bounded vocabulary and sanitized JSON object | LifecycleEventRepository |
| OutboxDelivery | `avuhz_outbox_deliveries` / `outbox_delivery_id` | tenant-aware lifecycle-event FK; bounded delivery state/error | OutboxRepository |

No normal repository loads authoritative data by object ID alone: tenant is required in every lookup.

## 5. Transaction, idempotency, and concurrency

A successful command transaction commits authoritative mutation, terminal idempotency result, one LifecycleEvent, and one `PENDING` OutboxDelivery together. Any failure rolls all four back. Publication happens after commit and is not part of command execution.

Idempotency uniqueness is `(tenant_id, trusted_principal_id, command_type, subject_type, subject_id, idempotency_key)`. Reservation stores fingerprint and fingerprint-schema version, processing state, retention class, attempt count, and prior-result reference—never raw payload. Same identity/key/fingerprint returns duplicate; same identity/key with a different fingerprint returns conflict. The unique reservation must be atomic under concurrency.

For engagements and scopes, durable mutation requires tenant, ID, and expected `record_version` to match in one update. Zero affected rows is stale/conflict. The check and mutation must not be split. Handoffs are immutable/versioned; approvals bind exact subject/version/digest.

## 5.1 Runtime Compatibility Remediation

The forward remediation preserves the approved contracts and runtime shapes: an unaccepted handoff has accepted_at set to NULL; a submitted scope may have no persisted canonical digest because the existing scope record does not emit one; lifecycle-event fields absent from the current minimal event envelope are nullable; and outbox destination and delivery idempotency are nullable until a future delivery worker supplies them. The outbox_delivery_id is persistence-owned with a UUID default. The outbox tenant remains required and is derived from its tenant-aware lifecycle-event relationship. Human approvals continue to bind the exact digest, scope version, and action-set version.

## 6. Tenant and RLS/access model

Canonical `tenant_id` is the UUID contract primitive. Every Slice 1 table carries it; relationships should use tenant-aware composite constraints where practical. Command repositories always apply tenant filters.

Recommended access model: **command service writes with a trusted server identity**, carrying attributable human/workload execution context. Direct client writes to authoritative tables are prohibited. Human client/Sekinfra sessions read bounded tenant-scoped read models through controlled query surfaces. Provider adapters, scheduler, and future n8n call bounded command/query interfaces only. n8n has no direct authoritative-table or service-role write access.

Future RLS: client users see only their tenant; Sekinfra humans receive bounded internal access; audit/security/idempotency/credential metadata are narrower; ordinary roles cannot rewrite append-only evidence; production authority writes require trusted command-service paths. Direct database access for command service is least-privilege and environment/audience bound.

## 7. Human and workload identity

Human claims require principal ID, tenant/org, caller type, role, audience, environment, authentication strength, and step-up status. Runtime resolves trusted facts separately from caller claims.

Workloads are separate identities for command service, provider adapter, scheduler, and future n8n. Each is distinct, short-lived, audience/environment/capability bound, and cannot fabricate human authority. No shared universal service credential or human approval role is permitted.

## 8. Environment and migration ownership

LOCAL, TEST, DEVELOPMENT, STAGING, and PRODUCTION must use strictly isolated mutable data; prefer separate projects/databases for production versus non-production. Production never shares mutable test state.

Migrations live in clean Git, are reviewed before execution, and are executed separately by environment. Never copy legacy migrations or infer targets from legacy metadata. Production execution requires explicit owner confirmation of target and change approval. No migration is executable until data/auth project, environment, tenant identity bridge, migration owner, and trusted service identity are confirmed.

## 9. Production fingerprint requirement

Development SHA-256 remains development-only. Production uses a runtime-supplied environment-specific keyed fingerprint (HMAC or equivalent), with key version persisted alongside the fingerprint but never the key. Rotation supports prior versions during controlled transition. Key material is never committed, logged, or stored in business tables.

## 10. Credential-remediation gate

Clean, isolated persistence-adapter development may proceed without legacy credential rotation only while legacy stays excluded, no value is copied, and no external connection is made. Any production target, provider, n8n, or legacy artifact reuse remains blocked on documented credential remediation and target authorization.

## 11. Recommended implementation batches

**A — schema and adapter skeleton:** approved migration set, local durable adapter skeleton, table constraints, and repository contract tests. **B — transactional execution:** repository implementations, transactional UnitOfWork, idempotency reservation, event/outbox atomicity, and durable-runtime tests. **C — access hardening:** RLS/grants, identity claim tests, tenant-denial tests, and durable test-environment acceptance.

## 12. Owner decisions

| Classification | Decision | Recommendation / consequence |
| --- | --- | --- |
| Approved from existing architecture | Command-service-controlled authoritative writes; n8n prohibited from direct writes; separate approvals; transactional outbox | Preserve Phase 3 guarantees. |
| Recommended default | Separate isolated production and non-production persistence targets; tenant-aware FKs; keyed production fingerprint | Limits blast radius and cross-tenant errors. |
| Owner input required | Which DATA project, AUTH project, environment, and migration target? | Blocks SQL/migrations and connected tests. |
| Owner input required | Who owns migration review/execution and production change approval? | Blocks production migration execution. |
| Owner input required | What tenant/identity bridge and human/workload identity issuer model will be used? | Blocks RLS and trusted identity integration. |
| Owner input required | Which approved secret manager supplies fingerprint keys and runtime secrets? | Blocks production fingerprinting and external integrations. |
| Blocked until external target known | RLS policy SQL, grants, project-specific migrations, and connected adapter tests | Require explicit target confirmation. |
