# Avuhz Agent Operating Rules

These rules apply to every coding or infrastructure agent working in this repository.

## Four operating lanes

Think in four lanes every session: **Security, Infrastructure, Automation, Business**.

Do not let infrastructure or automation work silently substitute for business-critical work. If asked to prioritize, explicitly name the tradeoff between platform hardening and outcomes such as landing, serving, or retaining paying clients.

## Verify before apply

Before any repository or provider change, explicitly confirm:

1. repository/resource;
2. environment;
3. provider project or namespace;
4. responsibility boundary (`AUTH`, `DATA`, runtime, observability, etc.);
5. exact resource being changed; and
6. whether the action is repository-local, provider read, or provider mutation.

Do not assume production is safe to touch. Production, staging, AUTH, and DATA are separate boundaries. DEVELOPMENT AUTH is Supabase `pwlhruwutoitnieactol`; DEVELOPMENT DATA is Supabase `gnuqaefotwgkwurjpyik`. They must never be conflated.

Apply one resource boundary at a time. Do not batch unrelated provider changes. A plan or package approval does not silently authorize provider execution.

## Security

- Never store credentials, tokens, keys, passwords, authenticated connection strings, or raw provider payloads in code, workflow JSON, configs, logs, documentation, evidence, or committed files.
- n8n credentials belong in n8n encrypted credentials; other secrets belong in the approved environment-scoped secret boundary. Never create a Git-backed secret path.
- Use least privilege. Runtime identities must not receive table ownership, `BYPASSRLS`, universal tenant authority, migration/DDL authority, or a generic service-role shortcut.
- Every authoritative Supabase table must have correctly scoped RLS before it is considered complete.
- If a proposed change introduces credential exposure, an RLS gap, an AUTH/DATA boundary violation, or a PII leak, stop and state the exposure before doing anything else.
- Log only operationally necessary information. Do not retain raw customer/provider payloads or full PII when a bounded reference or minimized form is sufficient.

## Architecture law

Avuhz owns reusable cross-domain infrastructure. Verticals are thin domain logic on top of the shared backbone.

Do not:

- create vertical-specific auth, billing, tenant-authority, or automation infrastructure;
- create a new billing/auth/automation path outside the shared Avuhz core;
- let n8n write authoritative Avuhz tables directly;
- make Avuhz depend on vertical/company implementation internals;
- treat events or read models as authoritative truth;
- treat green CI, a healthy endpoint, or an existing owner identity as provider-change authority; or
- touch production resources without explicit, exact production authorization.

## Current source-of-truth order

When documents conflict, use this order:

1. canonical deployed/provider evidence and latest bounded-authorization execution progress;
2. current code and canonical migrations/provider artifacts;
3. `ARCHITECTURE.md`;
4. `SECURITY.md`;
5. `docs/current-build-state.md` and `docs/roadmap.md`;
6. older detailed/historical documents under `docs/`.

Do not revive a superseded plan because an older narrative file mentions it.

## File and resource map

Derived from the canonical repository tree:

- architecture: `ARCHITECTURE.md`
- security/change policy: `SECURITY.md`
- current build/readiness state: `docs/current-build-state.md`
- roadmap: `docs/roadmap.md`
- runtime/service code: `src/avuhz_runtime/`, `src/avuhz_service/`, `src/avuhz_worker/`
- Supabase migrations: `supabase/migrations/`
- provider-specific SQL artifacts: `supabase/provider-artifacts/`
- bounded authorization plans and evidence: `contracts/plans/v1/`
- tests: `tests/`
- n8n workflow exports: none currently present on canonical `main`
- Supabase Edge Functions: none currently present on canonical `main`
- dashboard application code: none currently present on canonical `main`

## Current DEVELOPMENT boundary

AUTH v16 and DATA v3 are complete and verified. The DEVELOPMENT Auth hook exists but remains disabled. The hosted Render composition remains fail-closed because real hosted identity and DATA adapters are not yet injected.

The next provider-facing foundation boundary is a fresh forward-only AUTH plan for exactly one dedicated synthetic DEVELOPMENT Auth identity. Creating that plan does not itself authorize provider execution. Tenant metadata, allowlist binding, hook enablement, token issuance, hosted DATA wiring, staging, production, and Phase 6 remain later separate boundaries.

## Work discipline

Preserve interrupted work with `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`. Never reset, restore, clean, stash, discard, force-push, or weaken protections to make a change pass without separate owner authorization.

Run focused tests while implementing and the full applicable repository gate before merge. Keep evidence sanitized and digest-bound.

End every task with one explicit next action. Do not leave work in an ambiguous “done-ish” state.
