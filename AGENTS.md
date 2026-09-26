# Avuhz Agent Operating Rules

These instructions apply to every coding, infrastructure, automation, or documentation agent working in this repository.

## Think in four lanes every session

Always evaluate work through four lanes: **Security, Infrastructure, Automation, Business**.

Do not let infrastructure or automation work silently substitute for business-critical work. If asked to prioritize, name the tradeoff explicitly. For example, spending a day on platform hardening may reduce immediate time available to land, serve, or retain a paying client; conversely, rushing client delivery must not bypass security or authority boundaries.

## Verify before apply

Before changing anything, explicitly confirm:

- repository or external resource;
- environment;
- provider project / namespace;
- responsibility boundary (`AUTH`, `DATA`, runtime, automation, communications, billing, observability, etc.);
- exact resource being changed; and
- whether the action is repository-local, provider read, or provider mutation.

For DEVELOPMENT Supabase, AUTH is `pwlhruwutoitnieactol` and DATA is `gnuqaefotwgkwurjpyik`. Never substitute one for the other.

Never assume production is safe to touch. Production requires explicit, exact production authorization before any read that carries elevated authority or any mutation.

Apply one resource boundary at a time. Do not batch unrelated changes unless the owner explicitly approves that exact batch.

## Security behavior

Before writing code or applying a change, enforce `SECURITY.md` rather than treating it as advisory.

- Never hardcode or commit credentials, tokens, passwords, private keys, authenticated URLs, raw provider payloads, or secret-derived material.
- n8n credentials belong in n8n encrypted credentials when n8n is introduced; other secrets belong in the approved environment-scoped secret boundary or approved Vault design.
- Use least privilege. Do not reach for `service_role` unless a server-side necessity is proven and separately authorized.
- Every authoritative Supabase table must have correctly scoped RLS before it is complete.
- Stop on credential exposure, RLS gaps, unexpected ACL widening, AUTH/DATA boundary violations, or unnecessary PII retention.
- Log only operationally necessary data. Prefer opaque IDs, `sanitized_metadata`, and safe error codes over raw payloads.

Run focused tests while implementing and the full applicable repository gate before declaring a repository change complete. Do not weaken a security check to make CI pass.

## Architecture law

Avuhz owns reusable cross-domain infrastructure. Verticals are thin domain logic on top of the shared backbone.

Do not:

- create vertical-specific authentication, tenant authority, billing, or automation infrastructure;
- create a new billing, auth, or orchestration path outside shared Avuhz core services;
- let n8n write authoritative Avuhz tables directly;
- make Avuhz depend on a vertical's private implementation details;
- treat lifecycle events, outbox records, logs, or read models as authoritative state;
- treat green CI, a healthy endpoint, an approved plan, or an authenticated provider session as authority for a different resource change;
- conflate DEVELOPMENT AUTH and DEVELOPMENT DATA; or
- touch production resources without stated environment and resource confirmation plus exact authorization.

Shared primitives that are required but not yet implemented here—n8n orchestration, communications adapters, and Stripe billing/usage metering—must be added centrally. Do not hide those gaps by building a vertical-specific substitute.

## Source-of-truth order

When repository narratives disagree, resolve them in this order:

1. current deployed/provider evidence and latest bounded execution progress;
2. current code, canonical migrations, and provider artifacts;
3. `ARCHITECTURE.md` and `SECURITY.md`;
4. `docs/current-build-state.md` and `docs/roadmap.md`;
5. older design/history documents under `docs/`.

Do not revive expired, consumed, superseded, or narrower historical authority because an older document still mentions it.

## File and resource map

This map is derived from the current repository tree:

- root architecture context: `ARCHITECTURE.md`
- security/change rules: `SECURITY.md`
- agent rules: `AGENTS.md`
- current build/readiness truth: `docs/current-build-state.md`
- ordered roadmap: `docs/roadmap.md`
- Codex parallel-agent operating model: `docs/codex-operating-model.md`
- repo-scoped Codex skills: `.agents/skills/`
- runtime/service/worker code: `src/avuhz_runtime/`, `src/avuhz_service/`, `src/avuhz_worker/`
- contract schemas: `contracts/schemas/v1/`
- bounded authorization plans/evidence: `contracts/plans/v1/`
- Supabase migrations: `supabase/migrations/`
- provider-specific Supabase artifacts: `supabase/provider-artifacts/`
- preserved legacy schema inventory: `supabase/inventory/current_public_schema.sql`
- local Supabase config: `supabase/config.toml`
- repository tests/gates: `tests/`, `scripts/check-baseline.sh`, `.semgrep.yml`, `security/forbidden-path-patterns.txt`
- n8n workflow exports: **none currently present**; no canonical workflow-export path exists yet, and current forbidden-path rules reject `n8n-workflows/` and `.n8n/`
- Supabase Edge Function source: **none currently present**; local `edge_runtime` configuration does not mean an Edge Function is implemented
- dashboard/frontend application code: **none currently present**

Do not guess missing paths. If a future task introduces one of these absent resources, inspect the actual resulting tree and update this map in the same bounded change.

## Current DEVELOPMENT boundary

Do not hardcode a current AUTH/DATA version into agent instructions. That state changes more frequently than this operating file should.

Before work that depends on current DEVELOPMENT status, read `docs/current-build-state.md` and the latest bounded execution/progress evidence for that exact resource. Use `docs/roadmap.md` only for sequence, not as proof that a provider action occurred.

DEVELOPMENT AUTH and DATA remain separate projects and responsibilities. Never reuse an expired, consumed, stopped, superseded, or narrower historical authorization for a later action.

## Parallel Codex execution

For milestone-sized repository work, use the operating model in `docs/codex-operating-model.md`.

Parallelize only independent repository-local lanes with non-overlapping file/resource ownership. Prefer isolated worktrees or subagents for implementation, independent review, and readiness analysis when that reduces elapsed time without creating conflicting authority.

External/provider authority remains single-writer. Never run parallel provider mutations, secret operations, deployments, or bounded approval-window actions against the same resource. A review agent may inspect those changes but must remain read-only unless separately authorized.

Repo-scoped reusable Codex workflows live under `.agents/skills/`. Use the milestone-orchestrator skill for safe decomposition and the change-review skill for an independent pre-integration review.

## Work discipline

Use `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`.

Before editing, inspect current code and working-tree state. Preserve valid interrupted work instead of resetting or cleaning it. Do not stash, discard, restore, force-push, delete, or rewrite user work merely to obtain a clean tree without explicit authorization.

Keep repository changes scoped. A documentation task must not silently become a provider task; an AUTH task must not silently become a DATA task; infrastructure work must not silently create business-domain behavior.

For external actions, preflight the exact target immediately before mutation and verify the postcondition immediately afterward. Record only sanitized evidence required by the contract.

## Task completion rule

Do not leave work in a vague “done-ish” state. At the end of every task:

- state what changed and what was verified;
- state any blocker, security finding, or known gap that remains; and
- state one explicit next action.

If the requested boundary is complete but the next boundary requires fresh authorization, stop there and name that next boundary instead of proceeding implicitly.
