# Codex Operating Model

This document defines how Codex should be used to accelerate Avuhz without weakening the repository's authority, tenant-isolation, or security controls.

The goal is not "more agents doing more things." The goal is to run independent repository work in parallel while keeping every external/provider mutation single-writer, explicitly authorized, and separately verified.

## Operating rule

For any substantial milestone, use one coordinating thread and delegate independent work into isolated Codex worktrees or subagents when doing so does not create overlapping write authority.

Default shape:

1. **Coordinator** — owns the milestone definition, decomposition, integration order, and final status.
2. **Critical-path implementation lane** — advances the repository-local code that directly moves the current milestone toward completion.
3. **Security/review lane** — independently reviews requirements and diffs for security, tenant isolation, authority, secret, PII, and architectural boundary violations.
4. **Readiness lane** — independently reconciles code, tests, `docs/current-build-state.md`, and `docs/roadmap.md`; identifies what still blocks the next milestone.
5. **Authority lane** — used only when an exact external/provider read or mutation is separately authorized. This lane is single-writer and is never duplicated across agents.

The coordinator may collapse lanes for small tasks. It must not create parallelism just for appearance.

## Four business lanes still apply

Every session must still evaluate the repository through the four lanes defined in `AGENTS.md`:

- Security
- Infrastructure
- Automation
- Business

Parallel Codex work is an engineering execution pattern, not a replacement for that business framing.

If infrastructure or automation work competes with a business-critical objective, state the tradeoff explicitly.

## What may run in parallel

Parallelize work when the tasks are independent and repository-local, for example:

- implementation and independent review;
- runtime adapter interfaces and their tests;
- failure-path tests and documentation reconciliation;
- contract/schema review and security review;
- migration design review while a separate agent writes non-provider tests;
- readiness audits that do not modify the same files as the implementation lane.

Each parallel lane must have:

- a clear goal;
- a bounded file/resource surface;
- explicit "done when" criteria;
- a statement that it has no provider authority unless separately granted;
- a required output: commit/diff, review findings, or readiness report.

## What must not run in parallel

Do not parallelize two agents against the same external authority boundary.

The following remain single-writer unless the owner explicitly authorizes a different exact model:

- Supabase AUTH provider mutation;
- Supabase DATA provider mutation;
- secret creation, retrieval, rotation, or retirement;
- Render environment/deployment mutation;
- n8n credential or workflow deployment;
- communications-provider mutation;
- billing-provider mutation;
- staging or production changes;
- any action governed by a bounded approval window.

A second agent may review the plan, code, or evidence for these tasks, but must remain read-only with respect to the provider resource.

## Coordinator workflow

For a milestone-sized task, the coordinator should:

1. Read only the source-of-truth files relevant to the task. Use `docs/current-build-state.md` for current state, `docs/roadmap.md` for sequence, `ARCHITECTURE.md` for service boundaries, and `SECURITY.md` for change controls.
2. State the exact repository/environment/resource boundary before any change.
3. Define one milestone outcome and concrete completion criteria.
4. Split the work into independent lanes only where file/resource ownership does not conflict.
5. Prefer isolated worktrees/subagents for parallel repository work.
6. Keep external/provider authority in one lane.
7. Require an independent review of implementation diffs before integration.
8. Integrate one bounded resource/file change at a time.
9. Run focused tests and the full applicable repository gate.
10. Reconcile `docs/current-build-state.md` only when the task changes canonical state.
11. End with: what changed, what was verified, what remains blocked, and one next action.

## Independent review pattern

Implementation and review should not share the same reasoning thread when an independent check is practical.

The review lane should receive:

- the task requirement;
- the relevant architecture/security constraints; and
- the resulting diff or commit.

It should then try to disprove correctness by checking at minimum:

- hidden credential or secret exposure;
- AUTH/DATA conflation;
- tenant/RLS bypass or ACL widening;
- PII/logging regressions;
- alternate authority paths;
- vertical-specific shared infrastructure;
- mutation paths that bypass the governed Executor/API boundary;
- stale or contradictory state documentation;
- tests that prove only the positive path while missing required denial/failure behavior.

The reviewer should report findings first. It should not silently rewrite the implementation unless explicitly assigned a separate fix task.

## Critical path versus control plane

Classify work before delegating it:

**Critical path** directly moves the current Avuhz milestone toward a usable, verified platform capability.

**Control plane** provides the authorization, security, evidence, governance, or certification required to make that capability safe.

Both are required, but control-plane work must not silently become the product roadmap. When a control-plane task expands, the coordinator must say whether it delays the critical path and why that delay is justified.

## Long-running goals

For long Codex runs, externalize durable state in repository files rather than relying on chat context.

A long-running goal should define:

- outcome;
- constraints;
- authoritative source files;
- allowed file/resource surface;
- prohibited external actions;
- verification commands;
- stop conditions;
- final deliverables.

Do not create a new planning document when an existing canonical state/roadmap file already serves the purpose.

## Suggested milestone prompt

Use this shape when starting a substantial Codex task:

```text
Goal:
<one outcome>

Current source of truth:
- docs/current-build-state.md
- <only other relevant files>

Boundary:
- repository: AnonymousKoo/avuhz-infra
- environment: <LOCAL/TEST/DEVELOPMENT/etc.>
- responsibility: <AUTH/DATA/runtime/etc.>
- provider authority: NONE unless separately stated

Parallel lanes:
- implementation: <bounded files/outcome>
- review: independent security/architecture review of implementation
- readiness: reconcile blockers and next milestone
- authority: none, or exact separately authorized boundary

Done when:
- <functional result>
- <focused tests>
- ./scripts/check-baseline.sh passes
- independent review has no unresolved blocking finding
- final status names the next action
```

## Repository skills

Repo-scoped Codex skills live under `.agents/skills/`.

Use skills for repeatable workflows, not as a duplicate architecture manual. Keep their descriptions short and let them point back to canonical repository documents for current facts.

The initial skills are:

- `avuhz-milestone-orchestrator` — decompose a milestone into safe parallel lanes and integrate results.
- `avuhz-change-review` — perform an independent security/architecture/readiness review of a proposed Avuhz change.

These skills do not grant external/provider authority.
