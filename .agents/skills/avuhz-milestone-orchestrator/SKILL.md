---
name: avuhz-milestone-orchestrator
description: Decompose a substantial Avuhz milestone into safe parallel repository lanes while keeping provider authority single-writer.
---

Use this skill for milestone-sized Avuhz work that can benefit from multiple isolated agents or worktrees.

Read only the canonical files relevant to the task:
- `AGENTS.md` for operating rules;
- `SECURITY.md` for stop conditions and authority rules;
- `docs/current-build-state.md` for current state;
- `docs/roadmap.md` for milestone order;
- `ARCHITECTURE.md` when service boundaries matter;
- `docs/codex-operating-model.md` for the parallel execution model.

Before changing anything, state and verify repository, environment, responsibility boundary, exact resource, and whether the action is repository-local, provider read, or provider mutation.

For substantial repository-local work, prefer this lane structure when the surfaces are independent:

1. **Implementation** — directly advances the current critical-path capability.
2. **Independent review** — read-only review of the requirement and resulting diff for security, authority, tenant isolation, PII, and architecture violations.
3. **Readiness** — read-only reconciliation of implementation, tests, current state, roadmap, and the next blocker.
4. **Authority** — only when separately authorized; exactly one lane may perform the approved provider action.

Do not create parallel agents that edit the same files or mutate the same external resource. Do not parallelize provider mutations, secret operations, deployment mutations, or bounded approval-window execution.

Give each delegated lane:
- one goal;
- bounded files/resources;
- explicit done criteria;
- explicit provider-authority status;
- expected output.

Require independent review before integration when practical.

Integrate one bounded resource change at a time. Run focused tests plus `./scripts/check-baseline.sh` before declaring repository work complete.

Finish with:
- what changed;
- what was verified;
- unresolved blockers/findings;
- the next explicit action.

Do not let control-plane work silently replace the product critical path. If governance/security work delays a platform capability, state that tradeoff and why it is necessary.
