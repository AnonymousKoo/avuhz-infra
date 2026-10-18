# Local Autonomous Engineering Queue — Phase 1

This phase adds a fail-closed, non-executing controller for `AAE/local`. It validates a pre-approved repository-local manifest, checks that every target still matches its approved baseline, and records deterministic queue state. It does not run commands, edit target files, invoke a model, contact a provider, schedule work, or create or widen approval.

## Boundary

- Repository: `AnonymousKoo/avuhz-infra`
- Environment: `LOCAL` only
- Namespace: `AAE/local`
- Responsibility: repository-local engineering-controller scaffolding
- Authority effect: none; the approval artifact is explicitly `REPOSITORY_LOCAL_ONLY` and sets `provider_authority` to `false`
- State: an explicit absolute directory outside the checkout

This controller is additive. It does not replace `avuhz-milestone-orchestrator`, `avuhz-change-review`, or `scripts/run-engineering-dry-run.py`.

## Manifest contract

The JSON Schema is at `docs/schemas/local-engineering-queue-manifest.schema.json`. The stdlib validator independently enforces the same security-critical constraints, including:

- exact top-level and nested keys;
- `LOCAL`, `AAE/local`, the exact repository reference, and repository-local scope;
- a canonical absolute worktree root with exclusive local ownership;
- unique discrete task IDs and exact task-to-file ownership;
- reference-only acceptance criteria and stop conditions, with no command or shell fields;
- one approved baseline for every allowed path (`ABSENT` or a SHA-256 digest);
- an exact approved task list, digest-bound scope, and digest-bound immutable approval artifact;
- denial of provider/remote/deployment/production/n8n/credential scopes; and
- denial of absolute paths, traversal, symlinks, sensitive paths, and target paths outside the worktree.

The approval `scope_digest` is the canonical SHA-256 digest of every manifest member except `approval`. The `approval_digest` is the canonical SHA-256 digest of the approval object with `approval_digest` omitted. Canonical JSON uses sorted keys, compact separators, ASCII output, and the `sha256:` prefix. Approval artifacts must be created and approved outside this controller; the controller only verifies them.

Target baselines are the dirty-target protection boundary. The controller checks each baseline before `READY` and again before `DRY_RUN_VERIFIED`. A path approved as absent must remain absent. An approved existing regular file must retain its exact digest. A mismatch becomes a persistent `BLOCKED` result, and the target is never changed.

## State and restart behavior

The private state directory must have no group or other permissions. When absent, the controller creates it with mode `0700`. The atomic state file is `<state-dir>/queue-state.json`, written with a same-directory temporary file, file sync, atomic replace, and directory sync. Persisted state is fully shape-checked on every read. It contains only IDs, digests, status, stable block codes, and transition names. Manifest content, model content, credentials, exception text, and file contents are not copied into state or summaries.

The only success path is:

```text
QUEUED -> READY -> DRY_RUN_VERIFIED
```

Any target drift or manifest mismatch moves the enrolled record to `BLOCKED`. Restarting from `QUEUED` or `READY` resumes at the next validation boundary. Re-enqueuing a manifest ID, reusing a task ID, repeating a transition, or replaying a verified manifest is rejected.

The registry is intentionally single-process Phase 1 scaffolding. Atomic replacement protects crash consistency, but concurrent writers are not supported; future concurrency requires a separately reviewed lock/transaction design.

## Run locally

Use a state directory outside the checkout. The `--dry-run` flag is mandatory and there is no execution mode:

```bash
python3 scripts/run-local-engineering-queue-dry-run.py \
  --dry-run \
  --manifest /absolute/path/to/approved-manifest.json \
  --state-dir /absolute/path/outside-the-checkout/aae-local-state
```

A successful invocation prints a deterministic sanitized JSON summary and exits `0`. A denied or blocked invocation prints only a stable error code and exits `2`. A second invocation after verification is rejected as replay.

Run the focused tests:

```bash
python3 -m unittest tests.engineering.test_local_engineering_queue -v
```

Run the full repository gate:

```bash
./scripts/check-baseline.sh
```

## Architecture alignment and future gates

The queue is a local control-plane aid, not authoritative Avuhz state and not an alternate Executor/API path. It has no AUTH, DATA, tenant, RLS, migration, deployment, communications, billing, n8n, or provider responsibility. Its state proves only that an immutable local manifest and unchanged target baselines passed Phase 1 validation.

Any future phase that executes repository work must be separately designed, authorized, and reviewed. At minimum it must add an allowlisted non-shell action catalog, isolated worktree lifecycle, concurrent-writer safety, bounded resource limits, output redaction, recovery behavior, human review gates, and complete repository verification. Provider reads or mutations, secrets, deployments, schedulers/daemons, unattended Codex operation, and production remain separate prohibited boundaries until exact fresh authority exists.
