# LOCAL trusted-source/worktree observer v1

Phase 2B v1 adds a fail-closed, operator-controlled source observation for the
Phase 2A admission input. It is repository-local, `LOCAL`, `AAE/local`, and has
provider authority `NONE`. It does not admit work, consume an approval, start
Codex, run a worker or scheduler, contact a network, inspect credentials, or
authorize execution.

## Exact boundary

The caller pins the canonical worktree root, canonical common Git directory,
branch, immutable commit, commit-tree object ID, reviewed-artifact digest, and
isolation ID. The observer requires a registered linked worktree whose `.git`
file and reciprocal common-directory worktree record match those pins. A main
checkout, symlinked repository, relocated root, foreign common directory,
detached head, malformed registry, alternate object store, lock, or ambiguous
identity is denied with a stable code.

Only `/usr/bin/git` is permitted. The observer supplies fixed argument vectors,
uses no command shell, clears the inherited environment, denies inherited Git
control/trace variables (an ambient pager variable is ignored and still not
forwarded), disables system/global configuration, replacement
objects, optional locks, prompts, fsmonitor, untracked cache, hooks, and pagers,
and bounds each command to 1 MiB of stdout/stderr and an operator-selected
0.05–30 second timeout. It runs only these repository-local reads: local config
key names without includes, top-level/common-directory discovery, symbolic
HEAD, commit/tree resolution, index listing, and porcelain status. Dangerous
local config keys and object alternates are denied. No fetch, remote, hook,
helper, checkout, reset, index refresh, or other repository write is allowed.

The clean check covers tracked changes and all untracked paths. Index entries
marked assume-unchanged, skip-worktree/sparse, or with any other non-normal
flag are denied before status because Git can otherwise hide tracked drift.
Tracked symlinks are denied rather than interpreted. Gitlinks/submodules are denied in
v1 because safely validating their nested Git metadata and drift would require
a separately bounded recursive observer; this fail-closed rule means submodule
drift can never receive PASS.
The observer checks for Git locks before and after the read set and repeats the
branch/commit/tree reads to detect evident concurrent drift. Every denial
raises `ObservationDenied` containing only a stable code; command output,
paths, environment values, configuration values, and exception text are not
returned or logged.

## Result and Phase 2A handoff

A PASS result contains `observed_source` as the exact frozen
`TrustedRepositoryObservation` type consumed by
`local_codex_admission.py`. The reviewed digest is an independently pinned
operator input carried into that shape; this observer does not create or sign
review approval. Issuer private keys, approvals, and Phase 2A trust anchors are
not accepted or returned. The JSON projection is defined by
`docs/schemas/local-worktree-observation-v1.schema.json`.

`execution_authorized` is always false, `provider_authority` is always `NONE`,
and `os_isolation_certified` is always false. Source observation PASS proves
neither host/process isolation nor credential isolation. It is not permission for unattended execution.

## Race boundary and later requirement

This module has an unavoidable time-of-check/time-of-use gap. Its repeated
reads detect some races but cannot create an exclusive worktree lease or freeze
the filesystem. Any later execution design must first acquire a separately
reviewed exclusive lease, then repeat this complete observation while holding
that lease immediately before execution. OS credential isolation must also be
designed and certified separately. Until both exist, execution remains
unauthorized.

## Offline verification

```text
python3 -m unittest tests.engineering.test_local_worktree_observer -v
python3 -m unittest tests.security.test_local_worktree_observer_boundary -v
python3 -m unittest tests.engineering.test_local_codex_admission -v
python3 -m unittest tests.security.test_local_codex_admission_boundary -v
python3 -m unittest discover -s tests/engineering -p 'test_*.py'
```

Tests create synthetic Git repositories and linked worktrees only under
temporary directories. They do not touch provider services, networks, live
credentials, or the primary checkout.
