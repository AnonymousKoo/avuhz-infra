# LOCAL exclusive worktree lease v1

Phase 2C adds one fail-closed, host-local reservation primitive for cooperating
AAE workers. It is not a scheduler, task runner, Codex dispatcher, admission
issuer, Git mutator, provider adapter, or execution authorization.

## Fixed boundary

- Repository: `AnonymousKoo/avuhz-infra`
- Environment and namespace: `LOCAL`, `AAE/local`
- Responsibility: exclusive reservation of one identified isolated worktree
- Provider authority: `NONE`
- Network, secrets, n8n, deployment, live services, and production: prohibited

Every public result fixes `execution_authorized` and
`os_isolation_certified` to false. A lease proves only that this process holds a
cooperative advisory lock for the exact path-derived key. It does not turn the Phase 2B `observed_source` into authorization.

## Filesystem and ownership contract

The host operator must pre-provision the one fixed directory
`/run/user/<uid>/avuhz-aae-local-worktree-leases-v1` outside every worktree and
every `.git` directory. The public acquisition API has no directory override.
The directory must be real, non-symlink, owned by the current UNIX user, and
mode `0700`; the module does not create it. The exact
worktree root is also a canonical absolute real directory. Every existing path
component is checked with `lstat`; symlinked parents fail closed.

The lock filename is derived only from SHA-256 of a domain-separated canonical
worktree root. A caller cannot choose it, so all cooperating contenders for the
same root address the same lock. Lock and state files must be owner-owned
regular files with mode `0600` and one link. Symlinks, hardlinks, foreign modes,
oversized or noncanonical state, duplicate JSON keys, and malformed state are
denied. State replacement is same-directory, lock-protected, synced, and
atomic. A leftover state temporary file after a crash causes a fail-closed
write denial and requires operator inspection; it is never silently removed.

Acquisition uses `fcntl.flock(LOCK_EX | LOCK_NB)`. The returned handle retains
the descriptor. A live owner cannot be displaced. The kernel lock is released
when the open file description is closed. Because explicit `LOCK_UN` on an
inherited descriptor would also release that shared lock, the handle binds
release to its creator PID and denies inherited-handle release after `fork`.
This protects cooperating workers using the API; a same-UID adversary can still
issue direct syscalls. Release requires the same opaque owner ID, writes
`RELEASED` state while locked, then unlocks and closes. Repeating the
same scoped release on that handle is idempotent; another owner is denied.

## Source and deadline semantics

Acquisition exact-compares a trusted Phase 2B observation with the requested
worktree root, commit, tree, reviewed-artifact digest, isolation ID, repository,
and clean flag. `LOCAL` and `AAE/local` are fixed. This comparison is still a
time-of-check observation.

The acquisition and deadline timestamps are controlled metadata.
`deadline_enforced` is always false. A deadline does not unlock a descriptor,
permit stealing, reclaim a worktree, or prove resource bounds. After a deadline
or crash, any continuation requires a fresh signed ownership admission, a fresh
complete Phase 2B observer check, and successful acquisition based on the
actual OS lock state. No timestamp alone permits reuse.

## Known isolation gap and next gate

`flock` is advisory. Another process under the same UNIX UID can ignore it and
write the worktree, and same-UID access is not an OS-enforced isolation proof.
Every cooperating AAE worker must honor the exclusive lease. Immediately before
any future task, the complete observer check must be repeated while the lease
is held; the lease does not make a prior observation durable.

Before unattended execution, a separately reviewed phase must provide and test
an external OS sandbox: a distinct principal and/or isolated mount, no inherited
secrets, enforced no-network policy, and measured CPU, memory, process, wall
clock, and output limits. This prototype provides none of those controls and
cannot execute a Codex job.

Focused verification:

```bash
python3 -m unittest tests.engineering.test_local_worktree_lease tests.security.test_local_worktree_lease_boundary -v
```
