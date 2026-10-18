# LOCAL Codex signed admission v1

Phase 2A adds a fail-closed signed admission preflight in front of the Phase 1
LOCAL engineering queue. It verifies scope and consumes a nonce. It does not
execute a worker, Codex, Git, a command, a script, a hook, a scheduler, or a
provider action.

## Fixed boundary

- Repository: `AnonymousKoo/avuhz-infra`
- Environment and namespace: `LOCAL`, `AAE/local`
- Mode: `PREFLIGHT_ONLY`
- Provider authority: `NONE`
- Network and GitHub mutation: false
- Responsibility: repository-local engineering admission control
- Provider reads or mutations: none

This is security/control-plane work. It does not add a client-serving worker or
advance a queued task. A future execution phase requires a fresh design,
authorization, and review.

## Trust and signed contract

The strict schema is
`docs/schemas/local-codex-admission-v1.schema.json`; the security-critical
validator is `src/avuhz_engineering/local_codex_admission.py`. The entire JSON
document must use sorted keys, compact separators, ASCII JSON, and no trailing
newline. Duplicate keys, non-finite numbers, whitespace variants, unknown keys,
or noncanonical encodings are rejected. Ed25519 signs the canonical `payload`
bytes, which include the domain separator
`AVUHZ_LOCAL_CODEX_ADMISSION_V1`.

The signed payload binds all of the following:

- exact repository, `LOCAL`, `AAE/local`, issuer, version, purpose, and
  `PREFLIGHT_ONLY` mode;
- immutable source branch, commit, tree, and reviewed-artifact digest;
- exact Phase 1 manifest ID, canonical manifest digest, approval digest, task
  ID, allowed target paths, canonical worktree root, and a unique trusted
  worktree isolation ID;
- a nonce, prompt digest (never prompt text), static command-profile IDs and
  their catalog digest, and the complete static stop-condition set;
- wall-clock, CPU, PID, memory, and output bounds;
- network false, provider authority `NONE`, and GitHub mutation false; and
- exact UTC-second timestamps with a validity interval no longer than ten
  minutes.

Command profiles are opaque identifiers, not commands or mappings to commands:
`inspect.source.v1`, `edit.allowed-paths.v1`, `test.focused.v1`,
`test.engineering.v1`, and `test.baseline.v1`. The manifest has no argv, shell,
environment, executable, callback, or hook surface.

The public key and its SHA-256 fingerprint are independent trusted inputs to
the validator. An operator must pin them, together with the expected issuer and
key ID, outside the repository, checkout, and manifest. The manifest contains
no public key. A key supplied by the signer, a self-computed fingerprint, a PR
approval, and the Phase 1 approval hashes are not trust roots. Private keys must
never enter this repository, its environment, logs, fixtures, or artifacts.

The repository declares `cryptography` as a runtime dependency, and admission
uses its genuine Ed25519 public-key verifier. There is no custom cryptography
and no unsigned or self-signed acceptance mode.

## Source observations and Phase 1 integration

The validator accepts a frozen `TrustedRepositoryObservation` collected and
authenticated by a separate trusted caller. It exact-compares repository,
branch, commit, tree, reviewed digest, and clean-worktree state. This module is
intentionally unable to invoke Git or a subprocess, so it does not independently
discover or prove those facts. Missing, stale, wrong-branch, wrong-repository,
or dirty observations fail closed. The same observation binds the canonical
worktree root and a unique isolation ID; a shared ownership label is not an
isolation identity.

The existing Phase 1 manifest remains authoritative for queue shape and path
policy. Phase 2A calls its validator, binds its exact canonical and approval
digests, requires one matching task, and requires exact equality with that
task's allowed paths. Phase 1 denial of traversal, symlinks, secret-sensitive
paths, shell/command fields, provider scope, and unknown keys is preserved. No
Phase 1 state is changed and no Phase 1 approval is widened.

## Durable replay decision

Pure validation returns `PREFLIGHT_VERIFIED_REPLAY_UNCLAIMED`, which is not
claimable state and is not authority to execute. The only public admission and
nonce-consumption entry point is `admit_preflight`; it accepts raw signed bytes
and every trusted input, repeats complete validation immediately before its
atomic nonce insert, and never accepts an `AdmissionCandidate`. It returns
`PREFLIGHT_ADMITTED` only after that insert. Both results set execution and retry
authority to false; the latter also reports network and GitHub mutation
authority false and provider authority `NONE`. There is no `EXECUTE` transition.

The replay database must be provisioned before admission as an absolute
`.sqlite3` regular file outside the checkout. Its parent must be owned by the
current local user with no group/other permissions, and the file must be owned
by that user with mode `0600`. Neither may be a symlink. The exact schema is:

```sql
CREATE TABLE avuhz_local_codex_admission_nonce_v1 (
  nonce_digest TEXT NOT NULL PRIMARY KEY,
  task_digest TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  claimed_at TEXT NOT NULL
);
```

Admission opens only an existing database in read/write mode, requires SQLite
integrity and exact schema, requests `synchronous=FULL` and the rollback
journal, takes an exclusive transaction, inserts a one-way nonce digest, commits,
and syncs the parent directory. It never creates or repairs the schema. A
duplicate, corrupt database, lock/storage failure, weak permissions, symlink,
unexpected schema, or unavailable durability fails closed. There is no memory
fallback or automatic retry. This is single-host durable replay protection; it
does not claim distributed consumption safety.

## Stable denial surface

Failures raise `AdmissionStop` containing only a fixed status code. No manifest
value, signature, key, exception body, file content, prompt, or provider payload
is returned or logged. Representative codes include `SIGNATURE_INVALID`,
`TRUST_ANCHOR_UNVERIFIED`, `SOURCE_MISMATCH`, `WORKTREE_DIRTY`,
`AUTHORITY_INVALID`, `TIME_WINDOW_INVALID`, `PATH_ESCAPE`, `PATH_SYMLINK`,
`QUEUE_BINDING_INVALID`, `NONCE_REPLAY`, `REPLAY_STORE_CORRUPT`, and
`REPLAY_STORE_UNVERIFIED`.

## Offline verification

```text
python3 -m unittest tests.engineering.test_local_codex_admission -v
python3 -m unittest tests.security.test_local_codex_admission_boundary -v
python3 -m unittest tests.engineering.test_local_engineering_queue -v
python3 -m unittest discover -s tests/engineering -p 'test_*.py'
```

All tests use ephemeral in-memory test keys and private temporary local replay
files. They perform no network or provider activity and persist no key material
in repository files.

The next boundary is an independently authorized design for collecting and
authenticating source observations and operator trust anchors. It must remain
separate from any worker/execution phase.
