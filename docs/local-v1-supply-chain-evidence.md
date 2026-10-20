# LOCAL v1 supply-chain candidate

This R0 repository-local evidence tooling records an **unsigned inventory/SBOM
CANDIDATE**, always **NOT CERTIFIED**. It does not complete Gate 10, change runtime,
install dependencies, build a wheel, contact a registry or authenticate a release.
Python 3.12 standard library and local Git are sufficient.

Use a clean checkout under `/tmp` at the exact reviewed lowercase native Git
commit ID (40 hex characters for SHA1, 64 for SHA256). Choose a fresh output file outside that checkout, also under `/tmp`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/build-local-v1-supply-chain-candidate.py \
  --repo /tmp/reviewed-avuhz-checkout \
  --source-sha <exact-reviewed-native-hex-commit> \
  --output /tmp/fresh-supply-chain-candidate.json
```

An optional `--wheel /tmp/reviewed-artifact.whl` observes an existing real project
wheel. No wheel is built or downloaded. Omission records `MISSING`. The tool checks
ZIP members, project name/version and SHA256 RECORD consistency and hashes the
actual archive bytes. Compressed input is capped at 32 MiB, member count at 1024,
each declared/consumed member at 64 MiB and aggregate declared/consumed bytes
at 128 MiB. Central-directory headers are checked before ZIP member loading;
payload hashes use bounded streaming reads. Metadata and RECORD parsing each
have a 1 MiB cap. Repeated metadata reads count toward the consumed-byte cap.
ZIP64, split archives, unsupported compression, duplicate or ambiguous paths,
file/directory collisions and symlinks fail closed. A self-consistent forged wheel can pass those structural
checks: its classification remains `OBSERVED_UNAUTHENTICATED_ARCHIVE`. RECORD
consistency cannot establish provenance, source correspondence or trusted origin.

The tool rejects wrong SHA, dirty trees, manifest mismatch, non-exact or duplicate
direct Python pins, malformed npm metadata, tracked-byte substitution and unsafe
or symlink paths. Every tracked regular file is compared with the raw `HEAD`
blob size and native Git object hash, including its executable mode. Untracked
and ignored files/directories, tracked symlinks and submodules are denied.
Only `rev-parse` and `ls-tree` are invoked with replacement objects and lazy
fetch disabled; status, index flags, filters, hooks and smudge conversions cannot
substitute bytes. A filesystem walk excludes only the root `.git` pointer and
rejects nested `.git` entries without following symlinks. All filesystem inputs and outputs must be under `/tmp`;
parent traversal is rejected. Outputs use exclusive creation, private permissions,
file and parent-directory fsync. Existing outputs are never replaced. Exit 0
means only that candidate bytes were persisted; exit 2 means rejection and emits
a sanitized error. A failed write can leave an incomplete output; preserve it as
failure evidence and use a fresh path for any separately reviewed rerun.

Sorted JSON contains no timestamps or machine-specific paths, so identical observed
files and source SHA produce identical bytes. SHA256 values come from actual
tracked manifests, `src/` files, available contract schemas and optional wheel
bytes, checked against the pinned Git commit. Absent schemas are `MISSING`.
This is a selected source inventory, not a full repository or deployed inventory.
Python entries are only the matching declared direct pins in `requirements.txt`
and `pyproject.toml`. Build requirements and transitive Python resolution remain
unlocked. npm package-lock v3 entries are parsed separately; their declared SRI
values are metadata, never computed archive hashes or evidence of Python locking.
No npm archive is supplied or verified. Unsupported lock structures fail closed.

Verified distribution archive hashes are a prerequisite to a complete Python
hash-lock, including every resolved transitive and build dependency for the
approved interpreter/platform. Neither direct pins nor the local wheel supplies
that graph. The candidate always lists the missing complete hash-locked graph,
approved SBOM, authenticated exact-merge CI/PG17 proof, signed provenance,
immutable retention proof and explicit human Gate10 approval. Signed or immutable
release proof cannot be inferred from a candidate or a matching hash.

A future main-push CI/PG17 lane, artifact retention, trusted signing and policy
changes require separate exact approval. This change grants no push, PR, merge,
service, provider, credential, staging, production or customer-data authority.

Next action: independently review the exact candidate commit and plan the missing
release-evidence boundary for separate approval. LOCAL v1 remains NOT CERTIFIED;
DEVELOPMENT and production remain NOT_READY.

The separate [Python wheel-lock candidate](local-v1-python-lock.md) adds
actual archive-hash runtime, build/bootstrap and verifier locks for one exact
CPython 3.12.3 Linux x86_64 glibc 2.39 target, plus an offline closure verifier.
The earlier direct-only inventory and its missing-proof list retain their
original scope. The new candidate's observed wheel graph does not certify that
earlier inventory or supply human SBOM approval, signed provenance, retention
or exact-merge CI/PG17. All release statuses remain **NOT CERTIFIED**.
