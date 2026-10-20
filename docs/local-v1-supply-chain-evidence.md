# LOCAL v1 supply-chain candidate

This R0 repository-local evidence tooling records an **unsigned inventory/SBOM
CANDIDATE**, always **NOT CERTIFIED**. It does not complete Gate 10, change runtime,
install dependencies, build a wheel, contact a registry or authenticate a release.
Python 3.12 standard library and local Git are sufficient.

Use a clean checkout under `/tmp` at the exact reviewed 40-character lowercase
commit. Choose a fresh output file outside that checkout, also under `/tmp`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/build-local-v1-supply-chain-candidate.py \
  --repo /tmp/reviewed-avuhz-checkout \
  --source-sha <exact-reviewed-40-hex-commit> \
  --output /tmp/fresh-supply-chain-candidate.json
```

An optional `--wheel /tmp/reviewed-artifact.whl` observes an existing real project
wheel. No wheel is built or downloaded. Omission records `MISSING`. The tool checks
ZIP members, project name/version and SHA256 RECORD consistency and hashes the
actual archive bytes. A self-consistent forged wheel can pass those structural
checks: its classification remains `OBSERVED_UNAUTHENTICATED_ARCHIVE`. RECORD
consistency cannot establish provenance, source correspondence or trusted origin.

The tool rejects wrong SHA, dirty trees, manifest mismatch, non-exact or duplicate
direct Python pins, malformed npm metadata, tracked-byte substitution and unsafe
or symlink paths. All filesystem inputs and outputs must be under `/tmp`;
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
