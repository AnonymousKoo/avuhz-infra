# LOCAL v1 Python wheel lock candidate

**NOT CERTIFIED.** Gate10 Stage 1 is LOCAL/TEST dependency evidence only.
The source base is cached `origin/main` commit
`92bd1ab9f6395a7939c6f8c2191d0ee3d6a729e7`. No runtime, CI, policy,
provider, credential, service or customer-data change is included.

The single selected target is **CPython 3.12.3, Linux x86_64, glibc 2.39**.
The verifier requires that exact interpreter/host tuple. Accepted wheel tags
are compatible CPython/abi3/pure-Python tags and manylinux tags through 2.39,
including the legacy aliases. The downloaded cryptography wheel requires
manylinux 2.34: this set does **not** support glibc 2.17 merely because some
other wheels do. Other Python versions, operating systems, architectures,
libcs, debug ABIs and optional application extras are outside this proof.

`requirements/local-v1-runtime.lock` contains the four declared runtime roots
(with binary/crypto extras) and their complete applicable closure: 10 wheels.
`requirements/local-v1-build.lock` contains pip 24.3.1, setuptools 68.1.2,
wheel 0.45.1 and packaging 24.2. The reviewed backend remains
`setuptools.build_meta` with declared `setuptools>=68`; its wheel build hook
also needs wheel. The separate build environment contains no runtime packages.
`requirements/local-v1-validation.lock` contains packaging 24.2, used to parse
PEP 508 requirements/markers and wheel tags. Stdlib unittest needs no additional
test framework; architecture tests also use the runtime lock. Each entry has
one exact version and the SHA256 of the actual selected wheel archive.

Resolution used native Python 3.12.3 pip 24.0 with a cleared environment,
`PIP_CONFIG_FILE=/dev/null`, `--index-url https://pypi.org/simple`,
`--only-binary=:all:`, `--no-cache-dir` and disabled version checking. Only
public PyPI distributions were requested. No sdists or private indexes were
used. The bootstrap interpreter/system pip and existing baseline Semgrep,
Git, shell, jq and rg executables are environmental prerequisites, not
hash-locked artifacts in these files. This is not a lock of the entire CI or
baseline tool environment and does not replace same-commit CI/PG17 proof.

## Offline verification

Keep wheelhouses, isolated venvs and generated evidence outside the source
checkout in a fresh private directory under `/tmp` (mode 0700). Use a clean
checkout of the exact reviewed committed SHA. Do not use system-site-packages.
Before executing packaging, verify the validation wheel's archive SHA against
the reviewed lock and inspect its ZIP/RECORD with the existing stdlib
`build-local-v1-supply-chain-candidate.py` guards. A preexisting trusted pip
can install it into a fresh `venv --without-pip` using `pip --python` and
`--no-index --find-links=<validation-wheelhouse> --require-hashes -r
requirements/local-v1-validation.lock`. No network is needed thereafter.

```sh
PYTHONDONTWRITEBYTECODE=1 /tmp/private-evidence/validation-venv/bin/python \
  scripts/verify-local-v1-python-lock.py \
  --repo /tmp/reviewed-checkout --source-sha <exact-committed-sha> \
  --runtime-wheels /tmp/private-evidence/runtime-wheels \
  --build-wheels /tmp/private-evidence/build-wheels \
  --validation-wheels /tmp/private-evidence/validation-wheels \
  --output /tmp/private-evidence/fresh-python-sbom.json
```

The verifier uses the existing raw-Git source-byte and safe descriptor-path
guards. It rejects dirty/mismatched source, duplicate pins, missing/extra or
symlink archives, wrong metadata/tags, direct-pin drift and incomplete closure.
It evaluates markers against the fixed target and propagates selected extras;
URLs, unknown markers and host release/version markers are denied. It checks
compressed archive size, central-directory member counts and declared sizes
before opening members, caps consumed sizes, rejects traversal/symlinks/path
collisions and verifies every file against SHA256 RECORD. Explicit empty ZIP
directories are permitted. Bounds are 32 MiB compressed, 1024 members,
64 MiB per member, 128 MiB aggregate and 1 MiB parsed metadata/RECORD.

Output is deterministic CycloneDX 1.5 candidate JSON with scoped components,
actual archive hashes and dependency edges. Its inventory property records
filenames, canonical identities, versions, tags, Requires-Python and all declared
Requires-Dist entries, including inactive optional edges. It binds the exact
clean source SHA. Output uses exclusive private creation outside the checkout,
with fsync; existing outputs are preserved. Errors emit a fixed sanitized code.
Exit 0 means only **unsigned candidate persisted**, never human approval.
Public PyPI transport and matching RECORD/hashes do not authenticate publisher
identity, establish vulnerability safety or supply trusted build provenance.

## Isolated install and build proof

Install runtime with `pip --python <fresh-runtime-venv> install --no-index
--find-links=<runtime-wheelhouse> --require-hashes -r
requirements/local-v1-runtime.lock`. Install the build lock similarly into a
separate fresh build-only venv. Build a copy of reviewed source outside the
checkout with that venv's `python -m pip wheel <copied-source> --no-index
--no-deps --no-build-isolation --disable-pip-version-check --no-cache-dir
--wheel-dir <fresh-artifact-dir>`. Record copied source and built wheel hashes;
never build into the source checkout. Offline flags are not an OS sandbox.

Install the actual built project wheel by a fresh local archive-hash requirement
with no indexes/dependency resolution. From outside source, verify all 76 schema
bytes, schema loading and synthetic worker behavior using installed modules,
with socket operations denied. Preserve logs and the SHA-bound dossier privately.
Run the focused and full architecture suites using runtime plus validation locks;
run the unchanged baseline separately with metrics/version checks disabled.
No new release certificate is produced by any of these steps.

Remaining Gate10 proof: independent human lock/SBOM review, authenticated
exact-merge CI/PG17, trusted signed artifact/source provenance, immutable retention
and explicit human Gate10 approval. LOCAL v1 stays **NOT CERTIFIED**;
DEVELOPMENT and production stay **NOT_READY**. Next action: review this exact
candidate and private evidence before separately authorizing release proof.
