# Gate10 exact-merge WORM integration — LOCAL review proposal

Repository: `AnonymousKoo/avuhz-infra`. Environment: **LOCAL**. Namespace: **NONE**.
Responsibility: CI evidence and retention planning. Action: repository-local only.
Prepared against detached commit `42708b4aa409cbad371c91f3d06c28373b151b62`.
This amendment is an uncommitted review candidate, not part of that commit.
No GitHub run, network access, provider operation, resource creation, key use,
signing or deployment is authorized or performed by this preparation.
**LOCAL v1 remains NOT CERTIFIED.**

## Proposed CI evidence handoff

Preserve the manual exact-main-merge, repository/owner/actor, first-attempt,
source/workflow SHA, immutable checkout, historical recipe, digest, diff and
raw-byte integrity guards. Keep workflow-level `contents: read`; scope proposed
`contents: read`, `id-token: write`, `attestations: write` and
`artifact-metadata: write` permissions to the existing evidence job only.
This is an authority-affecting R2 workflow review candidate, with no run authority.

After successful integrity and disposable PostgreSQL cleanup, revalidate exactly
one regular nonsymlink wheel in `RUNNER_TEMP/avuhz-main-pr-gate-wheel`. Reject
symlinked parents, unsafe action-glob/output paths, missing or extra wheels,
nonregular files and SHA256 mismatch against `wheel_contents.outputs.wheel_sha256`.
Pass the absolute validated path through `GITHUB_OUTPUT`. Both subsequent actions
use that exact path; neither rebuilds the wheel.

The proposed required actions are pinned to the owner-supplied official v4 tag
SHAs (not independently fetched or verified during this offline preparation):

- `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6` with that subject path.
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` with the same
  path, `if-no-files-found: error`, `retention-days: 30` and a name containing
  source SHA, run ID and attempt.

Implicit success conditions prevent publication after prior failure, including
cleanup failure. No continuation on action error is permitted. The always-run
sanitized summary requires both outcome and conclusion success for every stage,
including wheel revalidation, attestation and upload, plus matching wheel digests.
A successful attestation action is a CI observation; independent provenance
verification and human certification remain absent. The summary stays noncertifying.
The earlier identity record's `provenance=absent` describes the pre-attestation
stage; the final summary says `provenance=not_independently_verified`.

## Distinct artifact and commit identities

The old LOCAL rebuilt wheel SHA256
`b0682bcf949faa49985eb8a4362f8d72af885b72c710b1b14ed88e6286dda899`
is **NOT** the future GitHub CI wheel identity. Do not substitute it for the
future run's observed wheel digest or claim build equivalence. Historical
successful CI without retained wheel bytes does not fill that gap.
A newly merged code commit needs its own exact-commit CI proof, including the
reviewed workflow/source SHA binding and retained bytes from its authorized run.
No historical suite result is promoted to proof for this amendment.

## External retention decision register

All external parameters remain **PENDING**; there are no inferred defaults.
The proposed 30-day GitHub artifact expiry is temporary retrieval only, **not WORM**,
not an external retention duration and not proof against deletion or privileged
mutation. GitHub artifacts, logs, summaries, attestations and local `/tmp` custody
do not establish external immutable retention or independent retrieval.

| Parameter | Required decision |
|---|---|
| Storage provider / region / service | PENDING |
| Account / project / namespace | PENDING |
| Bucket / container / object namespace | PENDING |
| Versioning and immutable object/version identifiers | PENDING |
| Retention lock mode, privileged bypass denial and policy authority | PENDING |
| Lock duration, start/end window, hold and expiry handling | PENDING |
| Writer identity and least-privilege write scope | PENDING |
| Storage administrator and lock administrator identities / separation | PENDING |
| Independent read-only retrieval identity and audit identity | PENDING |
| CI issuer, workflow identity, trusted roots and verifier policy | PENDING |
| Accountable owner, independent reviewer / verifier and human release approver | PENDING |
| Transfer window, retrieval deadline before GitHub expiry and failure escalation | PENDING |

Unknown or unresolved values block external execution and release acceptance.
No credentials, authenticated URLs, private keys or provider payloads belong in
this plan or the future sanitized evidence manifest.

## Separately authorized future boundaries

1. Review this concrete workflow amendment and resolve the pending owner decision
   register. Independently review job permissions and action pins. Approve any
   integration separately; no Git refs or commits are changed by this preparation.
2. After integration, separately authorize one exact eventual main merge SHA,
   workflow, actor, first-attempt dispatch and execution window. Record the actual
   run/source/workflow identities, required checks, wheel name/size/digest,
   attestation bundle and temporary artifact identity. A failed or ambiguous run
   requires a new decision; the amendment grants no retries or dispatch authority.
3. Independently retrieve the actual CI wheel and attestation, hash the bytes and
   verify subject, digest, exact commit, issuer/workflow identity and approved
   trust roots. Reject substituted subjects, unrelated commits, missing bundles,
   unapproved identities and unverified claims. Retain sanitized review results
   separately from the producer's output; action success alone is insufficient.
4. Separately authorize the exact external storage target and operation after all
   retention parameters are resolved. Retain wheel bytes, attestation/verification
   material, source/workflow/run bindings, dependency locks/SBOM and required
   review evidence in a digest-indexed manifest. Preserve immutable version IDs.
   Prove effective lock mode/window, overwrite/deletion and privileged bypass
   denial, applicable holds and audit references for every required object.
5. Through the separately controlled reader, independently retrieve the exact
   locked versions, compare actual bytes to manifest digests and record sanitized
   readback and lock evidence. Failed retrieval, digest mismatch or ineffective
   lock blocks acceptance; upload success never substitutes for this proof.
6. Require independent human Gate10 review of exact-commit CI proof, trust,
   retention/readback and outstanding release gates. Only an explicitly authorized
   human decision can approve release; no agent or summary certifies LOCAL v1.

Security owns authority, trust and substitution denial review. Infrastructure owns
external lock and recovery/readback proof. Automation owns the bounded CI handoff
and failure propagation. Business owns release acceptance and client priorities;
this preparation does not authorize intake, tenants, billing or client deployment.

Next approval: owner review of this LOCAL amendment and the pending retention
parameters. GitHub execution and external WORM operations remain separate future
authorization boundaries. No external resource is created by this plan.
