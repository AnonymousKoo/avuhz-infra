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
raw-byte integrity guards. Workflow and producer job permissions are explicitly
ONLY `contents: read`. The producer retains all existing validation, pinned
PostgreSQL 17, migration/replay, build, diff/integrity and cleanup stages.
This is an authority-affecting R2 workflow correction for PR #779's HIGH broad
permissions finding, with no run or integration authority.

After successful integrity and disposable PostgreSQL cleanup, revalidate exactly
one regular nonsymlink wheel in `RUNNER_TEMP/avuhz-main-pr-gate-wheel`. Reject
symlinked parents, extra entries, unsafe names and SHA256 mismatch against
`wheel_contents.outputs.wheel_sha256`. The expected filename is
`avuhz_service-<numeric.version>-py3-none-any.whl`. Upload only the validated
absolute path using the uniquely named source-SHA/run-ID/attempt artifact with
`if-no-files-found: error` and `retention-days: 30`.

The producer exports the revalidated wheel SHA256 and upload action's numeric
artifact ID. Its always-run summary requires every stage's outcome AND conclusion
to succeed, including wheel guard and upload, validates the artifact ID and matching
lowercase wheel digests, and reports only `exact_merge_producer_checks=passed`
and `signing_state=pending_separate_job`. It cannot claim overall Gate10 success
or a successful attestation. The archive's digest is not the wheel's SHA256.

A separate `attest-exact-wheel` job requires producer success through `needs` and
implicit `success()` scheduling. It uses a fresh GitHub-hosted runner and explicit
`contents: read`, `id-token: write`, `attestations: write` and
`artifact-metadata: write` permissions. The last permission supports the pinned
`actions/attest` v4 artifact-metadata publication contract; independent review of
the exact action's permission requirement remains necessary before publication.
Build dependencies and repository tests never receive these signing permissions.

The first signing step independently checks manual workflow_dispatch, exact
repository/owner IDs, main ref, actor and ID, workflow ref, first attempt, expected
reviewed workflow/source SHA, run ID, producer success, numeric artifact ID and
lowercase wheel digest. Inputs enter inline Python through environment variables,
never shell source. It rejects preexisting download paths and unsafe temp roots.
The download selects ONLY the exact same-run artifact ID through `artifact-ids`,
with no name/glob selection, token, cross-run or cross-repository override.
`merge-multiple: true` places the single selected archive directly into the guarded
signer directory, rather than relying on artifact-name directory behavior.

After download, independently repeat context checks and require exactly one regular
nonsymlink wheel, no extra files, directories or symlinks, a canonical absolute temp
path and safe expected wheel filename. Hash actual wheel bytes and compare with the
producer's lowercase SHA256 before passing the absolute subject path to attestation.
No checkout, dependency installation, repository script, wheel import, wheel execution
or artifact-provided code runs on this signer. Python runs isolated with `-B -I`.

The required actions are pinned to supplied official v4 commit SHAs. No GitHub read
or independent tag-resolution verification was performed during this offline correction;
verify the exact pins, especially download's refs/tags/v4 binding, in the separately
authorized GitHub connector review before publishing:

- Producer: `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`.
- Signer: `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093`.
- Signer: `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6`.

No continuation on action error is permitted. Producer failure prevents signing;
missing artifacts and failed or ambiguous download/verification/attestation block
workflow success. The signer always-run summary rechecks context, producer success,
all signing stage outcomes AND conclusions, path and digest; it fails closed for
failed, skipped, cancelled, missing or malformed evidence. Both summaries retain
`evidence_class=non-certified`, `certification_granted=false` and
`provenance=not_independently_verified`. Successful attestation remains a CI
observation; independent provenance verification and human certification are absent.
The earlier identity record's `provenance=absent` describes the pre-attestation stage.

## Distinct artifact and commit identities

The old LOCAL rebuilt wheel SHA256
`b0682bcf949faa49985eb8a4362f8d72af885b72c710b1b14ed88e6286dda899`
is **NOT** the future GitHub CI wheel identity. Do not substitute it for the
future run's observed wheel digest or claim build equivalence. Historical
successful CI without retained wheel bytes does not fill that gap.
The preparation source `42708b4` is not the eventual corrected PR main merge SHA.
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

Next action: independently review and publish only the corrected three blobs into
PR #779 via the GitHub connector under separate authorization; do not merge.
Owner decisions on the pending retention parameters remain required. GitHub execution and external WORM operations remain separate future
authorization boundaries. No external resource is created by this plan.
