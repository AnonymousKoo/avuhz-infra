# LOCAL v1 Gate10 exact-commit evidence closure dossier

Classification: R0 documentation-only; repository-local evidence reconciliation.
Repository: `AnonymousKoo/avuhz-infra`; environment: LOCAL/TEST; namespace: NONE.
Responsibility: release-evidence documentation and retention decision planning.
**LOCAL v1 NOT CERTIFIED. DEV/PROD NOT_READY. Release HOLD.**
This dossier grants no release authority and creates no release certificate.

## Boundary and evidence provenance

The subject of the evidence is source SHA
`3b0eadcae26f5695505a35a65775c9415b28b539`, with Git tree
`83735e94370fb7dc45720a28845d7d172b14bd49`.
Prior independent GitHub API verification established this as the exact merged main tree at the time of the observed run; this preparation does not refresh remote main.
Local inspection confirmed the clean SOURCE fixture has that Git tree;
this task did not contact GitHub to independently refresh remote-main state.
The new dossier is NOT in that source commit and must never be represented as such.
Its later publication changes the source tree; the old run cannot be promoted
into exact-commit proof for a newly merged main containing this document.

Preparation uses only a new isolated copy at
`/tmp/avuhz-gate10-evidence-closure-39700493187-20261021`, mode 0700.
SOURCE is `/tmp/avuhz-gate10-runner-env-correction-b187ceb-20261021`.
The original `/home/network-p/avuhz-infra-clean`, resume fixture
`/tmp/avuhz-resume-42708b4-20261021`, and existing evidence are preserved.
Target absence, SOURCE cleanliness and tree identity were checked before copying;
SOURCE cleanliness and tree identity were checked again after `cp -a`.
Only this dossier is added in the new copy; no runtime or workflow change occurs.

Remote observations below were independently checked in preceding GitHub API and Codex evidence-verification sessions; this authoring step reproduces their recorded results.
They are not newly fetched logs or verification reruns performed by this task.
Local verification covers repository contracts, workflow step names and this text.
No raw provider payload, credential, authenticated URL or private client data is retained.

## Evidence identifiers and immutable subject identities

- E01: [Gate10 run 39700493187](https://github.com/AnonymousKoo/avuhz-infra/actions/runs/39700493187).
- E02: workflow `.github/workflows/gate10-exact-merge-ci.yml` at the subject source.
- E03: uploaded GitHub artifact ID `12393350895`, same run, attempt `1`.
- E04: independently downloaded exact wheel and separate isolated rehash observation.
- E05: independent CLI Sigstore TUF-root integrity and attestation verification record.
- E06: [attestation 58449920](https://github.com/AnonymousKoo/avuhz-infra/attestations/58449920).
- E07: historical offline wheel identity; comparison only, not the CI subject.
- E08: locally inspected contracts and certification-script limits listed below.

E01 was a successful first-attempt `workflow_dispatch`, finished
`2026-10-22T00:45:05Z`. Both `exact-merge-evidence` and
`attest-exact-wheel` PASSED. These are job results, not a release decision.
The UTC completion date follows the local October 21 preparation label;
no earlier completion time is inferred from the dossier filename.

E03 artifact name:
`gate10-wheel-3b0eadcae26f5695505a35a65775c9415b28b539-39700493187-1`.
Artifact ZIP SHA256:
`623bd5768e8a1ff68a7a4d7589b7a936410b8b2ba4e1ef09c40057207784ab61`.
Artifact expiry: **2026-11-21T00:44:54Z UTC**.

E04 wheel filename: `avuhz_service-0.1.0-py3-none-any.whl`.
Wheel SHA256:
`9ddc983a7f8c432ebc7203c60491e1b9ca08ba719eba363e070aee935c93f2c1`.
The artifact archive hash and wheel hash DIFFER: they identify different bytes.
An archive digest must not be substituted for the attested wheel subject digest.
E07 historical offline wheel SHA256:
`b0682bcf949faa49985eb8a4362f8d72af885b72c710b1b14ed88e6286dda899`.
That offline wheel is NOT the CI wheel; no reproducible-build equivalence is claimed.

## Verified evidence matrix

PASS below means the specified observation passed in the supplied evidence record.
Workflow names map the observation to E02; they do not invent Gates 1–10 statuses.

| ID | Observation / named source step | Result | Limitation |
|---|---|---|---|
| E01/E02 | `Run canonical repository baseline` | PASS | Exact subject run only; no release authority. |
| E01/E02 | `Run portable repository unit suites` | PASS | Local portable suites, NOT true cross-repository acceptance. |
| E01/E02 | `Record cross-repository portability gap` | Gap recorded | `cross_repo_suite_portable=false` remains unresolved. |
| E01/E02 | `Run PostgreSQL migration suites` | PASS | Disposable PostgreSQL 17, not provider migration evidence. |
| E01/E02 | `Replay provider-neutral baseline locally` | PASS | Local replay, not DEVELOPMENT or production state. |
| E01/E02 | `Run disposable PostgreSQL integration suites` | PASS | Disposable PG17 integration scope only. |
| E01/E02 | `Build repository wheel` | PASS | Built CI wheel; no equivalence with E07. |
| E01/E02 | `Verify repository wheel contents` | PASS | Producer validation; not exhaustive supply-chain safety. |
| E01/E02 | `Check immutable commit diff hygiene` | PASS | Subject commit hygiene, not this new document's CI proof. |
| E01/E02 | `Verify final raw checkout integrity` | PASS | Subject checkout integrity only. |
| E01/E02/E03 | `Revalidate exact wheel subject`; `Upload exact CI wheel for temporary retrieval` | PASS | Temporary GitHub retention is not WORM. |
| E01/E02 | `Download exact same-run artifact ID`; `Verify downloaded wheel without executing it` | PASS | Signer checks precede attestation; separate independent verification is E05. |
| E01/E02/E06 | `Attest exact CI wheel` | PASS | Action logs report Sigstore public good signature and Rekor log. |
| E04 | Separate isolated exact-wheel byte rehash | PASS | Digest match establishes byte identity, not vulnerability safety. |
| E04 | All 221 wheel ZIP entries: path, duplicate and type checks | PASS | Structural checks are not exhaustive archive or supply-chain review. |
| E05 | Independent CLI Sigstore TUF-root integrity | PASS | Earlier initialization failure was environmental; later verification passed. |
| E05/E06 | `gh attestation verify`, exactly ONE attestation | PASS | Constrained identity verification, not human release signoff. |

E05 verified repository ID `1231399336`, source SHA/ref and workflow constraints,
and signer digest equal to the exact subject source SHA above.
The verified attestation subject is the E04 wheel digest, not E03's ZIP digest.
Independent source/wheel verification is already done; it is not a pending retry.
The earlier environmental TUF initialization failure is historical troubleshooting,
not an unresolved signed-evidence verification failure.
No broader trust, publisher safety or unrelated workflow conclusion is inferred.

## Contract reconciliation

E08 includes `contracts/proposals/v1/gate10-exact-merge-worm-integration-plan.md`.
Its pending exact-run and independent verification stages now have E01–E06 evidence
for this subject; its external retention decisions and human approval remain open.
Older preparation statements about absent provenance describe their earlier scope.
They do not negate the subsequently observed independent verification success.

`docs/local-v1-supply-chain-evidence.md` describes candidate inventory limits;
its older missing-proof list is not an assertion that this later run never occurred.
`docs/local-v1-python-lock.md` limits the lock to CPython 3.12.3, Linux x86_64,
glibc 2.39 and selected dependency/build/verifier wheel graphs.
Neither those lock files nor matching digests supply human SBOM approval,
a lock of the entire runner environment, or support for other platform tuples.

`scripts/certify-local-infrastructure-v1.py` emits offline component evidence,
never a Gates 1–10 release certificate. Its candidate inputs and local suites
cannot replace independent review, retained immutable evidence or release authority.
It is inspected as a contract here, not executed to mint a new certificate.

## Remaining release-gap decision register

All owner assignments are PENDING; role descriptions below are required decisions,
not invented named owners. No release date or implicit acceptance is assigned.

| Gap / status | Risk | Accountable owner decision | Evidence needed | Scope / minimal next action |
|---|---|---|---|---|
| G01 OPEN: cross-repo portability | Local suites may miss actual consuming-repository incompatibility. | Acceptance owner PENDING; independent reviewer PENDING. | Independently observed appropriate cross-repo acceptance, or explicit reviewed disposition with limits. | Separate cross-repo plan; identify consumers and acceptance criteria without assuming other clients. |
| G02 BLOCKED: WORM pending | Expiry, deletion or privileged mutation could destroy release evidence. | Retention owner, administrator and independent verifier PENDING. | Exact immutable versions, effective lock/denial proof and independent digest readback. | Choose design first; exact storage operations require separate authorization. |
| G03 OPEN: human security / SBOM lock review | Machine checks do not establish acceptable dependency or residual security risk. | Human security and dependency reviewers PENDING. | Explicit review of exact source, locks, SBOM, provenance and scoped residual findings. | Review evidence; do not infer approval from signature verification. |
| G04 BLOCKED: LOCAL v1 release owner signoff | Unowned acceptance could be mistaken for certification. | Explicit LOCAL v1 release owner PENDING. | Recorded exact-subject signoff after required gaps are resolved or properly dispositioned. | Keep release HOLD; no agent-generated certificate. |
| G05 OPEN: residual ZIP/supply-chain disposition | Structural checks may leave semantic, dependency or publisher risks. | Security reviewer PENDING. | Assess whether further checks are needed; record rationale and bounded findings. | Do not claim exhaustive safety or invent a failed check. |

## WORM design decisions required before operations

Every entry below is PENDING; no provider, resource or identity is preselected.

| Decision | Required specificity |
|---|---|
| Target | Provider, service, account/project, region and namespace. |
| Objects | Bucket/container, versioned object names and immutable version identifiers. |
| Lock | Immutability lock mode, duration and exact start/end policy. |
| Denials | Privileged bypass, overwrite and deletion denial; applicable hold behavior. |
| Writer | Least-privilege writer identity and exact permitted object operations. |
| Administration | Storage and lock administrator identities, with approved separation. |
| Verification | Separate independent read-only verifier identity and audit responsibility. |
| Custody | Digest-indexed exact bytes, source/workflow/run binding, locks/SBOM and reviews. |
| Readback | Independent retrieval of exact locked versions and actual-byte digest comparison. |
| Timing | Retrieval deadline before GitHub expiry and accountable escalation owner. |

Thirty-day GitHub retention is NOT WORM. Attestations, action logs and `/tmp`
custody also do not prove immutable long-term storage or independent retention.
Expiry at 2026-11-21T00:44:54Z UTC creates a finite retrieval window;
resolve the design and operation authorization before that deadline.
Urgency does not authorize storage creation, upload, lock changes or credentials.
An upload result alone would not satisfy lock effectiveness or independent readback.
No external resources were created and no storage operation is authorized here.

## Four-lane assessment and release hold

Security: exact-subject verification passed; human risk and lock/SBOM review remain.
Infrastructure: disposable PG17 evidence passed; WORM target and retention proof remain.
Automation: exact-run producer/signer evidence passed; true cross-repo proof remains.
Business: release acceptance remains unowned and pending; no release date is promised.
Retention planning consumes effort that could otherwise serve first-client discovery;
this bounded closure supports evidence preservation without authorizing client intake,
tenants, billing, communications, application access or deployment.

Release HOLD remains explicit: LOCAL v1 NOT CERTIFIED; DEV/PROD NOT_READY.
This dossier closes documentation of observed evidence, not the release gaps.
No CI dispatch, authentication, secret operation, provider access, production action,
external WORM/storage operation, remote Git, PR, deployment or signing is performed.
This local preparation creates no commit or publication. A separately reviewed documentation-only PR may publish this dossier; doing so changes main identity and does not retroactively certify the subject commit.

Next specific decision boundary: the owner chooses the WORM design and required
writer/admin/independent-verifier identity separation, then separately authorizes
exact target operations. Independent source/wheel verification is already complete.
Cross-repo acceptance planning remains a separate bounded work item.
