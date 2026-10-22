# Avuhz Local V1 release evidence audit — 2026-10-19

## Audit identity and conclusion

This repository-local, read-only evidence audit evaluates the first 12 Local V1
criteria in `AVUHZ_V1_COMPLETION.md` against exact merged `main` commit
`55ff37f2c70c31e9988340dacdb7577e43bbb5a9` (PR #757). The checklist itself is a
stale source snapshot of `99130ed4c57eccd839076c46a82405eacc6b666a` dated
2026-10-17; its status labels are not silently rewritten here.

Result: **8 PASS, 2 PARTIAL, 2 BLOCKED**. Local V1 release signoff is
**BLOCKED**. The merged unified acceptance suite and CI prove substantial
LOCAL/TEST behavior, but do not prove the OIA evidence-to-reviewed-finding-to-
diagnostic-agreement-to-authorized-handoff chain required by Item 5. Green CI is
not Local V1 signoff and makes no DEVELOPMENT, hosted-provider, client, staging,
or production claim.

Verified CI evidence supplied for this audit:

- PR #757 merged as exact SHA `55ff37f2c70c31e9988340dacdb7577e43bbb5a9`.
- **Main PR Gate: SUCCESS** for the merged change.
- **Avuhz Batch2 Governed Work LOCAL Certification: SUCCESS**, including the
  disposable PostgreSQL 17 unified suite: **9/9 passed, zero skipped**.

No workflow run identifier, immutable log artifact digest, or release-signoff
attestation was supplied to this repository record. Therefore these outcomes are
bounded audit inputs, not a durable release attestation or provider observation.

## Criterion-by-criterion record

`Source status` reproduces the stale checklist status vocabulary. `Audit status`
is the independent 2026-10-19 result at the merged SHA.

| # | Criterion source (condensed) | Source status at `99130ed` | Evidence at `55ff37f` | Audit status |
|---:|---|---|---|---|
| 1 | Preserve authority separation, least privilege, tenant RLS, fail closed | `SOURCE-VERIFIED` | `SECURITY.md`, canonical migration/RLS tests, Main PR Gate and baseline success; no provider claim | **PASS** |
| 2 | Client-neutral tenant/organization/owner onboarding | `PARTIAL` | `shared_client_onboarding_local_proof.py` plus unified tests 01–02 prove fictional PENDING-to-ACTIVE mechanics and denials while withholding live authority | **PASS** |
| 3 | Server-derived identity/membership/command authority with denials | `SOURCE-VERIFIED` | Existing guard/admission tests and unified tests reject forged, stale, revoked, caller-supplied, and wrong-scope authority | **PASS** |
| 4 | Provider-neutral command/query runtime and one transaction boundary | `SOURCE-VERIFIED` | Disposable PostgreSQL unified tests prove governed Work Item/UoW atomicity, rollback, and authoritative/event/outbox coupling | **PASS** |
| 5 | Connect OIA evidence, reviewed findings, and governed implementation handoff | `PARTIAL` | Methodology and Phase 5B architecture exist; `implementation_handoff.py` accepts already-approved opaque truth. No executable upstream binding contract/test exists | **BLOCKED** |
| 6 | Separate DEVELOPMENT evidence from current source/provider truth | `PARTIAL` | Boundary rules exist, but `docs/current-build-state.md` remains stale relative to merged shared communications/usage code and no fresh provider read is authorized here | **PARTIAL** |
| 7 | Transactional outbox and safe local worker | `SOURCE-VERIFIED` | Unified PostgreSQL path proves post-commit receipt/effects, rollback separation, safe retry/error behavior, and forged-event non-authority | **PASS** |
| 8 | Shared LOCAL/TEST n8n orchestration boundary | `PARTIAL` | Durable local receipt and CI composition execute, but there is no single documented clean-checkout command that a reviewer can run as the complete boundary | **PARTIAL** |
| 9 | Shared communications adapter and deterministic local fake | `NOT STARTED` | `shared_communications_local.py`, fanout composition, focused negatives, replay, retry, and unified exact-once evidence are merged | **PASS** |
| 10 | Shared usage metering and deterministic local billing fake | `NOT STARTED` | `shared_usage_billing_local.py`, fanout composition, focused negatives, replay, retry, and unified exact-once unpriced measurement evidence are merged | **PASS** |
| 11 | Shared acquisition-to-Work-Item intake without System 001 authority | `PARTIAL` | Governed-work PostgreSQL and unified tests prove fictional acquisition to one authoritative Work Item/event/outbox with replay and denial; no Work Item-to-Engagement conversion is required or claimed | **PASS** |
| 12 | One clean-checkout client-neutral Local V1 release gate | `PARTIAL` | CI invokes a fail-closed opt-in unified PostgreSQL suite and passed 9/9 with zero skips, but that suite omits Item 5 and no single documented clean-checkout release command exists | **BLOCKED** |

Items 13–14 in the checklist concern staging/production operational controls and
production launch certification. They are outside this Local V1 12-criterion
audit and remain blocked by their own authority and evidence requirements.

## Exact unmet release evidence

### Item 5 — OIA binding

Release evidence lacks an executable, client-neutral contract and tests proving:

- authorized, scoped evidence provenance without raw client/provider payloads;
- immutable draft provenance with AI restricted to `DRAFT`;
- fresh, attributable, independently trusted human finding finalization;
- a real distinction between findings delivery, counterparty agreement evidence,
  implementation authorization, and technical handoff acceptance;
- exact tenant/organization/engagement/assessment/subject and version/digest
  continuity through the chain;
- separate client/provider handoff approvals consumed by the existing
  `implementation_handoff:accept` boundary; and
- denial, replay, supersession, revocation, cross-tenant, concurrency, and atomic
  mutation/event/outbox behavior.

The non-canonical companion proposal
`docs/oia/oia-diagnostic-handoff-binding-design.md` is design evidence only. It
does not close Item 5.

### Item 6 — current truth

`docs/current-build-state.md` still says shared communications and usage are
unimplemented, while merged source now contains deterministic LOCAL fakes and
tests. That discrepancy must be reconciled in a separately bounded documentation
change. Any provider statement must still name the exact resource, commit,
observation time, and evidence under fresh read authority; source and CI cannot
refresh provider truth.

### Item 8 — reproducible clean-checkout entrypoint

The workflows contain CI steps, but the repository does not document one
reviewer-facing clean-checkout command that composes all required LOCAL/TEST n8n
receipt behavior, prerequisites, mandatory test counts, zero-skip checks, cleanup,
and safe failure semantics. A collection of workflow fragments is not that
command.

### Item 12 — unified release certification

The current unified suite deliberately covers onboarding, governed Work Item,
durable receipt, communications, usage, replay, rollback, tenant denial, and PII
rejection. It does not cover Item 5. Its successful 9/9 CI result therefore
cannot yield Local V1 release signoff. Durable certification also needs the exact
workflow run identity and immutable evidence/artifact references bound to the
reviewed commit, rather than an unbound success statement.

## Proposed future fail-closed release wrapper

No command is authorized or invented by this audit. Under a separate repository
approval, one repo-owned wrapper should:

1. require an exact reviewed commit and a clean checkout, and reject untracked or
   modified files;
2. create isolated temporary HOME/XDG state, prohibit provider credentials and
   provider contact, and use only fictional fixtures;
3. require an already approved, digest-pinned PostgreSQL 17 image; create one
   uniquely named, loopback-only, no-volume disposable database; refuse any
   pre-existing target; and always remove only the container it created;
4. run `scripts/check-baseline.sh`, prove Semgrep actually executed, and reject
   any skipped or bypassed security stage;
5. run the existing unified LOCAL suite with its mandatory PostgreSQL flags and
   exact expected inventory, then run the future Item 5 synthetic binding suite;
6. fail on any missing prerequisite, empty suite, skip, count drift, unsafe log,
   partial cleanup, digest mismatch, or nonzero subprocess exit;
7. emit a sanitized evidence manifest containing commit SHA, wrapper/source
   digest, pinned database image digest, test names/counts, zero-skip assertion,
   baseline/Semgrep result, start/end times, and exit codes; and
8. report PASS only when all 12 criteria are evidenced at the same commit. The
   result must state that it certifies LOCAL source behavior only.

This wrapper must not pull from the network by default, read hosted state, load
credentials, contact Supabase/n8n/Stripe/communications providers, or imply
DEVELOPMENT or production readiness.

## Handoff and next action

The owner should first approve or revise the authority, agreement-meaning,
cardinality, revision, revocation, digest/signature, and handoff-separation rules
in the companion non-canonical design. Then authorize bounded implementation and
test PRs, followed by the fail-closed clean-checkout release wrapper. After those
pass at one exact commit, reconcile stale build-state/completion documentation and
perform an explicit Local V1 signoff. Hosted/provider readiness remains a
separate, freshly authorized boundary.
