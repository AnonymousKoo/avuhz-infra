# OIA diagnostic-to-implementation handoff binding

> **NON-CANONICAL PROPOSAL — NOT APPROVAL OR AUTHORITY.** This document proposes a
> LOCAL/TEST contract for owner review. It implements nothing, grants no role or
> capability, and proves no live OIA, client agreement, provider state, or
> implementation authorization.

## Purpose and boundaries

The goal is a reviewable, client-neutral binding from consented OIA evidence to a
human-finalized finding, exact diagnostic-agreement evidence, and a separately
authorized `ImplementationHandoff` accepted through the existing governed
Executor/Unit-of-Work path. The binding must preserve tenant, organization,
engagement, assessment, and subject identity throughout; make every authority
transition attributable; and fail closed on missing, stale, conflicting, revoked,
or cross-scope evidence.

This proposal does **not**:

- assert that an authoritative OIA runtime/model or application access exists;
- create a Work Item-to-Engagement conversion or make a Work Item authoritative
  for an OIA engagement;
- turn evidence, AI output, findings delivery, an agreement receipt, an event, or
  an outbox record into implementation approval;
- add hosted intake, live/hosted authentication, client data, provider access,
  Supabase changes, n8n writes, communications, billing, or deployment authority;
- replace Phase 5C commercial authority, Phase 5D build authority, or the existing
  client and provider approvals required by `ImplementationHandoff`; or
- authorize implementation of this design.

## Existing contracts that remain authoritative in their own bounds

`docs/oia/universal-oia-methodology.md` separates a client report from an
authoritative finding and reserves finding finalization to a trusted human.
`docs/phase5b-oia-architecture.md` is architecture, not proof of an implemented
OIA backend. It proposes evidence provenance, reviewed findings, immutable
delivery manifests, and states that findings delivery is diagnostic completion,
not conversion or implementation approval.

`src/avuhz_runtime/implementation_handoff.py` begins later. Its existing
`ImplementationHandoffAcceptanceService.accept` accepts a complete, already
approved contract only when:

- the trusted tenant matches;
- the caller is an `INTERNAL_SERVICE` or `PROVIDER_ADAPTER` with
  `implementation_handoff:accept`;
- exact, separately attributable client and provider approval references exist;
- source artifact references are unique and bounded;
- the version, supersession/revocation state, and canonical SHA-256 digest are
  valid; and
- the Unit of Work can create the record against current history.

That service does not establish upstream OIA truth or approval. This proposal
must feed it without weakening or duplicating that boundary. A future command
composition must use the existing Executor/UoW transaction boundary; direct
table writes, browser writes, and n8n writes remain prohibited.

## Proposed LOCAL/TEST binding

This is a proposed sequence, not a claim that the named resources exist:

```text
authorized evidence intake
  -> immutable OIA evidence provenance
  -> immutable draft-finding revision (AI may propose DRAFT only)
  -> fresh trusted HUMAN_REVIEWER finalization
  -> exact CLIENT_SIGNER diagnostic-agreement evidence
  -> separate client + provider implementation-handoff approvals
  -> SERVICE_ADAPTER invokes existing implementation_handoff:accept command
  -> accepted ImplementationHandoff + lifecycle/outbox intent atomically commit
```

### 1. Evidence intake and draft finding

Evidence intake accepts only sanitized metadata and an opaque approved-object
reference, never raw provider payloads, credentials, full logs, or client data in
fixtures. The server resolves the current tenant, organization, engagement,
assessment, subject, permitted source/action, trusted capture time, and actor.
All bindings must agree with current authoritative records before an immutable
evidence-provenance record is admitted.

The proposed `OIADraftFindingRevision` is an immutable candidate snapshot bound
to exact evidence/observation/root-cause revisions and their digests. A change
creates a new draft revision; it does not rewrite history. This snapshot is a new
proposal and must not be confused with the mutable, expected-version `DRAFT`
described by the current Phase 5B architecture. The owner must decide whether it
is a separate review artifact or a revision to that architecture before coding.

AI may group evidence, identify gaps, suggest hypotheses, and author draft text.
Its attribution is `AI_ASSISTED`; its authority is always `DRAFT`. AI cannot
capture evidence, verify a root cause, finalize a finding, impersonate a human or
client, create an agreement, or authorize/accept a handoff.

### 2. Human-reviewed final finding

Only a freshly authenticated, trusted human with the exact delegated reviewer
role and proposed capability `oia:finding:finalize` may finalize. The proposed
role label is `HUMAN_REVIEWER`; it is vocabulary for owner review, **not a grant**.
The command must server-resolve reviewer identity, current delegation, freshness,
tenant/organization membership, assessment scope, and expected revision.

Finalization creates an immutable final finding revision and attribution record.
It cannot widen scope, convert limitations to facts, or approve implementation.
Any correction is a new independently reviewed revision that identifies the exact
superseded `(finding_id, version, digest)`; earlier history remains readable.

### 3. Diagnostic-agreement evidence

The proposed `CLIENT_SIGNER` label identifies the client counterparty permitted
to attest to the exact diagnostic-agreement artifact. It is not a repository role
or grant. The server must verify current counterparty authority independently and
must never manufacture a signature, infer agreement from delivery/open/click
events, or let an Avuhz reviewer self-sign for the client.

An agreement receipt should bind the tenant, organization, engagement,
assessment, exact finalized finding manifest, agreement identity/version/digest,
signer identity and organization, signature-verification provenance, trusted
verification time, and status. It records what was verified; it does not itself
grant assessment access, implementation authority, deployment authority, or
accept the handoff.

**OPEN OWNER QUESTION:** does a counterparty receipt merely prove delivery or
acknowledgement, or does it prove legally effective diagnostic agreement? These
meanings must be separate closed states unless counsel and the business owner
approve one exact interpretation. Neither meaning is implementation approval.

### 4. Separately authorized implementation handoff

The provider prepares an `ImplementationHandoff` only from exact current final
finding and diagnostic-agreement references. Existing contract fields and the
two distinct `CLIENT_APPROVER`/`PROVIDER_APPROVER` references remain required.
Handoff authorization is the upstream decision to approve the content;
acceptance is the later technical act of admitting that already-approved record.
They must never collapse into one actor, receipt, capability, or command.

The proposed `SERVICE_ADAPTER` label may consume approved evidence and invoke
only the existing `implementation_handoff:accept` capability through the command
Executor/UoW. It may not finalize findings, countersign, create approvals, widen
scope, select a tenant, or write authoritative tables directly. The existing
runtime caller types remain unchanged unless a separately approved contract
change maps this label to an existing trusted caller type.

## Integrity, replay, and lifecycle rules

- Canonical records use an explicit schema version and the existing
  sorted-key, compact, ASCII JSON profile before SHA-256; the digest field is
  excluded while hashing and represented as `sha256:<lowercase hex>`. Changing
  the profile requires a new version, never silent reinterpretation.
- Signature provenance binds the canonical digest plus tenant, organization,
  engagement, assessment, subject, purpose, and version. Retain the algorithm,
  verifier, non-secret key identifier, verified-at time, and opaque signature or
  verification receipt reference. Never store private keys or secret material.
- Every command has a tenant-scoped idempotency key and semantic request digest.
  Exact replay returns the original result; same-key semantic change conflicts;
  cross-tenant replay is denied.
- Final findings, agreement receipts, approvals, and accepted handoffs are
  immutable. Supersession uses exact predecessor identity/version/digest links.
  Stale, forked, missing, circular, or cross-assessment lineage fails closed.
- Revocation is attributable and versioned. A revoked prerequisite blocks new
  handoff acceptance. Whether a later upstream revocation invalidates an already
  accepted handoff is an owner decision; no asynchronous inference may silently
  mutate accepted truth. Existing terminal handoff revocation behavior remains.
- When implemented, each authoritative mutation, idempotency completion,
  lifecycle event, and outbox intent commits in one Executor/UoW transaction.
  Failure rolls all of them back. Events, receipts, logs, and read models remain
  non-authoritative and contain only sanitized metadata.

## Required test design

All fixtures are fictional and LOCAL/TEST only. At minimum, implementation must
prove these negative cases with zero authoritative writes, events, outbox intent,
or completed idempotency records:

1. AI/workload attempts to finalize a finding or pose as `HUMAN_REVIEWER`.
2. Stale authentication, revoked delegation, or missing exact reviewer capability.
3. Tenant, organization, engagement, assessment, or subject mismatch anywhere in
   the evidence-to-handoff chain.
4. Missing evidence digest, changed content under the same digest, unsupported
   canonicalization version, or invalid signature provenance.
5. A delivery/open/click receipt is presented as counterparty agreement.
6. Avuhz/provider identity is presented as `CLIENT_SIGNER`, or the client signer
   lacks current counterparty authority.
7. A finding is draft, superseded, revoked, stale, or outside the signed manifest.
8. Agreement acknowledgement is presented as implementation approval, or either
   exact client/provider handoff approval is absent or duplicated.
9. Same idempotency key carries changed semantics, or exact evidence is replayed
   across tenants.
10. A service adapter selects scope/tenant, finalizes, signs, writes a table
    directly, or lacks `implementation_handoff:accept`.
11. A concurrent supersession/finalization loses expected-version comparison.
12. An injected repository/event/outbox failure attempts a partial commit.

The positive synthetic fixture should use one fictional tenant, organization,
engagement, assessment, and subject. It records sanitized evidence provenance;
creates one immutable AI-assisted draft revision; has a distinct, freshly trusted
human finalize it; verifies an independently attributable fictional client
signature over the exact agreement/finding manifest; records separate fictional
client and provider handoff approvals; computes the existing canonical handoff
digest; and invokes the existing acceptance capability through Executor/UoW.
Assertions must cover the exact accepted version/digest, one atomic authoritative
record plus sanitized event/outbox intent, exact replay without duplicates, and
denial after revocation. Passing proves source behavior only.

## Implementation phases requiring separate approval

1. Owner decisions and threat/authority review; freeze vocabulary and schemas.
2. Contract/schema and pure validation tests only.
3. LOCAL in-memory command composition through the existing Executor/UoW.
4. Disposable PostgreSQL persistence, tenant RLS, atomicity, and replay tests.
5. Add the complete binding to a fail-closed clean-checkout Local V1 release gate.

Each phase is a new bounded repository change. Hosted adapters, real client data,
provider reads/mutations, and any DEVELOPMENT or production action remain outside
this sequence and require their own exact authority.

## Open owner decisions

- Which implemented authoritative source, if any, owns OIA assessment, evidence,
  finding, and reviewer-delegation truth?
- Is the immutable draft snapshot separate from, or a replacement for, the
  Phase 5B mutable draft model?
- Who may delegate/revoke `HUMAN_REVIEWER`, with what freshness and independence?
- Who is the legal `CLIENT_SIGNER`; is provider countersigning required; and how
  is current counterparty authority verified?
- Does the agreement receipt mean delivery, acknowledgement, or legally effective
  diagnostic agreement, and what evidence proves each state?
- What is the cardinality among assessments, findings/manifests, agreements, and
  handoffs? May one agreement select a strict subset of findings?
- When may a final finding be revised, who reviews the revision, and what happens
  to an agreement or handoff bound to the superseded version?
- What exact upstream decision authorizes handoff content, and how is that kept
  distinct from technical `accept` admission?
- What are revocation effective-time, notification, retention, and already-started
  implementation consequences?
- Which versioned signature/canonicalization profile and trusted time source are
  approved, and where are public verification keys/provenance maintained?

Until these decisions and the phased implementation are separately approved,
Item 5 remains blocked and this proposal must not be treated as canonical truth.
