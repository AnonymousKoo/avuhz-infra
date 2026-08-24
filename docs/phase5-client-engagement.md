# Phase 5 — Client Engagement Eligibility and Assessment Authority

## Mission and starting state

Phase 5 turns an approved diagnostic scope into a governed client engagement without treating scope approval as access authority. Post-Phase-4 authoritative records are AcquisitionHandoff, Engagement, DiagnosticScope, and HumanApproval. None proves a diagnostic agreement, payment satisfaction, or assessment access.

## Frozen boundaries

- **5A — Diagnostic eligibility and assessment authority/access:** verified diagnostic agreement authority, future provider-neutral diagnostic payment verification, and the future AssessmentAccessGrant eligibility and access boundary.
- **5B — OIA execution, evidence, and findings:** execute only within a valid assessment grant; record evidence and findings. It creates no ongoing authority.
- **5C — Conversion and ongoing eligibility:** conversion decision, Agreement #2, and separately governed ongoing authority/access.
- **5D — Implementation Brief / Codex Build Package:** a first-class package containing verified problem, desired outcome, current-system map, constraints, approved scope, integrations, access level, risks, requirements, acceptance criteria, and explicit prohibited changes.

## Agreement #1 and payment

`DiagnosticAgreementAuthority` is the first Phase 5 resource. It is the authoritative record that the diagnostic/OIA agreement has been verified. It has a tenant and engagement binding, a closed `DIAGNOSTIC_OIA` agreement type, opaque agreement reference, closed authority status, exact versioned DiagnosticScope reference and canonical scope digest, effective/end times, verified/recorded times, and record version. It deliberately does not contain a contract PDF, signature, provider payload, payment fact, credential, ongoing Agreement #2, or production-change authority.

Diagnostic payment verification is not yet implemented. It remains a separate future authoritative resource for the payment required for the diagnostic/OIA, with provider-neutral opaque reference and verified status. Legal authority and payment satisfaction must never share an ambiguous status.

## Assessment eligibility and access boundary

A future AssessmentAccessGrant may be created or approved only when all predicates hold: the Engagement is eligible/active; DiagnosticScope is `SCOPE_APPROVED`; its canonical digest exists; the exact scope/version binding matches; a required `DiagnosticAgreementAuthority` is currently `VERIFIED_ACTIVE` and valid; and the required diagnostic payment verification is verified. Scope approval alone never creates access.

Assessment access is diagnostic-only, temporary, read-only/non-destructive by default, and limited to the exact scope, digest, permitted action set, and bounded target systems. It cannot widen authority, cannot contain raw credential material, and requires explicit access verification plus explicit revocation/expiration. The permitted and prohibited diagnostic-action vocabularies remain unchanged from Phase 4.

Maximum TTL is 30 calendar days from successful access verification. It ends immediately, without grace period, on the earliest of findings delivery, assessment/OIA closure, agreement end, explicit revocation, or TTL expiry. Extension requires new client and Sekinfra authorization. Assessment access is distinct from future ongoing access.

## Credential separation

Raw credentials are prohibited from commands, business records, events, outbox, logs, reports, documentation, Git, and normal API payloads. A future grant may reference a secure credential mechanism only by opaque reference; authorization metadata is not credential material.

## Deferred work

No Phase 5B, 5C, or 5D resource is implemented here. No migration, Postgres repository, remote Supabase operation, provider integration, or runtime command execution is included. The next batch is exactly the separate `DiagnosticPaymentVerification` resource contract.
