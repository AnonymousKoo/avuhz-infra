# Infrastructure Authority V1 — DEVELOPMENT target-state review candidate

**Status:** LOCAL/TEST repository-only pure reviewer, NOT live discovery,
provider mutation, resource inventory storage, drift agent, authorization,
or Phase 5D DeploymentVerification.

## Grounded shared control plane

Existing Phase 5D deployment contracts define target reference/class,
expected artifact digest, observed-state fingerprint, and evidence
references. Existing runtime modules provide DeploymentAuthorization,
DeploymentExecution and DeploymentVerification as separately bounded,
tenant-scoped domain records. They do not themselves discover live
provider resources.

The new src/avuhz_runtime/infrastructure_state_review.py uses exactly
these conventions, with classes SYSTEM, SERVICE, COMPONENT, HOST_GROUP,
sha256 digests, fpvN fingerprints and MATCHED/MISMATCHED/BLOCKED
review markers. Test reference render.srv123 is synthetic, not a live
provider resource. No vertical-specific infrastructure is introduced.

Inputs: one trusted caller-injected canonical tenant UUID, a tuple of
1–50 desired DEVELOPMENT targets and 0–50 claimed observations, one
UTC clock and server policy limiting observation age to 1–1440 minutes.
Malformed, duplicate or extra targets, untrusted scope, non-development
environment, invalid fingerprints, evidence reference or non-UTC
timestamps are denied. Missing/stale/future observations result in
BLOCKED. Fresh digest difference returns MISMATCHED, equality MATCHED.

Outputs include only opaque target ID/class, one fixed status and an
opaque evidence reference. No provider config, credentials, PII, tenant
identifier or direct remediation instructions are returned.

**Never confuse a matching digest with independent verification.**
Desired targets and observations must first be authenticated,
tenant-authorized, bound to the exact immutable Phase 5D resource list,
and independently attested against a provider-owned read-only data
source. The module does NOT prove those facts or authorize execution.
A MISMATCHED result is a review signal, NOT an instruction to mutate.

## Missing V1 capabilities and acceptance gates

1. Verify exact provider project, namespace and environment plus one
   authorized DEVELOPMENT resource, such as the existing Avuhz Render
   command service.
2. Prove source-owned inventory and immutable approved desired state
   through one read-only, least-privilege provider adapter, including
   provider-authenticated provenance and canonical state hashing.
3. Persist scoped observations in Avuhz shared DATA/RLS/outbox via a
   separately approved shared persistence design; never build a second
   infrastructure database or tenant authority.
4. Require exact bounded Phase 5D approval for a proposed change.
5. Execute exactly one approved DEVELOPMENT operation and independently
   re-observe/verify its result; retain recovery/audit evidence.
6. Prove provider outage, stale proof, conflicting observations,
   cross-tenant denial, lost acknowledgment and rollback recovery.
   Production remains unapproved.

This source change only implements a pure comparison contract, not live
inventory, stored observations, automated remediation or hosted readiness.

LOCAL n8n 127.0.0.1:5678, production n8n.sekinfra.com, Supabase
DEVELOPMENT AUTH pwlhruwutoitnieactol and DATA gnuqaefotwgkwurjpyik
are separate, and none is changed by this source PR.

**Next action:** Run focused tests, full baseline and Codex review;
publish one source-only PR. Then separately approve an exact read-only
DEVELOPMENT provider observation. Do not call Infrastructure V1 ready
until the complete governed operational loop is certified.
