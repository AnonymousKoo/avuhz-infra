# Avuhz shared n8n workflows — legacy reconciliation and reuse boundary

**Status:** LOCAL/TEST repository-local documentation based on a sanitized local inventory and repository inspection, October 14, 2026. **Not** a hosted n8n inventory, workflow import, migration, customer cutover, or activation. Original legacy JSON was *not* copied into this repository.

## Verified resource boundary and source fidelity

- Repository: `AnonymousKoo/avuhz-infra`, isolated branch from `main` at `b1d40f88d02fd05fc1596c80a48d76921f4057c6`. Action class: `R0` source-only documentation, LOCAL/TEST; no hosted n8n/Supabase/Cal.com mutations or elevated provider reads. `avuhz-infra-clean` has an independent pre-existing dirty file; it was not modified.
- Responsibility: Avuhz architecture assigns shared **identity, tenant authority, domain/command service, authoritative DATA, lifecycle events, outbox, billing and communication boundaries**; this does not assert all these primitives are operationally installed. **n8n orchestrates** sanctioned event-driven workflow execution, waits, retries and provider actions; n8n does **not** authorize tenants, bill customers, or write Avuhz authoritative tables directly.
- DEVELOPMENT Supabase AUTH project `pwlhruwutoitnieactol` and DATA project `gnuqaefotwgkwurjpyik` are distinct; neither was accessed for this task. Production, hosted n8n, Cal.com, credentials, Supabase, n8n activations and Sekinfra deployments are outside this change.

| Evidence source | Observed status | Certainty and limitation |
| --- | --- | --- |
| Canonical Avuhz repository source | Zero tracked canonical n8n workflow JSON exports; `security/forbidden-path-patterns.txt` blocks `n8n-workflows/` and `.n8n/` | Verified repository file path inventory; **do not weaken these guards to import old JSON** |
| Canonical Avuhz orchestration code | `src/avuhz_worker/n8n_event_sink.py`, `local_n8n_receipt_http.py`, `local_n8n_receipt_store.py` and local synthetic worker/receiver tests exist | LOCAL/TEST adapters only; **not** proof of hosted receiver, verified private transport or durable provider receipt store |
| Older unversioned local checkout | 15 JSON workflow export structures, all with exported `active: true` | Metadata-only local audit; export flags **do not establish** present deployment, active state, valid credentials or tenant safety |
| Local n8n SQLite/workstation metadata (read-only observation, 2026-10-14) | `AI Auto Marketing Check` and `Avuhz Shared Event Receiver — LOCAL TEST (INACTIVE)`; both inactive. A local Docker `n8n` container was observed running at inspection time only | Historical local snapshot; container status can change and is **not** evidence of any remote/hosted n8n inventory or production state |
| Sekinfra website (repo/owner-reported context as of 2026-10-14) | Source-only PR #50 prepared an optional Cal.com link; owner requested production hold; website intake was reported fail-closed | External state was not independently re-verified in this audit; no authority to enable submissions or deploy either Sekinfra Vercel project |
| Cal.com → Avuhz (owner-reported context, 2026-10-14) | Owner reports Cal.com `cal-booking` webhook OFF; source-only Avuhz PR #675 proposes raw-body signature validation | Neither hosted webhook state nor PR status was re-verified here. HMAC alone does not authorize a booking or prevent replay; no credential activation authorized |

The legacy names below come from sanitized node-type/trigger metadata, **not** a node-by-node behavioral certification. Workflow titles are historical labels; they are not versioned template definitions, and a proposed reuse classification is not permission to activate a workflow.

## Fifteen legacy workflows mapped to reusable Avuhz systems

**Classification:** `Redesign` means retain business *intent*, replace untrusted ingress/direct data access; `Candidate` means inspect sanitized logic for reuse after shared contract/credential review; `Retire path` means do not reintroduce that old public/privileged entry point; the future behavior may be implemented through the existing shared backbone.

| Historical export | Family | Observed trigger / size | Decision and exact safe next use |
| --- | --- | --- | --- |
| Revenue Intake | **#001 Revenue Engine** | POST webhook, 12 nodes | **Redesign:** integrate consented acquisition through authenticated Avuhz ingress; trusted tenant binding and governed command; n8n may consume sanitized events, not accept unauthenticated lead authority |
| Call Booking Sync | **#001 + #002 Booking** | POST webhook, 23 nodes | **Redesign:** Cal.com owns availability; add signed/reconciled booking intake, deduplication and Work Item command before follow-up; Cal.com webhook **must remain OFF** until separately approved |
| Meeting Completed | **#002 + #005 Retention** | POST webhook, 7 nodes | **Redesign:** verified appointment completion or no-show evidence enters Avuhz command API before any follow-up |
| DocuSeal SA | **#003 Client Onboarding** | POST webhook, 8 nodes | **Redesign:** verify signature/contract provider callback, tenant/account mapping and accepted commercial handoff; no client creation from raw webhook |
| Payment Confirmation | **#003, shared billing integration** | POST webhook, 16 nodes | **Retire path:** no vertical-owned payment verification; shared Stripe billing and authorization must own payment state before onboarding n8n is notified; **shared billing implementation is not certified live** |
| Credentials request | **#003 Client Onboarding** | GET webhook, 7 nodes | **Retire path:** no public credential-collection webhook; replace with approved secure secret/access-grant process, not plaintext emails or n8n JSON storage |
| Credentials received | **#003 Client Onboarding** | POST webhook, 7 nodes | **Retire path:** prohibit raw credentials through n8n; use approved vault/access grant confirmation and reference-only events |
| Automation Runner | **#004 Work & Operations** | Schedule, 58 nodes | **Redesign:** candidate for sanctioned work assignment/retry runbook; must stop direct provider table updates and invoke governed Avuhz commands |
| Deployment States | **#004 Work & Operations** | POST webhook, 21 nodes | **Redesign:** authoritative deploy authorization/status remains in Avuhz; n8n may relay sanitized observations after trusted verification, not grant deploy authority |
| Failure Alerts | **#004 + shared reliability** | Error trigger, 3 nodes | **Candidate:** centralized non-PII alert routing from sanitized failures; no secrets/exception bodies or customer data in alert payloads |
| Infra Monitor Runner | **#004 + shared reliability** | Schedule, 6 nodes | **Candidate:** safe read-only health observations under scoped credentials, not direct elevated operational mutation |
| Trigger to Deployment | **#004 Work & Operations** | Schedule, 5 nodes | **Retire path:** autonomous deployment trigger is not authorization; future automation requires existing explicit deployment approval and single-resource execution gate |
| Follow-Up Engine | **#005 Customer Retention** (also #001 recovery) | Schedule, 43 nodes | **Redesign:** consume approved follow-up obligations with consent/suppression, per-tenant ownership, idempotent delivery and retry; do not let legacy timers become authoritative CRM state |
| Secure Dashboard API | **Shared command-center read model** | GET webhook, 6 nodes | **Retire path:** do not expose a dashboard API via unauthenticated n8n webhook; existing Avuhz authenticated read model and tenant policy must be authoritative |
| OIA Intake | **Sekinfra consulting only** | POST webhook, 16 nodes | **Separate:** Sekinfra OIA is an internal service method; do not make OIA a required Avuhz booking/onboarding/tenant template; any authorized OIA process still uses shared Avuhz controls |

**Security observation:** 10 of the 15 historical exports have Webhook nodes whose **native node-authentication parameter is absent or `none`**. That is a stop condition for direct import or activation, but is **not** proof that a historical workflow had no later custom check or that the currently hosted workflow has the same setting. The exports also contain HTTP/database operations, credential-related terms and possible contact fields. A sanitized metadata scan does **not** establish that any hardcoded secret is present or absent. Source files must be inspected privately and remediated without reproducing credentials, raw JSON, provider payloads, customer data or secret-derived hashes in Git, pull requests or logs.

## Required target execution boundary — not yet proven hosted

1. **Source event / command:** external booking/provider event **must arrive** through a separately approved authenticated ingress; Avuhz **must validate** provider authenticity, provenance, allowlisted event type, independently bound tenant and identity. Browser claims and Cal.com event identifiers are never authorization.
2. **Authoritative state:** the Avuhz shared command service **must check** capability, tenant membership, exact subject state/version, unique durable idempotency, transactional DATA RLS and permitted grants; state, event and outbox **must be committed atomically**. Repository code/contracts are not proof of hosted end-to-end execution. A payment, contract or signature only becomes business authority after its own certified shared domain decision.
3. **Orchestration:** a bounded Avuhz event projection **must go** to one approved authenticated shared n8n receiver. Its **future** durable receipt **must deduplicate** deliveries before effects and acknowledge only a committed receipt. Existing repository outbox code defines publish/retry/dead-letter behavior; hosted delivery is unverified. n8n **must use** encrypted credentials and a least-privileged Avuhz API for any later command; **never direct writes to authoritative Supabase tables**.
4. **Provider effects:** Cal.com is the selected calendar reservation source. Approved communications **must enforce** consent, opt-out, rate limits, safe templates, delivery/retry receipts and per-tenant routing. Follow-up obligations and overdue escalations **must reside** in authorized Avuhz state rather than wait-node memory alone. These hosted communication and deadline paths are not yet certified.
5. **Operational evidence:** test accepted, denied, duplicate, reordered, stale, cross-tenant, unauthorized, partial-failure, lost-ACK and recovery cases with synthetic records. Do not call an offline test, export flag or successful webhook response a live end-to-end system.

## Release gates — check each workflow before any hosted activation

- **Instance/environment:** identify a distinct authorized n8n **DEVELOPMENT** instance, namespace, version, deployment, credential backend and enabled feature set using independently approved read-only inventory. Never infer it from the local SQLite or an old JSON export. Explicit production scope/approval is separate.
- **Ingress:** native n8n auth on Avuhz event receiver plus an approved allowlisted origin; independently verify upstream signatures (Cal.com, contract/payment services), exact body, replay/freshness behavior and rate limits. A signed message still does not confer tenant/owner authority.
- **Tenant and RLS:** trusted server-side mapping for tenant, account and authorized owner; disallow browser/webhook tenant claims, `service_role`, overbroad RLS and provider-to-DATA direct writes. AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` remain distinct.
- **Contracts:** exact schema-validated sanitized event allowlist, correlation reference, idempotency key, monotonic state/version, duplicate/no-op and out-of-order behavior; no raw PII, credential values or unapproved provider payloads in n8n events.
- **Durable side effects:** authorized receipt store and atomic deduplication before sending email/SMS or scheduling; approved retry/backoff/alert and dead-letter flow; avoid double sends on webhook retry or lost acknowledgement.
- **Secrets and communications:** n8n encrypted credentials or approved Vault/environment secret manager, never hardcoded JSON/auth headers, execution logs or downloaded fixtures. Check consent, suppression, templates, cancellation and retention/privacy rules.
- **Proof:** one resource change at a time, synthetic DEVELOPMENT positive and denial tests with reviewed config, exact commit and provider evidence. Only then separately approve workflow activation, website/customer intake and production release.

**Repository path rule:** the canonical repo currently disallows `n8n-workflows/` and `.n8n/` via `security/forbidden-path-patterns.txt`. Do not delete or loosen that restriction simply to import the 15 old files. A future canonical sanitized workflow-artifact path and export/secret-scanning gate would require its own reviewed, exact source change; there is no such path yet.

## Prioritized conversion sequence

1. **Reconcile instance and receiver first:** with fresh permission, inventory exact DEVELOPMENT n8n instance and confirm if/where a versioned **shared authenticated Avuhz event receiver** exists. Reuse `docs/shared-n8n-authenticated-receiver-local-v1.md` as a spec, not a claim of hosted success.
2. **#001 Revenue Engine:** select only the historical *Revenue Intake* **business flow** for a sanitized one-workflow synthetic conversion: accepted Avuhz event → durable dedup receipt → owner/next-action notification. Do not restore its legacy webhook, data writes or credentials. Keep Sekinfra site PR #50/Cal.com receiver OFF until separately authorized.
3. **#002 Booking:** layer Cal.com event verification, provider reconciliation, cancellation/rescheduling semantics and tenant-bound Work Item transitions on the shared command/outbox; reuse appropriate orchestration logic from *Call Booking Sync* only after authorization.
4. **#003 Client Onboarding:** trigger only from verified acquisition/contract/payment approval through existing engagement/handoff contracts; use DocuSeal callbacks with signature checks, and replace credential request/receipt workflows with a secure access-grant mechanism. Do not create a parallel billing engine.
5. **#004 Work & Operations:** map the old runner and deployment-state logic to governed Work Item owner/hand-off/block/resume/recovery and separate deployment authorization; add sanitized failure/health notifications.
6. **#005 Customer Retention:** build tenant-configurable follow-up obligations and recovery around shared work/event state; reuse *Follow-Up Engine* scheduling patterns only after consent, deduplication and failure-recovery proof. OIA Intake stays Sekinfra-only.

**Business tradeoff:** this security/reconciliation work protects a future paying client's records, but is not a substitute for the immediate prospect conversation, demonstrating the existing offline System #001 outcome, and closing a first engagement. Keep those founder-facing actions ahead of speculative workflow rewrites.

## Known Gaps

- Hosted n8n workflows, their authentication modes, ownership, tenant/credential bindings, approval status and activity were **not** inspected. The local n8n container is separate; no hosted API key was retrieved.
- No complete node-by-node audit, secret verification, trusted export sanitization or certified import compatibility for the 15 unversioned legacy workflows. No workflow credentials or external resources were changed.
- No canonical sanitized n8n workflow exports or approved import path exist in current Avuhz main; only synthetic event/receipt integration adapters.
- Shared Cal.com ingress, durable provider event claim, full booking→ownership integration, communications/consent adapters and shared Stripe billing are not proven operational. Owner-reported as of 2026-10-14: public Sekinfra intake was disabled and the website production release was on hold; this audit did not re-verify current provider state.
- A prior separately verified DEVELOPMENT DATA reconciliation reported the Work Item table installed; this audit did **not** recheck the provider. Command idempotency and the complete hosted transaction/event/outbox/automation chain require separate provider verification and approvals. Do not infer hosted readiness from merged source.

**Next action:** obtain an **exact DEVELOPMENT n8n instance/namespace confirmation and separately authorized read-only hosted inventory**, then select **one** safe Avuhz event receiver / sanitized Revenue Intake conversion as a dedicated source/TEST PR. Require the Cal.com webhook to remain OFF until verified approval, and keep all production changes on hold. Do not copy the old JSON exports into the canonical repo.
