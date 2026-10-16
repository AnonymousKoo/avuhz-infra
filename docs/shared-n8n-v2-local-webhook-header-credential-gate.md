# Shared n8n receiver v2 — LOCAL native header credential registration gate

**Scope confirmation (2026-10-16):** `AnonymousKoo/avuhz-infra` LOCAL/TEST repository source only. Target LOCAL n8n is the existing DefNet Docker container with loopback `127.0.0.1:5678`. AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are separate DEVELOPMENT Supabase projects; neither is touched. No n8n resource, production, credentials, customer data, public route, or service is changed by this PR.

## Verified source and installed state

- Current exact merged `main` source commit at preparation: `f7cef0048f39712289a4144b35399218e5556507`. The receiver v2 source checksum is `sha256:fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`.
- The separately approved inactive-only receiver v2 import has already been performed and independently verified: one exact shared receiver exists INACTIVE, with no native credential bound; the original five-node System #001 child is unchanged/inactive; zero saved executions. Local n8n HTTP health is 200.
- Local receipt service bridge boundaries and actual Docker-originated private HTTP replay tests are verified, but there is **no approved persistent private receipt listener**, verified TLS inbound ingress, or running supervised source worker.

## New opt-in control

`scripts/prepare_shared_n8n_receiver_v2_header_credential_local.py` prepares **one dedicated LOCAL n8n native Header Auth credential**, using the existing supported `n8n import:credentials` command. It is a **source-only tool** until a separate exact owner authorization permits execution.

Read-only default:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_shared_n8n_receiver_v2_header_credential_local.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

Read-only validation checks the n8n Docker identity/network boundary, existing pristine System #001 child, exact v2 source receiver as installed, no active workflows/executions, one shared webhook, and **zero credentials bearing the new dedicated receiver name**. SQLite is opened `mode=ro` and `query_only`. Only constant safe pass/fail markers are printed.

The **write mode is not authorized by this PR**. Once an approved client-side secret boundary can supply a matching high-entropy ASCII token for the existing Avuhz sender, the operator may separately authorize the exact one-resource credential registration. Only then can `--import-one --approved-source-sha256 sha256:... --token-fd N` be used. The token FD must be inherited from that *approved private issuer*, with the writing side closed; a positional token, environment variable, committed file, stdout, GitHub variable, or copy-and-pasted chat secret is forbidden.

If approved, the tool reads the secret only from a private FD (size 32–512 ASCII printable bytes, with complete EOF); uses **one** supported n8n encrypted import via stdin for a single `httpHeaderAuth` credential named `Avuhz Shared Receiver v2 LOCAL inbound header`, with header `X-Avuhz-Webhook-Token`; and verifies read-only afterward. The postcondition checks exactly one encrypted-format credential, one project share, unchanged workflow contents/count, still-inactive receiver and child, no executed events, and no secret echo. No retries. If import or postcondition fails, STOP and independently inspect partial provider state; **do not run again** under the same approval.

**Do not register an arbitrary new credential without a matching approved secret source for Avuhz's outbound `N8nOutboxSink`.** The encrypted n8n storage is intentionally not exportable to the source worker. The sender must fetch the **same** credential from the separately approved private issuer at runtime without writing it to source, CLI args, logs, environment dumps or a new vertical-specific store. The existence, permissions and lifecycle of such an issuer have **not been verified**. This is a gating dependency, not a claimed completed integration.

## Execution path after credential registration (all are separately scoped)

1. **Only after independent owner authorization:** Register *one* native inbound header credential as above. Do not bind it to the receiver during that resource change.
2. In another exact authorized LOCAL step: bind the new credential reference to the already installed inactive v2 receiver. Confirm native header-auth denial behavior and no activation.
3. In separate approved resource steps, launch/configure the existing tenant-bound private receipt service, bind its *independent* n8n encrypted bridge credential and approved Docker-private receipt URL, and confirm a properly authenticated HTTPS ingress for outside Avuhz-to-n8n traffic. The public hop must use verified TLS; plaintext `127.0.0.1:5678` is not an acceptable transport bypass.
4. Under a new exact LOCAL execution approval, stage fictional acquisition data in an isolated RLS-scoped store, run the existing shared unattended dispatcher, and prove **one** intake transitions to a governed Work Item via actual native-authenticated n8n and committed receipt. Test replay, wrong-secret, wrong-tenant and backend-unavailable paths; restore inactive state and remove disposable resources. No hosted DATA/AUTH writes, real customer or production.
5. After unattended local certification, independently authorize real tenant/owner onboarding and operator experience. Booking, notifications, Stripe usage billing and production cutover are separate shared-core gates, not V1 achievements today.

**Four-lane decision:** Security and Infrastructure gain an auditable credential boundary, Automation gains a candidate reliable sender/receiver shared secret, and Business is still responsible for discovering and onboarding a paying customer. The repository has not yet established a real approved tenant or live operational pilot.

**Next action:** Merge source-only code after exact-head CI, independently verify an existing private shared secret issuer / sender secret strategy, then request narrowly scoped owner approval to register one LOCAL encrypted webhook credential. No provider mutation until both gates are satisfied.
