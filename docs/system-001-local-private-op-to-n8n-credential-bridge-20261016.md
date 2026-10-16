# System #001 LOCAL — private 1Password-to-encrypted-n8n credential bridge

**Confirmed namespace and action class:** `AnonymousKoo/avuhz-infra` LOCAL/TEST shared orchestration code, **repository-source-only change**. The exact existing DefNet n8n Docker container at loopback `127.0.0.1:5678` is READ-ONLY during this PR. Hosted Supabase DEVELOPMENT AUTH `pwlhruwutoitnieactol` and DATA `gnuqaefotwgkwurjpyik` are separate and untouched; no production, credential, vault, customer or billing changes.

## Why this one narrow component

Merged PR #719 prepared **one** native encrypted n8n header credential importer (private token input via inherited file descriptor; inactive workflow must remain unbound). Merged PR #721 prepared a source-only approved-1Password-field provider used by the existing Avuhz outbound `N8nOutboxSink`. Without this bridge, an operator would be tempted to manually copy/paste a secret into two systems, creating avoidable exposure.

New `scripts/prepare_shared_n8n_v2_op_to_encrypted_credential_local.py` composes the **existing two** shared interfaces. It does not create a second credential store or workflow engine. It has zero installed side effects unless independently authorized.

## Read-only default (safe now)

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  scripts/prepare_shared_n8n_v2_op_to_encrypted_credential_local.py \
  --target LOCAL_DEVELOPMENT_N8N_5678
```

The default verifies exact Docker/private source, pristine inactive System #001 child, shared receiver v2 exact source/checksum and **zero dedicated LOCAL inbound credentials** using the existing preflight. It performs **no 1Password read, sign-in, secret generation, SQLite write, n8n import or activation**.

## Separately authorized one-credential import only

The following prerequisites must ALL be satisfied *before* running write mode:

1. The owner privately signs into the **already registered** DefNet 1Password account. At initial observation `op whoami` was **not authenticated**; no vault contents or values were read.
2. One approved Avuhz LOCAL/TEST webhook field is identified and independently authorized by a private stable-ID 3-part `op://vault/item/field` reference. The reference is non-secret operational metadata, not authority to read another field. Never reuse AUTH/DATA tokens, production or unrelated credentials. The current repo has **no verified approved Avuhz field**, and no item creation, read or token rotation was approved by this PR.
3. The user separately approves **exactly one** LOCAL n8n native `httpHeaderAuth` encrypted credential registration, using exact merged source, v2 receiver source SHA-256 `fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f`, and the exact approved secret field. No retries, workflow binding, activation, receipt listener, outbound network request, customer data, hosted resources or production.

Only after these can a separately authorized operator invoke `--import-one --approved-source-sha256 sha256:... --approved-secret-reference op://...`. This run mode: rechecks the exact LOCAL n8n preflight; performs exactly one already-approved `op read --no-newline` in a signed-in owner session; captures the 32–512 printable ASCII token in private process memory; launches the existing canonical source-bound importer with an inherited OS pipe; streams the token through that pipe **without** placing the token in CLI arguments, environment variables, files, Git, stdout, stderr, logs or ChatGPT; and validates the importer's explicit success and independent read-only metadata. It can only register **one** dedicated inbound Header Auth credential with n8n encryption at rest. No workflow edits or activation.

On **any failure or ambiguous postcondition**, it stops without retry, rollback or provider cleanup (a failed import might have partially completed; do not retry under consumed approval). It never signs into 1Password or enumerates arbitrary vaults. All tests use generated in-memory synthetic tokens and process stubs—**no real op secret read or n8n resource change**.

## What still blocks a running Work Intake V1

- Native v2 receiver credential must **separately** be bound to that **inactive** workflow after encrypted registration.
- Approved LOCAL n8n private durable receipt service, its **independent** bridge credential and URL, and a verified TLS front end with a legitimate exact hostname/CA are not configured. The existing outbox transport requires HTTPS port 443 and strict hostname verification; LOCAL n8n currently listens on plain loopback port 5678 with no observed listener on 443 or 8443.
- The 1Password CLI may depend on a currently signed-in desktop/owner session. Even after one successful local test, session expiry or an interactive prompt could block a **truly unattended** dispatcher. Validate a noninteractive approved secret-access lifecycle and safe failure/recovery before any continuous LOCAL supervisor or V1 operating claim; this bridge supplies no sign-in or persistence workaround.
- Separately authorize one fictional unattended outbox event with one independently trusted tenant, shared Work Item writer and read-only negative/rollback evidence. Until that exact installed workflow test passes, the work intake system is not V1 operational.
- After that, one real customer pilot still requires genuine owner/legal-operator authority and correct tenant-scoped RLS; OIA discovery may continue separately. No vertical-owned auth, billing or automation is introduced.

**Next action:** exact-head CI and merge source-only bridge. Then owner sign-in and explicit private approved field selection, followed by **one separately authorized LOCAL encrypted inbound credential registration**. No credential writes on merge.
