# System #001 Gate D LOCAL dispatcher TLS 1.3

Status: source-only Stage 3 candidate. This runbook makes no claim that the
factory is deployed, the CA file is installed, nginx is active, n8n is active,
or any TLS/network verification has run.

## Scope

`build_system001_gate_d_local_sink` composes the existing validated event sink
and HTTPS transport only for profile `SYSTEM001_GATE_D_LOCAL_TLS13_V1` in
`LOCAL` or `TEST`. It pins:

- endpoint `https://avuhz-gate-d.test/webhook/avuhz-events` (implicit port 443;
  no query, fragment, credentials, alternate host, or alternate path);
- public CA path `/etc/avuhz/trust/avuhz-gate-d-local-ca.crt`;
- public CA SHA-256 fingerprint
  `9D:31:E5:0D:71:AC:0D:C0:04:96:B1:46:32:E3:B4:C0:15:AA:11:12:9C:F3:14:86:5A:EA:CF:CD:2C:77:CF:90`;
- one `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with only that verified public
  CA loaded through `cadata`, `CERT_REQUIRED`, hostname verification, and both
  minimum and maximum protocol version set to TLS 1.3.

The deployed factory has no CA/path/certificate/endpoint injection. It requires
root-owned, owner-readable/searchable, non-group/world-writable `/etc/avuhz`
and `/etc/avuhz/trust`, and a regular,
single-link, root-owned `0644` public CA file. Missing or changed metadata,
symlinks, an extra certificate, a wrong fingerprint, invalid profile, nonlocal
environment, TLS-policy mutation, or URL drift fails closed with a safe code.
It does not inspect `/etc/avuhz/private`, any leaf certificate, or key bytes.

The separately named fixture function builds only an SSL context from injected
public certificate bytes for offline tests. It cannot compose the deployed
sink and is not called by the deployed factory.

## Verification and rollback

Offline verification is the focused worker test followed by
`./scripts/check-baseline.sh`. Neither command authorizes live TLS, n8n,
services, trust installation, hosts changes, nginx, Supabase, Tailscale, or
production access.

Stage 4 remains pending separate approval. Before any activation, the nginx
template must be separately reviewed and changed from
`ssl_protocols TLSv1.2 TLSv1.3` to TLS 1.3 only, then separately installed,
validated, activated, and live-tested under exact fresh authority.

Stage 3 rollback is limited to removing/reverting this scoped factory binding
from dispatcher composition. Do not alter the public CA, system trust, private
leaf/key paths, nginx, hosts, n8n, or service state under Stage 3 rollback.

Next action: review and canonicalize this source-only patch; obtain a fresh,
exact Stage 4 source-change approval before changing the nginx template.
