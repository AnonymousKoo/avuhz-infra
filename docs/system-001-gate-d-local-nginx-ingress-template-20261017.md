# System #001 Gate D — inactive LOCAL nginx ingress template

**Status:** Gate D Stage 4 source-only TLS 1.3 hardening; inactive. This runbook does not authorize host changes, certificate creation or trust, hostname changes, nginx installation/reload, n8n activation, network access, or any provider action.

## Exact boundary

- Environment and host: `LOCAL/TEST`, operator-owned `DefNet` only.
- Existing automation resource: personal n8n project `axT3GLERZRiPXxnj`, shared receiver `0068feb4c96bdb5f`, still inactive.
- Proposed ingress resource: `avuhz-gate-d.test` at IPv4 loopback `127.0.0.1:443`, forwarding only `POST /webhook/avuhz-events` to `127.0.0.1:5678`.
- Source artifact: `contracts/templates/nginx/avuhz-system001-gate-d-loopback-inactive.conf`. It is not included by any host configuration.
- Excluded: IPv6, wildcard/public listeners, redirects, n8n UI/admin/API paths, Docker changes, credentials, certificate material, Supabase, DEVELOPMENT, STAGING, PRODUCTION, and customer data.

This is shared Avuhz ingress plumbing, not vertical-specific automation. A TLS response or green source test grants no business-owner, tenant, Work Item, receiver-activation, or provider authority.

## Read-only preflight before any approval request

Record only sanitized facts; do not read certificate private keys or n8n credential ciphertext.

1. Confirm the exact host is `DefNet`, the environment is `LOCAL/TEST`, and the intended n8n project/receiver IDs match above. Re-run the existing Gate D read-only preflight and require the receiver to remain inactive with zero unexpected active workflows or executions.
2. Inspect IPv4 and IPv6 listener tables. Stop if `:443` is already occupied or the proposed configuration would bind anything except `127.0.0.1:443`. Confirm n8n remains loopback-only at `127.0.0.1:5678`.
3. Confirm a proposed hosts entry resolves exactly `avuhz-gate-d.test` to `127.0.0.1`, with no IPv6 or non-loopback answer. Do not use public DNS or a tunnel.
4. Review the proposed certificate separately: SAN exactly covers `avuhz-gate-d.test`, the chain and client trust source are identified, validity is bounded, the private key path is host-private, and file ownership/mode limits it to the nginx runtime identity. Never copy certificate or key contents into source or evidence.
5. Validate the candidate nginx syntax offline against the intended nginx build. Require exactly one `ssl_protocols` directive whose sole value is `TLSv1.3`; any TLS 1.2, SSLv3, fallback token, duplicate, or conflicting protocol directive is a stop condition. Review the rendered listener, exact route, method denial, body/time bounds, upstream, redirect interception, catch-all denial, and absence of another included server/location that widens exposure.

Any ambiguous hostname, trust, listener, workflow, route, credential, or include state is a stop condition.

## Separate approvals and bounded verification

Obtain fresh exact approval for each resource boundary, in order:

1. the single local hostname mapping;
2. certificate provisioning and trust for that hostname, without exposing key material;
3. installation/include and reload of this exact ingress on `DefNet`; and
4. only after independent ingress verification, activation of receiver `0068feb4c96bdb5f` with its already-approved encrypted credential bindings and private durable receipt gate.

Do not batch these approvals. Stage 4 requires TLS 1.3 only, with no fallback; the merged Stage 3 PR #743 pins the same TLS 1.3-only policy but grants no host or activation authority. Ingress verification must prove a TLS 1.3 connection succeeds, TLS 1.2 and SSLv3 cannot negotiate, chain and hostname validation, only `127.0.0.1:443`, exact POST forwarding, bounded oversized-body rejection, non-POST denial, arbitrary/admin/UI/path denial, redirect denial, and unchanged loopback-only port 5678. Use fictional payloads only under a later exact acceptance authorization. Do not log headers or bodies.

## Rollback

If the separately approved ingress installation fails verification, stop requests, remove only the approved nginx include/link, restore the captured prior host configuration, and reload only under that same rollback authority. Independently verify the prior `:443` listener state, the unchanged loopback-only n8n listener, removal of the hostname/trust artifacts only if their approvals include removal, and that receiver `0068feb4c96bdb5f` is inactive. If any state is ambiguous, stop rather than retrying or widening access.

## Offline source proof

From the candidate snapshot, run:

```text
python -m unittest tests.security.test_system001_gate_d_nginx_template
```

The tests are structural and negative only: they require one TLS 1.3-only directive and reject TLS 1.2, SSLv3, fallback, duplicate, and conflicting protocol patterns. They open no socket, call no provider, generate no certificate, and do not establish installed ingress readiness.

**Next action:** review this source patch. A future host preflight or change requires fresh exact authority for its first resource boundary; do not install or activate from this runbook alone.
