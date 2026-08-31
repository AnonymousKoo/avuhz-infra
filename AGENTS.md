# Avuhz Clean Baseline — Agent Constraints

## Security

- Never store credentials, tokens, keys, passwords, authenticated connection strings, or raw provider payloads.
- Raw credential material is prohibited from contracts, fixtures, logs, documentation, Git, and generated output.
- Use fictional deterministic fixtures only.
- Do not copy files or Git history from `/home/network-p/avuhz-infra`.
- Do not connect to Supabase or another external system without explicit owner authorization.

## Architecture

- JSON Schema 2020-12 is the canonical provider-neutral contract source.
- Commands request changes; authoritative records determine truth; events describe accepted changes.
- n8n is a bounded command/query client and never writes authoritative data directly.
- Human approvals are separate attributable records.
- Tenant isolation, expected versions, idempotency, and transactional outbox behavior are mandatory.

## Build discipline

- Inspect and preserve interrupted or dirty work. Recover with `INSPECT -> PRESERVE -> COMPLETE -> VALIDATE -> COMMIT`; never reset, restore, clean, stash, or discard it without separate owner authorization.
- Implement one resource at a time, validate it, and stop for owner review.
- Run focused tests while implementing and the full applicable suites at certification.
- Do not push unless explicitly authorized, and never force push.
- Do not add agreements, payments, access, credentials, OIA, findings, conversion, implementation, deployment, managed service, or offboarding to Slice 1.
- Before future persistence work, confirm the Supabase DATA project, AUTH project, environment, tenant identity bridge, migration target, trusted service identity, and RLS approach.
