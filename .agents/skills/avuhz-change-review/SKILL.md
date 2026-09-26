---
name: avuhz-change-review
description: Independently review an Avuhz change for security, authority, tenant-isolation, architecture, and readiness regressions before integration.
---

Use this skill when reviewing a proposed Avuhz diff, commit, PR, migration, runtime change, or provider-action preparation.

Treat the review as independent. Start from the requirement, the relevant canonical constraints, and the resulting diff. Do not assume the implementation is correct because its authoring agent says it passed.

Read the minimum relevant sources:
- `SECURITY.md`;
- `AGENTS.md`;
- `ARCHITECTURE.md` when service boundaries are affected;
- `docs/current-build-state.md` when canonical state/readiness claims are affected;
- task-specific contracts, migrations, tests, or runtime files.

Check for blocking findings in this order:

1. credential, token, secret, authenticated URL, raw provider payload, or secret-derived material exposure;
2. wrong environment, provider project, namespace, or AUTH/DATA responsibility boundary;
3. RLS, tenant scoping, ACL widening, `BYPASSRLS`, migration/runtime authority mixing, or cross-tenant access;
4. a new mutation path outside the governed Avuhz Executor/API boundary;
5. n8n or another integration writing authoritative Avuhz state directly;
6. vertical-specific auth, billing, automation, communications, or other shared infrastructure;
7. unnecessary PII in logs, events, evidence, errors, or diagnostics;
8. lifecycle events, outbox records, read models, or logs being treated as authoritative state;
9. missing denial/failure-path tests, stale fixtures, or weakened security gates;
10. state documentation claiming a provider/deployment fact that the change does not prove.

Report findings first, ordered by severity, with exact file/resource references and why each finding matters.

If there are no blocking findings, say so explicitly and list the verification evidence checked.

Do not perform provider mutations or secret operations during review. Do not silently rewrite the implementation. If a fix is needed, return a bounded fix recommendation that can be assigned as a separate task.
