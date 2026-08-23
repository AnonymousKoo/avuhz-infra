-- Forward-only compatibility remediation for approved partial runtime approvals.
-- Scope, version, digest, action-set, tenant, and authority bindings remain required.

alter table public.avuhz_human_approvals
  alter column approving_principal_reference drop not null,
  alter column approving_organization_reference drop not null,
  alter column decision drop not null,
  alter column conditions drop not null,
  alter column effective_at drop not null,
  alter column evidence_reference drop not null,
  alter column correlation_id drop not null,
  alter column idempotency_key drop not null;
