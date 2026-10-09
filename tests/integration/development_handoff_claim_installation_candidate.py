"""DISPOSABLE-POSTGRES INSTALLATION CANDIDATE ONLY; NEVER A LIVE MIGRATION.

This SQL lives in a test-only Python module deliberately outside
supabase/migrations and provider-artifacts. Nothing in runtime, workflow,
or deployment imports it. A different, separately authorized migration
artifact and provider preflight are required before any DEVELOPMENT DATA
installation. The SQL does not and cannot independently prove a Supabase
project identity, trusted owner, or authenticated tenant.

Source: PR #583 review of the disconnected PR #582 claim adapter.
Future target only: DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
Distinct AUTH pwlhruwutoitnieactol must not be installed here.
"""

INSTALLATION_CANDIDATE_SQL = r"""
BEGIN;

DO $avuhz_handoff_install_preflight$
BEGIN
  -- Stop instead of adopting, replacing, or repairing unknown provider state.
  IF to_regnamespace('avuhz_handoff_control') IS NOT NULL
     OR EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname = 'avuhz_handoff_claim_writer'
     ) THEN
    RAISE EXCEPTION 'HANDOFF_CLAIM_PREEXISTING_RESOURCE_STOP';
  END IF;

  -- Canonical shared DATA schema, not AUTH or an arbitrary empty database.
  -- This is only a coarse guard: it is NOT proof of the provider project.
  IF to_regclass('public.avuhz_idempotency_records') IS NULL
     OR to_regclass('public.avuhz_implementation_handoffs') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = 'avuhz_command_service'
     ) THEN
    RAISE EXCEPTION 'HANDOFF_CLAIM_CANONICAL_DATA_BASELINE_MISSING';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = current_user AND (rolsuper OR rolcreaterole)
  ) OR NOT has_database_privilege(
      current_user, current_database(), 'CREATE'
    ) THEN
    RAISE EXCEPTION 'HANDOFF_CLAIM_MIGRATION_IDENTITY_UNVERIFIED';
  END IF;
END
$avuhz_handoff_install_preflight$;

CREATE ROLE avuhz_handoff_claim_writer
  NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT
  NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE SCHEMA avuhz_handoff_control;
REVOKE ALL ON SCHEMA avuhz_handoff_control FROM PUBLIC;

CREATE TABLE avuhz_handoff_control.avuhz_handoff_approval_claims (
  tenant_id uuid NOT NULL,
  stage text NOT NULL CHECK (stage IN (
    'AUTH_GLOBAL_LOGOUT', 'AUTH_GENERATE', 'AUTH_VERIFY', 'DATA_COMMAND'
  )),
  plan_id text NOT NULL CHECK (plan_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  step_id text NOT NULL CHECK (step_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  plan_digest text NOT NULL
    CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
  approval_digest text NOT NULL
    CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
  project_reference text NOT NULL,
  authorization_set_digest text NOT NULL
    CHECK (authorization_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  command_digest text NOT NULL
    CHECK (command_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_sha text NOT NULL
    CHECK (source_sha ~ '^[0-9a-f]{40}$'),
  claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, plan_id, step_id),
  UNIQUE (approval_digest),
  UNIQUE (tenant_id, authorization_set_digest, stage),
  UNIQUE (tenant_id, command_digest, stage),
  CONSTRAINT avuhz_handoff_stage_project_bound CHECK (
    (stage = 'DATA_COMMAND' AND project_reference = 'gnuqaefotwgkwurjpyik')
    OR
    (stage <> 'DATA_COMMAND' AND project_reference = 'pwlhruwutoitnieactol')
  )
);

REVOKE ALL ON TABLE
  avuhz_handoff_control.avuhz_handoff_approval_claims FROM PUBLIC;

ALTER TABLE avuhz_handoff_control.avuhz_handoff_approval_claims
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE avuhz_handoff_control.avuhz_handoff_approval_claims
  FORCE ROW LEVEL SECURITY;

CREATE POLICY avuhz_handoff_claim_writer_tenant
  ON avuhz_handoff_control.avuhz_handoff_approval_claims
  FOR INSERT TO avuhz_handoff_claim_writer
  WITH CHECK (
    tenant_id = NULLIF(
      current_setting('avuhz.handoff_claim_tenant', TRUE), ''
    )::uuid
  );

-- Explicit negative grants against existing Supabase-exposed/business roles.
-- Role membership, implicit privileges and default ACLs also need independent
-- hosted preflight; this code must not infer they are safe.
DO $avuhz_handoff_negative_grants$
DECLARE subject_role text;
BEGIN
  FOREACH subject_role IN ARRAY ARRAY[
    'anon', 'authenticated', 'service_role', 'avuhz_command_service'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = subject_role) THEN
      EXECUTE format(
        'REVOKE ALL ON SCHEMA avuhz_handoff_control FROM %I',
        subject_role
      );
      EXECUTE format(
        'REVOKE ALL ON TABLE avuhz_handoff_control.avuhz_handoff_approval_claims FROM %I',
        subject_role
      );
    END IF;
  END LOOP;
END
$avuhz_handoff_negative_grants$;

GRANT USAGE ON SCHEMA avuhz_handoff_control
  TO avuhz_handoff_claim_writer;
GRANT INSERT ON TABLE
  avuhz_handoff_control.avuhz_handoff_approval_claims
  TO avuhz_handoff_claim_writer;

-- No writer LOGIN, role membership, DSN, runner binding, or provider change.
COMMIT;
"""