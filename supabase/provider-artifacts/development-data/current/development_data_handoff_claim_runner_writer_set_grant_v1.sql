-- DEVELOPMENT DATA handoff claim-runner writer SET membership v1.
-- REVIEW ONLY; this file is NOT owner authorization or a deployable migration.
-- Proposed target: Supabase DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
-- DEVELOPMENT AUTH pwlhruwutoitnieactol, production and customer tenants excluded.
-- Exact, disposable-certified second resource candidate from
-- tests/integration/development_handoff_runner_role_candidate.py, with only
-- its OUTER BEGIN and COMMIT removed for a future separately approved
-- Supabase apply_migration transactional history envelope.
-- No role creation, password, credential, direct table grant or workflow call.
-- One PostgreSQL 17 membership only: SET TRUE, INHERIT FALSE, ADMIN FALSE.
-- Do not run via execute_sql, dispatch any workflow, or create credentials.
-- The runner may be authentically mapped by mechanisms OTHER than password.
-- A caller-settable tenant GUC is NOT human-owner, runner, or tenant authority;
-- DO NOT APPLY THIS GRANT before the separately reviewed trusted-source,
-- human-owner, signed-tenant provenance and credential threat model pass.
-- Future use requires a new exact resource/time/source-bound owner approval,
-- live preflight of runner and writer attributes, membership graph, RLS, ACLs,
-- and migration history, followed by independent negative-permission readback.
-- RUNNER_WRITER_SET_API_STATEMENTS_BEGIN
DO $avuhz_runner_membership_preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname='avuhz_handoff_claim_runner_dev'
      AND rolcanlogin AND NOT rolsuper
      AND NOT rolbypassrls AND NOT rolinherit
      AND NOT rolcreaterole AND NOT rolcreatedb
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname='avuhz_handoff_claim_writer'
      AND NOT rolcanlogin AND NOT rolbypassrls
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_class
    WHERE oid=to_regclass(
      'avuhz_handoff_control.avuhz_handoff_approval_claims'
    ) AND relrowsecurity AND relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_ROLE_OR_RLS_DRIFT';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members m
    JOIN pg_roles member ON member.oid=m.member
    JOIN pg_roles granted ON granted.oid=m.roleid
    WHERE (member.rolname='avuhz_handoff_claim_runner_dev'
       AND granted.rolname='avuhz_handoff_claim_writer')
       OR (member.rolname='avuhz_handoff_claim_runner_dev'
       AND granted.rolname='avuhz_command_service')
  ) OR has_table_privilege(
    'avuhz_handoff_claim_runner_dev',
    'avuhz_handoff_control.avuhz_handoff_approval_claims','INSERT'
  ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_MEMBERSHIP_PREEXISTING_STOP';
  END IF;
END
$avuhz_runner_membership_preflight$;

-- PostgreSQL 17 granular options. No INHERIT and no ADMIN delegation.
GRANT avuhz_handoff_claim_writer TO avuhz_handoff_claim_runner_dev
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

DO $avuhz_runner_membership_postcondition$
BEGIN
  IF (
    SELECT count(*) FROM pg_auth_members m
    JOIN pg_roles member ON member.oid=m.member
    JOIN pg_roles granted ON granted.oid=m.roleid
    WHERE member.rolname='avuhz_handoff_claim_runner_dev'
      AND granted.rolname='avuhz_handoff_claim_writer'
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) <> 1
  OR NOT pg_has_role(
    'avuhz_handoff_claim_runner_dev','avuhz_handoff_claim_writer','SET'
  )
  OR pg_has_role(
    'avuhz_handoff_claim_runner_dev','avuhz_handoff_claim_writer','USAGE'
  )
  OR has_table_privilege(
    'avuhz_handoff_claim_runner_dev',
    'avuhz_handoff_control.avuhz_handoff_approval_claims','INSERT'
  )
  OR has_schema_privilege(
    'avuhz_handoff_claim_runner_dev','avuhz_handoff_control','USAGE'
  ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_SET_MEMBERSHIP_UNVERIFIED';
  END IF;
END
$avuhz_runner_membership_postcondition$;
