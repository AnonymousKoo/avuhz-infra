-- DEVELOPMENT DATA shared handoff claim runner LOGIN-role creation v1.
-- REVIEW ONLY: not executable provider authority. This is ONE role, not a grant.
-- Supabase target ONLY: DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
-- DEVELOPMENT AUTH pwlhruwutoitnieactol and production are OUT OF SCOPE.
-- Exact statements from the separately disposable-certified role-only candidate,
-- with only its OUTER BEGIN and COMMIT removed so a future separately approved
-- Supabase apply_migration executor owns schema and migration-history atomicity.
-- Do NOT submit to raw execute_sql. No GitHub dispatch or credential creation.
-- LOGIN has PASSWORD NULL, NOINHERIT, NOBYPASSRLS and no direct table rights.
-- A NULL password does NOT guarantee all external auth methods are disabled.
-- No SET ROLE membership or table GRANT, token, password, secret, DSN or key.
-- Before any live application, independently preflight provider/project/source,
-- role absence, default ACLs, migration identity and approved execution window.
-- The caller-controlled tenant GUC is NOT authenticated identity. Never
-- activate the runner or issue credentials based on this DDL or green CI alone.
-- RUNNER_CREATE_API_STATEMENTS_BEGIN
DO $avuhz_runner_creation_preflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname='avuhz_handoff_claim_runner_dev'
  ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_PREEXISTING_ROLE_STOP';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles r
    JOIN pg_class c ON c.oid = to_regclass(
      'avuhz_handoff_control.avuhz_handoff_approval_claims'
    )
    WHERE r.rolname='avuhz_handoff_claim_writer'
      AND NOT r.rolcanlogin
      AND NOT r.rolsuper
      AND NOT r.rolbypassrls
      AND NOT r.rolinherit
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) OR to_regclass('public.avuhz_implementation_handoffs') IS NULL THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_DATA_LEDGER_UNVERIFIED';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname=current_user
      AND (rolsuper OR rolcreaterole)
  ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_CREATOR_UNTRUSTED';
  END IF;
  IF coalesce(current_setting('createrole_self_grant',true),'') <> '' THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_SELF_GRANT_UNTRUSTED';
  END IF;
END
$avuhz_runner_creation_preflight$;

-- Password NULL is intentional; no usable password or DSN is generated.
-- The login has no direct schema rights, no inherited writer right, no key.
CREATE ROLE avuhz_handoff_claim_runner_dev
  LOGIN PASSWORD NULL CONNECTION LIMIT 1
  NOINHERIT NOSUPERUSER NOBYPASSRLS
  NOCREATEDB NOCREATEROLE NOREPLICATION;

DO $avuhz_runner_creation_postcondition$
DECLARE
  runner_oid oid;
  creator_oid oid;
  creator_super boolean;
  actual_edges integer;
  expected_edges integer;
BEGIN
  SELECT oid INTO STRICT runner_oid FROM pg_roles
    WHERE rolname='avuhz_handoff_claim_runner_dev';
  SELECT oid, rolsuper INTO STRICT creator_oid, creator_super FROM pg_roles
    WHERE rolname=current_user;
  SELECT count(*) INTO actual_edges FROM pg_auth_members
    WHERE member=runner_oid OR roleid=runner_oid;

  IF creator_super THEN
    IF actual_edges <> 0 THEN
      RAISE EXCEPTION 'HANDOFF_RUNNER_MEMBERSHIP_UNTRUSTED';
    END IF;
  ELSE
    SELECT count(*) INTO expected_edges FROM pg_auth_members m
      JOIN pg_roles grantor ON grantor.oid=m.grantor
      WHERE m.roleid=runner_oid AND m.member=creator_oid
        AND grantor.rolsuper AND m.admin_option
        AND NOT m.set_option AND NOT m.inherit_option;
    IF actual_edges <> 1 OR expected_edges <> 1 THEN
      RAISE EXCEPTION 'HANDOFF_RUNNER_MEMBERSHIP_UNTRUSTED';
    END IF;
  END IF;

  IF has_schema_privilege(
       'avuhz_handoff_claim_runner_dev','avuhz_handoff_control','USAGE'
     )
     OR has_table_privilege(
       'avuhz_handoff_claim_runner_dev',
       'avuhz_handoff_control.avuhz_handoff_approval_claims','INSERT'
     )
     OR has_table_privilege(
       'avuhz_handoff_claim_runner_dev',
       'avuhz_handoff_control.avuhz_handoff_approval_claims','SELECT'
     )
     OR pg_has_role(
       'avuhz_handoff_claim_runner_dev','avuhz_handoff_claim_writer','SET'
     )
     OR EXISTS (
       SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND left(c.relname,6)='avuhz_'
          AND c.relkind IN ('r','p')
          AND (
            has_table_privilege('avuhz_handoff_claim_runner_dev',c.oid,'SELECT')
            OR has_table_privilege('avuhz_handoff_claim_runner_dev',c.oid,'INSERT')
            OR has_table_privilege('avuhz_handoff_claim_runner_dev',c.oid,'UPDATE')
            OR has_table_privilege('avuhz_handoff_claim_runner_dev',c.oid,'DELETE')
          )
     ) THEN
    RAISE EXCEPTION 'HANDOFF_RUNNER_UNEXPECTED_DIRECT_ACL';
  END IF;
END
$avuhz_runner_creation_postcondition$;
