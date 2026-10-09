"""REPOSITORY-ONLY PostgreSQL 17 runner-role authorization candidates.

Neither SQL string is a provider migration, deployable artifact or authority
to change a hosted database. Each represents a distinct future resource
approval: (1) passwordless LOGIN identity, (2) narrowly scoped SET membership.

DEVELOPMENT DATA gnuqaefotwgkwurjpyik only. DEVELOPMENT AUTH
pwlhruwutoitnieactol, production, GitHub secrets, and client systems excluded.
No password, DSN, private key, API credential or HTTP action is included.

The caller-settable 'avuhz.handoff_claim_tenant' setting is NOT authenticated
tenant provenance. Real runner access remains blocked until independent
GitHub/owner/signed-source binding, temporary credential design and approvals.
"""

# First separate provider boundary if later explicitly authorized: role only.
CREATE_RUNNER_CANDIDATE_SQL = r"""
BEGIN;

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

COMMIT;
"""

# SECOND, independently approved future resource: membership only.
# This is intentionally NOT bundled into CREATE_RUNNER_CANDIDATE_SQL.
GRANT_WRITER_SET_CANDIDATE_SQL = r"""
BEGIN;

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

COMMIT;
"""
