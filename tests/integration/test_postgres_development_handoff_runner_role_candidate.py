"""Disposable PostgreSQL 17 ONLY — runner-role and SET grant review candidates.

This test exercises TWO independent prospective provider resource operations.
No connection to hosted Supabase, AUTH, GitHub environment, or credential.
The local superuser simulation does NOT verify real login authentication.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

import psycopg
from psycopg import sql as psql
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/integration")]

from development_handoff_claim_installation_candidate import INSTALLATION_CANDIDATE_SQL
from development_handoff_runner_role_candidate import (
    CREATE_RUNNER_CANDIDATE_SQL, GRANT_WRITER_SET_CANDIDATE_SQL,
)

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
RUNNER = "avuhz_handoff_claim_runner_dev"
WRITER = "avuhz_handoff_claim_writer"
CREATOR = "avuhz_runner_role_creator_fixture"
TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"
TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
OTHER_TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f1"


def require_disposable() -> None:
    if not DSN:
        raise RuntimeError("DISPOSABLE_POSTGRES_DSN_MISSING")
    opts = conninfo_to_dict(DSN)
    if (
        opts.get("host") not in ("127.0.0.1", "localhost", "::1")
        or opts.get("user") != "postgres"
        or opts.get("dbname") != os.environ.get("AVUHZ_INTEGRATION_DATABASE")
        or not os.environ.get("AVUHZ_INTEGRATION_DATABASE")
    ):
        raise RuntimeError("DISPOSABLE_POSTGRES_SCOPE_INVALID")


@unittest.skipUnless(DSN, "disposable PostgreSQL DSN required")
class DevelopmentHandoffRunnerRoleCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        require_disposable()

    def setUp(self) -> None:
        require_disposable()
        with psycopg.connect(DSN, autocommit=True) as db:
            if db.execute(
                "select to_regnamespace('avuhz_handoff_control') is not null "
                "or exists(select 1 from pg_roles where rolname in (%s,%s,%s))",
                (RUNNER, WRITER, CREATOR),
            ).fetchone()[0]:
                raise AssertionError("DISPOSABLE_RUNNER_FIXTURE_NOT_CLEAN")
            db.execute(INSTALLATION_CANDIDATE_SQL)

    def tearDown(self) -> None:
        require_disposable()
        with psycopg.connect(DSN, autocommit=True) as db:
            # Single-use disposable fixture only, never a remotely pointed DSN.
            db.execute("drop role if exists avuhz_handoff_claim_runner_dev")
            db.execute("drop schema if exists avuhz_handoff_control cascade")
            db.execute("drop role if exists avuhz_handoff_claim_writer")
            db.execute("drop role if exists avuhz_runner_role_creator_fixture")
        super().tearDown()

    def create_runner(self) -> None:
        require_disposable()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(CREATE_RUNNER_CANDIDATE_SQL)

    def grant_set(self) -> None:
        require_disposable()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(GRANT_WRITER_SET_CANDIDATE_SQL)

    def membership(self):
        with psycopg.connect(DSN) as db:
            return db.execute(
                "select member.rolname, role.rolname,"
                " m.admin_option,m.inherit_option,m.set_option"
                " from pg_auth_members m"
                " join pg_roles member on member.oid=m.member"
                " join pg_roles role on role.oid=m.roleid"
                " where member.rolname=%s or role.rolname=%s"
                " order by member.rolname,role.rolname",
                (RUNNER, RUNNER),
            ).fetchall()

    def test_new_runner_is_password_null_and_lacks_any_direct_claim_access(self):
        self.create_runner()
        with psycopg.connect(DSN) as db:
            self.assertEqual(
                db.execute(
                    "select rolcanlogin,rolinherit,rolbypassrls,rolsuper,"
                    " rolcreaterole,rolcreatedb,rolreplication,rolconnlimit"
                    " from pg_roles where rolname=%s",
                    (RUNNER,),
                ).fetchone(),
                (True, False, False, False, False, False, False, 1),
            )
            # Only disposable superuser reads pg_authid; never print passwords.
            self.assertTrue(db.execute(
                "select rolpassword is null from pg_authid where rolname=%s",
                (RUNNER,),
            ).fetchone()[0])
            self.assertFalse(db.execute(
                "select has_schema_privilege(%s,'avuhz_handoff_control','USAGE')",
                (RUNNER,),
            ).fetchone()[0])
            self.assertFalse(db.execute(
                "select has_table_privilege(%s,%s,'INSERT')",
                (RUNNER,TABLE),
            ).fetchone()[0])
            self.assertFalse(db.execute(
                "select pg_has_role(%s,%s,'SET')",
                (RUNNER,WRITER),
            ).fetchone()[0])
        self.assertEqual(self.membership(), [])

    def test_preexisting_runner_creation_is_terminal_and_non_destructive(self):
        self.create_runner()
        with psycopg.connect(DSN,autocommit=True) as db:
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_RUNNER_PREEXISTING_ROLE_STOP",
            ):
                db.execute(CREATE_RUNNER_CANDIDATE_SQL)
            self.assertEqual(db.execute(
                "select count(*) from pg_roles where rolname=%s", (RUNNER,),
            ).fetchone()[0],1)

    def test_missing_ledger_or_forced_rls_blocks_role_creation(self):
        with psycopg.connect(DSN,autocommit=True) as db:
            db.execute(f"alter table {TABLE} no force row level security")
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_RUNNER_DATA_LEDGER_UNVERIFIED",
            ):
                db.execute(CREATE_RUNNER_CANDIDATE_SQL)
            self.assertFalse(db.execute(
                "select exists(select 1 from pg_roles where rolname=%s)",(RUNNER,),
            ).fetchone()[0])

    def test_non_superuser_pg17_creator_receives_admin_only_bootstrap_edge(self):
        with psycopg.connect(DSN,autocommit=True) as db:
            db.execute(
                "create role avuhz_runner_role_creator_fixture "
                "nologin nosuperuser createrole noinherit "
                "nobypassrls nocreatedb noreplication"
            )
            db.execute("set role avuhz_runner_role_creator_fixture")
            try:
                self.assertEqual(db.execute(
                    "select current_user,rolsuper from pg_roles where rolname=current_user"
                ).fetchone(),(CREATOR,False))
                db.execute(CREATE_RUNNER_CANDIDATE_SQL)
            finally:
                db.execute("reset role")
            actual=db.execute(
                "select granted.rolname,member.rolname,grantor.rolsuper,"
                " m.admin_option,m.inherit_option,m.set_option"
                " from pg_auth_members m"
                " join pg_roles granted on granted.oid=m.roleid"
                " join pg_roles member on member.oid=m.member"
                " join pg_roles grantor on grantor.oid=m.grantor"
                " where granted.rolname=%s",(RUNNER,),
            ).fetchall()
        self.assertEqual(actual,[(RUNNER,CREATOR,True,True,False,False)])

    def test_separately_scoped_set_edge_does_not_inherit_ledger_rights(self):
        self.create_runner()
        self.grant_set()
        self.assertEqual(self.membership(),[(RUNNER,WRITER,False,False,True)])
        with psycopg.connect(DSN) as db:
            self.assertTrue(db.execute(
                "select pg_has_role(%s,%s,'SET')",(RUNNER,WRITER),
            ).fetchone()[0])
            self.assertFalse(db.execute(
                "select pg_has_role(%s,%s,'USAGE')",(RUNNER,WRITER),
            ).fetchone()[0])
            for priv in ("SELECT","INSERT","UPDATE","DELETE","TRUNCATE"):
                self.assertFalse(db.execute(
                    "select has_table_privilege(%s,%s,%s)",
                    (RUNNER,TABLE,priv),
                ).fetchone()[0],priv)
            self.assertFalse(db.execute(
                "select has_schema_privilege(%s,'avuhz_handoff_control','USAGE')",
                (RUNNER,),
            ).fetchone()[0])

    def test_writer_grant_cannot_be_replayed(self):
        self.create_runner()
        self.grant_set()
        with psycopg.connect(DSN,autocommit=True) as db:
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_RUNNER_MEMBERSHIP_PREEXISTING_STOP",
            ):
                db.execute(GRANT_WRITER_SET_CANDIDATE_SQL)
        self.assertEqual(self.membership(),[(RUNNER,WRITER,False,False,True)])

    def test_grant_refuses_rbac_or_rls_drift(self):
        self.create_runner()
        with psycopg.connect(DSN,autocommit=True) as db:
            db.execute(f"alter table {TABLE} no force row level security")
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_RUNNER_ROLE_OR_RLS_DRIFT",
            ):
                db.execute(GRANT_WRITER_SET_CANDIDATE_SQL)
        self.assertEqual(self.membership(),[])

    def test_unexpected_business_runtime_membership_blocks_grant(self):
        self.create_runner()
        with psycopg.connect(DSN,autocommit=True) as db:
            db.execute(
                "grant avuhz_command_service to "
                "avuhz_handoff_claim_runner_dev "
                "with admin false, inherit false, set true"
            )
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_RUNNER_MEMBERSHIP_PREEXISTING_STOP",
            ):
                db.execute(GRANT_WRITER_SET_CANDIDATE_SQL)
            self.assertFalse(db.execute(
                "select pg_has_role(%s,%s,'SET')",(RUNNER,WRITER),
            ).fetchone()[0])

    def test_session_authorization_simulates_distinct_runner_identity(self):
        """Simulated role authority only; NOT a real login or credential test."""
        self.create_runner()
        self.grant_set()
        with psycopg.connect(DSN) as db:
            # Superuser-only disposable fixture changes session_user so
            # a postgres-superuser SET ROLE shortcut cannot mask a bad grant.
            db.execute("set session authorization avuhz_handoff_claim_runner_dev")
            self.assertEqual(db.execute(
                "select session_user,current_user"
            ).fetchone(),(RUNNER,RUNNER))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    db.execute(f"select * from {TABLE}")
            db.execute("set role avuhz_handoff_claim_writer")
            self.assertEqual(db.execute(
                "select session_user,current_user"
            ).fetchone(),(RUNNER,WRITER))
            self.assertFalse(db.execute(
                "select has_table_privilege(current_user,%s,'SELECT')",
                (TABLE,),
            ).fetchone()[0])
            # The role can claim only via the row-level scoped INSERT policy.
            # Without signed-tenant context the insertion must fail.
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    db.execute(
                        f"insert into {TABLE}"
                        " (tenant_id,stage,plan_id,step_id,plan_digest,"
                        " approval_digest,project_reference,"
                        " authorization_set_digest,command_digest,source_sha)"
                        " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (TENANT,"DATA_COMMAND","fictional.role.test",
                         "fictional.role.step","sha256:"+"1"*64,
                         "sha256:"+"2"*64,"gnuqaefotwgkwurjpyik",
                         "sha256:"+"3"*64,"sha256:"+"4"*64,"a"*40),
                    )
        with psycopg.connect(DSN) as db:
            self.assertEqual(db.execute(
                f"select count(*) from {TABLE}"
            ).fetchone()[0],0)

    def test_untrusted_session_tenant_guc_remains_explicit_blocker(self):
        """Proof of residual trust gap: SET role can set any tenant GUC.

        No live runner credential can be issued solely on these ACL tests.
        """
        self.create_runner()
        self.grant_set()
        with psycopg.connect(DSN) as db:
            db.execute("set session authorization avuhz_handoff_claim_runner_dev")
            db.execute("set role avuhz_handoff_claim_writer")
            db.execute(
                "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                (OTHER_TENANT,),
            )
            # Transaction-local GUC resets at transaction boundary; prove
            # unverified caller can freely set it, not that it authenticates.
            self.assertEqual(db.execute(
                "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                (OTHER_TENANT,),
            ).fetchone()[0],OTHER_TENANT)
        self.assertNotEqual(TENANT,OTHER_TENANT)


if __name__=="__main__":
    unittest.main()
