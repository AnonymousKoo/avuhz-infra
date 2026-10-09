"""Security certification of the test-only handoff-claim installation candidate.

Runs against the Main PR Gate's disposable PostgreSQL after the canonical
Avuhz baseline is replayed. Never run against hosted Supabase or real data.
The candidate is not in a deployable SQL path or runtime import path.
"""
from __future__ import annotations

import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
from psycopg import sql as psql
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]

from development_handoff_claim_installation_candidate import INSTALLATION_CANDIDATE_SQL
from avuhz_engineering.development_handoff_approval_gate import EXPECTED_STAGES
from avuhz_engineering.development_handoff_durable_claim_candidate import (
    DurableHandoffClaimStop, DurableStageClaim, claim_four_stages_candidate,
)
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
ROLE = "avuhz_handoff_claim_writer"
SCHEMA = "avuhz_handoff_control"
TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"
UNPRIVILEGED_ROLE = "avuhz_handoff_unprivileged_candidate"
NON_SUPER_CREATOR = "avuhz_handoff_creator_fixture"
TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
OTHER_TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f1"
AUTH_SET = "sha256:" + "b" * 64
COMMAND = "sha256:" + "c" * 64


def require_disposable_postgres() -> None:
    if DSN is None:
        raise RuntimeError("DISPOSABLE_POSTGRES_DSN_MISSING")
    info = conninfo_to_dict(DSN)
    if (
        info.get("host") not in ("127.0.0.1", "localhost", "::1")
        or not os.environ.get("AVUHZ_INTEGRATION_DATABASE")
        or info.get("dbname") != os.environ["AVUHZ_INTEGRATION_DATABASE"]
        or info.get("user") != "postgres"
    ):
        raise RuntimeError("DISPOSABLE_POSTGRES_SCOPE_INVALID")


@unittest.skipUnless(DSN, "disposable PostgreSQL DSN required")
class HandoffClaimInstallationCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        require_disposable_postgres()

    def setUp(self) -> None:
        with psycopg.connect(DSN, autocommit=True) as db:
            state = db.execute(
                "select to_regnamespace(%s) is not null, "
                "exists(select 1 from pg_roles where rolname=%s)",
                (SCHEMA, ROLE),
            ).fetchone()
            if state != (False, False):
                raise AssertionError("DISPOSABLE_CLAIM_FIXTURE_NOT_CLEAN")

    def tearDown(self) -> None:
        # Only the checked loopback database is ever eligible for teardown.
        require_disposable_postgres()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute("drop schema if exists avuhz_handoff_control cascade")
            db.execute("drop role if exists avuhz_handoff_claim_writer")
            db.execute("drop role if exists avuhz_handoff_unprivileged_candidate")
            if db.execute(
                "select exists(select 1 from pg_roles where rolname=%s)",
                (NON_SUPER_CREATOR,),
            ).fetchone()[0]:
                db.execute(
                    psql.SQL("revoke create on database {} from {}").format(
                        psql.Identifier(os.environ["AVUHZ_INTEGRATION_DATABASE"]),
                        psql.Identifier(NON_SUPER_CREATOR),
                    )
                )
                db.execute("drop role avuhz_handoff_creator_fixture")
        super().tearDown()

    @staticmethod
    def install() -> None:
        require_disposable_postgres()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(INSTALLATION_CANDIDATE_SQL)

    @staticmethod
    def writer() -> psycopg.Connection:
        require_disposable_postgres()
        db = psycopg.connect(DSN)
        try:
            db.execute("set role avuhz_handoff_claim_writer")
            db.commit()
            return db
        except Exception:
            db.close()
            raise

    @staticmethod
    def claims() -> tuple[DurableStageClaim, ...]:
        return tuple(
            DurableStageClaim(
                stage=stage,
                plan_id=f"fictional.plan.{i}",
                step_id=f"handoff.stage.{i}",
                plan_digest="sha256:" + format(i, "064x"),
                approval_digest="sha256:" + format(i + 10, "064x"),
                project_reference=(
                    DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
                    else DEVELOPMENT_AUTH_PROJECT_REF
                ),
            )
            for i, stage in enumerate(EXPECTED_STAGES, start=1)
        )

    def run_claim(self):
        return claim_four_stages_candidate(
            connection_factory=self.writer,
            tenant_id=TENANT,
            source_sha="a" * 40,
            authorization_set_digest=AUTH_SET,
            command_digest=COMMAND,
            auth_project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            data_project_ref=DEVELOPMENT_DATA_PROJECT_REF,
            claims=self.claims(),
        )

    def insert_stage(self, db, tenant=TENANT, stage="AUTH_VERIFY",
                     project=DEVELOPMENT_AUTH_PROJECT_REF):
        claim = self.claims()[2]
        db.execute(
            f"insert into {TABLE} "
            "(tenant_id,stage,plan_id,step_id,plan_digest,approval_digest,"
            "project_reference,authorization_set_digest,command_digest,source_sha)"
            " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (tenant, stage, claim.plan_id, claim.step_id, claim.plan_digest,
             claim.approval_digest, project, AUTH_SET, COMMAND, "a" * 40),
        )

    def count_rows(self) -> int:
        with psycopg.connect(DSN) as db:
            return db.execute(f"select count(*) from {TABLE}").fetchone()[0]

    def test_install_has_forced_rls_and_exact_writer_policy(self):
        self.install()
        with psycopg.connect(DSN) as db:
            self.assertEqual(
                db.execute(
                    "select relrowsecurity, relforcerowsecurity "
                    "from pg_class where oid=to_regclass(%s)", (TABLE,),
                ).fetchone(), (True, True),
            )
            self.assertEqual(db.execute(
                "select policyname, cmd, roles, qual, with_check "
                "from pg_policies where schemaname=%s and tablename=%s",
                (SCHEMA, "avuhz_handoff_approval_claims"),
            ).fetchall()[0][:3], (
                "avuhz_handoff_claim_writer_tenant", "INSERT", [ROLE]
            ))
            self.assertEqual(db.execute(
                "select count(*) from pg_policies "
                "where schemaname=%s and tablename=%s",
                (SCHEMA, "avuhz_handoff_approval_claims"),
            ).fetchone()[0], 1)
            self.assertEqual(
                db.execute(
                    "select rolcanlogin, rolsuper, rolbypassrls, rolinherit, "
                    "rolcreatedb, rolcreaterole, rolreplication "
                    "from pg_roles where rolname=%s", (ROLE,),
                ).fetchone(), (False,) * 7,
            )
            self.assertEqual(
                db.execute(
                    "select count(*) from pg_auth_members "
                    "where member=(select oid from pg_roles where rolname=%s) "
                    "or roleid=(select oid from pg_roles where rolname=%s)",
                    (ROLE, ROLE),
                ).fetchone()[0], 0,
            )

    def test_non_superuser_creator_has_exact_postgresql17_admin_edge(self):
        """Emulate hosted DATA's non-superuser postgres CREATEROLE identity.

        The ordinary disposable fixture uses a superuser, which has no
        automatically granted role edge. Hosted PostgreSQL 17 instead creates
        one bootstrap-granted ADMIN TRUE, SET FALSE, INHERIT FALSE edge.
        """
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(
                "create role avuhz_handoff_creator_fixture "
                "nologin nosuperuser createrole noinherit nocreatedb "
                "nobypassrls noreplication"
            )
            db.execute(
                psql.SQL("grant create on database {} to {}").format(
                    psql.Identifier(os.environ["AVUHZ_INTEGRATION_DATABASE"]),
                    psql.Identifier(NON_SUPER_CREATOR),
                )
            )
            db.execute("set role avuhz_handoff_creator_fixture")
            try:
                self.assertEqual(
                    db.execute(
                        "select current_user, rolsuper from pg_roles "
                        "where rolname=current_user"
                    ).fetchone(),
                    (NON_SUPER_CREATOR, False),
                )
                db.execute(INSTALLATION_CANDIDATE_SQL)
            finally:
                db.execute("reset role")
            edges = db.execute(
                "select member.rolname, grantor.rolsuper, m.admin_option,"
                " m.inherit_option, m.set_option "
                "from pg_auth_members m "
                "join pg_roles granted on granted.oid=m.roleid "
                "join pg_roles member on member.oid=m.member "
                "join pg_roles grantor on grantor.oid=m.grantor "
                "where granted.rolname=%s",
                (ROLE,),
            ).fetchall()
            self.assertEqual(
                edges, [(NON_SUPER_CREATOR, True, True, False, False)]
            )
            self.assertFalse(
                db.execute("select pg_has_role(%s,%s,'SET')",
                           (NON_SUPER_CREATOR, ROLE)).fetchone()[0]
            )
            self.assertFalse(
                db.execute("select pg_has_role(%s,%s,'USAGE')",
                           (NON_SUPER_CREATOR, ROLE)).fetchone()[0]
            )
            self.assertEqual(
                db.execute("select relrowsecurity,relforcerowsecurity "
                           "from pg_class where oid=to_regclass(%s)",
                           (TABLE,)).fetchone(), (True, True)
            )
        self.assertEqual(self.count_rows(), 0)

    def test_no_exposed_role_or_business_command_direct_access(self):
        self.install()
        with psycopg.connect(DSN) as db:
            self.assertTrue(db.execute(
                "select has_table_privilege(%s,%s,'INSERT')",
                (ROLE, TABLE),
            ).fetchone()[0])
            for privilege in ("SELECT", "UPDATE", "DELETE", "TRUNCATE",
                              "REFERENCES", "TRIGGER"):
                self.assertFalse(db.execute(
                    "select has_table_privilege(%s,%s,%s)",
                    (ROLE, TABLE, privilege),
                ).fetchone()[0], privilege)
            for exposed in ("anon", "authenticated", "service_role",
                            "avuhz_command_service"):
                if db.execute(
                    "select exists(select 1 from pg_roles where rolname=%s)",
                    (exposed,),
                ).fetchone()[0]:
                    self.assertFalse(db.execute(
                        "select has_schema_privilege(%s,%s,'USAGE')",
                        (exposed, SCHEMA),
                    ).fetchone()[0], exposed)
                    self.assertFalse(db.execute(
                        "select has_table_privilege(%s,%s,'INSERT')",
                        (exposed, TABLE),
                    ).fetchone()[0], exposed)
            # Aclexplode with grantee=0 represents PUBLIC grants.
            self.assertFalse(db.execute(
                "select coalesce(bool_or(e.grantee=0),false) "
                "from pg_class c left join lateral "
                "aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) "
                "e on true where c.oid=to_regclass(%s)", (TABLE,),
            ).fetchone()[0])

    def test_exact_adapter_consumes_four_once_and_denies_replay(self):
        self.install()
        receipt = self.run_claim()
        self.assertEqual(receipt.claimed_stage_count, 4)
        self.assertFalse(receipt.live_execution_authorized)
        self.assertFalse(receipt.human_owner_binding_verified)
        self.assertFalse(receipt.provider_environment_installed)
        self.assertEqual(self.count_rows(), 4)
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.run_claim()
        self.assertEqual(self.count_rows(), 4)

    def test_six_independent_concurrent_claims_only_one_wins(self):
        self.install()
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(self.run_claim) for _ in range(6)]
            successes, blocked = [], []
            for future in futures:
                try:
                    successes.append(future.result())
                except DurableHandoffClaimStop as exc:
                    blocked.append(str(exc))
        self.assertEqual(len(successes), 1)
        self.assertEqual(blocked, ["HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"] * 5)
        self.assertEqual(self.count_rows(), 4)

    def test_existing_stage_collision_rolls_back_other_three(self):
        self.install()
        with psycopg.connect(DSN) as db:
            self.insert_stage(db)
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.run_claim()
        self.assertEqual(self.count_rows(), 1)

    def test_forced_rls_denies_missing_and_other_tenant(self):
        self.install()
        with self.writer() as db:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    self.insert_stage(db)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    db.execute(
                        "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                        (OTHER_TENANT,),
                    )
                    self.insert_stage(db)
        self.assertEqual(self.count_rows(), 0)

    def test_stage_project_mismatch_rejected_at_database_boundary(self):
        self.install()
        with self.writer() as db:
            with self.assertRaises(psycopg.errors.CheckViolation):
                with db.transaction():
                    db.execute(
                        "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                        (TENANT,),
                    )
                    self.insert_stage(db, project=DEVELOPMENT_DATA_PROJECT_REF)
        self.assertEqual(self.count_rows(), 0)

    def test_preexisting_schema_refuses_atomic_install(self):
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute("create schema avuhz_handoff_control")
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_CLAIM_PREEXISTING_RESOURCE_STOP",
            ):
                db.execute(INSTALLATION_CANDIDATE_SQL)
            # The failed BEGIN block must not create the role.
            db.execute("rollback")
            self.assertFalse(db.execute(
                "select exists(select 1 from pg_roles where rolname=%s)",
                (ROLE,),
            ).fetchone()[0])

    def test_preexisting_role_refuses_atomic_install(self):
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute("create role avuhz_handoff_claim_writer nologin")
            with self.assertRaisesRegex(
                psycopg.errors.RaiseException,
                "HANDOFF_CLAIM_PREEXISTING_RESOURCE_STOP",
            ):
                db.execute(INSTALLATION_CANDIDATE_SQL)
            db.execute("rollback")
            self.assertIsNone(db.execute(
                "select to_regnamespace(%s)", (SCHEMA,),
            ).fetchone()[0])

    def test_nonprivileged_role_cannot_install(self):
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(
                "create role avuhz_handoff_unprivileged_candidate "
                "nologin nosuperuser nocreaterole nocreatedb noinherit"
            )
            db.execute("set role avuhz_handoff_unprivileged_candidate")
            try:
                with self.assertRaisesRegex(
                    psycopg.errors.RaiseException,
                    "HANDOFF_CLAIM_MIGRATION_IDENTITY_UNVERIFIED",
                ):
                    db.execute(INSTALLATION_CANDIDATE_SQL)
            finally:
                db.execute("rollback")
                db.execute("reset role")
            self.assertIsNone(db.execute(
                "select to_regnamespace(%s)", (SCHEMA,),
            ).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
