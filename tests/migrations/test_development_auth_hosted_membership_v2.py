"""Hosted PostgreSQL 17 membership regression for DEVELOPMENT AUTH v2 correction."""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "supabase/migrations/20260912155000_development_auth_migration_identity_v2.sql"
HOOK = ROOT / "supabase/migrations/20260912155100_development_auth_custom_access_token_hook_v2.sql"
SEAL = ROOT / "supabase/migrations/20260912155200_development_auth_migration_identity_seal_v2.sql"
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_auth_hosted_membership_v2"
EXECUTOR = "avuhz_hosted_postgres_sim"


class DevelopmentAuthHostedMembershipV2StaticTests(unittest.TestCase):
    def test_exact_forward_correction_surface(self):
        for path in (BOOTSTRAP, HOOK, SEAL):
            self.assertTrue(path.exists(), path)
            sql = path.read_text()
            lower = sql.lower()
            self.assertEqual(len(re.findall(r"(?m)^begin;$", lower)), 1)
            self.assertTrue(lower.strip().endswith("commit;"))
            self.assertIn(
                "remote execution is unauthorized by default"
                if path != HOOK
                else "remote application is unauthorized by default",
                lower,
            )

        bootstrap = BOOTSTRAP.read_text().lower()
        hook = HOOK.read_text().lower()
        seal = SEAL.read_text().lower()

        self.assertIn("not rolsuper", bootstrap)
        self.assertIn("rolcreaterole", bootstrap)
        self.assertIn("membership.admin_option", bootstrap)
        self.assertIn("not membership.set_option", bootstrap)
        self.assertIn("grantor_role.rolsuper", bootstrap)
        self.assertIn("granted by current_user", bootstrap)
        self.assertNotIn("revoke avuhz_migration_service_dev from postgres;", bootstrap)

        self.assertIn("membership envelope mismatch", hook)
        self.assertIn("set local role avuhz_migration_service_dev", hook)
        self.assertNotIn("hook.enable", hook)

        self.assertIn(
            "revoke avuhz_migration_service_dev from postgres\n  granted by postgres;",
            seal,
        )
        self.assertIn("provider-imposed", seal)
        self.assertNotIn("revoke avuhz_migration_service_dev from postgres;", seal)

    def test_v1_artifacts_remain_immutable_and_distinct(self):
        for name in (
            "20260908132000_development_auth_migration_identity_v1.sql",
            "20260908133000_development_auth_custom_access_token_hook_v1.sql",
            "20260908134000_development_auth_migration_identity_seal_v1.sql",
        ):
            self.assertTrue((ROOT / "supabase/migrations" / name).exists())


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentAuthHostedMembershipV2PostgresTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, input_bytes=None, check=True):
        result = subprocess.run(
            [
                "docker",
                "exec",
                *(["-i"] if input_bytes is not None else []),
                CONTAINER,
                *args,
            ],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode:
            raise AssertionError(result.stderr.decode().strip())
        return result

    @classmethod
    def _psql(cls, statement, *, database=DATABASE, user="postgres", check=True):
        result = cls._docker(
            "psql",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
            "-U",
            user,
            "-d",
            database,
            "-c",
            statement,
            check=check,
        )
        return (
            result.returncode,
            result.stdout.decode().strip(),
            result.stderr.decode().strip(),
        )

    @classmethod
    def _apply(cls, sql, *, user=EXECUTOR, check=True):
        return cls._docker(
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            user,
            "-d",
            DATABASE,
            input_bytes=sql.encode(),
            check=check,
        )

    @classmethod
    def _as_hosted_executor(cls, sql):
        # Keep the committed provider artifact exact while exercising its role-membership
        # logic under a local non-superuser CREATEROLE principal with a distinct name.
        return sql.replace("postgres", EXECUTOR)

    def setUp(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            f"drop role if exists avuhz_migration_service_dev;"
            f"drop role if exists {EXECUTOR};"
            "do $$ begin "
            "if not exists (select 1 from pg_roles where rolname='supabase_auth_admin') "
            "then create role supabase_auth_admin nologin; end if; end $$;",
            database="postgres",
        )
        self._psql(
            f"create role {EXECUTOR} login nosuperuser noinherit createrole "
            "nocreatedb noreplication nobypassrls;",
            database="postgres",
        )
        self._docker(
            "createdb",
            "-U",
            "postgres",
            "-O",
            EXECUTOR,
            DATABASE,
        )
        self._psql(
            "create schema if not exists auth authorization postgres;"
            "create schema if not exists storage authorization postgres;"
        )

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            f"drop role if exists avuhz_migration_service_dev;"
            f"drop role if exists {EXECUTOR};",
            database="postgres",
            check=False,
        )

    def test_exact_hosted_membership_chain_bootstrap_hook_and_seal(self):
        bootstrap = self._as_hosted_executor(BOOTSTRAP.read_text())
        hook = self._as_hosted_executor(HOOK.read_text())
        seal = self._as_hosted_executor(SEAL.read_text())

        self._apply(bootstrap)

        _, bootstrap_memberships, _ = self._psql(
            "select grantor_role.rolsuper::int||'|'||"
            "(membership.grantor=member_role.oid)::int||'|'||"
            "membership.admin_option::int||'|'||"
            "membership.inherit_option::int||'|'||"
            "membership.set_option::int "
            "from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "join pg_roles grantor_role on grantor_role.oid=membership.grantor "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            f"and member_role.rolname='{EXECUTOR}' "
            "order by (membership.grantor=member_role.oid)::int;",
        )
        self.assertEqual(
            bootstrap_memberships.splitlines(),
            ["1|0|1|0|0", "0|1|0|0|1"],
        )

        self._apply(hook)
        _, function_state, _ = self._psql(
            "select owner.rolname||'|'||function.prosecdef::int||'|'||"
            "function.provolatile::text||'|'||array_to_string(function.proconfig,',') "
            "from pg_proc function "
            "join pg_roles owner on owner.oid=function.proowner "
            "where function.oid=to_regprocedure("
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)');"
            "select has_function_privilege("
            "'supabase_auth_admin',"
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)',"
            "'EXECUTE')::int;",
        )
        self.assertEqual(
            function_state.splitlines(),
            [
                "avuhz_migration_service_dev|0|s|search_path=pg_catalog",
                "1",
            ],
        )

        self._apply(seal)

        _, sealed_membership, _ = self._psql(
            "select grantor_role.rolsuper::int||'|'||"
            "membership.admin_option::int||'|'||"
            "membership.inherit_option::int||'|'||"
            "membership.set_option::int "
            "from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "join pg_roles grantor_role on grantor_role.oid=membership.grantor "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            f"and member_role.rolname='{EXECUTOR}';"
            "select count(*) from pg_namespace namespace "
            "cross join lateral aclexplode(coalesce(namespace.nspacl,'{}'::aclitem[])) acl "
            "join pg_roles grantee on grantee.oid=acl.grantee "
            "where namespace.nspname='public' "
            "and grantee.rolname='avuhz_migration_service_dev';",
        )
        self.assertEqual(sealed_membership.splitlines(), ["1|1|0|0", "0"])

        code, _, error = self._psql(
            "set role avuhz_migration_service_dev;",
            user=EXECUTOR,
            check=False,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("permission denied to set role", error.lower())

    def test_bootstrap_failure_rolls_back_role(self):
        bootstrap = self._as_hosted_executor(BOOTSTRAP.read_text())
        injected = bootstrap.replace("\ncommit;", "\nselect 1/0;\ncommit;")
        result = self._apply(injected, check=False)
        self.assertNotEqual(result.returncode, 0)
        _, role_count, _ = self._psql(
            "select count(*) from pg_roles "
            "where rolname='avuhz_migration_service_dev';",
            database="postgres",
        )
        self.assertEqual(role_count, "0")


if __name__ == "__main__":
    unittest.main()
