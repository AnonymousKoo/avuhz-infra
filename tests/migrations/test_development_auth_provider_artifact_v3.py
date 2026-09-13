"""Certify the DEVELOPMENT AUTH hosted provider-artifact v3 correction package."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-auth/current"
HISTORY_V1 = ROOT / "supabase/provider-artifacts/development-auth/history/v1"
HISTORY_V2 = ROOT / "supabase/provider-artifacts/development-auth/history/v2"
BOOTSTRAP = CURRENT / "development_auth_migration_identity_v3.sql"
HOOK = CURRENT / "development_auth_custom_access_token_hook_v2.sql"
SEAL = CURRENT / "development_auth_migration_identity_seal_v2.sql"
HISTORICAL_V2_BOOTSTRAP = (
    HISTORY_V2 / "20260912155000_development_auth_migration_identity_v2.sql"
)
HISTORICAL_V2_HOOK = (
    HISTORY_V2 / "20260912155100_development_auth_custom_access_token_hook_v2.sql"
)
HISTORICAL_V2_SEAL = (
    HISTORY_V2 / "20260912155200_development_auth_migration_identity_seal_v2.sql"
)
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_auth_provider_artifact_v3"
EXECUTOR = "avuhz_hosted_postgres_sim_v3"


class DevelopmentAuthProviderArtifactV3StaticTests(unittest.TestCase):
    def test_provider_artifact_namespace_is_not_the_migration_chain(self):
        for path in (BOOTSTRAP, HOOK, SEAL):
            self.assertTrue(path.exists(), path)
            lower = path.read_text().lower()
            self.assertEqual(len(re.findall(r"(?m)^begin;$", lower)), 1)
            self.assertTrue(lower.strip().endswith("commit;"))

        active_auth_migrations = list(
            (ROOT / "supabase/migrations").glob("*_development_auth_*.sql")
        )
        self.assertEqual(active_auth_migrations, [])

        for name in (
            "20260908132000_development_auth_migration_identity_v1.sql",
            "20260908133000_development_auth_custom_access_token_hook_v1.sql",
            "20260908134000_development_auth_migration_identity_seal_v1.sql",
        ):
            self.assertTrue((HISTORY_V1 / name).exists(), name)

        for path in (
            HISTORICAL_V2_BOOTSTRAP,
            HISTORICAL_V2_HOOK,
            HISTORICAL_V2_SEAL,
        ):
            self.assertTrue(path.exists(), path)

    def test_v2_history_and_current_reused_artifacts_are_exact(self):
        expected = {
            HISTORICAL_V2_BOOTSTRAP: (
                "2a9d7c4a688ffad34bb3049d0fde026b885202d4cdb3208538926af4676e1997"
            ),
            HISTORICAL_V2_HOOK: (
                "facb9001ec01b48e4988eb94b1a2f1c1ed6b2975a29e13092c87b09186c46e1c"
            ),
            HISTORICAL_V2_SEAL: (
                "712e06d100ab39be787a952942f5592ed2bd637abb96aaf121efc8247344b733"
            ),
        }
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

        self.assertEqual(HOOK.read_bytes(), HISTORICAL_V2_HOOK.read_bytes())
        self.assertEqual(SEAL.read_bytes(), HISTORICAL_V2_SEAL.read_bytes())

    def test_v3_checks_direct_function_acl_not_public_effective_access(self):
        lower = BOOTSTRAP.read_text().lower()
        self.assertIn("migration identity v3", lower)
        self.assertNotIn("has_function_privilege", lower)
        self.assertIn("acldefault('f', function.proowner)", lower)
        self.assertIn("function_acl.grantee = migration_role_oid", lower)
        self.assertIn("function_acl.privilege_type = 'execute'", lower)
        self.assertIn("unexpected direct function privilege", lower)
        self.assertIn("existing provider public execute defaults", lower)


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentAuthProviderArtifactV3PostgresTests(unittest.TestCase):
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
        self._psql(
            "create function public.provider_public_exec_fixture() "
            "returns integer language sql as 'select 1';",
            user=EXECUTOR,
        )
        self._psql(
            "create function auth.provider_auth_public_exec_fixture() "
            "returns integer language sql as 'select 1';"
            "create function storage.provider_storage_public_exec_fixture() "
            "returns integer language sql as 'select 1';"
        )
        _, public_exec_count, _ = self._psql(
            "select count(*) from pg_proc function "
            "join pg_namespace namespace on namespace.oid=function.pronamespace "
            "cross join lateral aclexplode("
            "coalesce(function.proacl,acldefault('f',function.proowner))) function_acl "
            "where namespace.nspname in ('public','auth','storage') "
            "and function.proname like 'provider_%_public_exec_fixture' "
            "and function_acl.grantee=0 "
            "and function_acl.privilege_type='EXECUTE';"
        )
        self.assertEqual(public_exec_count, "3")

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            f"drop role if exists avuhz_migration_service_dev;"
            f"drop role if exists {EXECUTOR};",
            database="postgres",
            check=False,
        )

    def test_public_execute_baseline_allows_exact_v3_hook_v2_seal_v2_chain(self):
        bootstrap = self._as_hosted_executor(BOOTSTRAP.read_text())
        hook = self._as_hosted_executor(HOOK.read_text())
        seal = self._as_hosted_executor(SEAL.read_text())

        self._apply(bootstrap)
        self._apply(hook)
        self._apply(seal)

        _, state, _ = self._psql(
            "select count(*) from pg_roles where rolname='avuhz_migration_service_dev';"
            "select count(*) from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            f"and member_role.rolname='{EXECUTOR}' "
            "and membership.admin_option "
            "and not membership.inherit_option "
            "and not membership.set_option;"
            "select (to_regprocedure("
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)') "
            "is not null)::int;"
        )
        self.assertEqual(state.splitlines(), ["1", "1", "1"])

        code, _, error = self._psql(
            "set role avuhz_migration_service_dev;",
            user=EXECUTOR,
            check=False,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("permission denied to set role", error.lower())

    def test_direct_execute_grant_fails_closed_and_rolls_back_role(self):
        bootstrap = self._as_hosted_executor(BOOTSTRAP.read_text())
        marker = "do $avuhz_development_auth_migration_identity_v3_postcondition$"
        self.assertEqual(bootstrap.count(marker), 1)
        injected = bootstrap.replace(
            marker,
            "grant execute on function public.provider_public_exec_fixture() "
            "to avuhz_migration_service_dev;\n\n" + marker,
        )
        result = self._apply(injected, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "unexpected direct function privilege",
            result.stderr.decode().lower(),
        )

        _, state, _ = self._psql(
            "select count(*) from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
            "select (function.proacl is null)::int "
            "from pg_proc function "
            "join pg_namespace namespace on namespace.oid=function.pronamespace "
            "where namespace.nspname='public' "
            "and function.proname='provider_public_exec_fixture';"
        )
        self.assertEqual(state.splitlines(), ["0", "1"])


if __name__ == "__main__":
    unittest.main()
