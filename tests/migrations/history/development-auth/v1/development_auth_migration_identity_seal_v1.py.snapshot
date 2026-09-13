"""Validation for the bounded DEVELOPMENT AUTH migration identity seal."""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_MIGRATION = (
    ROOT
    / "supabase/migrations/20260908132000_development_auth_migration_identity_v1.sql"
)
HOOK_MIGRATION = (
    ROOT
    / "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
)
MIGRATION = (
    ROOT
    / "supabase/migrations/20260908134000_development_auth_migration_identity_seal_v1.sql"
)
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_auth_migration_identity_seal_v1_certification"


class DevelopmentAuthMigrationIdentitySealStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text()
        cls.lower = cls.sql.lower()

    def test_exact_ordered_transactional_artifact(self):
        self.assertLess(BOOTSTRAP_MIGRATION.name, HOOK_MIGRATION.name)
        self.assertLess(HOOK_MIGRATION.name, MIGRATION.name)
        self.assertEqual(len(re.findall(r"(?m)^begin;$", self.lower)), 1)
        self.assertTrue(self.lower.strip().endswith("commit;"))
        self.assertIn("remote execution is unauthorized by default", self.lower)
        for forbidden in ("create temporary", "create temp", "pg_temp"):
            self.assertNotIn(forbidden, self.lower)

    def test_exact_seal_mutation_surface(self):
        self.assertEqual(
            re.findall(
                r"(?m)^revoke\s+([^;]+);$",
                self.lower,
            ),
            [
                "create on schema public from avuhz_migration_service_dev",
                "usage on schema public from avuhz_migration_service_dev",
                "avuhz_migration_service_dev from postgres",
            ],
        )
        for forbidden in (
            "create role",
            "alter role",
            "drop role",
            "create function",
            "alter function",
            "grant ",
            "create table",
            "alter table",
        ):
            self.assertNotIn(forbidden, self.lower)

    def test_exact_fail_closed_preflight(self):
        for phrase in (
            "session_user <> 'postgres' or current_user <> 'postgres'",
            "seal role attributes mismatch",
            "seal membership mismatch",
            "seal found direct database privilege",
            "seal public schema privilege mismatch",
            "seal found provider schema privilege",
            "seal found table privilege",
            "seal found sequence privilege",
            "seal requires the exact hook",
            "seal hook definition mismatch",
            "seal requires exact supabase_auth_admin schema usage",
            "seal hook acl mismatch",
        ):
            self.assertIn(phrase, self.lower)
        self.assertLess(
            self.lower.index("seal_preflight"),
            self.lower.index(
                "revoke create on schema public from "
                "avuhz_migration_service_dev"
            ),
        )

    def test_exact_sealed_postcondition(self):
        for phrase in (
            "sealed migration identity attributes mismatch",
            "sealed migration identity retains membership",
            "sealed migration identity retains direct database privilege",
            "sealed migration identity retains direct public schema privilege",
            "sealed migration identity retains provider schema privilege",
            "sealed migration identity retains table privilege",
            "sealed migration identity retains sequence privilege",
            "sealed hook changed unexpectedly",
            "sealed hook lost supabase_auth_admin access",
            "sealed hook acl widened unexpectedly",
        ):
            self.assertIn(phrase, self.lower)


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentAuthMigrationIdentitySealLocalPostgresTests(unittest.TestCase):
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
    def _psql(
        cls,
        statement,
        *,
        database=DATABASE,
        user="postgres",
        check=True,
    ):
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
    def _apply(cls, sql, *, user="postgres", check=True):
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

    def setUp(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            "drop role if exists avuhz_migration_service_dev;"
            "drop role if exists avuhz_unexpected_executor;"
            "drop role if exists avuhz_wrong_executor;",
            database="postgres",
        )
        self._docker("createdb", "-U", "postgres", DATABASE)
        self._psql(
            "do $$ begin "
            "if not exists (select 1 from pg_roles "
            "where rolname='supabase_auth_admin') "
            "then create role supabase_auth_admin nologin; "
            "end if;"
            "if not exists (select 1 from pg_roles where rolname='anon') "
            "then create role anon nologin; end if;"
            "if not exists (select 1 from pg_roles "
            "where rolname='authenticated') "
            "then create role authenticated nologin; end if;"
            "if not exists (select 1 from pg_roles "
            "where rolname='service_role') "
            "then create role service_role nologin; end if;"
            "end $$;"
            "create table public.avuhz_fixture_no_access(id bigint);"
            "create sequence public.avuhz_fixture_no_access_seq;"
        )
        self._apply(BOOTSTRAP_MIGRATION.read_text())
        self._apply(HOOK_MIGRATION.read_text())

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            "drop role if exists avuhz_migration_service_dev;"
            "drop role if exists avuhz_unexpected_executor;"
            "drop role if exists avuhz_wrong_executor;",
            database="postgres",
        )

    def test_exact_sealed_role_function_and_acl_state(self):
        self._apply(MIGRATION.read_text())
        _, output, _ = self._psql(
            "select rolcanlogin::int,rolsuper::int,rolinherit::int,"
            "rolcreatedb::int,rolcreaterole::int,rolreplication::int,"
            "rolbypassrls::int from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
            "select count(*) from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            "or member_role.rolname='avuhz_migration_service_dev';"
            "select count(*) from pg_database database_record "
            "cross join lateral aclexplode(coalesce("
            "database_record.datacl,'{}'::aclitem[])) database_acl "
            "join pg_roles grantee on grantee.oid=database_acl.grantee "
            "where database_record.datname=current_database() "
            "and grantee.rolname='avuhz_migration_service_dev';"
            "select count(*) from pg_namespace namespace "
            "cross join lateral aclexplode(coalesce("
            "namespace.nspacl,'{}'::aclitem[])) schema_acl "
            "join pg_roles grantee on grantee.oid=schema_acl.grantee "
            "where namespace.nspname='public' "
            "and grantee.rolname='avuhz_migration_service_dev';"
            "select pg_get_userbyid(function.proowner) from pg_proc function "
            "where function.oid="
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)'"
            "::regprocedure;"
            "select has_schema_privilege("
            "'supabase_auth_admin','public','USAGE')::int,"
            "has_function_privilege("
            "'supabase_auth_admin',"
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)',"
            "'EXECUTE')::int;"
            "select count(*) from information_schema.routine_privileges "
            "where routine_schema='public' "
            "and routine_name='avuhz_development_custom_access_token_hook_v1' "
            "and grantee in ('PUBLIC','anon','authenticated','service_role');"
            "select count(*) from pg_tables "
            "where schemaname='public' "
            "and tablename='avuhz_fixture_no_access';"
        )
        self.assertEqual(
            output.splitlines(),
            [
                "0|0|0|0|0|0|0",
                "0",
                "0",
                "0",
                "avuhz_migration_service_dev",
                "1|1",
                "0",
                "1",
            ],
        )

    def test_wrong_executor_fails_before_seal(self):
        self._psql(
            "create role avuhz_wrong_executor login;",
            database="postgres",
        )
        result = self._apply(
            MIGRATION.read_text(),
            user="avuhz_wrong_executor",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "requires the exact approved postgres executor session",
            result.stderr.decode(),
        )

    def test_role_attribute_drift_fails_without_repair(self):
        self._psql("alter role avuhz_migration_service_dev login;")
        result = self._apply(MIGRATION.read_text(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seal role attributes mismatch", result.stderr.decode())
        _, login, _ = self._psql(
            "select rolcanlogin::int from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
        )
        self.assertEqual(login, "1")

    def test_membership_drift_fails_without_repair(self):
        self._psql(
            "create role avuhz_unexpected_executor nologin;"
            "grant avuhz_migration_service_dev "
            "to avuhz_unexpected_executor "
            "with admin false, inherit false, set true;",
            database="postgres",
        )
        result = self._apply(MIGRATION.read_text(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seal membership mismatch", result.stderr.decode())

    def test_schema_privilege_drift_fails_without_repair(self):
        self._psql(
            "grant usage on schema public to avuhz_migration_service_dev "
            "with grant option;"
        )
        result = self._apply(MIGRATION.read_text(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "seal public schema privilege mismatch",
            result.stderr.decode(),
        )

    def test_hook_acl_drift_fails_without_repair(self):
        self._psql(
            "grant execute on function "
            "public.avuhz_development_custom_access_token_hook_v1(jsonb) "
            "to anon;"
        )
        result = self._apply(MIGRATION.read_text(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "seal hook acl mismatch",
            result.stderr.decode().lower(),
        )

    def test_transaction_failure_rolls_back_seal(self):
        injected = MIGRATION.read_text().replace(
            "\ndo $avuhz_development_auth_migration_identity_seal_postcondition$",
            "\nselect 1/0;"
            "\ndo $avuhz_development_auth_migration_identity_seal_postcondition$",
        )
        result = self._apply(injected, check=False)
        self.assertNotEqual(result.returncode, 0)
        _, output, _ = self._psql(
            "select count(*) from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            "and member_role.rolname='postgres';"
            "select count(*) from pg_namespace namespace "
            "cross join lateral aclexplode(coalesce("
            "namespace.nspacl,'{}'::aclitem[])) schema_acl "
            "join pg_roles grantee on grantee.oid=schema_acl.grantee "
            "where namespace.nspname='public' "
            "and grantee.rolname='avuhz_migration_service_dev';"
        )
        self.assertEqual(output.splitlines(), ["1", "2"])


if __name__ == "__main__":
    unittest.main()
