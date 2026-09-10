"""Validation for the bounded DEVELOPMENT AUTH migration identity bootstrap."""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = (
    ROOT
    / "supabase/migrations/20260908132000_development_auth_migration_identity_v1.sql"
)
HOOK_MIGRATION = (
    ROOT
    / "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
)
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_auth_migration_identity_v1_certification"


class DevelopmentAuthMigrationIdentityStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text()
        cls.lower = cls.sql.lower()

    def test_exact_ordered_transactional_artifact(self):
        self.assertTrue(MIGRATION.exists())
        self.assertLess(MIGRATION.name, HOOK_MIGRATION.name)
        self.assertEqual(len(re.findall(r"(?m)^begin;$", self.lower)), 1)
        self.assertTrue(self.lower.strip().endswith("commit;"))
        self.assertIn("remote execution is unauthorized by default", self.lower)
        for forbidden in ("create temporary", "create temp", "pg_temp"):
            self.assertNotIn(forbidden, self.lower)

    def test_exact_nologin_role_definition(self):
        created = re.findall(r"create\s+role\s+([a-z0-9_]+)", self.lower)
        self.assertEqual(created, ["avuhz_migration_service_dev"])
        for attribute in (
            "nologin",
            "nosuperuser",
            "noinherit",
            "nocreatedb",
            "nocreaterole",
            "noreplication",
            "nobypassrls",
        ):
            self.assertIn(attribute, self.lower)
        self.assertNotRegex(
            self.lower,
            r"create\s+role\s+avuhz_migration_service_dev[\s\S]*?\bpassword\b",
        )
        self.assertNotIn("create function", self.lower)
        self.assertNotIn("alter role", self.lower)

    def test_exact_set_role_membership_options(self):
        self.assertIn(
            "grant avuhz_migration_service_dev to postgres\n"
            "  with admin false, inherit false, set true",
            self.lower,
        )
        self.assertIn("membership.admin_option", self.lower)
        self.assertIn("membership.inherit_option", self.lower)
        self.assertIn("membership.set_option", self.lower)
        for forbidden in (
            "grant postgres to avuhz_migration_service_dev",
            "grant service_role to",
            "grant authenticated to",
            "grant anon to",
            "with admin true",
            "with inherit true",
            "with set false",
        ):
            self.assertNotIn(forbidden, self.lower)

    def test_minimum_direct_privileges_only(self):
        self.assertIn(
            "revoke all privileges on database %i from avuhz_migration_service_dev",
            self.lower,
        )
        self.assertNotIn(
            "grant connect on database %i to avuhz_migration_service_dev",
            self.lower,
        )
        self.assertIn(
            "grant usage on schema public to avuhz_migration_service_dev",
            self.lower,
        )
        self.assertIn(
            "grant create on schema public to avuhz_migration_service_dev",
            self.lower,
        )
        self.assertNotIn("with grant option", self.lower)
        self.assertIn(
            "grant usage on schema public to supabase_auth_admin",
            self.lower,
        )
        self.assertLess(
            self.lower.index("grant usage on schema public to supabase_auth_admin"),
            self.lower.index("set local role avuhz_migration_service_dev"),
        )
        for forbidden in (
            "grant select",
            "grant insert",
            "grant update",
            "grant delete",
            "grant truncate",
            "grant usage on all sequences",
        ):
            self.assertNotIn(forbidden, self.lower)

    def test_fail_closed_preflight_and_postcondition(self):
        for phrase in (
            "session_user <> 'postgres' or current_user <> 'postgres'",
            "already exists unexpectedly",
            "requires the public schema",
            "requires supabase_auth_admin",
            "unexpected direct database privilege",
            "public schema privilege mismatch",
            "unexpected provider schema privilege",
            "unexpected table privilege",
            "unexpected sequence privilege",
            "unexpected function privilege",
            "hook v1 was created during identity bootstrap",
            "set local role avuhz_migration_service_dev",
            "current_user <> 'avuhz_migration_service_dev'",
            "bounded set role transition failed",
        ):
            self.assertIn(phrase, self.lower)


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentAuthMigrationIdentityLocalPostgresTests(unittest.TestCase):
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
            "drop role if exists avuhz_wrong_executor;",
            database="postgres",
        )
        self._docker("createdb", "-U", "postgres", DATABASE)
        self._psql(
            "create table public.avuhz_fixture_no_access(id bigint);"
            "create sequence public.avuhz_fixture_no_access_seq;"
            "create schema auth;"
            "create table auth.avuhz_fixture_no_access(id bigint);"
            "create schema storage;"
            "create table storage.avuhz_fixture_no_access(id bigint);"
            "do $$ begin "
            "if not exists (select 1 from pg_roles "
            "where rolname='supabase_auth_admin') "
            "then create role supabase_auth_admin nologin; "
            "end if; end $$;"
        )

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._psql(
            "drop role if exists avuhz_migration_service_dev;"
            "drop role if exists avuhz_wrong_executor;",
            database="postgres",
        )

    def test_exact_role_membership_and_privilege_envelope(self):
        self._apply(MIGRATION.read_text())
        _, output, _ = self._psql(
            "select rolcanlogin::int, rolsuper::int, rolinherit::int, "
            "rolcreatedb::int, rolcreaterole::int, rolreplication::int, "
            "rolbypassrls::int from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
            "select membership.admin_option::int,"
            "membership.inherit_option::int,membership.set_option::int "
            "from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "where granted_role.rolname='avuhz_migration_service_dev' "
            "and member_role.rolname='postgres';"
            "select count(*) from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "join pg_roles member_role on member_role.oid=membership.member "
            "where (granted_role.rolname='avuhz_migration_service_dev' "
            "or member_role.rolname='avuhz_migration_service_dev');"
            "select count(*) from pg_database database_record "
            "cross join lateral aclexplode(coalesce("
            "database_record.datacl,'{}'::aclitem[])) database_acl "
            "join pg_roles grantee on grantee.oid=database_acl.grantee "
            "where database_record.datname=current_database() "
            "and grantee.rolname='avuhz_migration_service_dev';"
            "select has_database_privilege("
            "'avuhz_migration_service_dev',current_database(),'CONNECT')::int,"
            "has_database_privilege("
            "'avuhz_migration_service_dev',current_database(),'TEMPORARY')::int;"
            "select schema_acl.privilege_type||'|'||"
            "schema_acl.is_grantable::int::text "
            "from pg_namespace namespace "
            "cross join lateral aclexplode(coalesce("
            "namespace.nspacl,'{}'::aclitem[])) schema_acl "
            "join pg_roles grantee on grantee.oid=schema_acl.grantee "
            "where namespace.nspname='public' "
            "and grantee.rolname='avuhz_migration_service_dev' "
            "order by schema_acl.privilege_type;"
            "select count(*) from pg_namespace namespace "
            "cross join lateral aclexplode(coalesce("
            "namespace.nspacl,'{}'::aclitem[])) schema_acl "
            "join pg_roles grantee on grantee.oid=schema_acl.grantee "
            "where namespace.nspname='public' "
            "and grantee.rolname='supabase_auth_admin' "
            "and schema_acl.privilege_type='USAGE' "
            "and not schema_acl.is_grantable;"
            "select has_table_privilege("
            "'avuhz_migration_service_dev',"
            "'public.avuhz_fixture_no_access','SELECT,INSERT,UPDATE,DELETE')::int,"
            "has_table_privilege("
            "'avuhz_migration_service_dev',"
            "'auth.avuhz_fixture_no_access','SELECT,INSERT,UPDATE,DELETE')::int,"
            "has_table_privilege("
            "'avuhz_migration_service_dev',"
            "'storage.avuhz_fixture_no_access','SELECT,INSERT,UPDATE,DELETE')::int;"
            "select has_sequence_privilege("
            "'avuhz_migration_service_dev',"
            "'public.avuhz_fixture_no_access_seq','USAGE,SELECT,UPDATE')::int;"
            "select count(*) from pg_proc function "
            "join pg_namespace namespace on namespace.oid=function.pronamespace "
            "where namespace.nspname='public' "
            "and function.proname="
            "'avuhz_development_custom_access_token_hook_v1';"
        )
        self.assertEqual(
            output.splitlines(),
            [
                "0|0|0|0|0|0|0",
                "0|0|1",
                "1",
                "0",
                "1|1",
                "CREATE|0",
                "USAGE|0",
                "1",
                "0|0|0",
                "0",
                "0",
            ],
        )

    def test_pg17_set_role_options_use_non_superuser_executor(self):
        """Dedicated NOSUPERUSER executor proves PG17 membership semantics without bypass."""
        self._psql(
            "drop role if exists avuhz_membership_executor;"
            "drop role if exists avuhz_membership_target;"
            "create role avuhz_membership_target nologin noinherit;"
            "create role avuhz_membership_executor login nosuperuser noinherit;",
            database="postgres",
        )
        code, _, _ = self._psql(
            "set role avuhz_membership_target;",
            user="avuhz_membership_executor", check=False,
        )
        self.assertNotEqual(code, 0)
        self._psql(
            "grant avuhz_membership_target to avuhz_membership_executor "
            "with admin false, inherit false, set true;",
            database="postgres",
        )
        _, attrs, _ = self._psql(
            "select r.rolsuper::int || '|' || current_user from pg_roles r "
            "where r.rolname=current_user;",
            user="avuhz_membership_executor", database="postgres",
        )
        self.assertEqual(attrs, "0|avuhz_membership_executor")
        _, options, _ = self._psql(
            "select admin_option::int||'|'||inherit_option::int||'|'||set_option::int "
            "from pg_auth_members m join pg_roles r on r.oid=m.roleid "
            "join pg_roles e on e.oid=m.member where r.rolname='avuhz_membership_target' "
            "and e.rolname='avuhz_membership_executor';",
            database="postgres",
        )
        self.assertEqual(options, "0|0|1")
        _, current, _ = self._psql(
            "begin; set local role avuhz_membership_target; select current_user; rollback;",
            user="avuhz_membership_executor", database="postgres",
        )
        self.assertEqual(current, "avuhz_membership_target")
        self._psql("revoke avuhz_membership_target from avuhz_membership_executor;", database="postgres")
        code, _, _ = self._psql("set role avuhz_membership_target;", user="avuhz_membership_executor", database="postgres", check=False)
        self.assertNotEqual(code, 0)
        self._psql("drop role avuhz_membership_executor; drop role avuhz_membership_target;", database="postgres")

    def test_existing_role_fails_closed(self):
        self._psql("create role avuhz_migration_service_dev nologin;")
        result = self._apply(MIGRATION.read_text(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists unexpectedly", result.stderr.decode())

    def test_wrong_executor_fails_before_role_creation(self):
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
        _, exists, _ = self._psql(
            "select count(*) from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
        )
        self.assertEqual(exists, "0")

    def test_transaction_failure_rolls_back_role_and_membership(self):
        injected = MIGRATION.read_text().replace(
            "\ncommit;",
            "\nselect 1/0;\ncommit;",
        )
        result = self._apply(injected, check=False)
        self.assertNotEqual(result.returncode, 0)
        _, output, _ = self._psql(
            "select count(*) from pg_roles "
            "where rolname='avuhz_migration_service_dev';"
            "select count(*) from pg_auth_members membership "
            "join pg_roles granted_role on granted_role.oid=membership.roleid "
            "where granted_role.rolname='avuhz_migration_service_dev';"
        )
        self.assertEqual(output.splitlines(), ["0", "0"])


if __name__ == "__main__":
    unittest.main()
