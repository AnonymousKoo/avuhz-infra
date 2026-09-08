"""Validation for the bounded DEVELOPMENT custom access-token hook migration."""
from __future__ import annotations

import json
import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_auth_hook_v1_certification"
ATOMIC_DATABASE = "avuhz_development_auth_hook_v1_atomic_failure"
TENANT = "e1000000-0000-4000-8000-000000000001"
AUDIENCE = "audience.avuhz.command-service.development"


class DevelopmentAuthHookMigrationStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text()
        cls.lower = cls.sql.lower()

    def test_exact_ordered_local_only_migration_boundary(self):
        self.assertTrue(MIGRATION.exists())
        self.assertRegex(
            MIGRATION.name,
            r"^[0-9]{14}_[A-Za-z0-9][A-Za-z0-9_-]*\.sql$",
        )
        self.assertEqual(len(re.findall(r"(?m)^begin;$", self.lower)), 1)
        self.assertTrue(self.lower.strip().endswith("commit;"))
        self.assertIn("remote application is unauthorized by default", self.lower)
        self.assertIn("local step 1 preparation only", self.lower)

        for forbidden in (
            "create table",
            "alter table",
            "create policy",
            "enable row level security",
            "create role",
            "alter role",
            "auth.hook.custom_access_token",
            "pg-functions://",
        ):
            self.assertNotIn(forbidden, self.lower)

    def test_exact_single_function_surface(self):
        created = re.findall(
            r"create\s+function\s+public\.([a-z0-9_]+)\s*\(",
            self.lower,
        )
        self.assertEqual(
            created,
            ["avuhz_development_custom_access_token_hook_v1"],
        )
        self.assertIn(
            "create function public.avuhz_development_custom_access_token_hook_v1(event jsonb)",
            self.lower,
        )
        self.assertIn("returns jsonb", self.lower)
        self.assertIn("language plpgsql", self.lower)
        self.assertIn("stable", self.lower)
        self.assertIn("set search_path = pg_catalog", self.lower)
        self.assertNotIn("security definer", self.lower)
        self.assertNotIn("create or replace function", self.lower)

    def test_fail_closed_preflight(self):
        required = (
            "requires the public schema",
            "lacks public schema privileges",
            "requires supabase_auth_admin",
            "already exists unexpectedly",
            "to_regprocedure('public.avuhz_development_custom_access_token_hook_v1(jsonb)')",
        )
        for phrase in required:
            self.assertIn(phrase, self.lower)

        self.assertLess(
            self.lower.index("avuhz_development_auth_hook_preflight"),
            self.lower.index(
                "create function public.avuhz_development_custom_access_token_hook_v1"
            ),
        )

    def test_tenant_and_audience_claims_are_bounded(self):
        self.assertIn("claims := claims - 'avuhz_tenant_id'", self.lower)
        self.assertIn("app_metadata := claims -> 'app_metadata'", self.lower)
        self.assertIn(
            "tenant_id_text := app_metadata ->> 'avuhz_tenant_id'",
            self.lower,
        )
        self.assertNotIn(
            "user_metadata ->> 'avuhz_tenant_id'",
            self.lower,
        )
        self.assertIn(AUDIENCE, self.sql)
        self.assertIn("'{aud}'", self.lower)
        self.assertIn("'{avuhz_tenant_id}'", self.lower)
        self.assertIn(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            self.sql,
        )

    def test_acl_is_least_privilege(self):
        self.assertIn(
            "revoke all on function "
            "public.avuhz_development_custom_access_token_hook_v1(jsonb) "
            "from public",
            self.lower,
        )
        self.assertIn(
            "array['anon', 'authenticated', 'service_role']",
            self.lower,
        )
        self.assertIn(
            "grant usage on schema public to supabase_auth_admin",
            self.lower,
        )
        self.assertIn(
            "grant execute on function "
            "public.avuhz_development_custom_access_token_hook_v1(jsonb)\n"
            "  to supabase_auth_admin",
            self.lower,
        )
        self.assertNotRegex(
            self.lower,
            r"grant\s+execute\s+on\s+function\s+"
            r"public\.avuhz_development_custom_access_token_hook_v1\(jsonb\)"
            r"\s+to\s+(?:anon|authenticated|service_role|public)",
        )


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentAuthHookMigrationLocalPostgresTests(unittest.TestCase):
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
    def _psql(cls, statement, *, database=DATABASE, check=True):
        result = cls._docker(
            "psql",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
            "-U",
            "postgres",
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
    def _apply(cls, database, sql, *, check=True):
        return cls._docker(
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            database,
            input_bytes=sql.encode(),
            check=check,
        )

    @classmethod
    def _fresh_database(cls, database):
        cls._docker("dropdb", "--if-exists", "-U", "postgres", database)
        cls._docker("createdb", "-U", "postgres", database)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CONTAINER:
            return
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
            CONTAINER,
        ):
            raise RuntimeError("invalid local container name")

        cls._fresh_database(DATABASE)
        cls._psql(
            "do $$ begin "
            "if not exists (select 1 from pg_roles "
            "where rolname='supabase_auth_admin') "
            "then create role supabase_auth_admin nologin; "
            "end if; end $$;"
        )
        cls._apply(DATABASE, MIGRATION.read_text())

    @classmethod
    def tearDownClass(cls):
        if CONTAINER:
            for database in (DATABASE, ATOMIC_DATABASE):
                cls._docker(
                    "dropdb",
                    "--if-exists",
                    "-U",
                    "postgres",
                    database,
                )
        super().tearDownClass()

    def _call_hook(self, event: dict, *, check=True):
        payload = json.dumps(event, separators=(",", ":"))
        delimiter = "$avuhz_test_json$"
        if delimiter in payload:
            raise ValueError("invalid local test payload")

        statement = (
            "select public.avuhz_development_custom_access_token_hook_v1("
            f"{delimiter}{payload}{delimiter}::jsonb"
            ")::text"
        )
        code, output, error = self._psql(statement, check=check)
        return code, json.loads(output) if output else None, error

    def test_exact_function_acl_and_no_schema_expansion(self):
        _, output, _ = self._psql(
            "select count(*) from pg_proc p "
            "join pg_namespace n on n.oid=p.pronamespace "
            "where n.nspname='public' "
            "and p.proname='avuhz_development_custom_access_token_hook_v1';"
            "select count(*) from pg_tables "
            "where schemaname='public' and tablename like 'avuhz_%';"
            "select count(*) from pg_policies "
            "where schemaname='public' and policyname like 'avuhz_%';"
            "select has_function_privilege("
            "'supabase_auth_admin',"
            "'public.avuhz_development_custom_access_token_hook_v1(jsonb)',"
            "'EXECUTE')::int;"
            "select count(*) from information_schema.routine_privileges "
            "where routine_schema='public' "
            "and routine_name='avuhz_development_custom_access_token_hook_v1' "
            "and grantee in ('PUBLIC','anon','authenticated','service_role');"
        )
        self.assertEqual(output.splitlines(), ["1", "0", "0", "1", "0"])

    def test_valid_provider_controlled_tenant_sets_exact_claims(self):
        _, result, _ = self._call_hook(
            {
                "claims": {
                    "aud": "authenticated",
                    "sub": "synthetic.subject",
                    "app_metadata": {
                        "avuhz_tenant_id": TENANT,
                    },
                    "user_metadata": {
                        "avuhz_tenant_id":
                        "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    },
                }
            }
        )
        self.assertEqual(result["claims"]["aud"], AUDIENCE)
        self.assertEqual(
            result["claims"]["avuhz_tenant_id"],
            TENANT,
        )
        self.assertEqual(
            result["claims"]["sub"],
            "synthetic.subject",
        )
        self.assertNotEqual(
            result["claims"]["avuhz_tenant_id"],
            result["claims"]["user_metadata"]["avuhz_tenant_id"],
        )

    def test_missing_provider_tenant_removes_untrusted_top_level_claim(self):
        _, result, _ = self._call_hook(
            {
                "claims": {
                    "aud": "authenticated",
                    "app_metadata": {},
                    "avuhz_tenant_id":
                    "ffffffff-ffff-4fff-8fff-ffffffffffff",
                }
            }
        )
        self.assertNotIn(
            "avuhz_tenant_id",
            result["claims"],
        )
        self.assertEqual(
            result["claims"]["aud"],
            "authenticated",
        )

    def test_invalid_provider_tenant_fails_closed(self):
        code, _, error = self._call_hook(
            {
                "claims": {
                    "app_metadata": {
                        "avuhz_tenant_id": "not-a-uuid",
                    }
                }
            },
            check=False,
        )
        self.assertNotEqual(code, 0)
        self.assertIn("tenant binding is invalid", error)

    def test_replay_refuses_preexisting_function(self):
        result = self._apply(
            DATABASE,
            MIGRATION.read_text(),
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "already exists unexpectedly",
            result.stderr.decode(),
        )
        _, count, _ = self._psql(
            "select count(*) from pg_proc p "
            "join pg_namespace n on n.oid=p.pronamespace "
            "where n.nspname='public' "
            "and p.proname="
            "'avuhz_development_custom_access_token_hook_v1'"
        )
        self.assertEqual(count, "1")

    def test_transaction_failure_leaves_no_partial_hook(self):
        self._fresh_database(ATOMIC_DATABASE)
        self._psql(
            "do $$ begin "
            "if not exists (select 1 from pg_roles "
            "where rolname='supabase_auth_admin') "
            "then create role supabase_auth_admin nologin; "
            "end if; end $$;",
            database=ATOMIC_DATABASE,
        )

        injected = MIGRATION.read_text().replace(
            "\ncommit;",
            "\nselect 1/0;\ncommit;",
        )
        result = self._apply(
            ATOMIC_DATABASE,
            injected,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

        _, output, _ = self._psql(
            "select count(*) from pg_proc p "
            "join pg_namespace n on n.oid=p.pronamespace "
            "where n.nspname='public' "
            "and p.proname="
            "'avuhz_development_custom_access_token_hook_v1';",
            database=ATOMIC_DATABASE,
        )
        self.assertEqual(output, "0")


if __name__ == "__main__":
    unittest.main()
