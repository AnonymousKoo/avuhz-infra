"""Certify the bounded DEVELOPMENT DATA outbox-trigger search_path repair."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
BOOTSTRAP = CURRENT / "development_data_migration_identity_v1.sql"
ROLE_BINDING = CURRENT / "development_data_migration_role_binding_v1.sql"
SEAL = CURRENT / "development_data_migration_identity_seal_v1.sql"
REPAIR = CURRENT / "development_data_outbox_search_path_repair_v1.sql"
MIGRATION = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_data_outbox_search_path_repair_v1"
EXECUTOR = "avuhz_hosted_data_postgres_sim_v1"
MIGRATION_ROLE = "avuhz_data_migration_service_dev"
COMMAND_ROLE = "avuhz_command_service"
FUNCTION = "public.avuhz_guard_outbox_transition()"


def composed_migration() -> str:
    migration = MIGRATION.read_text(encoding="utf-8")
    binding = ROLE_BINDING.read_text(encoding="utf-8")
    marker = "begin;\n"
    if migration.lower().count(marker) != 1:
        raise AssertionError("canonical migration must contain exactly one leading BEGIN")
    insertion = binding.splitlines()[-1] + "\n"
    return migration.replace(marker, marker + insertion, 1)


class DevelopmentDataOutboxSearchPathRepairV1StaticTests(unittest.TestCase):
    def test_repair_is_one_shot_and_function_configuration_only(self):
        sql = REPAIR.read_text(encoding="utf-8").lower()
        mutation = "alter function public.avuhz_guard_outbox_transition() set search_path to '';"

        self.assertEqual(sql.count("\nbegin;\n"), 1)
        self.assertTrue(sql.strip().endswith("commit;"))
        self.assertEqual(sql.count(mutation), 1)
        self.assertIn("function_record.proconfig is not null", sql)
        self.assertIn("cardinality(function_record.proconfig) <> 1", sql)
        self.assertIn("search_path=\"\"", sql)
        self.assertNotIn("create or replace function", sql)
        self.assertNotIn("alter role ", sql)
        self.assertNotIn("alter table ", sql)
        self.assertNotIn("grant usage ", sql)
        self.assertNotIn("revoke ", sql)


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentDataOutboxSearchPathRepairV1PostgresTests(unittest.TestCase):
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
            f"drop role if exists {COMMAND_ROLE};"
            f"drop role if exists {MIGRATION_ROLE};"
            f"drop role if exists {EXECUTOR};",
            database="postgres",
            check=False,
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
            f"drop role if exists {COMMAND_ROLE};"
            f"drop role if exists {MIGRATION_ROLE};"
            f"drop role if exists {EXECUTOR};",
            database="postgres",
            check=False,
        )

    def _run_sealed_chain(self):
        self._apply(self._as_hosted_executor(BOOTSTRAP.read_text(encoding="utf-8")))
        self._apply(composed_migration())
        self._apply(self._as_hosted_executor(SEAL.read_text(encoding="utf-8")))

    def _function_fingerprint(self):
        _, value, _ = self._psql(
            "select function.oid::text || '|' || md5(function.prosrc) || '|' || "
            "function.proowner::text || '|' || function.prosecdef::int::text || '|' || "
            "function.provolatile || '|' || function.proleakproof::int::text || '|' || "
            "coalesce(function.proacl::text, '<null>') "
            "from pg_proc function join pg_namespace namespace "
            "on namespace.oid=function.pronamespace "
            "where namespace.nspname='public' "
            "and function.proname='avuhz_guard_outbox_transition' "
            "and pg_get_function_identity_arguments(function.oid)='';"
        )
        return value

    def test_repair_pins_empty_search_path_without_changing_function_or_tenant_surface(self):
        self._run_sealed_chain()

        _, pre_state, _ = self._psql(
            "select (function.proconfig is null)::int "
            "from pg_proc function join pg_namespace namespace "
            "on namespace.oid=function.pronamespace "
            "where namespace.nspname='public' "
            "and function.proname='avuhz_guard_outbox_transition' "
            "and pg_get_function_identity_arguments(function.oid)='';"
        )
        self.assertEqual(pre_state, "1")
        before = self._function_fingerprint()

        self._apply(REPAIR.read_text(encoding="utf-8"), user="postgres")

        after = self._function_fingerprint()
        self.assertEqual(after, before)

        _, state, _ = self._psql(
            "select coalesce(array_to_string(function.proconfig, ','), '<null>') "
            "from pg_proc function join pg_namespace namespace "
            "on namespace.oid=function.pronamespace "
            "where namespace.nspname='public' "
            "and function.proname='avuhz_guard_outbox_transition' "
            "and pg_get_function_identity_arguments(function.oid)='';"
            "select count(*) from pg_trigger trigger join pg_class relation "
            "on relation.oid=trigger.tgrelid join pg_namespace namespace "
            "on namespace.oid=relation.relnamespace "
            "where not trigger.tgisinternal "
            "and trigger.tgfoid='public.avuhz_guard_outbox_transition()'::regprocedure "
            "and trigger.tgname='avuhz_guard_outbox_transition' "
            "and namespace.nspname='public' and relation.relname='avuhz_outbox_deliveries' "
            "and trigger.tgtype=19 and trigger.tgenabled='O';"
            "select count(*) from pg_class relation join pg_namespace namespace "
            "on namespace.oid=relation.relnamespace where namespace.nspname='public' "
            "and relation.relkind in ('r','p') and relation.relname like 'avuhz\\_%' escape '\\';"
            "select count(*) from pg_class relation join pg_namespace namespace "
            "on namespace.oid=relation.relnamespace where namespace.nspname='public' "
            "and relation.relkind in ('r','p') and relation.relname like 'avuhz\\_%' escape '\\' "
            "and relation.relrowsecurity;"
            "select count(*) from pg_policy policy join pg_class relation on relation.oid=policy.polrelid "
            "join pg_namespace namespace on namespace.oid=relation.relnamespace "
            "where namespace.nspname='public' and relation.relname like 'avuhz\\_%' escape '\\' "
            "and policy.polname='avuhz_command_service_tenant_isolation';"
            f"select pg_has_role('postgres','{MIGRATION_ROLE}','SET')::int;"
            f"select pg_has_role('{MIGRATION_ROLE}','{COMMAND_ROLE}','SET')::int;"
            "select count(*) from information_schema.role_table_grants grants "
            "where grants.table_schema='public' and grants.table_name like 'avuhz\\_%' escape '\\' "
            "and grants.grantee in ('PUBLIC','anon','authenticated','service_role');"
        )
        lines = state.splitlines()
        self.assertIn(lines[0], ('search_path=', 'search_path=""'))
        self.assertEqual(lines[1:], ["1", "16", "16", "16", "0", "0", "0"])

    def test_repair_replay_fails_closed(self):
        self._run_sealed_chain()
        self._apply(REPAIR.read_text(encoding="utf-8"), user="postgres")

        replay = self._apply(
            REPAIR.read_text(encoding="utf-8"),
            user="postgres",
            check=False,
        )
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("pre-repair state mismatch", replay.stderr.decode().lower())


if __name__ == "__main__":
    unittest.main()
