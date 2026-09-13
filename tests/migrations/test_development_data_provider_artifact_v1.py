"""Certify the DEVELOPMENT DATA migration-identity bootstrap, scoped migration, and seal."""
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
MIGRATION = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_development_data_provider_artifact_v1"
EXECUTOR = "avuhz_hosted_data_postgres_sim_v1"
MIGRATION_ROLE = "avuhz_data_migration_service_dev"
COMMAND_ROLE = "avuhz_command_service"


def composed_migration() -> str:
    migration = MIGRATION.read_text(encoding="utf-8")
    binding = ROLE_BINDING.read_text(encoding="utf-8")
    marker = "begin;\n"
    if migration.lower().count(marker) != 1:
        raise AssertionError("canonical migration must contain exactly one leading BEGIN")
    insertion = binding.splitlines()[-1] + "\n"
    return migration.replace(marker, marker + insertion, 1)


class DevelopmentDataProviderArtifactV1StaticTests(unittest.TestCase):
    def test_artifact_shapes_are_bounded(self):
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8").lower()
        seal = SEAL.read_text(encoding="utf-8").lower()
        binding_lines = [
            line.strip().lower()
            for line in ROLE_BINDING.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("--")
        ]

        self.assertEqual(binding_lines, [f"set local role {MIGRATION_ROLE};"])
        for sql in (bootstrap, seal):
            self.assertEqual(sql.count("\nbegin;\n"), 1)
            self.assertTrue(sql.strip().endswith("commit;"))

        self.assertIn(
            f"grant usage on schema public to {MIGRATION_ROLE} with grant option;",
            bootstrap,
        )
        self.assertIn(f"grant create on schema public to {MIGRATION_ROLE};", bootstrap)
        self.assertNotIn("has_sequence_privilege(", bootstrap)
        self.assertIn("acldefault('s', sequence.relowner)", bootstrap)
        self.assertIn("sequence_acl.grantee = migration_role_oid", bootstrap)
        self.assertIn(
            "sequence_acl.privilege_type in ('usage', 'select', 'update')",
            bootstrap,
        )
        self.assertIn(f"alter role {MIGRATION_ROLE} nocreaterole;", seal)
        self.assertIn(f"revoke usage on schema public from {MIGRATION_ROLE} cascade;", seal)
        self.assertIn(f"grant usage on schema public to {COMMAND_ROLE};", seal)

    def test_composed_migration_binds_before_preflight(self):
        sql = composed_migration().lower()
        self.assertEqual(sql.count(f"set local role {MIGRATION_ROLE};"), 1)
        self.assertLess(
            sql.index(f"set local role {MIGRATION_ROLE};"),
            sql.index("do $avuhz_initial_preflight$"),
        )
        self.assertEqual(sql.count("create table public.avuhz_"), 16)
        self.assertEqual(sql.count(" enable row level security;"), 16)


@unittest.skipUnless(
    CONTAINER,
    "explicit disposable local PostgreSQL container is required",
)
class DevelopmentDataProviderArtifactV1PostgresTests(unittest.TestCase):
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

    def _run_chain(self):
        self._apply(self._as_hosted_executor(BOOTSTRAP.read_text(encoding="utf-8")))
        self._apply(composed_migration())
        self._apply(self._as_hosted_executor(SEAL.read_text(encoding="utf-8")))

    def test_exact_chain_seals_role_and_preserves_tenant_surface(self):
        self._run_chain()

        _, state, _ = self._psql(
            f"select count(*) from pg_roles where rolname='{MIGRATION_ROLE}' "
            "and not rolcanlogin and not rolsuper and not rolinherit "
            "and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls;"
            f"select pg_has_role('{EXECUTOR}','{MIGRATION_ROLE}','SET')::int;"
            f"select pg_has_role('{MIGRATION_ROLE}','{COMMAND_ROLE}','SET')::int;"
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
            f"select has_schema_privilege('{COMMAND_ROLE}','public','USAGE')::int;"
            "select count(*) from pg_namespace namespace cross join lateral "
            "aclexplode(coalesce(namespace.nspacl,'{}'::aclitem[])) schema_acl "
            f"where namespace.nspname='public' and schema_acl.grantee=(select oid from pg_roles where rolname='{MIGRATION_ROLE}');"
            "select count(*) from information_schema.role_table_grants grants "
            "where grants.table_schema='public' and grants.table_name like 'avuhz\\_%' escape '\\' "
            "and grants.grantee in ('PUBLIC','anon','authenticated','service_role');"
        )
        self.assertEqual(
            state.splitlines(),
            ["1", "0", "0", "16", "16", "16", "1", "0", "0"],
        )

        _, owners, _ = self._psql(
            "select count(*) from pg_class relation join pg_namespace namespace "
            "on namespace.oid=relation.relnamespace join pg_roles owner_role "
            "on owner_role.oid=relation.relowner where namespace.nspname='public' "
            "and relation.relkind in ('r','p') and relation.relname like 'avuhz\\_%' escape '\\' "
            f"and owner_role.rolname='{MIGRATION_ROLE}';"
            "select count(*) from pg_proc function join pg_namespace namespace "
            "on namespace.oid=function.pronamespace join pg_roles owner_role "
            "on owner_role.oid=function.proowner where namespace.nspname='public' "
            "and function.proname like 'avuhz\\_%' escape '\\' "
            f"and owner_role.rolname<>'{MIGRATION_ROLE}';"
        )
        self.assertEqual(owners.splitlines(), ["16", "0"])

    def test_unexpected_migration_role_membership_blocks_seal(self):
        self._apply(self._as_hosted_executor(BOOTSTRAP.read_text(encoding="utf-8")))
        self._apply(composed_migration())
        self._psql("create role avuhz_unexpected_data_member nologin;", user=EXECUTOR)
        self._psql(
            f"grant {MIGRATION_ROLE} to avuhz_unexpected_data_member "
            "with admin false, inherit false, set false;",
            user=EXECUTOR,
        )

        result = self._apply(
            self._as_hosted_executor(SEAL.read_text(encoding="utf-8")),
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pre-seal membership envelope mismatch", result.stderr.decode().lower())

        self._psql("drop role avuhz_unexpected_data_member;", user=EXECUTOR, check=False)


if __name__ == "__main__":
    unittest.main()
