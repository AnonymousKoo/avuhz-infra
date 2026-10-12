"""Certify a REVIEW-ONLY, source-bound DEVELOPMENT DATA owner wrapper.

Provider mutations are prohibited. Integration tests mutate only a fresh
disposable PostgreSQL 17 database, not Supabase or production.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
WRAPPER = CURRENT / "development_data_acquisition_intake_event_owner_wrapper_v1.sql"
MIGRATION = ROOT / "supabase/migrations/20261012140000_enable_shared_acquisition_intake_received_event.sql"
BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
PRIOR = ROOT / "supabase/migrations/20261002213000_enable_implementation_handoff_command_intake.sql"
BOOTSTRAP = CURRENT / "development_data_migration_identity_v1.sql"
SEAL = CURRENT / "development_data_migration_identity_seal_v1.sql"
BINDING = CURRENT / "development_data_migration_role_binding_v1.sql"
EXPECTED_DIGEST = "0c4fbc10952666afe72d57e2a0d29ac486b603fe4a4bbcf7be07694310d758ff"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_intake_event_owner_wrapper_v1"
EXECUTOR = "avuhz_hosted_data_postgres_sim_v1"
OWNER = "avuhz_data_migration_service_dev"
COMMAND = "avuhz_command_service"
START = "-- CANONICAL_INTAKE_EVENT_SQL_BODY_BEGIN (exact original source, minus BEGIN/COMMIT)\n"
END = "\n-- CANONICAL_INTAKE_EVENT_SQL_BODY_END"


def canonical_body(source):
    match = re.search(r"(?m)^BEGIN;\n([\s\S]*?)^COMMIT;\s*\Z", source)
    if match is None or len(re.findall(r"(?m)^BEGIN;$", source)) != 1:
        raise AssertionError("original migration transaction drift")
    return match.group(1).strip()


def synthetic_sql(source):
    # Only a disposable local test replaces Supabase's non-superuser
    # CREATEROLE postgres with an isolated simulated hosted executor.
    return source.replace("postgres", EXECUTOR)


def wrapped_initial_migration():
    source = BASELINE.read_text(encoding="utf-8")
    marker = "begin;\n"
    if source.lower().count(marker) != 1:
        raise AssertionError("initial migration boundary drift")
    return source.replace(marker, marker + BINDING.read_text(encoding="utf-8").strip().splitlines()[-1] + "\n", 1)


def wrapped_prior_migration():
    source = PRIOR.read_text(encoding="utf-8")
    match = re.search(r"(?im)^begin;\s*\n", source)
    if match is None:
        raise AssertionError("prior migration boundary drift")
    binding = "SET LOCAL ROLE avuhz_data_migration_service_dev;\n"
    return source[:match.end()] + binding + source[match.end():]


class AcquisitionIntakeOwnerWrapperStaticTests(unittest.TestCase):
    def test_exact_source_and_transaction(self):
        source = MIGRATION.read_text(encoding="utf-8")
        wrapped = WRAPPER.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), EXPECTED_DIGEST)
        self.assertIn(EXPECTED_DIGEST, wrapped)
        self.assertIn("2ed7c6c3b35536409a9bfeb50594a6588ac04cd5", wrapped)
        self.assertIn("a8510c3bfcc74713cc26aea8e13e9de44acbae10", wrapped)
        self.assertEqual(wrapped.count(START), 1)
        self.assertEqual(wrapped.count(END), 1)
        self.assertEqual(wrapped.split(START, 1)[1].split(END, 1)[0].strip(),
                         canonical_body(source))
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", wrapped)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", wrapped)), 1)

    def test_exact_one_temporary_grant_and_revoke_after_original_sql(self):
        sql = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("REVIEW-ONLY. NOT APPROVED FOR REMOTE EXECUTION", sql)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", sql)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", sql)
        self.assertEqual(sql.count("GRANT avuhz_data_migration_service_dev TO postgres"), 1)
        self.assertEqual(sql.count("REVOKE avuhz_data_migration_service_dev FROM postgres"), 1)
        self.assertEqual(sql.count("SET LOCAL ROLE avuhz_data_migration_service_dev;"), 1)
        self.assertEqual(sql.count("RESET ROLE;"), 1)
        self.assertLess(sql.index("GRANT avuhz_data_migration_service_dev TO postgres"),
                        sql.index("SET LOCAL ROLE"))
        self.assertLess(sql.index("SET LOCAL ROLE"), sql.index(START))
        self.assertLess(sql.index(END), sql.index("RESET ROLE;"))
        self.assertLess(sql.index("RESET ROLE;"), sql.index("REVOKE avuhz_data_migration_service_dev FROM postgres"))
        self.assertLess(sql.index("REVOKE avuhz_data_migration_service_dev FROM postgres"),
                        sql.index("AVUHZ_INTAKE_OWNER_MEMBERSHIP_NOT_RESEALED_STOP"))
        self.assertNotRegex(sql, r"(?im)^\s*(?:INSERT|UPDATE|DELETE|CREATE\s+ROLE|ALTER\s+ROLE)\s")
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s+(?:SELECT|INSERT|UPDATE|USAGE)\s")
        # Two constraints are each dropped and then re-added in the canonical SQL.
        self.assertEqual(sql.count("ALTER TABLE public.avuhz_lifecycle_events"), 4)
        self.assertIn("AVUHZ_INTAKE_OWNER_SEALED_MEMBERSHIP_DRIFT_STOP", sql)
        self.assertIn("AVUHZ_INTAKE_OWNER_MEMBERSHIP_NOT_RESEALED_STOP", sql)
        self.assertFalse(any(
            "acquisition_intake_event_owner_wrapper" in p.name
            for p in (ROOT / "supabase/migrations").glob("*.sql")
        ))


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 required")
class AcquisitionIntakeOwnerWrapperPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, input_bytes=None, check=True):
        result = subprocess.run(
            ["docker", "exec", *(("-i",) if input_bytes is not None else []), CONTAINER, *args],
            input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        if check and result.returncode:
            raise AssertionError(result.stderr.decode().strip())
        return result

    @classmethod
    def apply(cls, sql, *, user=EXECUTOR, check=True):
        return cls.docker(
            "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", DB,
            input_bytes=sql.encode("utf-8"), check=check,
        )

    @classmethod
    def query(cls, sql, *, user="postgres"):
        return cls.docker(
            "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", DB,
            "-c", sql,
        ).stdout.decode().strip()

    def setUp(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("invalid disposable PostgreSQL container")
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-U", "postgres", "-d", "postgres", "-c",
            f"DROP ROLE IF EXISTS {COMMAND}; DROP ROLE IF EXISTS {OWNER}; DROP ROLE IF EXISTS {EXECUTOR};",
            check=False,
        )
        self.docker(
            "psql", "-U", "postgres", "-d", "postgres", "-c",
            f"CREATE ROLE {EXECUTOR} LOGIN NOSUPERUSER NOINHERIT CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;",
        )
        self.docker("createdb", "-U", "postgres", "-O", EXECUTOR, DB)
        self.query(
            "CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION postgres;"
            "CREATE SCHEMA IF NOT EXISTS storage AUTHORIZATION postgres;"
        )
        self.apply(synthetic_sql(BOOTSTRAP.read_text(encoding="utf-8")))
        self.apply(wrapped_initial_migration())
        self.apply(wrapped_prior_migration())
        self.apply(synthetic_sql(SEAL.read_text(encoding="utf-8")))

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-U", "postgres", "-d", "postgres", "-c",
            f"DROP ROLE IF EXISTS {COMMAND}; DROP ROLE IF EXISTS {OWNER}; DROP ROLE IF EXISTS {EXECUTOR};",
            check=False,
        )

    def live_state(self):
        return self.query(
            "SELECT relrowsecurity::int || ':' || relforcerowsecurity::int "
            "FROM pg_class WHERE oid='public.avuhz_lifecycle_events'::regclass;"
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='public.avuhz_lifecycle_events'::regclass "
            "AND conname='avuhz_lifecycle_events_event_type_check';"
            f"SELECT pg_has_role('{EXECUTOR}','{OWNER}','SET')::int;"
            "SELECT count(*) FROM pg_auth_members m "
            f"WHERE m.roleid=(SELECT oid FROM pg_roles WHERE rolname='{OWNER}') "
            f"AND m.member=(SELECT oid FROM pg_roles WHERE rolname='{EXECUTOR}') "
            f"AND m.grantor=(SELECT oid FROM pg_roles WHERE rolname='{EXECUTOR}');"
        ).splitlines()

    def test_success_preserves_tenant_rls_and_reseals_membership(self):
        before = self.live_state()
        self.assertEqual(before[0], "1:0")
        self.assertNotIn("acquisition.intake.received", before[1])
        self.assertEqual(before[2:], ["0", "0"])
        self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")))
        after = self.live_state()
        self.assertEqual(after[0], before[0])
        self.assertIn("acquisition.intake.received", after[1])
        self.assertIn("implementation_handoff.accepted", after[1])
        self.assertEqual(after[2:], ["0", "0"])
        self.assertEqual(self.query(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_lifecycle_events' "
            "AND policyname='avuhz_command_service_tenant_isolation';"), "1")
        self.assertIn("ACQUISITION_INTAKE", self.query(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='public.avuhz_lifecycle_events'::regclass "
            "AND conname='avuhz_lifecycle_events_authoritative_subject_type_check';"))

    def test_replay_fails_closed_without_reopening_owner_edge(self):
        sql = synthetic_sql(WRAPPER.read_text(encoding="utf-8"))
        self.apply(sql)
        first = self.live_state()
        retry = self.apply(sql, check=False)
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("AVUHZ_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP",
                      retry.stderr.decode())
        self.assertEqual(first, self.live_state())

    def test_failure_after_ddl_rolls_back_both_sql_and_temporary_set_edge(self):
        sql = synthetic_sql(WRAPPER.read_text(encoding="utf-8"))
        self.assertEqual(sql.count("\nRESET ROLE;\n"), 1)
        corrupted = sql.replace("\nRESET ROLE;\n",
                                "\nSELECT 1/0; -- disposable failure injection\nRESET ROLE;\n")
        original = self.live_state()
        failed = self.apply(corrupted, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(original, self.live_state())

    def test_unapproved_identity_cannot_execute(self):
        current = self.live_state()
        rejected = self.apply(synthetic_sql(
            WRAPPER.read_text(encoding="utf-8")), user="postgres", check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("AVUHZ_INTAKE_OWNER_SESSION_MISMATCH_STOP",
                      rejected.stderr.decode())
        self.assertEqual(current, self.live_state())


if __name__ == "__main__":
    unittest.main()
