"""Certify the review-only, source-bound Work Intake lifecycle owner wrapper.

Only disposable, offline PostgreSQL 17 may execute the wrapper during tests.
The failed previous hosted attempt is consumed; no Supabase, AUTH, or hosted
migration is authorized by this source or these test fixtures.
"""
from __future__ import annotations

import hashlib
import os
import re
import unittest
from pathlib import Path

import test_development_data_acquisition_event_owner_wrapper_v1 as prior
synthetic_sql = prior.synthetic_sql

ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
MIGRATION = ROOT / "supabase/migrations/20261014031000_enable_shared_work_intake_lifecycle_events.sql"
WRAPPER = CURRENT / "development_data_work_intake_event_owner_wrapper_v1.sql"
ACQUISITION = CURRENT / "development_data_acquisition_intake_event_owner_wrapper_v1.sql"
ACQUISITION_ACL_SOURCE = CURRENT / "development_data_acquisition_event_outbox_owner_grants_v1.sql"
SOURCE_DIGEST = "a16f6dfda1b02146170f0feb3a49f139b403a32de7db70a163436730dca2da9e"
SOURCE_COMMIT = "04076c4003ce787f6ef1aa955b6c3ef977eab509"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
START = "-- CANONICAL_WORK_INTAKE_EVENT_SQL_BODY_BEGIN (exact original source, minus BEGIN/COMMIT)\n"
END = "\n-- CANONICAL_WORK_INTAKE_EVENT_SQL_BODY_END"
EVENTS = (
    "work_intake.opened", "work_intake.handoff_offered",
    "work_intake.handoff_accepted", "work_intake.handoff_cancelled",
    "work_intake.blocked", "work_intake.resumed", "work_intake.resolved",
)


def canonical_body(source: str) -> str:
    found = re.search(r"(?m)^BEGIN;\n([\s\S]*?)^COMMIT;\s*\Z", source)
    if found is None or len(re.findall(r"(?m)^BEGIN;$", source)) != 1:
        raise AssertionError("canonical Work Intake migration drift")
    return found.group(1).strip()


class WorkIntakeOwnerWrapperStaticTests(unittest.TestCase):
    def test_exact_migration_source_and_review_only_boundary(self):
        original = MIGRATION.read_text(encoding="utf-8")
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(), SOURCE_DIGEST)
        self.assertIn(SOURCE_COMMIT, wrapper)
        self.assertIn(SOURCE_DIGEST, wrapper)
        self.assertIn("NOT APPROVED FOR REMOTE EXECUTION", wrapper)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", wrapper)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", wrapper)
        self.assertEqual(wrapper.count(START), 1)
        self.assertEqual(wrapper.count(END), 1)
        self.assertEqual(
            wrapper.split(START, 1)[1].split(END, 1)[0].strip(),
            canonical_body(original),
        )
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", wrapper)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", wrapper)), 1)

    def test_temporary_membership_is_sole_explicit_role_change(self):
        source = WRAPPER.read_text(encoding="utf-8")
        grant = "GRANT avuhz_data_migration_service_dev TO postgres"
        revoke = "REVOKE avuhz_data_migration_service_dev FROM postgres"
        self.assertEqual(source.count(grant), 1)
        self.assertEqual(source.count(revoke), 1)
        self.assertEqual(source.count("SET LOCAL ROLE avuhz_data_migration_service_dev;"), 1)
        self.assertEqual(source.count("\nRESET ROLE;\n"), 1)
        self.assertLess(source.index(grant), source.index("SET LOCAL ROLE"))
        self.assertLess(source.index("SET LOCAL ROLE"), source.index(START))
        self.assertLess(source.index(END), source.index("RESET ROLE;"))
        self.assertLess(source.index("RESET ROLE;"), source.index(revoke))
        self.assertLess(source.index(revoke), source.index("AVUHZ_WORK_INTAKE_OWNER_MEMBERSHIP_NOT_RESEALED_STOP"))
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_SEALED_MEMBERSHIP_DRIFT_STOP", source)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP", source)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_VOCABULARY_POSTCONDITION_STOP", source)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_RLS_CHANGED_STOP", source)
        self.assertNotRegex(source, r"(?im)^\s*(?:INSERT|UPDATE|DELETE|CREATE\s+ROLE|ALTER\s+ROLE)\s")
        self.assertNotRegex(source, r"(?im)^\s*GRANT\s+(?:SELECT|INSERT|UPDATE|USAGE)\s")
        self.assertFalse((ROOT / "supabase/migrations/development_data_work_intake_event_owner_wrapper_v1.sql").exists())


@unittest.skipUnless(CONTAINER, "disposable local PostgreSQL 17 required")
class WorkIntakeOwnerWrapperPostgresTests(unittest.TestCase):
    # Reuse the independently certified hosted-role simulation, sealed-role
    # fixture and existing prior owner-wrapper test helpers exactly.
    docker = prior.AcquisitionIntakeOwnerWrapperPostgresTests.__dict__["docker"]
    apply = prior.AcquisitionIntakeOwnerWrapperPostgresTests.__dict__["apply"]
    query = prior.AcquisitionIntakeOwnerWrapperPostgresTests.__dict__["query"]
    live_state = prior.AcquisitionIntakeOwnerWrapperPostgresTests.live_state

    def setUp(self):
        prior.AcquisitionIntakeOwnerWrapperPostgresTests.setUp(self)
        # The acquisition policy fixtures create one disposable cluster-scoped
        # role, which must not survive fixture setup/teardown across tests.
        self.docker(
            "psql", "-U", "postgres", "-d", "postgres",
            "-c", "DROP ROLE IF EXISTS avuhz_acquisition_service_dev;",
            check=False,
        )
        self.apply(synthetic_sql(ACQUISITION.read_text(encoding="utf-8")))

    def tearDown(self):
        try:
            prior.AcquisitionIntakeOwnerWrapperPostgresTests.tearDown(self)
        finally:
            self.docker(
                "psql", "-U", "postgres", "-d", "postgres",
                "-c", "DROP ROLE IF EXISTS avuhz_acquisition_service_dev;",
                check=False,
            )

    def _subject_constraint(self):
        return self.query(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='public.avuhz_lifecycle_events'::regclass "
            "AND conname='avuhz_lifecycle_events_authoritative_subject_type_check';"
        )

    def _policy(self):
        return self.query(
            "SELECT roles::text||':'||cmd||':'||qual||':'||with_check "
            "FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_lifecycle_events' "
            "AND policyname='avuhz_command_service_tenant_isolation';"
        )

    def _install_expected_acquisition_event_policies(self):
        # Recreate only the two known DEVELOPMENT DATA acquisition event
        # policies, from the canonical provider artifact, on disposable PG17.
        self.query(
            "CREATE ROLE avuhz_acquisition_service_dev NOLOGIN NOBYPASSRLS;"
            "CREATE TABLE public.avuhz_acquisition_intake_requests "
            "(tenant_id uuid NOT NULL, intake_id uuid NOT NULL);"
            "ALTER TABLE public.avuhz_acquisition_intake_requests "
            "ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.avuhz_acquisition_intake_requests "
            "FORCE ROW LEVEL SECURITY;"
        )
        source = ACQUISITION_ACL_SOURCE.read_text(encoding="utf-8")
        for name in ("avuhz_acquisition_event_read", "avuhz_acquisition_event_insert"):
            block = re.search(
                rf"(?ms)^CREATE POLICY {name}\n.+?^  \);",
                source,
            )
            if block is None:
                raise AssertionError("acquisition policy artifact changed")
            self.query(block.group(0))
        policy_count = self.query(
            "SELECT count(*) FROM pg_policies "
            "WHERE schemaname='public' AND tablename='avuhz_lifecycle_events';"
        )
        self.assertEqual(policy_count, "3")

    def test_success_with_actual_three_policy_development_data_shape(self):
        self._install_expected_acquisition_event_policies()
        prior = self._policy()
        self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")))
        self.assertEqual(prior, self._policy())
        self.assertIn("work_intake.opened", self.live_state()[1])
        self.assertEqual(self.live_state()[2:], ["0","0"])

    def test_altered_command_policy_predicate_rejected_even_with_tenant_marker(self):
        self.query(
            "ALTER POLICY avuhz_command_service_tenant_isolation "
            "ON public.avuhz_lifecycle_events "
            "USING (tenant_id= NULLIF(current_setting('avuhz.tenant_id',true),'')::uuid OR true) "
            "WITH CHECK (tenant_id= NULLIF(current_setting('avuhz.tenant_id',true),'')::uuid OR true);"
        )
        prior = self.live_state()
        rejected = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP",rejected.stderr.decode())
        self.assertEqual(prior,self.live_state())

    def test_command_policy_extra_roles_and_unexpected_public_policy_rejected(self):
        self.query(
            "ALTER POLICY avuhz_command_service_tenant_isolation "
            "ON public.avuhz_lifecycle_events TO PUBLIC;"
        )
        rejected = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP",rejected.stderr.decode())

    def test_unreviewed_public_policy_is_rejected_before_ddl(self):
        self.query(
            "CREATE POLICY unauthorized_public_event_read "
            "ON public.avuhz_lifecycle_events "
            "FOR SELECT TO PUBLIC USING (true);"
        )
        before=self.live_state()
        rejected=self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP",rejected.stderr.decode())
        self.assertEqual(before,self.live_state())

    def test_extra_unknown_subject_type_in_previous_constraint_rejected(self):
        old=self._subject_constraint()
        assert old.count("ARRAY[")==1
        modified=old.replace("ARRAY[","ARRAY['UNREVIEWED_TYPE'::text, ",1)
        self.query(
            "ALTER TABLE public.avuhz_lifecycle_events "
            "DROP CONSTRAINT avuhz_lifecycle_events_authoritative_subject_type_check;"
            "ALTER TABLE public.avuhz_lifecycle_events "
            "ADD CONSTRAINT avuhz_lifecycle_events_authoritative_subject_type_check "
            + modified + ";"
        )
        before=self.live_state()
        denied=self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP",denied.stderr.decode())
        self.assertEqual(before,self.live_state())

    def test_extra_unknown_event_type_in_previous_constraint_rejected(self):
        original = self.query(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='public.avuhz_lifecycle_events'::regclass "
            "AND conname='avuhz_lifecycle_events_event_type_check';"
        )
        assert original.count("ARRAY[")==1
        amended = original.replace("ARRAY[","ARRAY['unreviewed.event'::text, ",1)
        self.query(
            "ALTER TABLE public.avuhz_lifecycle_events "
            "DROP CONSTRAINT avuhz_lifecycle_events_event_type_check;"
            "ALTER TABLE public.avuhz_lifecycle_events "
            "ADD CONSTRAINT avuhz_lifecycle_events_event_type_check "
            + amended + ";"
        )
        prior = self.live_state()
        rejected = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP",rejected.stderr.decode())
        self.assertEqual(prior,self.live_state())

    def test_altered_acquisition_event_insert_scope_rejected(self):
        self._install_expected_acquisition_event_policies()
        self.query(
            "ALTER POLICY avuhz_acquisition_event_insert "
            "ON public.avuhz_lifecycle_events WITH CHECK (true);"
        )
        rejected = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")),check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP",rejected.stderr.decode())

    def test_postcondition_checks_existing_policy_then_rolls_back_everything(self):
        original = synthetic_sql(WRAPPER.read_text(encoding="utf-8"))
        marker = "\nRESET ROLE;\n"
        self.assertEqual(original.count(marker),1)
        # Synthetic injection after the canonical SQL, before resealing:
        # the final policy seal must fail and roll back all transaction DDL.
        corrupted = original.replace(marker,
            "\nALTER POLICY avuhz_command_service_tenant_isolation "
            "ON public.avuhz_lifecycle_events USING (true);"
            "\nRESET ROLE;\n",1)
        prior = self.live_state()
        failed = self.apply(corrupted,check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_RLS_CHANGED_STOP",failed.stderr.decode())
        self.assertEqual(prior,self.live_state())

    def test_owner_wrapper_succeeds_preserving_sealed_roles_rls_and_prior_vocabulary(self):
        before = self.live_state()
        policy_before = self._policy()
        self.assertEqual(before[0], "1:0")
        self.assertIn("acquisition.intake.received", before[1])
        self.assertNotIn("work_intake.opened", before[1])
        self.assertEqual(before[2:], ["0", "0"])
        self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")))
        after = self.live_state()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[2:], ["0", "0"])
        self.assertEqual(self._policy(), policy_before)
        self.assertIn("acquisition.intake.received", after[1])
        self.assertIn("implementation_handoff.accepted", after[1])
        for event in EVENTS:
            self.assertIn(event, after[1])
        subject = self._subject_constraint()
        self.assertIn("ACQUISITION_INTAKE", subject)
        self.assertIn("WORK_ITEM", subject)
        self.assertEqual(len(EVENTS), 7)

    def test_replay_denied_with_zero_data_or_owner_permission_drift(self):
        sql = synthetic_sql(WRAPPER.read_text(encoding="utf-8"))
        self.apply(sql)
        before = self.live_state()
        attempted = self.apply(sql, check=False)
        self.assertNotEqual(attempted.returncode, 0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_EVENT_VOCABULARY_DRIFT_STOP", attempted.stderr.decode())
        self.assertEqual(before, self.live_state())

    def test_injected_failure_after_alter_rolls_back_sql_and_role_grant(self):
        sql = synthetic_sql(WRAPPER.read_text(encoding="utf-8"))
        self.assertEqual(sql.count("\nRESET ROLE;\n"), 1)
        failed_source = sql.replace(
            "\nRESET ROLE;\n",
            "\nSELECT 1/0; -- synthetic rollback verification only\nRESET ROLE;\n",
        )
        before = self.live_state()
        denied = self.apply(failed_source, check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(before, self.live_state())
        self.assertNotIn("work_intake.opened", self.live_state()[1])

    def test_unapproved_database_executor_denied(self):
        before = self.live_state()
        denied = self.apply(
            synthetic_sql(WRAPPER.read_text(encoding="utf-8")),
            user="postgres", check=False,
        )
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_SESSION_MISMATCH_STOP", denied.stderr.decode())
        self.assertEqual(before, self.live_state())

    def test_sealed_role_membership_drift_denied_before_any_ddl(self):
        before = self.live_state()
        self.query(
            "GRANT avuhz_data_migration_service_dev TO avuhz_hosted_data_postgres_sim_v1 "
            "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;"
        )
        denied = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")), check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_SEALED_MEMBERSHIP_DRIFT_STOP", denied.stderr.decode())
        self.assertNotIn("work_intake.opened", self.live_state()[1])
        # This deliberate synthetic drift is cleaned by tearDown, not by the wrapper.

    def test_missing_tenant_rls_stops_before_any_ddl(self):
        self.query("ALTER TABLE public.avuhz_lifecycle_events DISABLE ROW LEVEL SECURITY;")
        before = self.live_state()
        denied = self.apply(synthetic_sql(WRAPPER.read_text(encoding="utf-8")), check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("AVUHZ_WORK_INTAKE_OWNER_TABLE_OR_TENANT_RLS_DRIFT_STOP", denied.stderr.decode())
        self.assertEqual(before, self.live_state())


if __name__ == "__main__":
    unittest.main()
