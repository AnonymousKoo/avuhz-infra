"""Review-only DEVELOPMENT DATA isolated acquisition event/outbox permissions.

Tests run only on a disposable PG17 container and test a sealed migrated owner.
Never contacts hosted Supabase, n8n, AUTH, secrets, or production.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

from test_development_data_acquisition_event_owner_wrapper_v1 import (
    BOOTSTRAP, SEAL, OWNER, COMMAND, EXECUTOR,
    synthetic_sql, wrapped_initial_migration, wrapped_prior_migration,
)

ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
SOURCE = CURRENT / "development_data_acquisition_event_outbox_owner_grants_v1.sql"
REGISTRY = CURRENT / "development_data_shared_acquisition_registry_role_v1.sql"
EVENT_VOCABULARY = CURRENT / "development_data_acquisition_intake_event_owner_wrapper_v1.sql"
FIXTURES = (
    ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py",
    ROOT / "tests/integration/test_development_data_tenant_owner_membership_candidate.py",
    ROOT / "tests/integration/test_development_data_acquisition_intake_candidate.py",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_acquisition_event_outbox_owner_grants"
ACQUISITION = "avuhz_acquisition_service_dev"
TENANT_A = "e3110000-0000-4000-8000-000000000001"
TENANT_B = "e3110000-0000-4000-8000-000000000002"
ORG_A = "e3110000-0000-4000-8000-000000000011"
ORG_B = "e3110000-0000-4000-8000-000000000012"
INTAKE_A = "e3110000-0000-4000-8000-000000000031"
EVENT_A = "e3110000-0000-4000-8000-000000000041"
REQ_A = "e3110000-0000-4000-8000-000000000021"
CORRELATION = "e3110000-0000-4000-8000-000000000051"


class AcquisitionEventOutboxStaticTests(unittest.TestCase):
    def test_one_owner_bounded_transaction_for_two_existing_event_tables(self):
        s = SOURCE.read_text()
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", s)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", s)), 1)
        self.assertIn("REVIEW ONLY. NOT APPROVED FOR REMOTE EXECUTION", s)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", s)
        self.assertIn("AUTH pwlhruwutoitnieactol", s)
        self.assertEqual(s.count("GRANT avuhz_data_migration_service_dev TO postgres"), 1)
        self.assertEqual(s.count("REVOKE avuhz_data_migration_service_dev FROM postgres"), 1)
        self.assertEqual(s.count("SET LOCAL ROLE avuhz_data_migration_service_dev;"), 1)
        self.assertEqual(s.count("RESET ROLE;"), 1)
        self.assertIn("event_type='acquisition.intake.received'", s)
        self.assertIn("sanitized_metadata=jsonb_build_object(", s)
        self.assertIn("status='PENDING'", s)
        self.assertIn("destination_reference='internal.lifecycle-events'", s)
        self.assertNotRegex(s, r"(?im)^\s*GRANT\s+(?:ALL|UPDATE|DELETE|TRUNCATE)\b")
        self.assertNotRegex(s, r"(?im)^\s*(?:INSERT\s+INTO|UPDATE\s+public|DELETE\s+FROM|CREATE\s+ROLE)\b")
        self.assertNotIn("TO avuhz_command_service;", s)
        self.assertFalse(any("acquisition_event_outbox_owner_grants" in x.name
            for x in (ROOT / "supabase/migrations").glob("*.sql")))


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class AcquisitionEventOutboxPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, data=None, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise RuntimeError("untrusted disposable container")
        cmd = ["docker", "exec", *(["-i"] if data is not None else []),
               CONTAINER, *args]
        res = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=False, timeout=140)
        if check and res.returncode:
            err = [q.split("ERROR:", 1)[1].strip()
                   for q in res.stderr.decode(errors="replace").splitlines()
                   if "ERROR:" in q]
            # Do not emit raw provider, SQL body or contact information.
            safe = re.sub(r"[^A-Za-z0-9_ .:-]", "",
                          err[0] if err else "DISPOSABLE_PG_FAILURE")[:128]
            raise AssertionError("ACQUISITION_DISPOSABLE_TEST_FAILED: " + safe)
        return res

    @classmethod
    def sql(cls, query, *, user="postgres", check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", user, "-d", DB, "-c", query, check=check,
        )

    @classmethod
    def apply(cls, source, *, user=EXECUTOR, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", user, "-d", DB,
            data=source.encode("utf-8"), check=check,
        )

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-X", "-U", "postgres", "-d", "postgres", "-c",
            f"DROP ROLE IF EXISTS {ACQUISITION}; DROP ROLE IF EXISTS {COMMAND};"
            f"DROP ROLE IF EXISTS {OWNER}; DROP ROLE IF EXISTS {EXECUTOR};",
            check=False,
        )
        self.docker(
            "psql", "-X", "-U", "postgres", "-d", "postgres", "-c",
            f"CREATE ROLE {EXECUTOR} LOGIN NOSUPERUSER NOINHERIT "
            "CREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;"
        )
        self.docker("createdb", "-U", "postgres", "-O", EXECUTOR, DB)
        self.sql(
            "CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION postgres;"
            "CREATE SCHEMA IF NOT EXISTS storage AUTHORIZATION postgres;"
        )
        self.apply(synthetic_sql(BOOTSTRAP.read_text()))
        self.apply(wrapped_initial_migration())
        self.apply(wrapped_prior_migration())
        self.apply(synthetic_sql(SEAL.read_text()))
        for p in FIXTURES:
            self.apply(runpy.run_path(str(p))["INSTALLATION_CANDIDATE_SQL"])
        self.apply(synthetic_sql(EVENT_VOCABULARY.read_text()))
        self.apply(synthetic_sql(REGISTRY.read_text()))

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-X", "-U", "postgres", "-d", "postgres", "-c",
            f"DROP ROLE IF EXISTS {ACQUISITION}; DROP ROLE IF EXISTS {COMMAND};"
            f"DROP ROLE IF EXISTS {OWNER}; DROP ROLE IF EXISTS {EXECUTOR};",
            check=False,
        )

    def seed(self):
        for tenant, org, suffix, digest in (
            (TENANT_A, ORG_A, "a", "a"*64),
            (TENANT_B, ORG_B, "b", "b"*64),
        ):
            self.sql(
                "INSERT INTO public.avuhz_tenant_organizations "
                "(tenant_id,organization_id,business_reference,lifecycle_state) VALUES "
                f"('{tenant}','{org}','fictional.{suffix}','ACTIVE');"
                "INSERT INTO public.avuhz_tenant_owner_memberships "
                "(tenant_id,organization_id,principal_subject_digest,member_role,membership_state,verified_at) VALUES "
                f"('{tenant}','{org}','sha256:{digest}','OWNER','ACTIVE',now());"
            )

    @staticmethod
    def scope(tenant=TENANT_A):
        return (f"BEGIN;SET LOCAL ROLE {ACQUISITION};"
                f"SET LOCAL avuhz.tenant_id='{tenant}';")

    @staticmethod
    def insert_intake(tenant=TENANT_A, org=ORG_A):
        return (
            "INSERT INTO public.avuhz_acquisition_intake_requests "
            "(intake_id,tenant_id,organization_id,external_request_id,source_system,"
            "route_reference,business_name,contact_name,contact_email,contact_phone,"
            "preferred_contact_method,contact_requested,diagnostic_summary) VALUES "
            f"('{INTAKE_A}','{tenant}','{org}','{REQ_A}',"
            "'website.synthetic','diagnostic.oia','Fictional Example Company',"
            "'Example Operator','synthetic@example.invalid',null,'EMAIL',true,"
            "'Synthetic offline test only');"
        )

    @staticmethod
    def insert_event(*, event_type="acquisition.intake.received",
                     metadata=None, tenant=TENANT_A):
        if metadata is None:
            metadata = (f"'{{\"intake_id\":\"{INTAKE_A}\","
                        "\"intake_state\":\"RECEIVED\"}'::jsonb")
        return (
            "INSERT INTO public.avuhz_lifecycle_events "
            "(lifecycle_event_id,tenant_id,engagement_id,event_type,event_schema_version,"
            "authoritative_subject_type,authoritative_subject_id,"
            "authoritative_subject_version,occurred_at,producer_reference,"
            "correlation_id,causation_id,idempotency_key,visibility,sanitized_metadata) "
            f"VALUES ('{EVENT_A}','{tenant}',null,'{event_type}',1,"
            f"'ACQUISITION_INTAKE','{INTAKE_A}',1,now(),"
            f"'command.acquisition','{CORRELATION}',null,"
            f"'acquisition-intake:{INTAKE_A}','INTEGRATION_INTERNAL',{metadata});"
        )

    @staticmethod
    def insert_outbox(status="PENDING", delivery_key=None):
        key = delivery_key or ("outbox-delivery:" + EVENT_A)
        return (
            "INSERT INTO public.avuhz_outbox_deliveries "
            "(tenant_id,lifecycle_event_id,destination_reference,status,delivery_idempotency_key)"
            " SELECT tenant_id,"
            f"'{EVENT_A}','internal.lifecycle-events','{status}','{key}' "
            "FROM public.avuhz_lifecycle_events "
            f"WHERE lifecycle_event_id='{EVENT_A}';"
        )

    def state(self):
        return self.sql(
            "SELECT count(*) FROM public.avuhz_acquisition_intake_requests;"
            "SELECT count(*) FROM public.avuhz_lifecycle_events "
            "WHERE event_type='acquisition.intake.received';"
            "SELECT count(*) FROM public.avuhz_outbox_deliveries;"
            f"SELECT pg_has_role('{EXECUTOR}','{OWNER}','SET')::int;"
        ).stdout.decode().splitlines()

    def test_atomic_intake_event_outbox_and_sealed_owner(self):
        self.seed()
        self.apply(synthetic_sql(SOURCE.read_text()))
        self.assertEqual(self.state(), ["0", "0", "0", "0"])
        self.sql(self.scope() + self.insert_intake() + self.insert_event()
                 + self.insert_outbox() + "COMMIT;")
        self.assertEqual(self.state(), ["1", "1", "1", "0"])
        self.assertEqual(self.sql(
            "SELECT sanitized_metadata FROM public.avuhz_lifecycle_events"
            f" WHERE lifecycle_event_id='{EVENT_A}';"
        ).stdout.decode().count("RECEIVED"), 1)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM pg_policies "
            "WHERE tablename IN ('avuhz_lifecycle_events','avuhz_outbox_deliveries')"
            " AND policyname LIKE 'avuhz_acquisition_%';"
        ).stdout.decode().strip(), "3")

    def test_rollback_forged_events_and_cross_tenant_rejected(self):
        self.seed()
        self.apply(synthetic_sql(SOURCE.read_text()))
        err = self.sql(self.scope()+self.insert_intake()+self.insert_event()
                       +"SELECT 1/0;", check=False)
        self.assertNotEqual(err.returncode, 0)
        self.assertEqual(self.state(), ["0", "0", "0", "0"])
        for invalid in (
            self.insert_event(event_type="engagement.opened"),
            self.insert_event(metadata="'{\"intake_id\":\"wrong\",\"contact_email\":\"fake@example.invalid\"}'::jsonb"),
            self.insert_event(tenant=TENANT_B),
        ):
            with self.subTest(kind=invalid[:70]):
                r=self.sql(self.scope()+self.insert_intake()+invalid,check=False)
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(self.state(), ["0","0","0","0"])

    def test_outbox_restrictions_and_second_wrapper_execution_stop(self):
        self.seed()
        sql=synthetic_sql(SOURCE.read_text())
        self.apply(sql)
        self.sql(self.scope()+self.insert_intake()+self.insert_event()+"COMMIT;")
        for invalid in (
            self.insert_outbox(status="PUBLISHED"),
            self.insert_outbox(delivery_key="invalid-delivery-key"),
        ):
            with self.subTest(kind=invalid[:90]):
                self.assertNotEqual(self.sql(self.scope()+invalid,check=False).returncode,0)
        self.assertEqual(self.state(), ["1","1","0","0"])
        denied=self.sql(self.scope()+
            "SELECT sanitized_metadata FROM public.avuhz_lifecycle_events;",
            check=False)
        self.assertNotEqual(denied.returncode,0)
        retry=self.apply(sql,check=False)
        self.assertNotEqual(retry.returncode,0)
        self.assertEqual(self.state(), ["1","1","0","0"])


if __name__ == "__main__":
    unittest.main()
