"""Opt-in disposable Docker/PostgreSQL certification for the current-tree baseline."""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_rebaseline_certification"
TENANT = "e1000000-0000-4000-8000-000000000001"
OTHER = "e1000000-0000-4000-8000-000000000002"


@unittest.skipUnless(CONTAINER, "explicit disposable local PostgreSQL container is required")
class LocalProviderNeutralRebaselineTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, input_bytes=None, check=True):
        result = subprocess.run(
            ["docker", "exec", *( ["-i"] if input_bytes is not None else [] ), CONTAINER, *args],
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if check and result.returncode:
            raise AssertionError(result.stderr.decode().strip())
        return result

    @classmethod
    def _psql(cls, statement, *, check=True):
        result = cls._docker(
            "psql", "-q", "-v", "ON_ERROR_STOP=1", "-At", "-U", "postgres", "-d", DATABASE,
            "-c", statement, check=check,
        )
        return result.returncode, result.stdout.decode().strip(), result.stderr.decode().strip()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CONTAINER:
            return
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("invalid local container name")
        cls._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        cls._docker("createdb", "-U", "postgres", DATABASE)
        cls._docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", DATABASE,
            input_bytes=MIGRATION.read_bytes(),
        )
        cls._psql("grant avuhz_command_service to postgres")

    @classmethod
    def tearDownClass(cls):
        if CONTAINER:
            cls._psql("revoke avuhz_command_service from postgres", check=False)
            cls._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        super().tearDownClass()

    def test_exact_tables_rls_and_policies(self):
        _, output, _ = self._psql(
            "select count(*) from pg_tables where schemaname='public' and tablename like 'avuhz_%';"
            "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace "
            "where n.nspname='public' and c.relname like 'avuhz_%' and c.relrowsecurity;"
            "select count(*) from pg_policies where schemaname='public' and tablename like 'avuhz_%' "
            "and roles @> array['avuhz_command_service']::name[];"
        )
        self.assertEqual(output.splitlines(), ["14", "14", "14"])
        _, forbidden, _ = self._psql(
            "select count(*) from pg_tables where schemaname='public' and "
            "(tablename ilike '%oia%' or tablename ilike '%diagnostic%' or "
            "tablename ilike '%assessment%' or tablename ilike '%sekinfra%')"
        )
        self.assertEqual(forbidden, "0")

    def test_no_public_anon_or_authenticated_table_authority(self):
        _, output, _ = self._psql(
            "select count(*) from information_schema.role_table_grants where table_schema='public' "
            "and table_name like 'avuhz_%' and grantee in ('PUBLIC','anon','authenticated')"
        )
        self.assertEqual(output, "0")

    def test_tenant_isolation_and_bounded_service_access(self):
        account = "'{\"reference_type\":\"ACCOUNT\",\"reference_id\":\"account.fictional\"}'::jsonb"
        opportunity = "'{\"reference_type\":\"OPPORTUNITY\",\"reference_id\":\"opportunity.fictional\"}'::jsonb"
        for index, tenant in enumerate((TENANT, OTHER), 1):
            self._psql(
                "insert into public.avuhz_acquisition_handoffs "
                "(tenant_id,handoff_id,handoff_version,canonical_account_reference,"
                "acquisition_opportunity_reference,qualification_status,target_outcome,"
                "validated_constraints,stakeholder_context,assumptions,exclusions,"
                "requested_engagement_type,source_system,source_record_version,producer_identity,"
                "produced_at,correlation_id,idempotency_key) values "
                f"('{tenant}','e1000000-0000-4000-8000-{index:012d}',1,{account},{opportunity},"
                "'QUALIFIED','Provider-neutral test','[]','[]','[]','[]','IMPLEMENTATION',"
                f"'fictional','1','provider-adapter','2030-01-15T14:00:00Z',"
                f"'e1000000-0000-4000-8000-{index + 10:012d}','rls-seed-{index}')"
            )
        _, unbound, _ = self._psql(
            "set role avuhz_command_service; select count(*) from public.avuhz_acquisition_handoffs"
        )
        _, bound, _ = self._psql(
            f"set role avuhz_command_service; set avuhz.tenant_id='{TENANT}'; "
            "select count(*) from public.avuhz_acquisition_handoffs"
        )
        self.assertEqual((unbound, bound), ("0", "1"))
        code, _, _ = self._psql(
            f"set role avuhz_command_service; set avuhz.tenant_id='{TENANT}'; "
            "delete from public.avuhz_acquisition_handoffs", check=False
        )
        self.assertNotEqual(code, 0)

    def test_exact_handoff_round_trip_cross_tenant_denial_and_immutability(self):
        record = (
            "'{\"tenant_id\":\"" + TENANT + "\","
            "\"implementation_handoff_id\":\"e2000000-0000-4000-8000-000000000001\","
            "\"handoff_version\":1,\"source_engagement_reference\":\"engagement.fictional\","
            "\"handoff_digest\":\"sha256:" + "a" * 64 + "\",\"state\":\"APPROVED\"}'::jsonb"
        )
        self._psql(
            "insert into public.avuhz_implementation_handoffs "
            "(tenant_id,implementation_handoff_id,handoff_version,source_engagement_reference,"
            "handoff_digest,state,record,created_at) values "
            f"('{TENANT}','e2000000-0000-4000-8000-000000000001',1,'engagement.fictional',"
            f"'sha256:{'a' * 64}','APPROVED',{record},'2030-01-15T14:00:00Z')"
        )
        _, digest, _ = self._psql(
            f"set role avuhz_command_service; set avuhz.tenant_id='{TENANT}'; "
            "select handoff_digest from public.avuhz_implementation_handoffs"
        )
        _, cross_tenant, _ = self._psql(
            f"set role avuhz_command_service; set avuhz.tenant_id='{OTHER}'; "
            "select count(*) from public.avuhz_implementation_handoffs"
        )
        code, _, _ = self._psql(
            "update public.avuhz_implementation_handoffs set state='REVOKED'", check=False
        )
        self.assertEqual(digest, "sha256:" + "a" * 64)
        self.assertEqual(cross_tenant, "0")
        self.assertNotEqual(code, 0)

    def test_idempotency_transition_and_conflict(self):
        insert = (
            f"set role avuhz_command_service; set avuhz.tenant_id='{TENANT}'; "
            "insert into public.avuhz_idempotency_records "
            "(id,tenant_id,trusted_principal_id,command_type,subject_type,subject_id,subject_version,"
            "idempotency_key,semantic_request_fingerprint,fingerprint_schema_version,processing_status,"
            "retention_class,attempt_count) values "
            f"('e3000000-0000-4000-8000-000000000001','{TENANT}','service.fictional',"
            "'DraftImplementationBrief','IMPLEMENTATION_BRIEF','e3000000-0000-4000-8000-000000000002',"
            "1,'idempotency-fidelity-0001','fpv1:aaaaaaaaaaaaaaaa','v1','RESERVED',"
            "'OPERATIONAL_DEDUPLICATION',0)"
        )
        self._psql(insert)
        self._psql(
            f"set role avuhz_command_service; set avuhz.tenant_id='{TENANT}'; "
            "update public.avuhz_idempotency_records set processing_status='COMPLETED',"
            "result_reference='e3000000-0000-4000-8000-000000000003',completed_at=now(),"
            "record_version=record_version+1"
        )
        _, status, _ = self._psql(
            "select processing_status||':'||record_version from public.avuhz_idempotency_records"
        )
        conflict = insert.replace("e3000000-0000-4000-8000-000000000001", "e3000000-0000-4000-8000-000000000004").replace(
            "fpv1:aaaaaaaaaaaaaaaa", "fpv1:bbbbbbbbbbbbbbbb"
        )
        code, _, _ = self._psql(conflict, check=False)
        self.assertEqual(status, "COMPLETED:2")
        self.assertNotEqual(code, 0)

    def test_event_outbox_atomic_rollback(self):
        statement = (
            f"set role avuhz_command_service; begin; set local avuhz.tenant_id='{TENANT}'; "
            "insert into public.avuhz_lifecycle_events "
            "(lifecycle_event_id,tenant_id,event_type,authoritative_subject_id,idempotency_key) values "
            f"('e4000000-0000-4000-8000-000000000001','{TENANT}','engagement.handoff.accepted',"
            "'e4000000-0000-4000-8000-000000000002','rollback-event-0001'); "
            "insert into public.avuhz_outbox_deliveries (tenant_id,lifecycle_event_id,status) values "
            f"('{TENANT}','e4000000-0000-4000-8000-000000000001','PENDING'); select 1/0; commit"
        )
        code, _, _ = self._psql(statement, check=False)
        _, counts, _ = self._psql(
            "select (select count(*) from public.avuhz_lifecycle_events)::text||':'||"
            "(select count(*) from public.avuhz_outbox_deliveries)::text"
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(counts, "0:0")


if __name__ == "__main__":
    unittest.main()
