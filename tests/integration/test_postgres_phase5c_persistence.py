"""Local-only Phase 5C PostgreSQL authority and durability certification."""
from __future__ import annotations

import copy
import os
import sys
import threading
import unittest
from pathlib import Path

import psycopg
from jsonschema import Draft202012Validator, FormatChecker
from psycopg import sql
from psycopg.errors import InsufficientPrivilege
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]

from avuhz_runtime.guards import GuardPipeline
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.phase5c import Phase5CReadService, ongoing_access_usability
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5c_runtime as phase5c_runtime

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
ROLE = "avuhz_phase5c_rls_test"
DIGEST = "sha256:" + "a" * 64


@unittest.skipUnless(DSN, "local Phase 5C PostgreSQL DSN is required")
class Phase5CPostgresPersistenceTests(unittest.TestCase):
    OTHER_TENANT = "c5c20000-0000-4000-8000-000000000001"

    @classmethod
    def owner(cls, *, autocommit=False):
        return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)

    @classmethod
    def setUpClass(cls):
        with cls.owner(autocommit=True) as connection:
            connection.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(ROLE)))
            connection.execute(sql.SQL(
                "create role {} login nosuperuser nobypassrls nocreatedb nocreaterole noinherit"
            ).format(sql.Identifier(ROLE)))
            connection.execute(sql.SQL("grant avuhz_command_service to {}").format(sql.Identifier(ROLE)))

    @classmethod
    def tearDownClass(cls):
        with cls.owner(autocommit=True) as connection:
            connection.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(ROLE)))

    @classmethod
    def service_factory(cls):
        connection = psycopg.connect(DSN, user=ROLE, autocommit=True, row_factory=dict_row)
        connection.execute("set role avuhz_command_service")
        return connection

    def setUp(self):
        with self.owner() as connection:
            connection.execute(
                "truncate public.avuhz_idempotency_records,public.avuhz_outbox_deliveries,"
                "public.avuhz_lifecycle_events,public.avuhz_acquisition_handoffs cascade"
            )
        self.harness = phase5c_runtime.Phase5CRuntimeTests()
        self.harness.setUp()
        self.seed_delivered_findings()
        self.harness.executor = self.executor()

    def tearDown(self):
        with self.owner() as connection:
            connection.execute(
                "truncate public.avuhz_idempotency_records,public.avuhz_outbox_deliveries,"
                "public.avuhz_lifecycle_events,public.avuhz_acquisition_handoffs cascade"
            )

    def executor(self, store=None):
        return Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(),
            store or PostgresStore(self.service_factory), clock=lambda: self.harness.now,
            ids=self.harness.next_id, uow_factory=PostgresUnitOfWork,
        )

    def uow(self, tenant=None):
        context = self.harness.context(
            "ProposeOngoingAgreement", tenant=tenant or self.harness.tenant
        )
        return PostgresUnitOfWork(PostgresStore(self.service_factory), context)

    def seed_delivered_findings(self):
        h = self.harness
        assessment = copy.deepcopy(next(iter(h.store.oia_assessments.values())))
        finding = copy.deepcopy(next(iter(h.store.oia_findings.values())))
        delivery = copy.deepcopy(next(iter(h.store.oia_findings_deliveries.values())))
        grant = copy.deepcopy(next(iter(h.store.grants.values())))
        handoff_id = "c5c10000-0000-4000-8000-000000000010"
        proposal_id = "c5c10000-0000-4000-8000-000000000011"
        agreement_id = grant["diagnostic_agreement_authority_reference"]["reference_id"]
        payment_id = grant["diagnostic_payment_verification_reference"]["reference_id"]
        scope_id = grant["diagnostic_scope_reference"]["reference_id"]
        scope_version = grant["diagnostic_scope_reference"]["reference_version"]
        with self.owner() as connection:
            connection.execute(
                "insert into public.avuhz_acquisition_handoffs "
                "(tenant_id,handoff_id,handoff_version,canonical_account_reference,"
                "acquisition_opportunity_reference,qualification_status,target_outcome,"
                "validated_constraints,stakeholder_context,assumptions,exclusions,"
                "requested_engagement_type,source_system,source_record_version,producer_identity,"
                "produced_at,correlation_id,idempotency_key,accepted_at) "
                "values (%s,%s,1,'fictional-account','fictional-opportunity','QUALIFIED',"
                "'Fictional bounded diagnostic outcome',%s,%s,%s,%s,'DIAGNOSTIC_OIA',"
                "'fictional-source','1','fictional-producer',%s,%s,'phase5c-local-seed',%s)",
                (h.tenant, handoff_id, Jsonb([]), Jsonb([]), Jsonb([]), Jsonb([]),
                 h.now, "c5c10000-0000-4000-8000-000000000012", h.now),
            )
            connection.execute(
                "insert into public.avuhz_engagements "
                "(engagement_id,tenant_id,acquisition_handoff_id,acquisition_handoff_version,"
                "account_reference,acquisition_opportunity_reference,engagement_type,"
                "engagement_state,engagement_version,record_version,opened_at) "
                "values (%s,%s,%s,1,'fictional-account','fictional-opportunity',"
                "'DIAGNOSTIC_OIA','OPEN',1,1,%s)",
                (h.engagement_id, h.tenant, handoff_id, h.now),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_scopes "
                "(diagnostic_scope_id,tenant_id,engagement_id,scope_version,record_version,status,"
                "canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,"
                "excluded_systems,permitted_actions,prohibited_actions,assumptions,"
                "constraint_references,effective_at) values (%s,%s,%s,%s,1,'APPROVED',%s,1,"
                "'Fictional bounded scope',%s,%s,array['VIEW_CONFIGURATION'],"
                "array['CREATE','MODIFY','DELETE','DEPLOY','RESTART','ROTATE','GRANT','REVOKE',"
                "'CHANGE_CONFIGURATION','PRODUCTION_CHANGE'],%s,%s,%s)",
                (scope_id, h.tenant, h.engagement_id, scope_version, DIGEST,
                 Jsonb([{"system_reference_id": "system-001"}]), Jsonb([]),
                 Jsonb([]), Jsonb([]), h.now),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_agreement_authorities "
                "(diagnostic_agreement_authority_id,tenant_id,engagement_id,agreement_type,"
                "agreement_reference,status,diagnostic_scope_id,scope_version,"
                "canonical_scope_digest,effective_at,verified_at,recorded_at,record_version) "
                "values (%s,%s,%s,'DIAGNOSTIC_OIA','fictional-agreement','VERIFIED_ACTIVE',"
                "%s,%s,%s,%s,%s,%s,1)",
                (agreement_id, h.tenant, h.engagement_id, scope_id, scope_version,
                 DIGEST, h.now, h.now, h.now),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_payment_verifications "
                "(diagnostic_payment_verification_id,tenant_id,engagement_id,"
                "diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,"
                "payment_purpose,verification_status,provider_reference,amount_minor,currency,"
                "verified_at,record_version) values (%s,%s,%s,%s,1,'DIAGNOSTIC_OIA',"
                "'VERIFIED','fictional-payment',100,'USD',%s,1)",
                (payment_id, h.tenant, h.engagement_id, agreement_id, h.now),
            )
            connection.execute(
                "insert into public.avuhz_assessment_access_proposals "
                "(assessment_access_proposal_id,tenant_id,engagement_id,diagnostic_scope_id,"
                "scope_version,canonical_scope_digest,assessment_access_authority_digest,"
                "action_set_version,diagnostic_agreement_authority_id,"
                "diagnostic_agreement_authority_version,diagnostic_payment_verification_id,"
                "diagnostic_payment_verification_version,target_system_references,"
                "permitted_actions,status,consumed_at,record_version) values "
                "(%s,%s,%s,%s,%s,%s,%s,1,%s,1,%s,1,%s,array['VIEW_CONFIGURATION'],"
                "'CONSUMED',%s,2)",
                (proposal_id, h.tenant, h.engagement_id, scope_id, scope_version, DIGEST,
                 DIGEST, agreement_id, payment_id,
                 Jsonb([{"system_reference_id": "system-001"}]), h.now),
            )
            connection.execute(
                "insert into public.avuhz_assessment_access_grants "
                "(assessment_access_grant_id,tenant_id,engagement_id,"
                "source_assessment_access_proposal_id,source_assessment_access_proposal_version,"
                "diagnostic_scope_id,scope_version,canonical_scope_digest,"
                "assessment_access_authority_digest,action_set_version,"
                "diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,"
                "diagnostic_payment_verification_id,diagnostic_payment_verification_version,"
                "target_system_references,permitted_actions,status,approved_at,verified_at,"
                "active_from,expires_at,closed_at,closure_reason,record_version) values "
                "(%s,%s,%s,%s,2,%s,%s,%s,%s,1,%s,1,%s,1,%s,array['VIEW_CONFIGURATION'],"
                "'CLOSED',%s,%s,%s,'2030-02-15T15:00:00Z',%s,'FINDINGS_DELIVERED',3)",
                (grant["assessment_access_grant_id"], h.tenant, h.engagement_id, proposal_id,
                 scope_id, scope_version, DIGEST, DIGEST, agreement_id, payment_id,
                 Jsonb([{"system_reference_id": "system-001"}]),
                 h.now, grant["active_from"], grant["active_from"], grant["closed_at"]),
            )
            connection.execute(
                "insert into public.avuhz_oia_assessments "
                "(tenant_id,oia_assessment_id,engagement_id,diagnostic_scope_id,"
                "diagnostic_scope_version,assessment_access_grant_id,state,record_version,"
                "record,created_at,updated_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (h.tenant, assessment["oia_assessment_id"], h.engagement_id, scope_id,
                 scope_version, grant["assessment_access_grant_id"], assessment["state"],
                 assessment["record_version"], Jsonb(assessment), assessment["created_at"],
                 assessment["updated_at"]),
            )
            connection.execute(
                "insert into public.avuhz_oia_findings "
                "(tenant_id,oia_finding_id,finding_revision,oia_assessment_id,state,priority,"
                "content_digest,record,created_at,updated_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (h.tenant, finding["oia_finding_id"], finding["finding_revision"],
                 assessment["oia_assessment_id"], finding["state"], finding["priority"],
                 finding["content_digest"], Jsonb(finding), finding["created_at"], finding["updated_at"]),
            )
            connection.execute(
                "insert into public.avuhz_oia_findings_deliveries "
                "(tenant_id,oia_findings_delivery_id,oia_assessment_id,delivery_sequence,"
                "manifest_digest,record,delivered_at) values (%s,%s,%s,%s,%s,%s,%s)",
                (h.tenant, delivery["oia_findings_delivery_id"], assessment["oia_assessment_id"],
                 delivery["delivery_sequence"], delivery["manifest_digest"], Jsonb(delivery),
                 delivery["delivered_at"]),
            )
            item = delivery["finding_revisions"][0]
            connection.execute(
                "insert into public.avuhz_oia_findings_delivery_items "
                "(tenant_id,oia_findings_delivery_id,oia_finding_id,finding_revision,content_digest) "
                "values (%s,%s,%s,%s,%s)",
                (h.tenant, delivery["oia_findings_delivery_id"], item["oia_finding_id"],
                 item["finding_revision"], item["content_digest"]),
            )

    def test_complete_chain_restart_rls_schema_and_event_outbox(self):
        h = self.harness
        h.build_active()
        fresh = self.uow()
        try:
            records = {
                "oia-conversion-decision": fresh.oia_conversion_decisions.get_version(h.tenant, h.conversion_id, 1),
                "ongoing-agreement-authority": fresh.ongoing_agreement_authorities.get_version(h.tenant, h.agreement_id, 1),
                "ongoing-payment-verification": fresh.ongoing_payment_verifications.get(h.tenant, h.payment_id),
                "ongoing-access-grant": fresh.ongoing_access_grants.get(h.tenant, h.ongoing_grant_id),
            }
            self.assertTrue(ongoing_access_usability(fresh, h.tenant, h.ongoing_grant_id, h.now)["usable"])
            self.assertTrue(Phase5CReadService(fresh).eligibility(h.tenant, h.engagement_id, h.now)["eligible_for_ongoing_work"])
        finally:
            fresh.rollback(); fresh.close()
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        checker = FormatChecker()
        for slug, record in records.items():
            validator = Draft202012Validator(
                registry.expanded(f"urn:avuhz:schema:contracts:domain:{slug}:v1"),
                format_checker=checker,
            )
            self.assertEqual(list(validator.iter_errors(record)), [], slug)
        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in ("avuhz_idempotency_records", "avuhz_lifecycle_events", "avuhz_outbox_deliveries"))
        self.assertEqual(counts, (12, 12, 12))

        other = self.uow(self.OTHER_TENANT)
        try:
            self.assertIsNone(other.oia_conversion_decisions.get_version(h.tenant, h.conversion_id, 1))
            self.assertIsNone(other.ongoing_access_grants.get(h.tenant, h.ongoing_grant_id))
        finally:
            other.rollback(); other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(raw.execute("select count(*) from public.avuhz_ongoing_access_grants").fetchone()["count"], 0)
            with self.assertRaises(InsufficientPrivilege):
                raw.execute("set role postgres")
        finally:
            raw.rollback(); raw.close()

    def test_idempotency_across_uows_and_atomic_rollback(self):
        h = self.harness
        payload = {
            "oia_conversion_decision_id": h.conversion_id, "decision_version": 1,
            "oia_assessment_id": h.assessment_id, "oia_findings_delivery_id": h.delivery_id,
            "decision": "PROCEED", "selected_finding_revisions": [h.delivery_finding()],
        }
        raw = h.raw("RecordOIAConversionDecision", payload, key="phase5c-postgres-replay-0001")
        context = h.context("RecordOIAConversionDecision", role="CLIENT_DECISION_AUTHORITY")
        self.assertEqual(h.executor.execute(raw, context)["result"], "ACCEPTED")
        self.assertEqual(self.executor().execute(copy.deepcopy(raw), context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["decision"] = "DECLINE"
        changed["payload"]["selected_finding_revisions"] = []
        self.assertEqual(self.executor().execute(changed, context)["result"], "CONFLICT")

        self.tearDown(); self.setUp()
        h = self.harness
        raw = h.raw("RecordOIAConversionDecision", {
            "oia_conversion_decision_id": h.conversion_id, "decision_version": 1,
            "oia_assessment_id": h.assessment_id, "oia_findings_delivery_id": h.delivery_id,
            "decision": "PROCEED", "selected_finding_revisions": [h.delivery_finding()],
        }, key="phase5c-postgres-atomic-0001")
        store = PostgresStore(self.service_factory); store.fail_stage = "OUTBOX_APPEND"
        result = self.executor(store).execute(raw, h.context(
            "RecordOIAConversionDecision", role="CLIENT_DECISION_AUTHORITY"
        ))
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in ("avuhz_oia_conversion_decisions", "avuhz_human_approvals",
                                         "avuhz_idempotency_records", "avuhz_lifecycle_events",
                                         "avuhz_outbox_deliveries"))
        self.assertEqual(counts, (0, 0, 0, 0, 0))

    def test_multi_worker_concurrency_and_commercial_invalidation(self):
        h = self.harness
        h.build_active()
        barrier = threading.Barrier(2)
        outcomes = []

        def worker():
            uow = self.uow()
            try:
                current = uow.ongoing_payment_verifications.get(h.tenant, h.payment_id)
                barrier.wait()
                uow.ongoing_payment_verifications.invalidate(current, "VERIFICATION_REVOKED", h.now)
                uow.commit(); outcomes.append("ACCEPTED")
            except ValueError:
                uow.rollback(); outcomes.append("STALE")
            finally:
                uow.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(sorted(outcomes), ["ACCEPTED", "STALE"])
        fresh = self.uow()
        try:
            payment = fresh.ongoing_payment_verifications.get(h.tenant, h.payment_id)
            grant = fresh.ongoing_access_grants.get(h.tenant, h.ongoing_grant_id)
            self.assertEqual((payment["status"], payment["record_version"], grant["state"]),
                             ("INVALIDATED", 2, "ACTIVE"))
            self.assertFalse(ongoing_access_usability(fresh, h.tenant, h.ongoing_grant_id, h.now)["usable"])
        finally:
            fresh.rollback(); fresh.close()

    def test_revocation_offboarding_history_is_durable_and_immutable(self):
        h = self.harness
        h.build_active()
        h.execute("RevokeOngoingAccess", {
            "ongoing_access_grant_id": h.ongoing_grant_id,
            "revocation_reason": "EMERGENCY_SECURITY_REVOCATION",
        }, expected=3, role="SEKINFRA_ENGAGEMENT_AUTHORITY", caller_type="HUMAN")
        h.execute("InitiateOngoingOffboarding", {
            "ongoing_offboarding_id": h.offboarding_id,
            "oia_conversion_decision_id": h.conversion_id, "decision_version": 1,
            "ongoing_agreement_authority_id": h.agreement_id, "agreement_version": 1,
            "reason": "ENGAGEMENT_COMPLETED", "ongoing_access_grant_ids": [h.ongoing_grant_id],
        }, role="SEKINFRA_ENGAGEMENT_AUTHORITY")
        h.execute("VerifyOngoingAccessRevocation", {
            "ongoing_access_revocation_verification_id": h.revocation_id,
            "ongoing_access_grant_id": h.ongoing_grant_id,
            "ongoing_offboarding_id": h.offboarding_id,
        }, expected=4)
        h.execute("CompleteOngoingOffboarding", {
            "ongoing_offboarding_id": h.offboarding_id,
        }, expected=1)
        fresh = self.uow()
        try:
            offboarding = fresh.ongoing_offboardings.get(h.tenant, h.offboarding_id)
            verification = fresh.ongoing_access_revocation_verifications.get(h.tenant, h.revocation_id)
            self.assertEqual(offboarding["state"], "COMPLETED")
            self.assertEqual(verification["ongoing_access_grant_reference"]["reference_version"], 4)
            self.assertFalse(ongoing_access_usability(fresh, h.tenant, h.ongoing_grant_id, h.now)["usable"])
        finally:
            fresh.rollback(); fresh.close()
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        for slug, record in (("ongoing-offboarding", offboarding),
                             ("ongoing-access-revocation-verification", verification)):
            validator = Draft202012Validator(registry.expanded(
                f"urn:avuhz:schema:contracts:domain:{slug}:v1"
            ))
            self.assertEqual(list(validator.iter_errors(record)), [], slug)
        raw = self.service_factory()
        try:
            raw.execute("select set_config('avuhz.tenant_id',%s,false)", (h.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_ongoing_access_revocation_verifications "
                    "where tenant_id=%s and ongoing_access_revocation_verification_id=%s",
                    (h.tenant, h.revocation_id),
                )
        finally:
            raw.rollback(); raw.close()


if __name__ == "__main__":
    unittest.main()
