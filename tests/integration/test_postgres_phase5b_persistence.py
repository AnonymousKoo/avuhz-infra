"""Local-only Phase 5B PostgreSQL durability, isolation, and atomicity certification."""
from __future__ import annotations

import copy
import itertools
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import psycopg
from jsonschema import Draft202012Validator, FormatChecker
from psycopg import sql
from psycopg.errors import InsufficientPrivilege
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
RLS_PASSWORD = os.environ.get("AVUHZ_PHASE5B_RLS_TEST_PASSWORD")
ROLE = "avuhz_phase5b_rls_test"
NOW = "2030-01-15T15:00:00Z"
LATER = "2030-01-16T15:00:00Z"
DIGEST = "sha256:" + "a" * 64
METHODOLOGY = {
    "methodology_id": "oia-methodology",
    "version": "1.0.0",
    "content_digest": "sha256:" + "b" * 64,
}


def uid(slot, value):
    return f"a5{slot}00000-0000-4000-8000-{value:012d}"


def trusted(tenant, capability="oia:open", principal="phase5b-service"):
    return TrustedExecutionContext(
        True, principal, "INTERNAL_SERVICE", tenant, None, frozenset({capability}),
        frozenset(), "TEST", "avuhz-command-api", "STRONG", False,
        "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
    )


@unittest.skipUnless(DSN and RLS_PASSWORD, "local Phase 5B PostgreSQL DSN and test password are required")
class Phase5BPostgresPersistenceTests(unittest.TestCase):
    A = uid(1, 1)
    B = uid(2, 1)

    @classmethod
    def owner(cls, *, autocommit=False):
        return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)

    @classmethod
    def setUpClass(cls):
        with cls.owner(autocommit=True) as connection:
            connection.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(ROLE)))
            connection.execute(
                sql.SQL("create role {} login password {} nosuperuser nobypassrls nocreatedb nocreaterole noinherit")
                .format(sql.Identifier(ROLE), sql.Literal(RLS_PASSWORD))
            )
            connection.execute(sql.SQL("grant avuhz_command_service to {}").format(sql.Identifier(ROLE)))

    @classmethod
    def tearDownClass(cls):
        with cls.owner(autocommit=True) as connection:
            connection.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(ROLE)))

    @classmethod
    def service_factory(cls):
        connection = psycopg.connect(
            DSN, user=ROLE, password=RLS_PASSWORD, autocommit=True, row_factory=dict_row
        )
        connection.execute("set role avuhz_command_service")
        return connection

    def setUp(self):
        with self.owner() as connection:
            connection.execute(
                "truncate public.avuhz_idempotency_records,public.avuhz_outbox_deliveries,"
                "public.avuhz_lifecycle_events,public.avuhz_acquisition_handoffs cascade"
            )
        self.seed_base(self.A, 1)
        self.seed_base(self.B, 2)

    def tearDown(self):
        with self.owner() as connection:
            connection.execute(
                "truncate public.avuhz_idempotency_records,public.avuhz_outbox_deliveries,"
                "public.avuhz_lifecycle_events,public.avuhz_acquisition_handoffs cascade"
            )

    @staticmethod
    def ids(slot):
        return {
            "tenant": uid(slot, 1), "handoff": uid(slot, 2), "engagement": uid(slot, 3),
            "scope": uid(slot, 4), "agreement": uid(slot, 5), "payment": uid(slot, 6),
            "proposal": uid(slot, 7), "grant": uid(slot, 8), "assessment": uid(slot, 9),
            "plan": uid(slot, 10), "item": uid(slot, 11), "evidence": uid(slot, 12),
            "observation": uid(slot, 13), "replacement_observation": uid(slot, 14),
            "root": uid(slot, 15), "finding": uid(slot, 16), "delivery": uid(slot, 17),
            "replacement_finding": uid(slot, 18), "second_delivery": uid(slot, 19),
        }

    def seed_base(self, tenant, slot):
        value = self.ids(slot)
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
                "'fictional-source','1','fictional-producer',%s,%s,'phase5b-local-seed',%s)",
                (tenant, value["handoff"], Jsonb([]), Jsonb([]), Jsonb([]), Jsonb([]),
                 NOW, uid(slot, 30), NOW),
            )
            connection.execute(
                "insert into public.avuhz_engagements "
                "(engagement_id,tenant_id,acquisition_handoff_id,acquisition_handoff_version,"
                "account_reference,acquisition_opportunity_reference,engagement_type,"
                "engagement_state,engagement_version,record_version,opened_at) "
                "values (%s,%s,%s,1,'fictional-account','fictional-opportunity',"
                "'DIAGNOSTIC_OIA','OPEN',1,1,%s)",
                (value["engagement"], tenant, value["handoff"], NOW),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_scopes "
                "(diagnostic_scope_id,tenant_id,engagement_id,scope_version,record_version,status,"
                "canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,"
                "excluded_systems,permitted_actions,prohibited_actions,assumptions,"
                "constraint_references,effective_at) "
                "values (%s,%s,%s,1,1,'APPROVED',%s,1,'Fictional bounded scope',%s,%s,"
                "array['VIEW_CONFIGURATION'],array['CREATE','MODIFY','DELETE','DEPLOY','RESTART',"
                "'ROTATE','GRANT','REVOKE','CHANGE_CONFIGURATION','PRODUCTION_CHANGE'],%s,%s,%s)",
                (value["scope"], tenant, value["engagement"], DIGEST,
                 Jsonb([{"system_reference_id": "fictional-system-01"}]), Jsonb([]),
                 Jsonb([]), Jsonb([]), NOW),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_agreement_authorities "
                "(diagnostic_agreement_authority_id,tenant_id,engagement_id,agreement_type,"
                "agreement_reference,status,diagnostic_scope_id,scope_version,"
                "canonical_scope_digest,effective_at,verified_at,recorded_at,record_version) "
                "values (%s,%s,%s,'DIAGNOSTIC_OIA','fictional-agreement','VERIFIED_ACTIVE',"
                "%s,1,%s,%s,%s,%s,1)",
                (value["agreement"], tenant, value["engagement"], value["scope"], DIGEST,
                 NOW, NOW, NOW),
            )
            connection.execute(
                "insert into public.avuhz_diagnostic_payment_verifications "
                "(diagnostic_payment_verification_id,tenant_id,engagement_id,"
                "diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,"
                "payment_purpose,verification_status,provider_reference,amount_minor,currency,"
                "verified_at,record_version) "
                "values (%s,%s,%s,%s,1,'DIAGNOSTIC_OIA','VERIFIED','fictional-payment',100,'USD',%s,1)",
                (value["payment"], tenant, value["engagement"], value["agreement"], NOW),
            )
            connection.execute(
                "insert into public.avuhz_assessment_access_proposals "
                "(assessment_access_proposal_id,tenant_id,engagement_id,diagnostic_scope_id,"
                "scope_version,canonical_scope_digest,assessment_access_authority_digest,"
                "action_set_version,diagnostic_agreement_authority_id,"
                "diagnostic_agreement_authority_version,diagnostic_payment_verification_id,"
                "diagnostic_payment_verification_version,target_system_references,"
                "permitted_actions,status,consumed_at,record_version) "
                "values (%s,%s,%s,%s,1,%s,%s,1,%s,1,%s,1,%s,"
                "array['VIEW_CONFIGURATION'],'CONSUMED',%s,2)",
                (value["proposal"], tenant, value["engagement"], value["scope"], DIGEST,
                 DIGEST, value["agreement"], value["payment"],
                 Jsonb([{"system_reference_id": "fictional-system-01"}]), NOW),
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
                "active_from,expires_at,record_version) "
                "values (%s,%s,%s,%s,2,%s,1,%s,%s,1,%s,1,%s,1,%s,"
                "array['VIEW_CONFIGURATION'],'ACTIVE',%s,%s,%s,'2030-02-15T15:00:00Z',2)",
                (value["grant"], tenant, value["engagement"], value["proposal"],
                 value["scope"], DIGEST, DIGEST, value["agreement"], value["payment"],
                 Jsonb([{"system_reference_id": "fictional-system-01"}]), NOW, NOW, NOW),
            )

    def uow(self, tenant, store=None):
        return PostgresUnitOfWork(
            store or PostgresStore(self.service_factory), trusted(tenant)
        )

    def assessment(self, slot=1):
        value = self.ids(slot)
        return {
            "tenant_id": value["tenant"], "oia_assessment_id": value["assessment"],
            "engagement_id": value["engagement"], "diagnostic_scope_id": value["scope"],
            "diagnostic_scope_version": 1, "canonical_scope_digest": DIGEST,
            "assessment_access_grant_id": value["grant"], "state": "IN_PROGRESS",
            "record_version": 1, "opened_at": NOW, "created_at": NOW, "updated_at": NOW,
        }

    def plan(self, slot=1):
        value = self.ids(slot)
        return {
            "tenant_id": value["tenant"], "oia_assessment_plan_id": value["plan"],
            "engagement_id": value["engagement"], "oia_assessment_id": value["assessment"],
            "diagnostic_scope_id": value["scope"], "diagnostic_scope_version": 1,
            "canonical_scope_digest": DIGEST, "methodology_reference": copy.deepcopy(METHODOLOGY),
            "plan_version": 1, "state": "APPROVED",
            "objectives": [{"objective_id": "lead-response",
                            "operational_question": "How reliably is fictional work assigned?",
                            "intended_outcome": "Fictional work has accountable ownership."}],
            "process_areas": [{"process_area_id": "lead-intake", "name": "Lead intake",
                               "diagnostic_purpose": "Trace fictional assignment and timing."}],
            "completion_criteria": {
                "material_areas_addressed": True, "required_items_resolved": True,
                "critical_blocks_documented": True, "sufficiency_evaluated": True,
                "contradictions_addressed": True, "material_gaps_handled": True,
                "limitations_documented": True, "human_review_required": True,
            },
            "limitations": [], "record_version": 3, "created_by": "fictional-plan-service",
            "reviewed_by": "fictional-reviewer", "approved_by": "fictional-approver",
            "created_at": NOW, "reviewed_at": NOW, "approved_at": NOW, "updated_at": NOW,
        }

    def evidence(self, slot=1):
        value = self.ids(slot)
        return {
            "tenant_id": value["tenant"], "oia_evidence_id": value["evidence"],
            "oia_assessment_id": value["assessment"],
            "source_system_reference": "fictional-system-01",
            "evidence_type": "CONFIGURATION_SNAPSHOT", "captured_at": NOW,
            "captured_by": "fictional-evidence-service", "scope_action": "VIEW_CONFIGURATION",
            "secure_object_reference": "fictional-secure-object-01",
            "content_digest": "sha256:" + "c" * 64, "sensitivity": "RESTRICTED",
            "retention_status": "AVAILABLE", "created_at": NOW,
        }

    def inspection(self, slot=1):
        value = self.ids(slot)
        target = {
            "target_system_reference": {"system_reference_id": "fictional-system-01"},
            "diagnostic_action": "VIEW_CONFIGURATION",
        }
        return {
            "tenant_id": value["tenant"], "oia_inspection_item_id": value["item"],
            "engagement_id": value["engagement"], "oia_assessment_id": value["assessment"],
            "oia_assessment_plan_id": value["plan"], "plan_version": 1,
            "methodology_reference": copy.deepcopy(METHODOLOGY),
            "objective_id": "lead-response", "process_area_id": "lead-intake",
            "what_to_inspect": "Inspect fictional assignment configuration.",
            "why_it_matters": "Ownership is material to fictional operations.",
            "inspection_lenses": ["PROCESS", "SYSTEMS_AND_CONFIGURATION"],
            "expected_evidence": [{
                "expectation_id": "configuration-state",
                "why_sought": "Establish fictional configuration state.",
                "evidence_type": "CONFIGURATION_SNAPSHOT",
                "minimum_characteristics": ["attributable fictional state"],
                "minimum_support_level": "SYSTEM_SUPPORTED", "required": True,
                "planned_target_action": copy.deepcopy(target),
            }],
            "planned_target_action": target, "required": True,
            "coverage_state": "SUFFICIENTLY_EVIDENCED",
            "sufficiency_evaluation": {
                "state": "SUFFICIENT", "direct_evidence": True,
                "corroborating_evidence": True, "source_reliability": "HIGH",
                "representativeness": "REASONABLE", "contradiction_state": "NONE",
                "missing_material_evidence": False, "confidence": "HIGH",
                "rationale": "The fictional evidence supports this bounded judgment.",
            },
            "materiality": {"dimensions": ["TIME", "ACCOUNTABILITY"],
                            "investigation_depth": "STANDARD",
                            "rationale": "Fictional ownership is operationally material."},
            "limitations": [], "linked_evidence_ids": [value["evidence"]],
            "record_version": 1, "created_by": "fictional-inspection-service",
            "created_at": NOW, "updated_at": NOW,
        }

    def observation(self, slot=1, replacement=False):
        value = self.ids(slot)
        observation_id = value["replacement_observation"] if replacement else value["observation"]
        return {
            "tenant_id": value["tenant"], "oia_observation_id": observation_id,
            "oia_assessment_id": value["assessment"], "evidence_ids": [value["evidence"]],
            "system_process_area": "lead-intake",
            "observed_condition": "Fictional ownership is inconsistently recorded.",
            "expected_condition": "Fictional ownership is always attributable.",
            "confidence": "HIGH", "state": "RECORDED", "record_version": 1,
            "created_by": "fictional-analyst", "created_at": NOW, "updated_at": NOW,
        }

    def root_cause(self, slot=1, confidence="VERIFIED", version=3):
        value = self.ids(slot)
        return {
            "tenant_id": value["tenant"], "oia_root_cause_id": value["root"],
            "oia_assessment_id": value["assessment"],
            "cause_statement": "Fictional ownership fallback is not configured.",
            "confidence": confidence, "supporting_observation_ids": [value["observation"]],
            "supporting_evidence_ids": [value["evidence"]], "record_version": version,
            "created_by": "fictional-analyst", "created_at": NOW, "updated_at": NOW,
        }

    def finding(self, slot=1, *, finding_id=None, revision=1, state="DRAFT"):
        value = self.ids(slot)
        record = {
            "tenant_id": value["tenant"], "oia_finding_id": finding_id or value["finding"],
            "oia_assessment_id": value["assessment"], "finding_revision": revision,
            "state": state, "title": "Fictional ownership is unreliable",
            "summary": "Fictional work lacks consistent accountable follow-up.",
            "verified_operational_problem": "Required fictional ownership is not consistently recorded.",
            "business_operational_impact": "Fictional delays and operational risk increase.",
            "system_process_category": "inbound-routing",
            "supporting_observation_ids": [value["observation"]],
            "supporting_evidence_ids": [value["evidence"]],
            "root_cause_ids": [value["root"]],
            "desired_outcome": "Every fictional item has accountable ownership.",
            "intervention_category": "PROCESS_CHANGE",
            "priority_inputs": {"impact": "HIGH", "urgency": "MEDIUM",
                                "operational_criticality": "MEDIUM",
                                "confidence": "HIGH", "dependency_blocking": False},
            "priority": "HIGH", "confidence": "HIGH", "created_by": "fictional-reviewer",
            "created_at": NOW, "updated_at": NOW,
        }
        if state == "FINAL":
            record.update(finalized_by="fictional-reviewer", finalized_at=NOW,
                          content_digest="sha256:" + "d" * 64)
        return record

    def delivery(self, slot=1, *, delivery_id=None, sequence=1, finding=None):
        value = self.ids(slot)
        finding = finding or self.finding(slot, state="FINAL")
        return {
            "tenant_id": value["tenant"],
            "oia_findings_delivery_id": delivery_id or value["delivery"],
            "oia_assessment_id": value["assessment"], "delivery_sequence": sequence,
            "finding_revisions": [{
                "oia_finding_id": finding["oia_finding_id"],
                "finding_revision": finding["finding_revision"],
                "content_digest": finding["content_digest"],
            }],
            "delivered_at": NOW, "delivered_by": "fictional-reviewer",
            "client_recipient_reference": "fictional-client-authority",
            "delivery_channel_reference": "fictional-local-portal",
            "manifest_digest": "sha256:" + ("e" if sequence == 1 else "f") * 64,
        }

    def create_graph(self, slot=1):
        value = self.ids(slot)
        records = {
            "assessment": self.assessment(slot), "plan": self.plan(slot),
            "evidence": self.evidence(slot), "inspection": self.inspection(slot),
            "observation": self.observation(slot),
            "replacement_observation": self.observation(slot, True),
            "root": self.root_cause(slot), "finding": self.finding(slot),
        }
        uow = self.uow(value["tenant"])
        try:
            uow.oia_assessments.create(records["assessment"])
            uow.oia_assessment_plans.create_initial(records["plan"])
            uow.oia_evidence_items.create(records["evidence"])
            uow.oia_inspection_items.create(records["inspection"])
            uow.oia_observations.create(records["observation"])
            uow.oia_observations.create(records["replacement_observation"])
            uow.oia_root_causes.create(records["root"])
            uow.oia_findings.create(records["finding"])
            uow.commit()
        finally:
            uow.close()
        return records

    @staticmethod
    def event(value, event_id, event_type, subject_type, subject_id, version, key):
        return {
            "event_id": event_id, "event_type": event_type, "event_schema_version": 1,
            "tenant_id": value["tenant"], "engagement_id": value["engagement"],
            "authoritative_subject_reference": {
                "reference_type": subject_type, "reference_id": subject_id,
            },
            "authoritative_subject_version": version, "occurred_at": NOW,
            "producer_reference": "fictional-command-service",
            "correlation_id": uid(1, 90), "command_id": uid(1, 91),
            "subject_id": subject_id, "idempotency_key": key,
            "visibility": "TENANT_OPERATIONAL",
            "sanitized_metadata": {"record_version": version},
        }

    def test_catalog_rls_and_trusted_role_are_bounded(self):
        tables = {
            "avuhz_oia_assessments", "avuhz_oia_assessment_plans",
            "avuhz_oia_inspection_items", "avuhz_oia_evidence_items",
            "avuhz_oia_observations", "avuhz_oia_root_causes", "avuhz_oia_findings",
            "avuhz_oia_findings_deliveries",
        }
        with self.owner() as connection:
            available = {row["tablename"] for row in connection.execute(
                "select tablename from pg_tables where schemaname='public' and tablename like 'avuhz_oia_%'"
            )}
            self.assertTrue(tables <= available)
            for table in tables:
                row = connection.execute(
                    "select rowsecurity from pg_tables where schemaname='public' and tablename=%s",
                    (table,),
                ).fetchone()
                self.assertTrue(row["rowsecurity"])
                self.assertIsNotNone(connection.execute(
                    "select 1 from pg_policies where schemaname='public' and tablename=%s "
                    "and policyname='avuhz_command_service_tenant_isolation'", (table,)
                ).fetchone())
            role = connection.execute(
                "select rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit "
                "from pg_roles where rolname='avuhz_command_service'"
            ).fetchone()
            self.assertEqual(tuple(role.values()), (False, False, False, False, False, False))

        raw = self.service_factory()
        try:
            self.assertEqual(raw.execute("select count(*) from public.avuhz_oia_assessments").fetchone()["count"], 0)
            with self.assertRaises(InsufficientPrivilege):
                raw.execute("set role postgres")
        finally:
            raw.rollback()
            raw.close()

        for context in (SimpleNamespace(authenticated=False, tenant_id=self.A),
                        SimpleNamespace(authenticated=True, tenant_id=None)):
            with self.assertRaises(ValueError):
                PostgresUnitOfWork(PostgresStore(self.service_factory), context)

    def test_all_repositories_restart_and_schema_round_trip(self):
        expected = self.create_graph()
        fresh = self.uow(self.A)
        try:
            actual = {
                "assessment": fresh.oia_assessments.get(self.A, self.ids(1)["assessment"]),
                "plan": fresh.oia_assessment_plans.get_current(self.A, self.ids(1)["plan"]),
                "evidence": fresh.oia_evidence_items.get(self.A, self.ids(1)["evidence"]),
                "inspection": fresh.oia_inspection_items.get(self.A, self.ids(1)["item"]),
                "observation": fresh.oia_observations.get(self.A, self.ids(1)["observation"]),
                "root": fresh.oia_root_causes.get(self.A, self.ids(1)["root"]),
                "finding": fresh.oia_findings.get(self.A, self.ids(1)["finding"]),
            }
            self.assertEqual(actual, {name: expected[name] for name in actual})
            grant = fresh.assessment_access_grants.get(self.A, self.ids(1)["grant"])
            self.assertEqual((grant["status"], grant["record_version"]), ("ACTIVE", 2))
        finally:
            fresh.rollback()
            fresh.close()

        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        checker = FormatChecker()
        schemas = {
            "assessment": "oia-assessment", "plan": "oia-assessment-plan",
            "evidence": "oia-evidence-item", "inspection": "oia-inspection-item",
            "observation": "oia-observation", "root": "oia-root-cause",
            "finding": "oia-finding",
        }
        for name, slug in schemas.items():
            validator = Draft202012Validator(
                registry.expanded(f"urn:avuhz:schema:contracts:domain:{slug}:v1"),
                format_checker=checker,
            )
            self.assertEqual(list(validator.iter_errors(actual[name])), [], name)

    def test_rls_tenant_isolation_for_read_history_and_transition(self):
        self.create_graph()
        missing = PostgresUnitOfWork(PostgresStore(self.service_factory))
        try:
            self.assertIsNone(missing.oia_assessments.get(self.A, self.ids(1)["assessment"]))
        finally:
            missing.rollback()
            missing.close()

        other = self.uow(self.B)
        try:
            self.assertIsNone(other.oia_assessments.get(self.A, self.ids(1)["assessment"]))
            self.assertEqual(other.oia_findings.list_by_assessment(self.A, self.ids(1)["assessment"]), ())
            self.assertEqual(other.oia_findings_deliveries.list_by_assessment(self.A, self.ids(1)["assessment"]), ())
            with self.assertRaises(ValueError):
                other.oia_assessments.mark_ready(self.assessment(1), NOW)
        finally:
            other.rollback()
            other.close()

        owner = self.uow(self.A)
        try:
            self.assertIsNotNone(owner.oia_assessments.get(self.A, self.ids(1)["assessment"]))
            self.assertEqual(len(owner.oia_findings.list_by_assessment(self.A, self.ids(1)["assessment"])), 1)
        finally:
            owner.rollback()
            owner.close()

    def test_optimistic_concurrency_rejects_stale_assessment_and_finding(self):
        self.create_graph()
        first = self.uow(self.A)
        stale = self.uow(self.A)
        try:
            current = first.oia_findings.get(self.A, self.ids(1)["finding"])
            stale_current = stale.oia_findings.get(self.A, self.ids(1)["finding"])
            final = copy.deepcopy(current)
            final.update(state="FINAL", finalized_by="fictional-reviewer", finalized_at=NOW,
                         content_digest="sha256:" + "d" * 64, updated_at=NOW)
            first.oia_findings.finalize(current, final)
            first.commit()
            with self.assertRaises(ValueError):
                stale.oia_findings.finalize(stale_current, final)
            stale.rollback()
        finally:
            first.close()
            stale.close()

        first = self.uow(self.A)
        stale = self.uow(self.A)
        try:
            assessment = first.oia_assessments.get(self.A, self.ids(1)["assessment"])
            stale_assessment = stale.oia_assessments.get(self.A, self.ids(1)["assessment"])
            first.oia_assessments.mark_ready(assessment, NOW)
            first.commit()
            with self.assertRaises(ValueError):
                stale.oia_assessments.mark_ready(stale_assessment, NOW)
            stale.rollback()
        finally:
            first.close()
            stale.close()

    def open_raw(self, key="phase5b-postgres-open-0001", assessment_id=None):
        value = self.ids(1)
        assessment_id = assessment_id or value["assessment"]
        return {
            "command_id": uid(1, 40), "command_type": "OpenOIAAssessment",
            "command_schema_version": 1, "tenant_id": self.A,
            "engagement_id": value["engagement"], "subject_type": "OIA_ASSESSMENT",
            "subject_id": assessment_id, "requested_by": "phase5b-service",
            "caller_type": "INTERNAL_SERVICE",
            "caller_identity": {
                "subject": "phase5b-service", "audience": "avuhz-command-api",
                "caller_type": "INTERNAL_SERVICE", "tenant_ids": [self.A],
                "capabilities": ["oia:open"], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": uid(1, 41), "idempotency_key": key,
            "requested_at": NOW, "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:open-oia-assessment-payload:v1",
            "payload_version": 1,
            "payload": {
                "oia_assessment_id": assessment_id, "engagement_id": value["engagement"],
                "diagnostic_scope_id": value["scope"], "diagnostic_scope_version": 1,
                "canonical_scope_digest": DIGEST,
                "assessment_access_grant_id": value["grant"],
            },
        }

    def executor(self, store=None):
        sequence = itertools.count(50)
        return Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(),
            store or PostgresStore(self.service_factory), clock=lambda: NOW,
            ids=lambda: uid(1, next(sequence)), uow_factory=PostgresUnitOfWork,
        )

    def test_idempotency_restart_event_outbox_and_open_atomicity(self):
        raw = self.open_raw()
        self.assertEqual(self.executor().execute(raw, trusted(self.A))["result"], "ACCEPTED")
        self.assertEqual(self.executor().execute(copy.deepcopy(raw), trusted(self.A))["result"], "DUPLICATE")
        changed = self.open_raw(assessment_id=uid(1, 42))
        self.assertEqual(self.executor().execute(changed, trusted(self.A))["result"], "CONFLICT")

        fresh = self.uow(self.A)
        try:
            self.assertIsNotNone(fresh.oia_assessments.get(self.A, self.ids(1)["assessment"]))
        finally:
            fresh.rollback()
            fresh.close()
        with self.owner() as connection:
            counts = tuple(connection.execute(
                f"select count(*) from public.{table}"
            ).fetchone()["count"] for table in (
                "avuhz_oia_assessments", "avuhz_idempotency_records",
                "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
            ))
        self.assertEqual(counts, (1, 1, 1, 1))

        for stage in ("AUTHORITATIVE_WRITE", "LIFECYCLE_EVENT_APPEND",
                      "OUTBOX_APPEND", "IDEMPOTENCY_COMPLETE", "COMMIT"):
            with self.subTest(stage=stage):
                self.setUp()
                store = PostgresStore(self.service_factory)
                store.fail_stage = stage
                result = self.executor(store).execute(self.open_raw(), trusted(self.A))
                self.assertEqual(result["result"], "REJECTED")
                with self.owner() as connection:
                    counts = tuple(connection.execute(
                        f"select count(*) from public.{table}"
                    ).fetchone()["count"] for table in (
                        "avuhz_oia_assessments", "avuhz_idempotency_records",
                        "avuhz_lifecycle_events", "avuhz_outbox_deliveries",
                    ))
                self.assertEqual(counts, (0, 0, 0, 0))

    def prepare_delivery_state(self):
        self.create_graph()
        value = self.ids(1)
        uow = self.uow(self.A)
        try:
            current = uow.oia_findings.get(self.A, value["finding"])
            final = self.finding(1, state="FINAL")
            uow.oia_findings.finalize(current, final)
            assessment = uow.oia_assessments.get(self.A, value["assessment"])
            uow.oia_assessments.mark_ready(assessment, NOW)
            uow.commit()
        finally:
            uow.close()
        return final

    def delivery_transaction(self, *, fail_stage=None):
        value = self.ids(1)
        final = self.prepare_delivery_state()
        store = PostgresStore(self.service_factory)
        store.fail_stage = fail_stage
        uow = self.uow(self.A, store)
        key = (self.A, "phase5b-service", "DeliverOIAFindings",
               "OIA_FINDINGS_DELIVERY", "COMMAND", "phase5b-delivery-atomic-0001")
        prepared = SimpleNamespace(subject_id=value["delivery"], expected_record_version=2)
        event = self.event(value, uid(1, 70), "oia.findings_delivered",
                           "OIA_FINDINGS_DELIVERY", value["delivery"], 1, key[-1])
        try:
            uow.idempotency.reserve(key, "fpv1:" + "x" * 32, prepared)
            delivery = self.delivery(1, finding=final)
            uow.oia_findings_deliveries.create(delivery)
            assessment = uow.oia_assessments.get(self.A, value["assessment"])
            uow.oia_assessments.mark_delivered(assessment, delivery, NOW)
            uow.assessment_access_grants.close_for_lifecycle(
                self.A, value["grant"], NOW, "FINDINGS_DELIVERED"
            )
            uow.lifecycle_events.append(event)
            uow.outbox.append({"event_id": event["event_id"], "status": "PENDING"})
            uow.idempotency.save_result(key, {"command_id": uid(1, 71)})
            uow.commit()
            return delivery
        except (ValueError, RuntimeError):
            uow.rollback()
            return None
        finally:
            uow.close()

    def test_delivery_access_closure_and_atomic_rollback(self):
        delivery = self.delivery_transaction()
        self.assertIsNotNone(delivery)
        value = self.ids(1)
        fresh = self.uow(self.A)
        try:
            self.assertEqual(fresh.oia_assessments.get(self.A, value["assessment"])["state"], "FINDINGS_DELIVERED")
            grant = fresh.assessment_access_grants.get(self.A, value["grant"])
            self.assertEqual((grant["status"], grant["closure_reason"]), ("CLOSED", "FINDINGS_DELIVERED"))
            self.assertEqual(fresh.oia_findings_deliveries.get(self.A, value["delivery"]), delivery)
        finally:
            fresh.rollback()
            fresh.close()
        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in ("avuhz_idempotency_records", "avuhz_lifecycle_events",
                                         "avuhz_outbox_deliveries"))
        self.assertEqual(counts, (1, 1, 1))

        self.setUp()
        self.assertIsNone(self.delivery_transaction(fail_stage="OUTBOX_APPEND"))
        fresh = self.uow(self.A)
        try:
            self.assertIsNone(fresh.oia_findings_deliveries.get(self.A, value["delivery"]))
            self.assertEqual(fresh.oia_assessments.get(self.A, value["assessment"])["state"], "READY_FOR_DELIVERY")
            self.assertEqual(fresh.assessment_access_grants.get(self.A, value["grant"])["status"], "ACTIVE")
        finally:
            fresh.rollback()
            fresh.close()
        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in ("avuhz_idempotency_records", "avuhz_lifecycle_events",
                                         "avuhz_outbox_deliveries"))
        self.assertEqual(counts, (0, 0, 0))

    def test_history_immutability_correction_redelivery_and_close(self):
        first_delivery = self.delivery_transaction()
        value = self.ids(1)
        uow = self.uow(self.A)
        try:
            original_observation = uow.oia_observations.get(self.A, value["observation"])
            replacement_observation = uow.oia_observations.get(self.A, value["replacement_observation"])
            uow.oia_observations.supersede(original_observation, replacement_observation, LATER)

            original_finding = uow.oia_findings.get(self.A, value["finding"])
            replacement = self.finding(
                1, finding_id=value["replacement_finding"], revision=1, state="DRAFT"
            )
            replacement["supersedes_finding_revision"] = {
                "oia_finding_id": value["finding"], "finding_revision": 1,
            }
            replacement["created_at"] = LATER
            replacement["updated_at"] = LATER
            uow.oia_findings.open_delivered_correction(original_finding, replacement, LATER)
            assessment = uow.oia_assessments.get(self.A, value["assessment"])
            uow.oia_assessments.reopen_for_correction(assessment, LATER)
            uow.commit()
        finally:
            uow.close()

        uow = self.uow(self.A)
        try:
            replacement = uow.oia_findings.get(self.A, value["replacement_finding"])
            final_replacement = copy.deepcopy(replacement)
            final_replacement.update(
                state="FINAL", finalized_by="fictional-reviewer", finalized_at=LATER,
                content_digest="sha256:" + "9" * 64, updated_at=LATER,
            )
            uow.oia_findings.finalize(replacement, final_replacement)
            second = self.delivery(
                1, delivery_id=value["second_delivery"], sequence=2,
                finding=final_replacement,
            )
            second["delivered_at"] = LATER
            uow.oia_findings_deliveries.create(second)
            assessment = uow.oia_assessments.get(self.A, value["assessment"])
            delivered = uow.oia_assessments.mark_delivered(assessment, second, LATER)
            uow.oia_assessments.close(delivered, LATER)
            uow.commit()
        finally:
            uow.close()

        fresh = self.uow(self.A)
        try:
            observations = fresh.oia_observations.list_by_assessment(self.A, value["assessment"])
            findings = fresh.oia_findings.list_by_assessment(self.A, value["assessment"])
            deliveries = fresh.oia_findings_deliveries.list_by_assessment(self.A, value["assessment"])
            self.assertEqual(len(observations), 2)
            self.assertEqual(fresh.oia_observations.get(self.A, value["observation"])["state"], "SUPERSEDED")
            self.assertEqual([(row["oia_finding_id"], row["state"]) for row in findings],
                             [(value["finding"], "SUPERSEDED"),
                              (value["replacement_finding"], "FINAL")])
            self.assertEqual(len(deliveries), 2)
            self.assertEqual(deliveries[0], first_delivery)
            self.assertEqual(deliveries[0]["finding_revisions"][0]["oia_finding_id"], value["finding"])
            self.assertEqual(deliveries[1]["finding_revisions"][0]["oia_finding_id"], value["replacement_finding"])
            self.assertEqual(fresh.oia_assessments.get(self.A, value["assessment"])["state"], "CLOSED")
            self.assertEqual(fresh.oia_evidence_items.get(self.A, value["evidence"]), self.evidence(1))
        finally:
            fresh.rollback()
            fresh.close()

        direct = self.service_factory()
        try:
            direct.execute("select set_config('avuhz.tenant_id',%s,true)", (self.A,))
            with self.assertRaises(InsufficientPrivilege):
                direct.execute(
                    "update public.avuhz_oia_findings_deliveries set delivered_at=%s "
                    "where tenant_id=%s and oia_findings_delivery_id=%s",
                    (LATER, self.A, value["delivery"]),
                )
        finally:
            direct.rollback()
            direct.close()


if __name__ == "__main__":
    unittest.main()
