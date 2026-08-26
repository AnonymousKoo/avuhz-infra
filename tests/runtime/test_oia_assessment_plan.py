import copy
import itertools
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.oia_assessment_plan import TrustedMethodologyCatalog
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


class OIAAssessmentPlanRuntimeTests(unittest.TestCase):
    tenant = "c1000000-0000-4000-8000-000000000001"
    other_tenant = "c1000000-0000-4000-8000-000000000099"
    plan_id = "c1000000-0000-4000-8000-000000000002"
    other_plan_id = "c1000000-0000-4000-8000-000000000092"
    engagement_id = "c1000000-0000-4000-8000-000000000003"
    assessment_id = "c1000000-0000-4000-8000-000000000004"
    other_assessment_id = "c1000000-0000-4000-8000-000000000094"
    scope_id = "c1000000-0000-4000-8000-000000000005"
    grant_id = "c1000000-0000-4000-8000-000000000006"
    now = "2030-01-15T15:00:00Z"
    scope_digest = "sha256:" + "a" * 64
    methodology = {"methodology_id": "oia-methodology", "version": "1.0.0", "content_digest": "sha256:" + "b" * 64}
    template = {"template_id": "roofing-home-services", "version": "1.0.0", "content_digest": "sha256:" + "c" * 64}

    def setUp(self):
        self.store = MemoryStore()
        self.store.engagements[self.engagement_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "engagement_state": "OPEN", "record_version": 1,
        }
        self.store.scopes[self.scope_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_scope_id": self.scope_id, "scope_version": 2,
            "canonical_scope_digest": self.scope_digest, "record_version": 3,
            "status": "APPROVED", "action_set_version": 1,
        }
        self.store.grants[(self.tenant, self.grant_id)] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "assessment_access_grant_id": self.grant_id, "record_version": 3,
            "status": "EXPIRED", "expires_at": "2030-01-01T00:00:00Z",
        }
        self.store.oia_assessments[(self.tenant, self.assessment_id)] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "oia_assessment_id": self.assessment_id,
            "diagnostic_scope_id": self.scope_id, "diagnostic_scope_version": 2,
            "canonical_scope_digest": self.scope_digest,
            "assessment_access_grant_id": self.grant_id,
            "state": "IN_PROGRESS", "record_version": 1,
            "opened_at": self.now, "created_at": self.now, "updated_at": self.now,
        }
        catalog = TrustedMethodologyCatalog([self.methodology], [self.template])
        sequence = itertools.count(200)
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now,
            ids=lambda: f"c1000000-0000-4000-8000-{next(sequence):012d}",
            methodology_catalog=catalog,
        )

    def context(self, capability="oia:plan:write", caller_type="INTERNAL_SERVICE", tenant=None):
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, "human.assessor-001" if human else "workload.plan-proposer", caller_type,
            tenant or self.tenant, None, frozenset({capability}), frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.assessor-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    def payload(self, template=False):
        value = {
            "oia_assessment_plan_id": self.plan_id,
            "engagement_id": self.engagement_id,
            "oia_assessment_id": self.assessment_id,
            "diagnostic_scope_id": self.scope_id,
            "diagnostic_scope_version": 2,
            "canonical_scope_digest": self.scope_digest,
            "methodology_reference": copy.deepcopy(self.methodology),
            "objectives": [{
                "objective_id": "lead-response",
                "operational_question": "How reliably are qualified inbound leads assigned and contacted?",
                "intended_outcome": "Qualified leads receive attributable follow-up within the intended service window.",
                "success_signal": "Assignment and response timestamps are consistently observable.",
            }],
            "process_areas": [{
                "process_area_id": "lead-intake", "name": "Lead intake and follow-up",
                "diagnostic_purpose": "Trace ownership, timing, handoffs, and exceptions from intake through estimate.",
            }],
            "completion_criteria": {
                "material_areas_addressed": True, "required_items_resolved": True,
                "critical_blocks_documented": True, "sufficiency_evaluated": True,
                "contradictions_addressed": True, "material_gaps_handled": True,
                "limitations_documented": True, "human_review_required": True,
            },
            "limitations": [],
        }
        if template:
            value["vertical_template_reference"] = copy.deepcopy(self.template)
        return value

    def raw(self, command="CreateOIAAssessmentPlan", payload=None, key=None, command_id=None,
            expected=None, tenant=None, engagement=None, caller_type="INTERNAL_SERVICE", capability=None,
            subject_id=None):
        capability = capability or {
            "CreateOIAAssessmentPlan": "oia:plan:write",
            "ReviseOIAAssessmentPlan": "oia:plan:write",
            "ReviewOIAAssessmentPlan": "oia:plan:review",
            "ApproveOIAAssessmentPlan": "oia:plan:approve",
        }[command]
        suffix = {
            "CreateOIAAssessmentPlan": "create-oia-assessment-plan",
            "ReviseOIAAssessmentPlan": "revise-oia-assessment-plan",
            "ReviewOIAAssessmentPlan": "review-oia-assessment-plan",
            "ApproveOIAAssessmentPlan": "approve-oia-assessment-plan",
        }[command]
        tenant = tenant or self.tenant
        raw = {
            "command_id": command_id or "c1000000-0000-4000-8000-000000000101",
            "command_type": command, "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.engagement_id,
            "subject_type": "OIA_ASSESSMENT_PLAN", "subject_id": subject_id or self.plan_id,
            "requested_by": "human.assessor-001" if caller_type == "HUMAN" else "workload.plan-proposer",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "human.assessor-001" if caller_type == "HUMAN" else "workload.plan-proposer",
                "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": [capability], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "c1000000-0000-4000-8000-000000000102",
            "idempotency_key": key or f"phase5b-plan-{command.lower()}-0001",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{suffix}-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload if payload is not None else self.payload()),
        }
        if expected is not None:
            raw["expected_record_version"] = expected
        return raw

    def create(self, template=False, key="phase5b-create-plan-0001"):
        raw = self.raw(payload=self.payload(template), key=key)
        result = self.executor.execute(raw, self.context())
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def review(self, expected=1, key="phase5b-review-plan-0001"):
        raw = self.raw("ReviewOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 1}, key=key,
                       command_id="c1000000-0000-4000-8000-000000000103", expected=expected,
                       caller_type="HUMAN", capability="oia:plan:review")
        return raw, self.executor.execute(raw, self.context("oia:plan:review", "HUMAN"))

    def approve(self, plan_version=1, expected=2, key="phase5b-approve-plan-0001"):
        raw = self.raw("ApproveOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": plan_version}, key=key,
                       command_id="c1000000-0000-4000-8000-000000000104", expected=expected,
                       caller_type="HUMAN", capability="oia:plan:approve")
        return raw, self.executor.execute(raw, self.context("oia:plan:approve", "HUMAN"))

    def revision_raw(self, current=1, replacement=2, expected=1, key="phase5b-revise-plan-0001"):
        payload = self.payload(template=True)
        for field in ("engagement_id", "oia_assessment_id", "diagnostic_scope_id", "diagnostic_scope_version", "canonical_scope_digest"):
            payload.pop(field)
        payload.update(current_plan_version=current, replacement_plan_version=replacement)
        payload["objectives"][0]["success_signal"] = "Response ownership and timestamps are reproducibly observable."
        return self.raw("ReviseOIAAssessmentPlan", payload, key=key,
                        command_id="c1000000-0000-4000-8000-000000000105", expected=expected)

    def current(self):
        return UnitOfWork(self.store).oia_assessment_plans.get_current(self.tenant, self.plan_id)

    def assert_no_plan_effects(self):
        self.assertEqual(self.store.oia_assessment_plans, {})
        self.assertEqual(self.store.events, [])
        self.assertEqual(self.store.outbox, [])

    def test_create_universal_plan_is_contract_valid_and_access_independent(self):
        raw = self.create()
        plan = self.current()
        self.assertEqual((plan["state"], plan["plan_version"], plan["record_version"]), ("DRAFT", 1, 1))
        self.assertNotIn("vertical_template_reference", plan)
        self.assertEqual(plan["canonical_scope_digest"], self.scope_digest)
        self.assertEqual(self.store.grants[(self.tenant, self.grant_id)]["status"], "EXPIRED")
        for forbidden in ("access_authorized", "grant_active", "payment_verified", "agreement_valid", "target_authorized", "action_authorized"):
            self.assertNotIn(forbidden, plan)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        fmt = FormatChecker()
        self.assertEqual(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-assessment-plan:v1"), format_checker=fmt).iter_errors(plan)), [])
        event = self.store.events[0]
        self.assertEqual(event["event_type"], "oia.assessment_plan_created")
        self.assertEqual(event["sanitized_metadata"], {"oia_assessment_id": self.assessment_id, "oia_assessment_plan_id": self.plan_id, "plan_version": 1})
        self.assertEqual(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=fmt).iter_errors(event)), [])
        self.assertEqual(self.store.outbox, [{"event_id": event["event_id"], "status": "PENDING"}])
        self.assertEqual(CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw).prepared.subject_id, self.plan_id)

    def test_trusted_vertical_template_and_exact_reference_failures(self):
        self.create(template=True)
        self.assertEqual(self.current()["vertical_template_reference"], self.template)
        cases = (
            ("unknown-methodology", lambda p: p["methodology_reference"].update(version="9.9.9")),
            ("methodology-digest", lambda p: p["methodology_reference"].update(content_digest="sha256:" + "d" * 64)),
            ("unknown-template", lambda p: p.update(vertical_template_reference={**self.template, "template_id": "unknown-template"})),
            ("template-digest", lambda p: p.update(vertical_template_reference={**self.template, "content_digest": "sha256:" + "d" * 64})),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp(); payload = self.payload(template=name.startswith("unknown-template") or name.startswith("template")); mutate(payload)
                self.assertEqual(self.executor.execute(self.raw(payload=payload), self.context())["result"], "REJECTED")
                self.assert_no_plan_effects()

    def test_foundation_correlation_and_closed_assessment_fail_closed(self):
        cases = (
            ("wrong-assessment", lambda p: p.update(oia_assessment_id=self.other_assessment_id)),
            ("wrong-engagement", lambda p: p.update(engagement_id="c1000000-0000-4000-8000-000000000093")),
            ("scope-version", lambda p: p.update(diagnostic_scope_version=1)),
            ("scope-digest", lambda p: p.update(canonical_scope_digest="sha256:" + "d" * 64)),
            ("closed", lambda p: self.store.oia_assessments[(self.tenant, self.assessment_id)].update(state="CLOSED")),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp(); payload = self.payload(); mutate(payload)
                engagement = payload["engagement_id"]
                self.assertEqual(self.executor.execute(self.raw(payload=payload, engagement=engagement), self.context())["result"], "REJECTED")
                self.assert_no_plan_effects()
        raw = self.raw(tenant=self.other_tenant)
        self.assertEqual(self.executor.execute(raw, self.context(tenant=self.tenant))["result"], "REJECTED")
        self.assert_no_plan_effects()

    def test_caller_authority_claims_are_schema_rejected(self):
        for field in ("access_authorized", "grant_active", "payment_verified", "agreement_valid", "target_authorized", "action_authorized"):
            with self.subTest(field=field):
                raw = self.raw(); raw["payload"][field] = True
                result = self.executor.execute(raw, self.context())
                self.assertEqual((result["result"], result["reason_code"]), ("VALIDATION_FAILED", "FIELD_FORBIDDEN"))
                self.assert_no_plan_effects()

    def test_one_lineage_and_revision_preserve_history(self):
        self.create(template=True)
        duplicate = self.raw(payload={**self.payload(), "oia_assessment_plan_id": self.other_plan_id}, subject_id=self.other_plan_id,
                             key="phase5b-create-plan-second-lineage")
        self.assertEqual(self.executor.execute(duplicate, self.context())["result"], "REJECTED")
        revision = self.revision_raw()
        self.assertEqual(self.executor.execute(revision, self.context())["result"], "ACCEPTED")
        uow = UnitOfWork(self.store)
        old = uow.oia_assessment_plans.get_version(self.tenant, self.plan_id, 1)
        current = uow.oia_assessment_plans.get_current(self.tenant, self.plan_id)
        self.assertEqual((old["state"], old["record_version"]), ("SUPERSEDED", 2))
        self.assertEqual((current["state"], current["plan_version"], current["supersedes_plan_version"], current["record_version"]), ("DRAFT", 2, 1, 1))
        self.assertEqual(len(uow.oia_assessment_plans.list_versions(self.tenant, self.plan_id)), 2)
        returned = uow.oia_assessment_plans.get_version(self.tenant, self.plan_id, 1); returned["state"] = "DRAFT"
        self.assertEqual(uow.oia_assessment_plans.get_version(self.tenant, self.plan_id, 1)["state"], "SUPERSEDED")
        self.assertEqual(self.store.events[-1]["event_type"], "oia.assessment_plan_revised")

    def test_stale_revision_and_closed_assessment_revision_reject(self):
        self.create()
        self.assertEqual(self.executor.execute(self.revision_raw(expected=99), self.context())["reason_code"], "VERSION_STALE")
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assertEqual(self.executor.execute(self.revision_raw(key="phase5b-revise-closed"), self.context())["result"], "REJECTED")
        self.assertEqual(len(UnitOfWork(self.store).oia_assessment_plans.list_versions(self.tenant, self.plan_id)), 1)

    def test_human_review_and_approval_lifecycle(self):
        self.create()
        review_raw, reviewed = self.review()
        self.assertEqual(reviewed["result"], "ACCEPTED")
        self.assertEqual((self.current()["state"], self.current()["record_version"], self.current()["reviewed_by"]), ("REVIEWED", 2, "human.assessor-001"))
        approve_raw, approved = self.approve()
        self.assertEqual(approved["result"], "ACCEPTED")
        plan = self.current()
        self.assertEqual((plan["state"], plan["record_version"], plan["approved_by"]), ("APPROVED", 3, "human.assessor-001"))
        self.assertEqual([event["event_type"] for event in self.store.events], ["oia.assessment_plan_created", "oia.assessment_plan_reviewed", "oia.assessment_plan_approved"])
        self.assertEqual(len(self.store.outbox), 3)
        for raw in (review_raw, approve_raw):
            prepared = CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw)
            self.assertTrue(hasattr(prepared, "prepared"))

    def test_workload_cannot_review_or_approve_and_review_is_required(self):
        self.create()
        review = self.raw("ReviewOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 1}, expected=1, capability="oia:plan:review")
        self.assertEqual(self.executor.execute(review, self.context("oia:plan:review"))["result"], "VALIDATION_FAILED")
        direct = self.raw("ApproveOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 1}, expected=1, caller_type="HUMAN", capability="oia:plan:approve")
        self.assertEqual(self.executor.execute(direct, self.context("oia:plan:approve", "HUMAN"))["result"], "REJECTED")
        _, result = self.review(); self.assertEqual(result["result"], "ACCEPTED")
        workload_approve = self.raw("ApproveOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 1}, expected=2, key="phase5b-workload-approve", capability="oia:plan:approve")
        self.assertEqual(self.executor.execute(workload_approve, self.context("oia:plan:approve"))["result"], "VALIDATION_FAILED")
        self.assertEqual(self.current()["state"], "REVIEWED")

    def test_approved_version_is_immutable_and_revision_is_new_version(self):
        self.create(); self.assertEqual(self.review()[1]["result"], "ACCEPTED"); self.assertEqual(self.approve()[1]["result"], "ACCEPTED")
        approved = copy.deepcopy(UnitOfWork(self.store).oia_assessment_plans.get_version(self.tenant, self.plan_id, 1))
        revision = self.revision_raw(expected=3, key="phase5b-revise-approved")
        self.assertEqual(self.executor.execute(revision, self.context())["result"], "ACCEPTED")
        historical = UnitOfWork(self.store).oia_assessment_plans.get_version(self.tenant, self.plan_id, 1)
        self.assertEqual({k: v for k, v in historical.items() if k not in ("state", "record_version", "updated_at")}, {k: v for k, v in approved.items() if k not in ("state", "record_version", "updated_at")})
        self.assertEqual(historical["state"], "SUPERSEDED")
        self.assertEqual(self.current()["plan_version"], 2)

    def test_idempotent_replays_and_create_semantic_conflict(self):
        create_raw = self.create()
        before = (copy.deepcopy(self.store.oia_assessment_plans), len(self.store.events), len(self.store.outbox))
        self.assertEqual(self.executor.execute(create_raw, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(create_raw); changed["payload"]["methodology_reference"]["version"] = "2.0.0"
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((self.store.oia_assessment_plans, len(self.store.events), len(self.store.outbox)), before)
        revision = self.revision_raw(); self.assertEqual(self.executor.execute(revision, self.context())["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(revision, self.context())["result"], "DUPLICATE")
        review = self.raw("ReviewOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 2}, expected=1, key="phase5b-review-v2", caller_type="HUMAN", capability="oia:plan:review")
        human_review = self.context("oia:plan:review", "HUMAN")
        self.assertEqual(self.executor.execute(review, human_review)["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(review, human_review)["result"], "DUPLICATE")
        approve = self.raw("ApproveOIAAssessmentPlan", {"oia_assessment_plan_id": self.plan_id, "plan_version": 2}, expected=2, key="phase5b-approve-v2", caller_type="HUMAN", capability="oia:plan:approve")
        human_approve = self.context("oia:plan:approve", "HUMAN")
        self.assertEqual(self.executor.execute(approve, human_approve)["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(approve, human_approve)["result"], "DUPLICATE")
        self.assertEqual((len(self.store.events), len(self.store.outbox)), (4, 4))

    def test_failpoints_roll_back_create_and_revision(self):
        for stage in ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT"):
            with self.subTest(operation="create", stage=stage):
                self.setUp(); self.store.fail_stage = stage
                before = copy.deepcopy(self.store)
                self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before.__dict__)
            with self.subTest(operation="revise", stage=stage):
                self.setUp(); self.create(); self.store.fail_stage = stage
                before = copy.deepcopy(self.store)
                self.assertEqual(self.executor.execute(self.revision_raw(), self.context())["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before.__dict__)


if __name__ == "__main__":
    unittest.main()
