import copy
import itertools
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


class OIAInspectionItemRuntimeTests(unittest.TestCase):
    tenant = "d1000000-0000-4000-8000-000000000001"
    other_tenant = "d1000000-0000-4000-8000-000000000099"
    engagement_id = "d1000000-0000-4000-8000-000000000003"
    assessment_id = "d1000000-0000-4000-8000-000000000004"
    other_assessment_id = "d1000000-0000-4000-8000-000000000094"
    plan_id = "d1000000-0000-4000-8000-000000000002"
    item_id = "d1000000-0000-4000-8000-000000000006"
    other_item_id = "d1000000-0000-4000-8000-000000000096"
    evidence_id = "d1000000-0000-4000-8000-000000000007"
    other_evidence_id = "d1000000-0000-4000-8000-000000000097"
    scope_id = "d1000000-0000-4000-8000-000000000005"
    agreement_id = "d1000000-0000-4000-8000-000000000011"
    payment_id = "d1000000-0000-4000-8000-000000000012"
    grant_id = "d1000000-0000-4000-8000-000000000013"
    now = "2030-01-15T15:00:00Z"
    digest = "sha256:" + "a" * 64
    methodology = {"methodology_id": "oia-methodology", "version": "1.0.0", "content_digest": "sha256:" + "b" * 64}

    def setUp(self):
        self.store = MemoryStore()
        self.store.engagements[self.engagement_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "engagement_state": "OPEN", "record_version": 1,
        }
        self.store.scopes[self.scope_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_scope_id": self.scope_id, "scope_version": 2,
            "canonical_scope_digest": self.digest, "record_version": 3,
            "status": "APPROVED", "action_set_version": 1,
            "in_scope_systems": [{"system_reference_id": "system-001"}],
            "permitted_diagnostic_actions": ["VIEW_CONFIGURATION"],
        }
        self.store.agreements[self.agreement_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_agreement_authority_id": self.agreement_id,
            "record_version": 1, "status": "VERIFIED_ACTIVE",
            "scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": self.scope_id, "reference_version": 2},
            "canonical_scope_digest": self.digest,
            "effective_at": "2030-01-01T00:00:00Z", "ends_at": "2030-02-01T00:00:00Z",
        }
        self.store.payments[self.payment_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_payment_verification_id": self.payment_id,
            "record_version": 1, "payment_purpose": "DIAGNOSTIC_OIA",
            "verification_status": "VERIFIED",
            "diagnostic_agreement_authority_reference": {
                "reference_type": "DIAGNOSTIC_AGREEMENT_AUTHORITY", "reference_id": self.agreement_id, "reference_version": 1,
            },
        }
        self.store.grants[(self.tenant, self.grant_id)] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "assessment_access_grant_id": self.grant_id, "record_version": 2,
            "status": "ACTIVE", "active_from": "2030-01-15T14:00:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
            "diagnostic_scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": self.scope_id, "reference_version": 2},
            "canonical_scope_digest": self.digest, "action_set_version": 1,
            "diagnostic_agreement_authority_reference": {"reference_type": "DIAGNOSTIC_AGREEMENT_AUTHORITY", "reference_id": self.agreement_id, "reference_version": 1},
            "diagnostic_payment_verification_reference": {"reference_type": "DIAGNOSTIC_PAYMENT_VERIFICATION", "reference_id": self.payment_id, "reference_version": 1},
            "target_system_references": [{"system_reference_id": "system-001"}],
            "permitted_actions": ["VIEW_CONFIGURATION"],
        }
        self.store.oia_assessments[(self.tenant, self.assessment_id)] = {
            "tenant_id": self.tenant, "oia_assessment_id": self.assessment_id,
            "engagement_id": self.engagement_id, "diagnostic_scope_id": self.scope_id,
            "diagnostic_scope_version": 2, "canonical_scope_digest": self.digest,
            "assessment_access_grant_id": self.grant_id, "state": "IN_PROGRESS",
            "record_version": 1, "opened_at": self.now, "created_at": self.now, "updated_at": self.now,
        }
        self.store.oia_assessment_plans[(self.tenant, self.plan_id, 1)] = self.plan()
        sequence = itertools.count(300)
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now,
            ids=lambda: f"d1000000-0000-4000-8000-{next(sequence):012d}",
        )

    def plan(self, state="APPROVED", version=1):
        result = {
            "tenant_id": self.tenant, "oia_assessment_plan_id": self.plan_id,
            "engagement_id": self.engagement_id, "oia_assessment_id": self.assessment_id,
            "diagnostic_scope_id": self.scope_id, "diagnostic_scope_version": 2,
            "canonical_scope_digest": self.digest, "methodology_reference": copy.deepcopy(self.methodology),
            "plan_version": version, "state": state,
            "objectives": [{"objective_id": "lead-response", "operational_question": "How reliably are qualified leads assigned and contacted?", "intended_outcome": "Qualified leads receive attributable follow-up."}],
            "process_areas": [{"process_area_id": "lead-intake", "name": "Lead intake", "diagnostic_purpose": "Trace assignment, response timing, and exception handling."}],
            "completion_criteria": {
                "material_areas_addressed": True, "required_items_resolved": True,
                "critical_blocks_documented": True, "sufficiency_evaluated": True,
                "contradictions_addressed": True, "material_gaps_handled": True,
                "limitations_documented": True, "human_review_required": True,
            },
            "limitations": [], "record_version": 3,
            "created_by": "workload.plan-proposer", "reviewed_by": "human.reviewer-001", "approved_by": "human.approver-001",
            "created_at": self.now, "reviewed_at": self.now, "approved_at": self.now, "updated_at": self.now,
        }
        if version > 1:
            result["supersedes_plan_version"] = version - 1
        return result

    def context(self, caller_type="INTERNAL_SERVICE", tenant=None):
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, "human.assessor-001" if human else "workload.inspection-manager", caller_type,
            tenant or self.tenant, None, frozenset({"oia:inspection:manage"}), frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.assessor-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    def create_payload(self, item_id=None, system=True, target="system-001", action="VIEW_CONFIGURATION"):
        planned = {"target_system_reference": {"system_reference_id": target}, "diagnostic_action": action}
        expectation = {
            "expectation_id": "configuration-state", "why_sought": "Establish whether the intended configuration and operational state are present.",
            "evidence_type": "CONFIGURATION_SNAPSHOT", "minimum_characteristics": ["attributable configuration state"],
            "minimum_support_level": "SYSTEM_SUPPORTED", "required": True,
        }
        value = {
            "oia_inspection_item_id": item_id or self.item_id,
            "engagement_id": self.engagement_id, "oia_assessment_id": self.assessment_id,
            "oia_assessment_plan_id": self.plan_id, "plan_version": 1,
            "objective_id": "lead-response", "process_area_id": "lead-intake",
            "what_to_inspect": "Inspect the configured assignment and response workflow state.",
            "why_it_matters": "Missing assignment controls can create delayed and unowned client work.",
            "inspection_lenses": ["PROCESS", "SYSTEMS_AND_CONFIGURATION"],
            "expected_evidence": [expectation],
            "sampling_strategy": {
                "population_context": "Authorized fictional workflow configurations.",
                "selection_method": "TARGETED",
                "selection_rationale": "Inspect the configuration governing the material assignment path.",
                "target_sample_rationale": "One authoritative configuration is the bounded population for this objective.",
            },
            "required": True,
            "materiality": {"dimensions": ["TIME", "ACCOUNTABILITY"], "investigation_depth": "STANDARD", "rationale": "Assignment timing and ownership are material to reliable operations."},
            "limitations": [], "assessor_notes": "Planning intent only; access remains independently evaluated.",
        }
        if system:
            value["planned_target_action"] = copy.deepcopy(planned)
            value["expected_evidence"][0]["planned_target_action"] = copy.deepcopy(planned)
        return value

    @staticmethod
    def sufficiency(state="NOT_EVALUATED", contradiction="NONE", missing=True):
        values = {
            "NOT_EVALUATED": (False, False, "UNKNOWN", "NOT_ASSESSED", "LOW"),
            "INSUFFICIENT": (False, False, "LOW", "LIMITED", "LOW"),
            "PARTIAL": (True, False, "HIGH", "LIMITED", "MEDIUM"),
            "CONTRADICTORY": (True, True, "HIGH", "LIMITED", "LOW"),
            "SUFFICIENT": (True, True, "HIGH", "REASONABLE", "HIGH"),
        }
        direct, corroborating, reliability, representative, confidence = values[state]
        return {
            "state": state, "direct_evidence": direct, "corroborating_evidence": corroborating,
            "source_reliability": reliability, "representativeness": representative,
            "contradiction_state": contradiction, "missing_material_evidence": missing,
            "confidence": confidence, "rationale": "The bounded evidence state supports only this inspection coverage judgment.",
        }

    def evidence(self, evidence_id=None, assessment_id=None, tenant=None, evidence_type="CONFIGURATION_SNAPSHOT"):
        evidence_id = evidence_id or self.evidence_id
        tenant = tenant or self.tenant
        self.store.oia_evidence_items[(tenant, evidence_id)] = {
            "tenant_id": tenant, "oia_evidence_id": evidence_id,
            "oia_assessment_id": assessment_id or self.assessment_id,
            "source_system_reference": "system-001", "evidence_type": evidence_type,
            "captured_at": "2030-01-15T14:30:00Z", "captured_by": "workload.evidence-collector",
            "scope_action": "VIEW_CONFIGURATION", "secure_object_reference": "secure-object-001",
            "content_digest": "sha256:" + "d" * 64, "sensitivity": "RESTRICTED",
            "retention_status": "AVAILABLE", "created_at": "2030-01-15T14:31:00Z",
        }

    def raw(self, command, payload, expected=None, key=None, command_id=None, tenant=None, engagement=None, caller_type="INTERNAL_SERVICE"):
        slug = {
            "CreateOIAInspectionItem": "create-oia-inspection-item",
            "UpdateOIAInspectionItem": "update-oia-inspection-item",
            "MarkOIAInspectionItemBlocked": "mark-oia-inspection-item-blocked",
        }[command]
        tenant = tenant or self.tenant
        raw = {
            "command_id": command_id or {"CreateOIAInspectionItem": "d1000000-0000-4000-8000-000000000101", "UpdateOIAInspectionItem": "d1000000-0000-4000-8000-000000000102", "MarkOIAInspectionItemBlocked": "d1000000-0000-4000-8000-000000000103"}[command],
            "command_type": command, "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.engagement_id,
            "subject_type": "OIA_INSPECTION_ITEM", "subject_id": payload["oia_inspection_item_id"],
            "requested_by": "human.assessor-001" if caller_type == "HUMAN" else "workload.inspection-manager",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "human.assessor-001" if caller_type == "HUMAN" else "workload.inspection-manager",
                "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": ["oia:inspection:manage"],
                "environment": "TEST", "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d1000000-0000-4000-8000-000000000110",
            "idempotency_key": key or f"phase5b-inspection-{command.lower()}-0001",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{slug}-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            raw["expected_record_version"] = expected
        return raw

    def create(self, payload=None, key="phase5b-create-inspection-0001"):
        raw = self.raw("CreateOIAInspectionItem", payload or self.create_payload(), key=key)
        result = self.executor.execute(raw, self.context())
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def update_payload(self, coverage, evidence_ids=(), sufficiency=None, limitations=(), **extra):
        result = {
            "oia_inspection_item_id": self.item_id, "coverage_state": coverage,
            "sufficiency_evaluation": copy.deepcopy(sufficiency or self.sufficiency()),
            "limitations": list(copy.deepcopy(limitations)), "linked_evidence_ids": list(evidence_ids),
        }
        result.update(extra)
        return result

    def update(self, payload, expected, caller_type="INTERNAL_SERVICE", key="phase5b-update-inspection-0001"):
        raw = self.raw("UpdateOIAInspectionItem", payload, expected=expected, key=key, caller_type=caller_type)
        return raw, self.executor.execute(raw, self.context(caller_type))

    def block(self, reason="BLOCKED_BY_AUTHORITY", limitation="AUTHORITY_UNAVAILABLE", expected=1, key="phase5b-block-inspection-0001"):
        payload = {
            "oia_inspection_item_id": self.item_id, "blocked_reason": reason,
            "blocked_explanation": "The planned diagnostic action cannot proceed under the current bounded condition.",
            "limitations": [{"classification": limitation, "explanation": "The required inspection remains unavailable within the current assessment boundary."}],
        }
        raw = self.raw("MarkOIAInspectionItemBlocked", payload, expected=expected, key=key)
        return raw, self.executor.execute(raw, self.context())

    def item(self):
        return UnitOfWork(self.store).oia_inspection_items.get(self.tenant, self.item_id)

    def assert_no_item_effects(self):
        self.assertEqual(self.store.oia_inspection_items, {})
        self.assertEqual(self.store.events, [])
        self.assertEqual(self.store.outbox, [])

    def test_create_happy_path_is_approved_plan_bound_and_contract_valid(self):
        raw = self.create()
        item = self.item()
        self.assertEqual((item["coverage_state"], item["record_version"]), ("NOT_STARTED", 1))
        self.assertEqual((item["oia_assessment_id"], item["oia_assessment_plan_id"], item["plan_version"]), (self.assessment_id, self.plan_id, 1))
        self.assertEqual(item["methodology_reference"], self.methodology)
        self.assertEqual(item["linked_evidence_ids"], [])
        self.assertNotIn("target_authorized", item)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1"); fmt = FormatChecker()
        self.assertEqual(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-inspection-item:v1"), format_checker=fmt).iter_errors(item)), [])
        event = self.store.events[0]
        self.assertEqual(event["event_type"], "oia.inspection_item_created")
        self.assertEqual(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=fmt).iter_errors(event)), [])
        self.assertEqual(self.store.outbox, [{"event_id": event["event_id"], "status": "PENDING"}])
        self.assertTrue(hasattr(CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw), "prepared"))

    def test_only_current_approved_plan_may_create_or_execute(self):
        for state in ("DRAFT", "REVIEWED", "SUPERSEDED"):
            with self.subTest(state=state):
                self.setUp(); self.store.oia_assessment_plans[(self.tenant, self.plan_id, 1)]["state"] = state
                self.assertEqual(self.executor.execute(self.raw("CreateOIAInspectionItem", self.create_payload()), self.context())["result"], "REJECTED")
                self.assert_no_item_effects()
        self.setUp(); self.create(); self.store.oia_assessment_plans[(self.tenant, self.plan_id, 1)]["state"] = "SUPERSEDED"
        self.store.oia_assessment_plans[(self.tenant, self.plan_id, 2)] = self.plan(version=2)
        start = self.update_payload("IN_PROGRESS")
        self.assertEqual(self.update(start, 1)[1]["result"], "REJECTED")
        self.assertEqual(self.item()["coverage_state"], "NOT_STARTED")

    def test_create_correlation_wrong_tenant_assessment_plan_version_and_closed(self):
        cases = (
            ("assessment", lambda p: p.update(oia_assessment_id=self.other_assessment_id)),
            ("plan-version", lambda p: p.update(plan_version=2)),
            ("engagement", lambda p: p.update(engagement_id="d1000000-0000-4000-8000-000000000093")),
            ("closed", lambda p: self.store.oia_assessments[(self.tenant, self.assessment_id)].update(state="CLOSED")),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp(); payload = self.create_payload(); mutate(payload)
                raw = self.raw("CreateOIAInspectionItem", payload, engagement=payload["engagement_id"])
                self.assertEqual(self.executor.execute(raw, self.context())["result"], "REJECTED")
                self.assert_no_item_effects()
        self.setUp(); raw = self.raw("CreateOIAInspectionItem", self.create_payload(), tenant=self.other_tenant)
        self.assertEqual(self.executor.execute(raw, self.context(tenant=self.tenant))["result"], "REJECTED")
        self.assert_no_item_effects()

    def test_system_start_revalidates_current_authority_and_non_system_does_not(self):
        self.create(); start = self.update_payload("IN_PROGRESS")
        self.assertEqual(self.update(start, 1)[1]["result"], "ACCEPTED")
        self.assertEqual(self.item()["coverage_state"], "IN_PROGRESS")
        self.setUp(); self.store.grants[(self.tenant, self.grant_id)]["status"] = "EXPIRED"; self.create()
        self.assertEqual(self.item()["coverage_state"], "NOT_STARTED")
        self.setUp(); self.create(self.create_payload(system=False)); self.store.grants[(self.tenant, self.grant_id)]["status"] = "EXPIRED"
        self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "ACCEPTED")
        self.assertEqual(self.store.grants[(self.tenant, self.grant_id)]["status"], "EXPIRED")

    def test_expired_payment_terminal_target_and_action_start_fail_closed(self):
        mutations = (
            ("exact-expiry", lambda: self.store.grants[(self.tenant, self.grant_id)].update(expires_at=self.now)),
            ("payment", lambda: self.store.payments[self.payment_id].update(verification_status="INVALIDATED")),
            ("revoked", lambda: self.store.grants[(self.tenant, self.grant_id)].update(status="REVOKED")),
            ("closed", lambda: self.store.grants[(self.tenant, self.grant_id)].update(status="CLOSED")),
            ("assessment-binding", lambda: self.store.grants[(self.tenant, self.grant_id)]["diagnostic_scope_reference"].update(reference_version=1)),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                self.setUp(); self.create(); mutate(); before = copy.deepcopy(self.store.grants)
                self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "REJECTED")
                self.assertEqual(self.item()["coverage_state"], "NOT_STARTED"); self.assertEqual(self.store.grants, before)
        self.setUp(); self.store.scopes[self.scope_id]["in_scope_systems"].append({"system_reference_id": "system-002"}); self.create(self.create_payload(target="system-002"))
        self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "REJECTED")
        self.setUp(); self.store.scopes[self.scope_id]["permitted_diagnostic_actions"].append("VIEW_METRICS"); self.create(self.create_payload(action="VIEW_METRICS"))
        self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "REJECTED")

    def test_non_destructive_vocabulary_and_access_claims_are_rejected(self):
        payload = self.create_payload(); payload["planned_target_action"]["diagnostic_action"] = "MODIFY_CONFIGURATION"; payload["expected_evidence"][0]["planned_target_action"]["diagnostic_action"] = "MODIFY_CONFIGURATION"
        result = self.executor.execute(self.raw("CreateOIAInspectionItem", payload), self.context())
        self.assertEqual(result["result"], "VALIDATION_FAILED"); self.assert_no_item_effects()
        for field in ("target_authorized", "action_authorized", "grant_active", "access_usable", "payment_verified"):
            with self.subTest(field=field):
                self.setUp(); payload = self.create_payload(); payload[field] = True
                self.assertEqual(self.executor.execute(self.raw("CreateOIAInspectionItem", payload), self.context())["reason_code"], "FIELD_FORBIDDEN")
                self.assert_no_item_effects()

    def test_partial_contradictory_and_human_sufficient_coverage(self):
        self.create(); self.evidence()
        partial = self.update_payload("PARTIALLY_EVIDENCED", [self.evidence_id], self.sufficiency("PARTIAL"))
        self.assertEqual(self.update(partial, 1)[1]["result"], "ACCEPTED")
        contradictory = self.update_payload("PARTIALLY_EVIDENCED", [self.evidence_id], self.sufficiency("CONTRADICTORY", "UNRESOLVED", True))
        self.assertEqual(self.update(contradictory, 2, key="phase5b-contradictory-evidence")[1]["result"], "ACCEPTED")
        false_sufficient = self.update_payload("SUFFICIENTLY_EVIDENCED", [self.evidence_id], self.sufficiency("CONTRADICTORY", "UNRESOLVED", True), stop_reason="EVIDENCE_SUFFICIENT", stop_rationale="Further evidence is not expected to change the current confidence.")
        self.assertEqual(self.update(false_sufficient, 3, "HUMAN", "phase5b-false-sufficiency")[1]["result"], "REJECTED")
        sufficient = self.update_payload("SUFFICIENTLY_EVIDENCED", [self.evidence_id], self.sufficiency("SUFFICIENT", "NONE", False), stop_reason="EVIDENCE_SUFFICIENT", stop_rationale="Further evidence is not expected to change the bounded inspection confidence.", intervention_class="PROCESS_CHANGE")
        self.assertEqual(self.update(sufficient, 3, "HUMAN", "phase5b-sufficient-evidence")[1]["result"], "ACCEPTED")
        self.assertEqual((self.item()["coverage_state"], self.item()["sufficiency_evaluation"]["state"]), ("SUFFICIENTLY_EVIDENCED", "SUFFICIENT"))
        self.assertFalse(any(event["event_type"].startswith("oia.observation") for event in self.store.events))

    def test_workload_cannot_assert_sufficiency_and_insufficient_cannot_advance(self):
        self.create(); self.evidence()
        partial = self.update_payload("PARTIALLY_EVIDENCED", [self.evidence_id], self.sufficiency("PARTIAL"))
        self.assertEqual(self.update(partial, 1)[1]["result"], "ACCEPTED")
        weak = self.update_payload("SUFFICIENTLY_EVIDENCED", [self.evidence_id], self.sufficiency("INSUFFICIENT"), stop_reason="EVIDENCE_SUFFICIENT", stop_rationale="The caller incorrectly claims that weak evidence is sufficient.")
        self.assertEqual(self.update(weak, 2, "HUMAN", "phase5b-insufficient-sufficiency")[1]["result"], "REJECTED")
        strong = self.update_payload("SUFFICIENTLY_EVIDENCED", [self.evidence_id], self.sufficiency("SUFFICIENT", missing=False), stop_reason="EVIDENCE_SUFFICIENT", stop_rationale="The bounded evidence supports this inspection judgment only.")
        self.assertEqual(self.update(strong, 2, "INTERNAL_SERVICE", "phase5b-workload-sufficiency")[1]["result"], "REJECTED")
        self.assertEqual(self.item()["coverage_state"], "PARTIALLY_EVIDENCED")

    def test_existing_evidence_links_after_expiry_and_evidence_boundaries(self):
        self.create(); self.evidence(); self.store.grants[(self.tenant, self.grant_id)].update(status="EXPIRED", expires_at=self.now)
        partial = self.update_payload("PARTIALLY_EVIDENCED", [self.evidence_id], self.sufficiency("PARTIAL"))
        self.assertEqual(self.update(partial, 1)[1]["result"], "ACCEPTED")
        self.assertEqual(self.store.grants[(self.tenant, self.grant_id)]["status"], "EXPIRED")
        self.setUp(); self.create(); unknown = self.update_payload("PARTIALLY_EVIDENCED", [self.other_evidence_id], self.sufficiency("PARTIAL"))
        self.assertEqual(self.update(unknown, 1)[1]["result"], "REJECTED")
        self.evidence(self.other_evidence_id, self.other_assessment_id)
        self.assertEqual(self.update(unknown, 1, key="phase5b-cross-assessment-evidence")[1]["result"], "REJECTED")
        self.store.oia_evidence_items.pop((self.tenant, self.other_evidence_id)); self.evidence(self.other_evidence_id, tenant=self.other_tenant)
        self.assertEqual(self.update(unknown, 1, key="phase5b-cross-tenant-evidence")[1]["result"], "REJECTED")

    def test_authority_and_dependency_blocking_preserve_truth(self):
        self.create(); self.store.grants[(self.tenant, self.grant_id)]["status"] = "EXPIRED"
        raw, result = self.block()
        self.assertEqual(result["result"], "ACCEPTED")
        item = self.item(); self.assertEqual((item["coverage_state"], item["blocked_reason"], item["stop_reason"]), ("BLOCKED", "BLOCKED_BY_AUTHORITY", "AUTHORITY_UNAVAILABLE"))
        self.assertEqual(item["linked_evidence_ids"], []); self.assertEqual(self.store.grants[(self.tenant, self.grant_id)]["status"], "EXPIRED")
        self.assertEqual(self.store.events[-1]["event_type"], "oia.inspection_item_blocked")
        self.setUp(); self.create(); _, dependency = self.block("DEPENDENCY_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE")
        self.assertEqual(dependency["result"], "ACCEPTED")
        self.assertEqual((self.item()["blocked_reason"], self.item()["stop_reason"]), ("DEPENDENCY_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE"))
        self.setUp(); self.create(); _, bounded = self.block("NON_DESTRUCTIVE_BOUNDARY", "SCOPE_BOUNDARY", key="phase5b-non-destructive-block")
        self.assertEqual(bounded["result"], "ACCEPTED")
        self.assertEqual((self.item()["blocked_reason"], self.item()["stop_reason"]), ("NON_DESTRUCTIVE_BOUNDARY", "NON_DESTRUCTIVE_BOUNDARY"))
        self.assertTrue(hasattr(CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw), "prepared"))

    def test_not_applicable_stop_limitation_sampling_materiality_and_intervention_boundaries(self):
        payload = self.create_payload(); payload["limitations"] = [{"classification": "TIME_WINDOW_LIMITATION", "explanation": "The available assessment window excludes a seasonal operating period."}]
        self.create(payload)
        not_applicable = self.update_payload("NOT_APPLICABLE", limitations=payload["limitations"], stop_reason="LOW_MATERIALITY", stop_rationale="The process is not material to the approved engagement objectives.")
        self.assertEqual(self.update(not_applicable, 1, "HUMAN")[1]["result"], "ACCEPTED")
        item = self.item(); self.assertEqual(item["coverage_state"], "NOT_APPLICABLE")
        self.assertEqual(item["sampling_strategy"], payload["sampling_strategy"]); self.assertEqual(item["materiality"], payload["materiality"]); self.assertEqual(item["limitations"], payload["limitations"])
        self.setUp(); self.create(payload); removal = self.update_payload("IN_PROGRESS", limitations=[])
        self.assertEqual(self.update(removal, 1)[1]["result"], "REJECTED")
        self.setUp(); self.create(); early_intervention = self.update_payload("IN_PROGRESS", intervention_class="PROCESS_CHANGE")
        self.assertEqual(self.update(early_intervention, 1)[1]["result"], "REJECTED")

    def test_closed_assessment_rejects_create_update_and_block(self):
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assertEqual(self.executor.execute(self.raw("CreateOIAInspectionItem", self.create_payload()), self.context())["result"], "REJECTED")
        self.setUp(); self.create(); self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "REJECTED")
        self.assertEqual(self.block()[1]["result"], "REJECTED")
        self.assertEqual(self.item()["coverage_state"], "NOT_STARTED")

    def test_stale_concurrency_and_idempotency_replay_conflict(self):
        create_raw = self.create(); before = (len(self.store.oia_inspection_items), len(self.store.events), len(self.store.outbox))
        self.assertEqual(self.executor.execute(create_raw, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(create_raw); changed["payload"]["why_it_matters"] = "A changed semantic inspection purpose must conflict under the same reservation."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((len(self.store.oia_inspection_items), len(self.store.events), len(self.store.outbox)), before)
        update_raw, accepted = self.update(self.update_payload("IN_PROGRESS"), 1); self.assertEqual(accepted["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(update_raw, self.context())["result"], "DUPLICATE")
        changed_update = copy.deepcopy(update_raw); changed_update["payload"]["assessor_notes"] = "changed"
        self.assertEqual(self.executor.execute(changed_update, self.context())["result"], "CONFLICT")
        stale = self.raw("UpdateOIAInspectionItem", self.update_payload("PARTIALLY_EVIDENCED", sufficiency=self.sufficiency("PARTIAL")), expected=1, key="phase5b-stale-update")
        self.assertEqual(self.executor.execute(stale, self.context())["reason_code"], "VERSION_STALE")
        self.setUp(); self.create(); self.store.grants[(self.tenant, self.grant_id)]["status"] = "EXPIRED"; block_raw, result = self.block(); self.assertEqual(result["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(block_raw, self.context())["result"], "DUPLICATE")
        changed_block = copy.deepcopy(block_raw); changed_block["payload"]["blocked_reason"] = "DEPENDENCY_UNAVAILABLE"
        self.assertEqual(self.executor.execute(changed_block, self.context())["result"], "CONFLICT")

    def test_coverage_read_model_and_history(self):
        self.create(); second = self.create_payload(self.other_item_id, system=False)
        self.assertEqual(self.executor.execute(self.raw("CreateOIAInspectionItem", second, key="phase5b-create-second-item"), self.context())["result"], "ACCEPTED")
        coverage = UnitOfWork(self.store).oia_inspection_items.coverage_for_plan(self.tenant, self.plan_id, 1)
        self.assertEqual(set(coverage["required_unresolved_item_ids"]), {self.item_id, self.other_item_id}); self.assertFalse(coverage["ready_for_observation_analysis"])
        self.store.grants[(self.tenant, self.grant_id)]["status"] = "EXPIRED"; self.assertEqual(self.block()[1]["result"], "ACCEPTED")
        second_payload = {"oia_inspection_item_id": self.other_item_id, "blocked_reason": "DEPENDENCY_UNAVAILABLE", "blocked_explanation": "A required client dependency is unavailable during the assessment window.", "limitations": [{"classification": "DEPENDENCY_UNAVAILABLE", "explanation": "The dependency cannot be inspected during the current bounded assessment."}]}
        second_block = self.raw("MarkOIAInspectionItemBlocked", second_payload, expected=1, key="phase5b-block-second-item")
        self.assertEqual(self.executor.execute(second_block, self.context())["result"], "ACCEPTED")
        coverage = UnitOfWork(self.store).oia_inspection_items.coverage_for_current_assessment(self.tenant, self.assessment_id)
        self.assertEqual((coverage["oia_assessment_plan_id"], coverage["plan_version"]), (self.plan_id, 1))
        self.assertEqual(coverage["required_unresolved_item_ids"], ()); self.assertTrue(coverage["ready_for_observation_analysis"])
        self.store.oia_assessment_plans[(self.tenant, self.plan_id, 1)]["state"] = "SUPERSEDED"; self.store.oia_assessment_plans[(self.tenant, self.plan_id, 2)] = self.plan(version=2)
        self.assertEqual(len(UnitOfWork(self.store).oia_inspection_items.list_by_plan(self.tenant, self.plan_id, 1)), 2)
        self.assertEqual(UnitOfWork(self.store).oia_inspection_items.list_by_plan(self.tenant, self.plan_id, 2), ())

    def test_progress_and_block_events_are_contract_valid(self):
        self.create()
        self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "ACCEPTED")
        self.assertEqual(self.block("DEPENDENCY_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE", expected=2, key="phase5b-block-progressed-item")[1]["result"], "ACCEPTED")
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1"); fmt = FormatChecker()
        item_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-inspection-item:v1"), format_checker=fmt)
        event_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=fmt)
        self.assertEqual(list(item_validator.iter_errors(self.item())), [])
        self.assertEqual([event["event_type"] for event in self.store.events], ["oia.inspection_item_created", "oia.inspection_item_progressed", "oia.inspection_item_blocked"])
        self.assertTrue(all(not list(event_validator.iter_errors(event)) for event in self.store.events))
        self.assertEqual(len(self.store.outbox), 3)

    def test_failpoints_roll_back_create_and_update(self):
        stages = ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT")
        for stage in stages:
            with self.subTest(operation="create", stage=stage):
                self.setUp(); self.store.fail_stage = stage; before = copy.deepcopy(self.store)
                self.assertEqual(self.executor.execute(self.raw("CreateOIAInspectionItem", self.create_payload()), self.context())["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before.__dict__)
            with self.subTest(operation="update", stage=stage):
                self.setUp(); self.create(); self.store.fail_stage = stage; before = copy.deepcopy(self.store)
                self.assertEqual(self.update(self.update_payload("IN_PROGRESS"), 1)[1]["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before.__dict__)


if __name__ == "__main__":
    unittest.main()
