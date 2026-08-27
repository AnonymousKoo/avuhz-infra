import copy
import hashlib
import itertools
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.oia_finding import (
    FindingPriorityPolicyV1,
    derive_finding_set_readiness,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.contracts.validate_oia_finding_priority_policy import derive as contract_derive
from tests.runtime import test_oia_root_cause as root_module


class OIAFindingRuntimeTests(unittest.TestCase):
    finding_id = "e4000000-0000-4000-8000-000000000001"
    second_finding_id = "e4000000-0000-4000-8000-000000000002"
    unknown_id = "e4000000-0000-4000-8000-000000000099"

    def setUp(self):
        base = root_module.OIARootCauseRuntimeTests()
        base.setUp()
        base.create(); base.support(); base.verify()
        self.base = base
        self.store = base.store
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: base.base.base.now,
            ids=iter((f"e4000000-0000-4000-8000-{value:012d}" for value in range(100, 999))).__next__,
        )

    @property
    def tenant(self): return self.base.tenant
    @property
    def engagement_id(self): return self.base.engagement_id
    @property
    def assessment_id(self): return self.base.assessment_id
    @property
    def observation_id(self): return self.base.observation_id
    @property
    def evidence_id(self): return self.base.evidence_id
    @property
    def root_id(self): return self.base.root_id

    def context(self, command_type="CreateOIAFinding", caller_type="HUMAN", tenant=None):
        capability = "oia:finding:finalize" if command_type == "FinalizeOIAFinding" else "oia:finding:write"
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, "human.reviewer-001" if human else "workload.finding-suggester",
            caller_type, tenant or self.tenant, None, frozenset({capability}), frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.reviewer-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    @staticmethod
    def priority_inputs(impact="HIGH", urgency="MEDIUM", operational="MEDIUM", confidence="HIGH", blocking=False):
        return {
            "impact": impact, "urgency": urgency,
            "operational_criticality": operational,
            "confidence": confidence, "dependency_blocking": blocking,
        }

    def payload(self, finding_id=None, roots=True, priority_inputs=None):
        value = {
            "oia_finding_id": finding_id or self.finding_id,
            "oia_assessment_id": self.assessment_id,
            "title": "Inbound response ownership is unreliable",
            "summary": "Qualified inbound work frequently lacks accountable follow-up.",
            "verified_operational_problem": "Required response ownership is not consistently recorded.",
            "business_operational_impact": "Unowned work increases response delay and operational risk.",
            "system_process_category": "inbound-routing",
            "supporting_observation_ids": [self.observation_id],
            "supporting_evidence_ids": [self.evidence_id],
            "desired_outcome": "Every qualified item has accountable response ownership.",
            "intervention_category": "PROCESS_CHANGE",
            "priority_inputs": copy.deepcopy(priority_inputs or self.priority_inputs()),
            "confidence": (priority_inputs or self.priority_inputs())["confidence"],
        }
        if roots: value["root_cause_ids"] = [self.root_id]
        return value

    def raw(self, command_type="CreateOIAFinding", payload=None, expected=None, key=None,
            command_id=None, tenant=None, engagement=None, caller_type="HUMAN"):
        tenant = tenant or self.tenant
        payload = copy.deepcopy(payload or self.payload())
        capability = "oia:finding:finalize" if command_type == "FinalizeOIAFinding" else "oia:finding:write"
        schema_name = {
            "CreateOIAFinding": "create-oia-finding-payload",
            "UpdateOIAFindingAnalysis": "update-oia-finding-analysis-payload",
            "FinalizeOIAFinding": "finalize-oia-finding-payload",
        }[command_type]
        principal = "human.reviewer-001" if caller_type == "HUMAN" else "workload.finding-suggester"
        value = {
            "command_id": command_id or "e4000000-0000-4000-8000-000000000010",
            "command_type": command_type, "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.engagement_id,
            "subject_type": "OIA_FINDING", "subject_id": payload["oia_finding_id"],
            "requested_by": principal, "caller_type": caller_type,
            "caller_identity": {
                "subject": principal, "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": [capability], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "e4000000-0000-4000-8000-000000000011",
            "idempotency_key": key or f"phase5b-finding-{command_type.lower()}-0001",
            "requested_at": self.base.base.base.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{schema_name}:v1",
            "payload_version": 1, "payload": payload,
        }
        if expected is not None: value["expected_record_version"] = expected
        return value

    def create(self, payload=None, key="phase5b-finding-create-0001", finding_id=None):
        payload = copy.deepcopy(payload or self.payload(finding_id=finding_id))
        raw = self.raw(payload=payload, key=key)
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        return raw

    def update(self, payload=None, expected=1, key="phase5b-finding-update-0001"):
        payload = copy.deepcopy(payload or self.payload())
        payload.pop("oia_assessment_id", None)
        raw = self.raw("UpdateOIAFindingAnalysis", payload, expected, key)
        self.assertEqual(self.executor.execute(raw, self.context("UpdateOIAFindingAnalysis"))["result"], "ACCEPTED")
        return raw

    def finalize(self, revision=1, key="phase5b-finding-finalize-0001"):
        payload = {"oia_finding_id": self.finding_id, "finding_revision": revision}
        raw = self.raw("FinalizeOIAFinding", payload, revision, key)
        self.assertEqual(self.executor.execute(raw, self.context("FinalizeOIAFinding"))["result"], "ACCEPTED")
        return raw

    def finding(self, revision=None, finding_id=None):
        repo = UnitOfWork(self.store).oia_findings
        return repo.get_revision(self.tenant, finding_id or self.finding_id, revision) if revision else repo.get(self.tenant, finding_id or self.finding_id)

    def assert_rejected_without_effect(self, raw, context=None):
        before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency))
        result = self.executor.execute(raw, context or self.context(raw["command_type"]))
        self.assertIn(result["result"], ("REJECTED", "VALIDATION_FAILED"))
        self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency), before)
        return result

    def test_create_happy_path_contract_event_outbox_snapshot_and_no_mutation(self):
        diagnostic_before = copy.deepcopy((self.store.grants, self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes))
        self.create()
        finding = self.finding()
        self.assertEqual((finding["state"], finding["finding_revision"], finding["priority"], finding["created_by"]), ("DRAFT", 1, "HIGH", "human.reviewer-001"))
        self.assertEqual((self.store.events[0]["event_type"], self.store.events[0]["authoritative_subject_version"], self.store.outbox[0]["status"]), ("oia.finding_created", 1, "PENDING"))
        self.assertEqual(set(self.store.events[0]["sanitized_metadata"]), {"oia_assessment_id", "oia_finding_id", "record_version"})
        snapshot = self.store.snapshot(CommandValidator(ROOT / "contracts/schemas/v1").prepare(self.raw()).prepared)
        self.assertEqual((snapshot.subject_type, snapshot.record_version, snapshot.state), ("OIA_FINDING", 1, "DRAFT"))
        self.assertEqual((self.store.grants, self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes), diagnostic_before)

    def test_observation_only_and_verified_cause_paths_are_supported(self):
        self.create(self.payload(roots=False))
        self.assertNotIn("root_cause_ids", self.finding())
        self.setUp(); self.create()
        self.assertEqual(self.finding()["root_cause_ids"], [self.root_id])
        second = self.payload(self.second_finding_id)
        self.create(second, "phase5b-finding-second-for-root-0001")
        self.assertEqual(len(UnitOfWork(self.store).oia_findings.list_current_by_assessment(self.tenant, self.assessment_id)), 2)

    def test_hypothesis_and_supported_root_causes_cannot_masquerade_as_verified(self):
        for confidence in ("HYPOTHESIS", "SUPPORTED"):
            with self.subTest(confidence=confidence):
                self.setUp(); self.store.oia_root_causes[(self.tenant, self.root_id)]["confidence"] = confidence
                self.assert_rejected_without_effect(self.raw(key=f"phase5b-finding-{confidence.lower()}-cause-0001"))

    def test_observation_and_evidence_correlation_negatives(self):
        cases = []
        unknown = self.payload(); unknown["supporting_observation_ids"] = [self.unknown_id]; cases.append(unknown)
        wrong_evidence = self.payload(); wrong_evidence["supporting_evidence_ids"] = [self.unknown_id]; cases.append(wrong_evidence)
        for index, payload in enumerate(cases, 1):
            with self.subTest(case=index):
                self.assert_rejected_without_effect(self.raw(payload=payload, key=f"phase5b-finding-unknown-support-{index:04d}"))
        self.setUp(); self.store.oia_observations[(self.tenant, self.observation_id)]["oia_assessment_id"] = self.base.base.base.other_assessment_id
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-cross-assessment-observation-0001"))
        self.setUp(); self.assert_rejected_without_effect(self.raw(engagement=self.unknown_id, key="phase5b-finding-cross-engagement-observation-0001"))
        self.setUp(); self.store.oia_evidence_items[(self.tenant, self.evidence_id)]["oia_assessment_id"] = self.base.base.base.other_assessment_id
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-cross-assessment-evidence-0001"))
        self.setUp(); other = self.base.base.base.other_tenant
        evidence = self.store.oia_evidence_items.pop((self.tenant, self.evidence_id)); evidence["tenant_id"] = other
        self.store.oia_evidence_items[(other, self.evidence_id)] = evidence
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-cross-tenant-evidence-0001"))
        self.setUp(); other = self.base.base.base.other_tenant
        source = copy.deepcopy(self.store.oia_observations[(self.tenant, self.observation_id)]); source["tenant_id"] = other
        self.store.oia_observations[(other, self.observation_id)] = source
        self.assert_rejected_without_effect(self.raw(tenant=other, key="phase5b-finding-cross-tenant-observation-0001"), self.context(tenant=other))

    def test_root_cause_correlation_negatives(self):
        unknown = self.payload(); unknown["root_cause_ids"] = [self.unknown_id]
        self.assert_rejected_without_effect(self.raw(payload=unknown, key="phase5b-finding-unknown-root-0001"))
        self.setUp(); self.store.oia_root_causes[(self.tenant, self.root_id)]["oia_assessment_id"] = self.base.base.base.other_assessment_id
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-cross-assessment-root-0001"))
        self.setUp(); self.assert_rejected_without_effect(self.raw(engagement=self.unknown_id, key="phase5b-finding-cross-engagement-root-0001"))
        self.setUp(); other = self.base.base.base.other_tenant
        source = copy.deepcopy(self.store.oia_root_causes[(self.tenant, self.root_id)]); source["tenant_id"] = other
        self.store.oia_root_causes[(other, self.root_id)] = source
        self.assert_rejected_without_effect(self.raw(tenant=other, key="phase5b-finding-cross-tenant-root-0001"), self.context(tenant=other))

    def test_superseded_or_contradictory_support_rejects_new_truth(self):
        self.store.oia_observations[(self.tenant, self.observation_id)]["state"] = "SUPERSEDED"
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-superseded-observation-0001"))
        self.setUp(); self.create()
        item = self.store.oia_inspection_items[(self.tenant, self.base.base.base.item_id)]
        item["coverage_state"] = "PARTIALLY_EVIDENCED"
        item["sufficiency_evaluation"] = self.base.base.base.sufficiency("CONTRADICTORY", contradiction="UNRESOLVED", missing=True)
        final = self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, "phase5b-finding-contradicted-final-0001")
        self.assert_rejected_without_effect(final)

    def test_update_creates_history_and_rederives_priority(self):
        self.create(self.payload(priority_inputs=self.priority_inputs("LOW", "LOW", "LOW", "HIGH", False)))
        changed = self.payload(priority_inputs=self.priority_inputs("CRITICAL", "CRITICAL", "LOW", "HIGH", False)); changed.pop("oia_assessment_id")
        self.update(changed)
        old, current = self.finding(1), self.finding(2)
        self.assertEqual((old["state"], old["priority"], current["state"], current["priority"]), ("SUPERSEDED", "LOW", "DRAFT", "CRITICAL"))
        self.assertEqual(current["supersedes_finding_revision"], {"oia_finding_id": self.finding_id, "finding_revision": 1})
        self.assertTrue(old["content_digest"].startswith("sha256:"))
        self.assertEqual((self.store.events[-1]["event_type"], self.store.events[-1]["authoritative_subject_version"]), ("oia.finding_updated", 2))
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        schema = registry.expanded("urn:avuhz:schema:contracts:domain:oia-finding:v1")
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(old)))
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(current)))
        event_schema = registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")
        self.assertFalse(list(Draft202012Validator(event_schema).iter_errors(self.store.events[-1])))

    def test_finalize_is_human_attributed_immutable_and_schema_representable(self):
        self.create(); self.finalize()
        finding = self.finding()
        self.assertEqual((finding["state"], finding["finalized_by"], finding["priority"]), ("FINAL", "human.reviewer-001", "HIGH"))
        self.assertTrue(finding["content_digest"].startswith("sha256:"))
        self.assertEqual(self.store.events[-1]["event_type"], "oia.finding_finalized")
        update = self.payload(); update.pop("oia_assessment_id")
        self.assert_rejected_without_effect(self.raw("UpdateOIAFindingAnalysis", update, 1, "phase5b-finding-update-final-0001"))
        self.assert_rejected_without_effect(self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, "phase5b-finding-refinalize-0001"))

        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
        for revision in UnitOfWork(self.store).oia_findings.list_by_assessment(self.tenant, self.assessment_id):
            self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-finding:v1"), format_checker=formatter).iter_errors(revision)))
        for event in self.store.events:
            self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=formatter).iter_errors(event)))

    def test_workload_and_role_priority_spoofing_fail_closed(self):
        workload = self.context(caller_type="INTERNAL_SERVICE")
        raw = self.raw(caller_type="INTERNAL_SERVICE", key="phase5b-finding-workload-create-0001")
        self.assert_rejected_without_effect(raw, workload)
        self.create()
        update = self.payload(); update.pop("oia_assessment_id")
        workload_update = self.raw("UpdateOIAFindingAnalysis", update, 1, "phase5b-finding-workload-update-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(workload_update, self.context("UpdateOIAFindingAnalysis", "INTERNAL_SERVICE"))
        final = self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, "phase5b-finding-workload-final-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(final, self.context("FinalizeOIAFinding", "INTERNAL_SERVICE"))
        for index, field in enumerate(("priority", "priority_override", "severity_override", "finalized_by", "approved_by", "human_approved", "reviewer_role"), 1):
            self.setUp(); payload = self.payload(); payload[field] = "CRITICAL"
            result = self.assert_rejected_without_effect(self.raw(payload=payload, key=f"phase5b-finding-spoof-{index:04d}"))
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_priority_runtime_has_all_tuple_parity_and_critical_safety(self):
        policy_path = ROOT / "contracts/policies/oia-finding-priority-policy.v1.json"
        before = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        runtime = FindingPriorityPolicyV1(policy_path)
        levels = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        confidences = ("LOW", "MEDIUM", "HIGH")
        count = 0
        for values in itertools.product(levels, levels, levels, confidences, (False, True)):
            vector = dict(zip(("impact", "urgency", "operational_criticality", "confidence", "dependency_blocking"), values))
            self.assertEqual(runtime.derive(vector), contract_derive(vector)); count += 1
        self.assertEqual(count, 384)
        self.assertNotEqual(runtime.derive(self.priority_inputs("LOW", "CRITICAL", "LOW", "HIGH", False)), "CRITICAL")
        self.assertNotEqual(runtime.derive(self.priority_inputs("CRITICAL", "HIGH", "LOW", "HIGH", False)), "CRITICAL")
        self.assertNotEqual(runtime.derive(self.priority_inputs("CRITICAL", "CRITICAL", "LOW", "LOW", False)), "CRITICAL")
        self.assertNotEqual(runtime.derive(self.priority_inputs("LOW", "LOW", "LOW", "HIGH", True)), "CRITICAL")
        self.assertEqual(runtime.derive(self.priority_inputs("CRITICAL", "CRITICAL", "LOW", "HIGH", False)), "CRITICAL")
        self.assertEqual(runtime.derive(self.priority_inputs("CRITICAL", "CRITICAL", "LOW", "LOW", True)), "MEDIUM")
        self.assertEqual(runtime.derive(self.priority_inputs("CRITICAL", "CRITICAL", "LOW", "MEDIUM", True)), "HIGH")
        self.assertEqual(hashlib.sha256(policy_path.read_bytes()).hexdigest(), before)

    def test_finalization_rechecks_priority_and_phase5d_fields_are_forbidden(self):
        self.create()
        self.store.oia_findings[(self.tenant, self.finding_id, 1)]["priority"] = "CRITICAL"
        final = self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, "phase5b-finding-priority-recheck-0001")
        self.assert_rejected_without_effect(final)
        self.setUp(); invalid = self.payload(); invalid["intervention_category"] = "CODEX_BUILD_PACKAGE"
        self.assert_rejected_without_effect(self.raw(payload=invalid, key="phase5b-finding-unbounded-intervention-0001"))
        for index, field in enumerate(("implementation_specification", "technical_architecture", "deployment_steps", "production_authorization", "raw_provider_payload"), 1):
            payload = self.payload(); payload[field] = "prohibited"
            result = self.assert_rejected_without_effect(self.raw(payload=payload, key=f"phase5b-finding-phase5d-boundary-{index:04d}"))
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_closed_assessment_rejects_create_update_and_finalize(self):
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(self.raw(key="phase5b-finding-closed-create-0001"))
        self.setUp(); self.create(); self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        update = self.payload(); update.pop("oia_assessment_id")
        self.assert_rejected_without_effect(self.raw("UpdateOIAFindingAnalysis", update, 1, "phase5b-finding-closed-update-0001"))
        self.assert_rejected_without_effect(self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, "phase5b-finding-closed-final-0001"))

    def test_existing_analysis_survives_expiry_and_payment_invalidation(self):
        grant = self.store.grants[(self.tenant, self.base.base.base.grant_id)]
        grant["status"] = "EXPIRED"; grant["expires_at"] = self.base.base.base.now
        self.store.payments[self.base.base.base.payment_id]["verification_status"] = "INVALIDATED"
        before = copy.deepcopy((self.store.grants, self.store.payments, self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes))
        self.create(); changed = self.payload(); changed.pop("oia_assessment_id"); self.update(changed); self.finalize(2)
        self.assertEqual(self.finding()["state"], "FINAL")
        self.assertEqual((self.store.grants, self.store.payments, self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes), before)

    def test_create_update_finalize_replay_conflict_and_uniqueness(self):
        create = self.create(); before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(create, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(create); changed["payload"]["summary"] += " Changed."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        duplicate = copy.deepcopy(create); duplicate["idempotency_key"] = "phase5b-finding-new-key-identity-0001"; duplicate["command_id"] = self.unknown_id
        self.assertEqual(self.executor.execute(duplicate, self.context())["result"], "REJECTED")
        self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox), before)
        update = self.payload(); update.pop("oia_assessment_id"); update_raw = self.update(update)
        before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(update_raw, self.context("UpdateOIAFindingAnalysis"))["result"], "DUPLICATE")
        changed = copy.deepcopy(update_raw); changed["payload"]["summary"] += " Changed."
        self.assertEqual(self.executor.execute(changed, self.context("UpdateOIAFindingAnalysis"))["result"], "CONFLICT")
        self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox), before)
        final = self.finalize(2); before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(final, self.context("FinalizeOIAFinding"))["result"], "DUPLICATE")
        changed = copy.deepcopy(final); changed["payload"]["finding_revision"] = 1; changed["expected_record_version"] = 1
        self.assertEqual(self.executor.execute(changed, self.context("FinalizeOIAFinding"))["result"], "CONFLICT")
        self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox), before)

    def test_stale_versions_and_finalize_predecessor_fail_closed(self):
        self.create(); update = self.payload(); update.pop("oia_assessment_id")
        stale = self.raw("UpdateOIAFindingAnalysis", update, 99, "phase5b-finding-stale-update-0001")
        result = self.assert_rejected_without_effect(stale); self.assertEqual(result["reason_code"], "VERSION_STALE")
        mismatch = self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 2, "phase5b-finding-mismatch-final-0001")
        self.assertEqual(self.assert_rejected_without_effect(mismatch)["result"], "VALIDATION_FAILED")

    def test_read_summary_and_finding_set_readiness_are_derived_only(self):
        self.create()
        uow = UnitOfWork(self.store)
        self.assertEqual(derive_finding_set_readiness(uow, self.tenant, self.assessment_id)["readiness"], "NOT_READY")
        self.finalize(); uow = UnitOfWork(self.store)
        readiness = derive_finding_set_readiness(uow, self.tenant, self.assessment_id)
        self.assertEqual((readiness["readiness"], readiness["final_finding_count"]), ("READY", 1))
        summary = uow.oia_findings.summary_by_assessment(self.tenant, self.assessment_id, self.base.base.base.now)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:read-models:oia-findings-summary-view:v1")).iter_errors(summary)))
        self.assertEqual(self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"], "IN_PROGRESS")
        self.assertEqual(self.store.oia_findings_deliveries, {})

    def test_create_update_finalize_failpoints_roll_back_every_component(self):
        stages = ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT")
        for stage in stages:
            with self.subTest(command="create", stage=stage):
                self.setUp(); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency))
                self.assertEqual(self.executor.execute(self.raw(key=f"phase5b-finding-create-fail-{stage.lower()}"), self.context())["result"], "REJECTED")
                self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency), before)
            with self.subTest(command="update", stage=stage):
                self.setUp(); self.create(); self.store.fail_stage = stage; payload = self.payload(); payload.pop("oia_assessment_id")
                before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency))
                raw = self.raw("UpdateOIAFindingAnalysis", payload, 1, f"phase5b-finding-update-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(raw, self.context("UpdateOIAFindingAnalysis"))["result"], "REJECTED")
                self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency), before)
            with self.subTest(command="finalize", stage=stage):
                self.setUp(); self.create(); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency))
                raw = self.raw("FinalizeOIAFinding", {"oia_finding_id": self.finding_id, "finding_revision": 1}, 1, f"phase5b-finding-final-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(raw, self.context("FinalizeOIAFinding"))["result"], "REJECTED")
                self.assertEqual((self.store.oia_findings, self.store.events, self.store.outbox, self.store.idempotency), before)


if __name__ == "__main__": unittest.main()
