import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_oia_inspection_item as inspection_module


class OIAObservationRuntimeTests(unittest.TestCase):
    observation_id = "d2000000-0000-4000-8000-000000000001"
    replacement_id = "d2000000-0000-4000-8000-000000000002"
    third_id = "d2000000-0000-4000-8000-000000000003"
    second_evidence_id = "d2000000-0000-4000-8000-000000000004"
    second_item_id = "d2000000-0000-4000-8000-000000000005"

    def setUp(self):
        base = inspection_module.OIAInspectionItemRuntimeTests()
        base.setUp()
        self.base = base
        self.store = base.store
        base.create()
        base.evidence()
        partial = base.update_payload(
            "PARTIALLY_EVIDENCED", [base.evidence_id], base.sufficiency("PARTIAL", missing=True)
        )
        self.assertEqual(base.update(partial, 1)[1]["result"], "ACCEPTED")
        sufficient = base.update_payload(
            "SUFFICIENTLY_EVIDENCED", [base.evidence_id],
            base.sufficiency("SUFFICIENT", missing=False),
            stop_reason="EVIDENCE_SUFFICIENT",
            stop_rationale="The governed evidence is sufficient for this diagnostic objective.",
        )
        self.assertEqual(base.update(sufficient, 2, caller_type="HUMAN", key="phase5b-support-sufficient-0001")[1]["result"], "ACCEPTED")
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: base.now,
            ids=iter((f"d2000000-0000-4000-8000-{value:012d}" for value in range(100, 999))).__next__,
        )

    def context(self, caller_type="HUMAN", tenant=None):
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, "human.analyst-001" if human else "workload.observation-suggester",
            caller_type, tenant or self.base.tenant, None,
            frozenset({"oia:observation:record"}), frozenset(), "TEST",
            "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.analyst-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    def payload(self, observation_id=None, evidence_ids=None, confidence="MEDIUM"):
        return {
            "oia_observation_id": observation_id or self.observation_id,
            "oia_assessment_id": self.base.assessment_id,
            "evidence_ids": list(evidence_ids or [self.base.evidence_id]),
            "system_process_area": "lead-intake",
            "observed_condition": "The authoritative workflow configuration has no attributable escalation path for unassigned inbound work.",
            "expected_condition": "Inbound work has an attributable assignment and escalation path.",
            "confidence": confidence,
        }

    def raw_record(self, payload=None, key="phase5b-record-observation-0001", command_id=None, tenant=None, engagement=None, caller_type="HUMAN"):
        payload = copy.deepcopy(payload or self.payload())
        tenant = tenant or self.base.tenant
        principal = "human.analyst-001" if caller_type == "HUMAN" else "workload.observation-suggester"
        return {
            "command_id": command_id or "d2000000-0000-4000-8000-000000000010",
            "command_type": "RecordOIAObservation", "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.base.engagement_id,
            "subject_type": "OIA_OBSERVATION", "subject_id": payload["oia_observation_id"],
            "requested_by": principal, "caller_type": caller_type,
            "caller_identity": {
                "subject": principal, "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": ["oia:observation:record"],
                "environment": "TEST", "authentication_strength": "STRONG",
                "step_up_performed": False, "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d2000000-0000-4000-8000-000000000011",
            "idempotency_key": key, "requested_at": self.base.now, "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:record-oia-observation-payload:v1",
            "payload_version": 1, "payload": payload,
        }

    def raw_supersede(self, original=None, replacement=None, expected=1, key="phase5b-supersede-observation-0001", caller_type="HUMAN", tenant=None):
        original = original or self.observation_id
        replacement = replacement or self.replacement_id
        tenant = tenant or self.base.tenant
        principal = "human.analyst-001" if caller_type == "HUMAN" else "workload.observation-suggester"
        return {
            "command_id": "d2000000-0000-4000-8000-000000000012",
            "command_type": "SupersedeOIAObservation", "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": self.base.engagement_id,
            "subject_type": "OIA_OBSERVATION", "subject_id": original,
            "expected_record_version": expected, "requested_by": principal,
            "caller_type": caller_type,
            "caller_identity": {
                "subject": principal, "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": ["oia:observation:record"],
                "environment": "TEST", "authentication_strength": "STRONG",
                "step_up_performed": False, "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d2000000-0000-4000-8000-000000000013",
            "idempotency_key": key, "requested_at": self.base.now, "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:supersede-oia-observation-payload:v1",
            "payload_version": 1,
            "payload": {"oia_observation_id": original, "replacement_oia_observation_id": replacement},
        }

    def record(self, observation_id=None, key=None, payload=None):
        value = copy.deepcopy(payload or self.payload(observation_id))
        raw = self.raw_record(value, key or f"phase5b-record-{value['oia_observation_id']}")
        result = self.executor.execute(raw, self.context())
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def observation(self, observation_id=None, tenant=None):
        return UnitOfWork(self.store).oia_observations.get(
            tenant or self.base.tenant, observation_id or self.observation_id
        )

    def assert_rejected_without_effect(self, raw, context=None):
        before = copy.deepcopy((self.store.oia_observations, self.store.events, self.store.outbox))
        self.assertIn(self.executor.execute(raw, context or self.context())["result"], ("REJECTED", "VALIDATION_FAILED"))
        self.assertEqual((self.store.oia_observations, self.store.events, self.store.outbox), before)

    def test_record_happy_path_contract_event_and_outbox(self):
        self.record()
        observation = self.observation()
        self.assertEqual((observation["state"], observation["record_version"], observation["created_by"]), ("RECORDED", 1, "human.analyst-001"))
        self.assertEqual(observation["evidence_ids"], [self.base.evidence_id])
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value:isinstance(value,str) and value.endswith("Z"))
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-observation:v1"), format_checker=formatter).iter_errors(observation)))
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=formatter).iter_errors(self.store.events[0])))
        self.assertEqual((self.store.events[0]["event_type"], self.store.outbox[0]["status"]), ("oia.observation_recorded", "PENDING"))
        self.assertEqual((len(self.store.events), len(self.store.outbox)), (1, 1))
        self.assertEqual(
            set(self.store.events[0]["sanitized_metadata"]),
            {"oia_assessment_id", "oia_observation_id", "record_version"},
        )
        self.assertFalse(hasattr(self.store, "oia_root_causes")); self.assertFalse(hasattr(self.store, "oia_findings"))

    def test_sufficient_support_does_not_invent_numeric_confidence_threshold(self):
        item = self.store.oia_inspection_items[(self.base.tenant, self.base.item_id)]
        item["sufficiency_evaluation"]["confidence"] = "MEDIUM"
        self.record(payload=self.payload(confidence="HIGH"))
        self.assertEqual(self.observation()["confidence"], "HIGH")

    def test_multi_evidence_and_multi_inspection_are_supported_without_mutation(self):
        self.base.evidence(self.second_evidence_id)
        first = self.store.oia_inspection_items[(self.base.tenant, self.base.item_id)]
        second = copy.deepcopy(first); second["oia_inspection_item_id"] = self.second_item_id
        second["linked_evidence_ids"] = [self.second_evidence_id]
        self.store.oia_inspection_items[(self.base.tenant, self.second_item_id)] = second
        evidence_before = copy.deepcopy(self.store.oia_evidence_items)
        self.record(payload=self.payload(evidence_ids=[self.base.evidence_id, self.second_evidence_id], confidence="HIGH"))
        self.assertEqual(set(self.observation()["evidence_ids"]), {self.base.evidence_id, self.second_evidence_id})
        self.assertEqual(self.store.oia_evidence_items, evidence_before)

    def test_inspection_plan_methodology_and_process_correlation_are_required(self):
        key = (self.base.tenant, self.base.item_id)
        original = copy.deepcopy(self.store.oia_inspection_items[key])
        mutations = (
            ("unknown", None),
            ("tenant", {"tenant_id": self.base.other_tenant}),
            ("engagement", {"engagement_id": "d2000000-0000-4000-8000-000000000090"}),
            ("assessment", {"oia_assessment_id": self.base.other_assessment_id}),
            ("plan", {"oia_assessment_plan_id": "d2000000-0000-4000-8000-000000000091"}),
            ("plan_version", {"plan_version": 2}),
            ("methodology", {"methodology_reference": {**self.base.methodology, "version": "2.0.0"}}),
            ("objective", {"objective_id": "unrelated-objective"}),
            ("process_area", {"process_area_id": "unrelated-area"}),
        )
        for index, (name, mutation) in enumerate(mutations, start=1):
            with self.subTest(correlation=name):
                if mutation is None:
                    self.store.oia_inspection_items.pop(key, None)
                else:
                    item = copy.deepcopy(original)
                    item.update(mutation)
                    self.store.oia_inspection_items[key] = item
                self.assert_rejected_without_effect(
                    self.raw_record(key=f"phase5b-inspection-correlation-{index:04d}")
                )
                self.store.oia_inspection_items[key] = copy.deepcopy(original)

    def test_unknown_and_cross_boundary_evidence_are_rejected(self):
        unknown = self.payload(evidence_ids=["d2000000-0000-4000-8000-000000000099"])
        self.assert_rejected_without_effect(self.raw_record(unknown))
        self.base.evidence(self.second_evidence_id, tenant=self.base.other_tenant)
        self.assert_rejected_without_effect(self.raw_record(self.payload(evidence_ids=[self.second_evidence_id]), key="phase5b-wrong-tenant-evidence-0001"))
        self.base.evidence(self.second_evidence_id, assessment_id=self.base.other_assessment_id)
        self.assert_rejected_without_effect(self.raw_record(self.payload(evidence_ids=[self.second_evidence_id]), key="phase5b-wrong-assessment-evidence-0001"))
        self.assert_rejected_without_effect(self.raw_record(engagement="d2000000-0000-4000-8000-000000000098", key="phase5b-wrong-engagement-0001"))

    def test_insufficient_contradictory_blocked_and_not_applicable_support_are_rejected(self):
        item = self.store.oia_inspection_items[(self.base.tenant, self.base.item_id)]
        for index, (coverage, sufficiency) in enumerate((
            ("PARTIALLY_EVIDENCED", self.base.sufficiency("PARTIAL", missing=True)),
            ("PARTIALLY_EVIDENCED", self.base.sufficiency("CONTRADICTORY", contradiction="UNRESOLVED", missing=True)),
            ("BLOCKED", self.base.sufficiency("INSUFFICIENT", missing=True)),
            ("NOT_APPLICABLE", self.base.sufficiency("NOT_EVALUATED", missing=True)),
        )):
            item["coverage_state"] = coverage; item["sufficiency_evaluation"] = sufficiency
            raw = self.raw_record(key=f"phase5b-unsupported-observation-000{index+1}")
            self.assert_rejected_without_effect(raw)

    def test_existing_evidence_remains_analysable_after_access_and_payment_expiry(self):
        for index, expires_at in enumerate((self.base.now, "2030-01-15T14:59:59Z"), start=1):
            with self.subTest(expires_at=expires_at):
                if index > 1:
                    self.setUp()
                grant = self.store.grants[(self.base.tenant, self.base.grant_id)]
                grant["status"] = "EXPIRED"; grant["expires_at"] = expires_at
                self.store.payments[self.base.payment_id]["verification_status"] = "INVALIDATED"
                before = copy.deepcopy((grant, self.store.payments[self.base.payment_id], self.store.oia_evidence_items))
                self.record(key=f"phase5b-expired-analysis-{index:04d}")
                self.assertEqual((grant, self.store.payments[self.base.payment_id], self.store.oia_evidence_items), before)

    def test_closed_assessment_workload_and_role_spoof_are_rejected(self):
        self.store.oia_assessments[(self.base.tenant, self.base.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(self.raw_record())
        self.store.oia_assessments[(self.base.tenant, self.base.assessment_id)]["state"] = "IN_PROGRESS"
        self.assert_rejected_without_effect(self.raw_record(caller_type="INTERNAL_SERVICE", key="phase5b-workload-observation-0001"), self.context("INTERNAL_SERVICE"))
        spoof = self.raw_record(key="phase5b-role-spoof-0001"); spoof["payload"]["verified_by"] = "human.fake"
        self.assert_rejected_without_effect(spoof)

    def test_root_cause_finding_and_implementation_fields_fail_schema(self):
        for index, field in enumerate(("root_cause_id", "causal_confidence", "finding_priority", "approved_intervention", "deployment_instruction")):
            raw = self.raw_record(key=f"phase5b-boundary-field-000{index+1}"); raw["payload"][field] = "forbidden"
            self.assert_rejected_without_effect(raw)

    def test_record_replay_conflict_and_identity_uniqueness(self):
        raw = self.record()
        before = copy.deepcopy((self.store.oia_observations, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "DUPLICATE")
        self.assertEqual((self.store.oia_observations, self.store.events, self.store.outbox), before)
        changed = copy.deepcopy(raw); changed["payload"]["observed_condition"] = "A changed semantic condition."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        changed_identity = copy.deepcopy(raw)
        changed_identity["subject_id"] = self.third_id
        changed_identity["payload"]["oia_observation_id"] = self.third_id
        self.assertEqual(self.executor.execute(changed_identity, self.context())["result"], "CONFLICT")
        self.base.evidence(self.second_evidence_id)
        changed_evidence = copy.deepcopy(raw)
        changed_evidence["payload"]["evidence_ids"] = [self.second_evidence_id]
        self.assertEqual(self.executor.execute(changed_evidence, self.context())["result"], "CONFLICT")
        duplicate_identity = self.raw_record(key="phase5b-different-key-same-observation-0001", command_id="d2000000-0000-4000-8000-000000000099")
        self.assert_rejected_without_effect(duplicate_identity)

    def test_supersede_happy_path_preserves_history_evidence_and_read_resolution(self):
        self.record(); self.record(self.replacement_id)
        evidence_before = copy.deepcopy(self.store.oia_evidence_items)
        raw = self.raw_supersede()
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        repository = UnitOfWork(self.store).oia_observations
        original = repository.get(self.base.tenant, self.observation_id)
        self.assertEqual((original["state"], original["record_version"], original["superseded_by_observation_id"]), ("SUPERSEDED", 2, self.replacement_id))
        self.assertEqual(repository.resolve_current(self.base.tenant, self.observation_id)["oia_observation_id"], self.replacement_id)
        self.assertEqual(len(repository.list_by_assessment(self.base.tenant, self.base.assessment_id)), 2)
        self.assertEqual(len(repository.list_current_by_assessment(self.base.tenant, self.base.assessment_id)), 1)
        self.assertEqual(self.store.oia_evidence_items, evidence_before)
        self.assertEqual((self.store.events[-1]["event_type"], self.store.outbox[-1]["status"]), ("oia.observation_superseded", "PENDING"))
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value:isinstance(value,str) and value.endswith("Z"))
        observation_schema = registry.expanded("urn:avuhz:schema:contracts:domain:oia-observation:v1")
        event_schema = registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")
        self.assertFalse(list(Draft202012Validator(observation_schema, format_checker=formatter).iter_errors(original)))
        self.assertFalse(list(Draft202012Validator(observation_schema, format_checker=formatter).iter_errors(repository.get(self.base.tenant, self.replacement_id))))
        self.assertFalse(list(Draft202012Validator(event_schema, format_checker=formatter).iter_errors(self.store.events[-1])))

    def test_supersede_rejects_closed_assessment_and_cross_assessment_replacement(self):
        self.record(); self.record(self.replacement_id)
        replacement_key = (self.base.tenant, self.replacement_id)
        replacement = self.store.oia_observations[replacement_key]
        replacement["oia_assessment_id"] = self.base.other_assessment_id
        self.assert_rejected_without_effect(
            self.raw_supersede(key="phase5b-supersede-cross-assessment-0001")
        )
        replacement["oia_assessment_id"] = self.base.assessment_id
        self.store.oia_assessments[(self.base.tenant, self.base.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(
            self.raw_supersede(key="phase5b-supersede-closed-assessment-0001")
        )

    def test_supersede_unknown_cross_tenant_terminal_and_workload_are_rejected(self):
        self.record(); self.record(self.replacement_id)
        self.assert_rejected_without_effect(self.raw_supersede(original=self.third_id, key="phase5b-supersede-unknown-0001"))
        self.assert_rejected_without_effect(self.raw_supersede(tenant=self.base.other_tenant, key="phase5b-supersede-cross-tenant-0001"), self.context(tenant=self.base.other_tenant))
        self.assert_rejected_without_effect(self.raw_supersede(caller_type="INTERNAL_SERVICE", key="phase5b-supersede-workload-0001"), self.context("INTERNAL_SERVICE"))
        accepted = self.raw_supersede(); self.assertEqual(self.executor.execute(accepted, self.context())["result"], "ACCEPTED")
        self.record(self.third_id)
        self.assert_rejected_without_effect(self.raw_supersede(replacement=self.third_id, expected=2, key="phase5b-supersede-terminal-0001"))

    def test_supersede_replay_and_same_key_conflict(self):
        self.record(); self.record(self.replacement_id); self.record(self.third_id)
        raw = self.raw_supersede(); self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        before = copy.deepcopy((self.store.oia_observations, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(raw); changed["payload"]["replacement_oia_observation_id"] = self.third_id
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((self.store.oia_observations, self.store.events, self.store.outbox), before)

    def test_record_and_supersede_failpoints_roll_back_all_effects(self):
        stages = ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT")
        for stage in stages:
            with self.subTest(command="record", stage=stage):
                self.setUp(); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_observations, self.store.events, self.store.outbox, self.store.idempotency))
                self.assertEqual(self.executor.execute(self.raw_record(key=f"phase5b-record-fail-{stage.lower()}"), self.context())["result"], "REJECTED")
                self.assertEqual((self.store.oia_observations, self.store.events, self.store.outbox, self.store.idempotency), before)
            with self.subTest(command="supersede", stage=stage):
                self.setUp(); self.record(); self.record(self.replacement_id); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_observations, self.store.events, self.store.outbox, self.store.idempotency))
                self.assertEqual(self.executor.execute(self.raw_supersede(key=f"phase5b-supersede-fail-{stage.lower()}"), self.context())["result"], "REJECTED")
                self.assertEqual((self.store.oia_observations, self.store.events, self.store.outbox, self.store.idempotency), before)


if __name__ == "__main__":
    unittest.main()
