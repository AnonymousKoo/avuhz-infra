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
from tests.runtime import test_oia_observation as observation_module


class OIARootCauseRuntimeTests(unittest.TestCase):
    root_id = "d3000000-0000-4000-8000-000000000001"
    second_root_id = "d3000000-0000-4000-8000-000000000002"
    unknown_observation_id = "d3000000-0000-4000-8000-000000000003"

    def setUp(self):
        base = observation_module.OIAObservationRuntimeTests()
        base.setUp()
        base.record()
        self.base = base
        self.store = base.store
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: base.base.now,
            ids=iter((f"d3000000-0000-4000-8000-{value:012d}" for value in range(100, 999))).__next__,
        )

    @property
    def tenant(self):
        return self.base.base.tenant

    @property
    def engagement_id(self):
        return self.base.base.engagement_id

    @property
    def assessment_id(self):
        return self.base.base.assessment_id

    @property
    def observation_id(self):
        return self.base.observation_id

    @property
    def evidence_id(self):
        return self.base.base.evidence_id

    def context(self, caller_type="HUMAN", tenant=None):
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, "human.analyst-001" if human else "workload.causal-suggester",
            caller_type, tenant or self.tenant, None,
            frozenset({"oia:root_cause:record"}), frozenset(), "TEST",
            "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.analyst-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    def payload(self, confidence="HYPOTHESIS", root_id=None, observation_ids=None, evidence_ids=None):
        value = {
            "oia_root_cause_id": root_id or self.root_id,
            "oia_assessment_id": self.assessment_id,
            "cause_statement": "Ownership is not assigned when the original recipient does not respond.",
            "confidence": confidence,
            "supporting_observation_ids": list(observation_ids or [self.observation_id]),
        }
        if evidence_ids is not None:
            value["supporting_evidence_ids"] = list(evidence_ids)
        return value

    def raw(self, payload=None, expected=None, key="phase5b-root-cause-0001", command_id=None,
            tenant=None, engagement=None, caller_type="HUMAN"):
        payload = copy.deepcopy(payload or self.payload())
        tenant = tenant or self.tenant
        principal = "human.analyst-001" if caller_type == "HUMAN" else "workload.causal-suggester"
        value = {
            "command_id": command_id or "d3000000-0000-4000-8000-000000000010",
            "command_type": "RecordOIARootCause", "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.engagement_id,
            "subject_type": "OIA_ROOT_CAUSE", "subject_id": payload["oia_root_cause_id"],
            "requested_by": principal, "caller_type": caller_type,
            "caller_identity": {
                "subject": principal, "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": ["oia:root_cause:record"],
                "environment": "TEST", "authentication_strength": "STRONG",
                "step_up_performed": False, "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d3000000-0000-4000-8000-000000000011",
            "idempotency_key": key, "requested_at": self.base.base.now, "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:record-oia-root-cause-payload:v1",
            "payload_version": 1, "payload": payload,
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def execute(self, confidence="HYPOTHESIS", expected=None, key=None, payload=None, context=None):
        payload = copy.deepcopy(payload or self.payload(
            confidence,
            evidence_ids=None if confidence == "HYPOTHESIS" else [self.evidence_id],
        ))
        raw = self.raw(payload, expected, key or f"phase5b-root-{confidence.lower()}-0001")
        return raw, self.executor.execute(raw, context or self.context())

    def root(self, root_id=None, tenant=None):
        return UnitOfWork(self.store).oia_root_causes.get(
            tenant or self.tenant, root_id or self.root_id
        )

    def create(self):
        raw, result = self.execute()
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def support(self):
        raw, result = self.execute("SUPPORTED", 1, "phase5b-root-supported-0001")
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def verify(self):
        raw, result = self.execute("VERIFIED", 2, "phase5b-root-verified-0001")
        self.assertEqual(result["result"], "ACCEPTED")
        return raw

    def assert_rejected_without_effect(self, raw, context=None, validation_allowed=True):
        before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency))
        result = self.executor.execute(raw, context or self.context())
        allowed = ("REJECTED", "VALIDATION_FAILED") if validation_allowed else ("REJECTED",)
        self.assertIn(result["result"], allowed)
        self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency), before)
        return result

    def test_hypothesis_happy_path_contract_event_outbox_and_read(self):
        observation_before = copy.deepcopy(self.store.oia_observations)
        evidence_before = copy.deepcopy(self.store.oia_evidence_items)
        self.create()
        root = self.root()
        self.assertEqual((root["confidence"], root["record_version"], root["created_by"]),
                         ("HYPOTHESIS", 1, "human.analyst-001"))
        self.assertEqual(root["supporting_observation_ids"], [self.observation_id])
        self.assertNotIn("supporting_evidence_ids", root)
        self.assertEqual(self.store.oia_observations, observation_before)
        self.assertEqual(self.store.oia_evidence_items, evidence_before)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-root-cause:v1"), format_checker=formatter).iter_errors(root)))
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=formatter).iter_errors(self.store.events[0])))
        self.assertEqual((self.store.events[0]["event_type"], self.store.outbox[0]["status"]),
                         ("oia.root_cause_recorded", "PENDING"))
        self.assertEqual(set(self.store.events[0]["sanitized_metadata"]),
                         {"oia_assessment_id", "oia_root_cause_id", "record_version"})
        self.assertEqual(UnitOfWork(self.store).oia_root_causes.list_by_assessment(self.tenant, self.assessment_id), (root,))
        self.assertEqual(self.store.oia_findings, {})

    def test_supported_and_verified_happy_path_is_ordered_and_terminal(self):
        self.create(); self.support(); self.verify()
        root = self.root()
        self.assertEqual((root["confidence"], root["record_version"], root["supporting_evidence_ids"]),
                         ("VERIFIED", 3, [self.evidence_id]))
        self.assertEqual(self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"], "IN_PROGRESS")
        self.assertEqual([event["authoritative_subject_version"] for event in self.store.events], [1, 2, 3])
        self.assertEqual((len(self.store.events), len(self.store.outbox)), (3, 3))
        downgrade = self.raw(self.payload("HYPOTHESIS"), expected=3, key="phase5b-root-downgrade-0001")
        self.assert_rejected_without_effect(downgrade)

    def test_direct_hypothesis_to_verified_and_insufficient_support_are_rejected(self):
        self.create()
        direct = self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), expected=1,
                          key="phase5b-root-direct-verify-0001")
        self.assert_rejected_without_effect(direct)
        missing = self.raw(self.payload("SUPPORTED"), expected=1, key="phase5b-root-no-evidence-0001")
        self.assert_rejected_without_effect(missing)
        unknown = self.raw(self.payload("SUPPORTED", evidence_ids=["d3000000-0000-4000-8000-000000000099"]),
                           expected=1, key="phase5b-root-unknown-evidence-0001")
        self.assert_rejected_without_effect(unknown)

    def test_workload_cannot_create_support_or_verify_and_payload_roles_do_not_elevate(self):
        workload = self.context("INTERNAL_SERVICE")
        self.assert_rejected_without_effect(
            self.raw(caller_type="INTERNAL_SERVICE", key="phase5b-root-workload-create-0001"), workload
        )
        self.create()
        support = self.raw(self.payload("SUPPORTED", evidence_ids=[self.evidence_id]), expected=1,
                           key="phase5b-root-workload-support-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(support, workload)
        self.support()
        verify = self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), expected=2,
                          key="phase5b-root-workload-verify-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(verify, workload)
        for index, field in enumerate(("verified_by", "human_approved", "root_cause_verified", "reviewer_role"), 1):
            spoof = self.payload(); spoof[field] = "human.analyst-001"
            result = self.assert_rejected_without_effect(
                self.raw(spoof, key=f"phase5b-root-role-spoof-{index:04d}")
            )
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_unknown_and_cross_boundary_observations_are_rejected(self):
        unknown = self.raw(self.payload(observation_ids=[self.unknown_observation_id]), key="phase5b-root-unknown-observation-0001")
        self.assert_rejected_without_effect(unknown)
        source = copy.deepcopy(self.store.oia_observations[(self.tenant, self.observation_id)])
        other_tenant = self.base.base.other_tenant
        self.store.oia_observations[(other_tenant, self.observation_id)] = {**source, "tenant_id": other_tenant}
        self.assert_rejected_without_effect(
            self.raw(tenant=other_tenant, key="phase5b-root-cross-tenant-observation-0001"),
            self.context(tenant=other_tenant),
        )
        source["oia_assessment_id"] = self.base.base.other_assessment_id
        self.store.oia_observations[(self.tenant, self.observation_id)] = source
        self.assert_rejected_without_effect(self.raw(key="phase5b-root-cross-assessment-observation-0001"))
        self.setUp()
        self.assert_rejected_without_effect(
            self.raw(engagement="d3000000-0000-4000-8000-000000000090", key="phase5b-root-cross-engagement-observation-0001")
        )

    def test_multi_observation_support_validates_every_observation(self):
        self.base.record(self.base.replacement_id, key="phase5b-root-second-observation-0001")
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        multi = self.payload(observation_ids=[self.observation_id, self.base.replacement_id])
        self.assertEqual(self.executor.execute(self.raw(multi, key="phase5b-root-multi-observation-0001"), self.context())["result"], "ACCEPTED")
        support = self.payload("SUPPORTED", observation_ids=[self.observation_id, self.base.replacement_id], evidence_ids=[self.evidence_id])
        self.assertEqual(self.executor.execute(self.raw(support, 1, "phase5b-root-multi-support-0001"), self.context())["result"], "ACCEPTED")

    def test_superseded_observation_cannot_create_or_advance_but_history_is_preserved(self):
        self.base.record(self.base.replacement_id, key="phase5b-root-replacement-observation-0001")
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self.create()
        original_root = copy.deepcopy(self.root())
        supersede = self.base.raw_supersede(key="phase5b-root-supersede-source-0001")
        self.assertEqual(self.base.executor.execute(supersede, self.base.context())["result"], "ACCEPTED")
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self.assert_rejected_without_effect(
            self.raw(self.payload("SUPPORTED", evidence_ids=[self.evidence_id]), 1, "phase5b-root-superseded-advance-0001")
        )
        self.assertEqual(self.root(), original_root)
        new_root = self.payload(root_id=self.second_root_id)
        self.assert_rejected_without_effect(self.raw(new_root, key="phase5b-root-superseded-create-0001"))

    def test_contradictory_or_insufficient_governed_support_blocks_advancement(self):
        for index, sufficiency in enumerate((
            self.base.base.sufficiency("PARTIAL", missing=True),
            self.base.base.sufficiency("CONTRADICTORY", contradiction="UNRESOLVED", missing=True),
        ), 1):
            with self.subTest(case=index):
                self.setUp(); self.create()
                item = self.store.oia_inspection_items[(self.tenant, self.base.base.item_id)]
                item["coverage_state"] = "PARTIALLY_EVIDENCED"
                item["sufficiency_evaluation"] = sufficiency
                advance = self.raw(self.payload("SUPPORTED", evidence_ids=[self.evidence_id]), 1,
                                   f"phase5b-root-unsupported-causal-{index:04d}")
                self.assert_rejected_without_effect(advance)

        self.setUp(); self.create(); self.support()
        item = self.store.oia_inspection_items[(self.tenant, self.base.base.item_id)]
        item["coverage_state"] = "PARTIALLY_EVIDENCED"
        item["sufficiency_evaluation"] = self.base.base.sufficiency(
            "CONTRADICTORY", contradiction="UNRESOLVED", missing=True
        )
        verify = self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), 2,
                          "phase5b-root-contradicted-verify-0001")
        self.assert_rejected_without_effect(verify)

    def test_human_interview_alone_cannot_verify_causation(self):
        evidence = self.store.oia_evidence_items[(self.tenant, self.evidence_id)]
        evidence["evidence_type"] = "HUMAN_INTERVIEW_CORROBORATION"
        self.create(); self.support()
        before = copy.deepcopy(self.root())
        verify = self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), 2,
                          "phase5b-root-interview-only-verify-0001")
        self.assert_rejected_without_effect(verify)
        self.assertEqual(self.root(), before)

    def test_closed_assessment_rejects_create_support_and_verify(self):
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(self.raw(key="phase5b-root-closed-create-0001"))
        self.setUp(); self.create()
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(self.raw(self.payload("SUPPORTED", evidence_ids=[self.evidence_id]), 1, "phase5b-root-closed-support-0001"))
        self.setUp(); self.create(); self.support()
        self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"] = "CLOSED"
        self.assert_rejected_without_effect(self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), 2, "phase5b-root-closed-verify-0001"))

    def test_existing_analysis_survives_access_expiry_and_payment_invalidation(self):
        for index, expires_at in enumerate((self.base.base.now, "2030-01-15T14:59:59Z"), 1):
            with self.subTest(expires_at=expires_at):
                if index > 1:
                    self.setUp()
                grant_key = (self.tenant, self.base.base.grant_id)
                grant = self.store.grants[grant_key]
                grant["status"] = "EXPIRED"; grant["expires_at"] = expires_at
                self.store.payments[self.base.base.payment_id]["verification_status"] = "INVALIDATED"
                before = copy.deepcopy((self.store.grants, self.store.payments, self.store.oia_evidence_items, self.store.oia_observations))
                self.create(); self.support(); self.verify()
                self.assertEqual(self.root()["confidence"], "VERIFIED")
                self.assertEqual((self.store.grants, self.store.payments, self.store.oia_evidence_items, self.store.oia_observations), before)

    def test_create_support_and_verify_replay_conflict_and_identity_uniqueness(self):
        create = self.create()
        before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(create, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(create); changed["payload"]["cause_statement"] += " Changed."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        duplicate_identity = copy.deepcopy(create); duplicate_identity["idempotency_key"] = "phase5b-root-new-key-same-id-0001"
        duplicate_identity["command_id"] = "d3000000-0000-4000-8000-000000000020"
        self.assertEqual(self.executor.execute(duplicate_identity, self.context())["result"], "REJECTED")
        self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox), before)
        support = self.support(); before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(support, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(support); changed["payload"]["cause_statement"] += " Changed."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox), before)
        verify = self.verify(); before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(verify, self.context())["result"], "DUPLICATE")
        changed = copy.deepcopy(verify); changed["payload"]["cause_statement"] += " Changed."
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox), before)

    def test_stale_version_and_semantic_revision_fail_closed(self):
        self.create()
        stale = self.raw(self.payload("SUPPORTED", evidence_ids=[self.evidence_id]), 99, "phase5b-root-stale-0001")
        result = self.assert_rejected_without_effect(stale, validation_allowed=False)
        self.assertEqual(result["reason_code"], "VERSION_STALE")
        changed = self.payload("SUPPORTED", evidence_ids=[self.evidence_id]); changed["cause_statement"] += " Rewritten."
        self.assert_rejected_without_effect(self.raw(changed, 1, "phase5b-root-rewrite-0001"))
        removed = self.payload("SUPPORTED", observation_ids=[self.base.replacement_id], evidence_ids=[self.evidence_id])
        self.assert_rejected_without_effect(self.raw(removed, 1, "phase5b-root-remove-support-0001"))

    def test_uncontracted_reasoning_finding_and_intervention_fields_are_rejected(self):
        fields = ("alternative_explanations", "limitations", "rationale", "finding_priority", "intervention", "deployment_instruction")
        for index, field in enumerate(fields, 1):
            payload = self.payload(); payload[field] = ["bounded"] if field in ("alternative_explanations", "limitations") else "not permitted"
            result = self.assert_rejected_without_effect(self.raw(payload, key=f"phase5b-root-boundary-{index:04d}"))
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_create_and_verify_failpoints_roll_back_every_atomic_component(self):
        stages = ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT")
        for stage in stages:
            with self.subTest(command="create", stage=stage):
                self.setUp(); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency))
                self.assertEqual(self.executor.execute(self.raw(key=f"phase5b-root-create-fail-{stage.lower()}"), self.context())["result"], "REJECTED")
                self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency), before)
            with self.subTest(command="verify", stage=stage):
                self.setUp(); self.create(); self.support(); self.store.fail_stage = stage
                before = copy.deepcopy((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency))
                verify = self.raw(self.payload("VERIFIED", evidence_ids=[self.evidence_id]), 2,
                                  f"phase5b-root-verify-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(verify, self.context())["result"], "REJECTED")
                self.assertEqual((self.store.oia_root_causes, self.store.events, self.store.outbox, self.store.idempotency), before)


if __name__ == "__main__":
    unittest.main()
