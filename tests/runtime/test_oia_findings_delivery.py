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
from tests.runtime import test_oia_finding as finding_module


class OIAFindingsDeliveryRuntimeTests(unittest.TestCase):
    delivery_id = "f4000000-0000-4000-8000-000000000001"
    second_delivery_id = "f4000000-0000-4000-8000-000000000002"
    replacement_finding_id = "f4000000-0000-4000-8000-000000000003"
    unknown_id = "f4000000-0000-4000-8000-000000000099"

    def setUp(self):
        base = finding_module.OIAFindingRuntimeTests()
        base.setUp(); base.create(); base.finalize()
        self.base = base
        self.store = base.store
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: base.base.base.base.now,
            ids=iter((f"f4000000-0000-4000-8000-{value:012d}" for value in range(100, 999))).__next__,
        )

    @property
    def tenant(self): return self.base.tenant
    @property
    def engagement_id(self): return self.base.engagement_id
    @property
    def assessment_id(self): return self.base.assessment_id
    @property
    def finding_id(self): return self.base.finding_id
    @property
    def grant_id(self): return self.base.base.base.base.grant_id
    @property
    def now(self): return self.base.base.base.base.now

    def context(self, command_type, caller_type="HUMAN", tenant=None):
        capability = {
            "MarkOIAAssessmentReadyForDelivery": "oia:assessment:review",
            "DeliverOIAFindings": "oia:findings:deliver",
            "ReviseDeliveredOIAFinding": "oia:finding:finalize",
            "CloseOIAAssessment": "oia:assessment:close",
        }[command_type]
        human = caller_type == "HUMAN"
        principal = "human.reviewer-001" if human else "workload.delivery-001"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({capability}), frozenset(), "TEST", "avuhz-command-api",
            "STRONG", False, "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
            "human.reviewer-001" if human else None,
            "organization.sekinfra" if human else None,
        )

    def assessment(self):
        return UnitOfWork(self.store).oia_assessments.get(self.tenant, self.assessment_id)

    def finding(self, finding_id=None, revision=None):
        repo = UnitOfWork(self.store).oia_findings
        return repo.get_revision(self.tenant, finding_id or self.finding_id, revision) if revision else repo.get(self.tenant, finding_id or self.finding_id)

    def delivery(self, delivery_id=None):
        return UnitOfWork(self.store).oia_findings_deliveries.get(self.tenant, delivery_id or self.delivery_id)

    def raw(self, command_type, payload, expected, key=None, command_id=None,
            tenant=None, engagement=None, caller_type="HUMAN"):
        tenant = tenant or self.tenant
        schemas = {
            "MarkOIAAssessmentReadyForDelivery": "mark-oia-assessment-ready-for-delivery-payload",
            "DeliverOIAFindings": "deliver-oia-findings-payload",
            "ReviseDeliveredOIAFinding": "revise-delivered-oia-finding-payload",
            "CloseOIAAssessment": "close-oia-assessment-payload",
        }
        capability = {
            "MarkOIAAssessmentReadyForDelivery": "oia:assessment:review",
            "DeliverOIAFindings": "oia:findings:deliver",
            "ReviseDeliveredOIAFinding": "oia:finding:finalize",
            "CloseOIAAssessment": "oia:assessment:close",
        }[command_type]
        if command_type == "DeliverOIAFindings":
            subject_type, subject_id = "OIA_FINDINGS_DELIVERY", payload["oia_findings_delivery_id"]
        elif command_type == "ReviseDeliveredOIAFinding":
            subject_type, subject_id = "OIA_FINDING", payload["oia_finding_id"]
        else:
            subject_type, subject_id = "OIA_ASSESSMENT", payload["oia_assessment_id"]
        principal = "human.reviewer-001" if caller_type == "HUMAN" else "workload.delivery-001"
        return {
            "command_id": command_id or "f4000000-0000-4000-8000-000000000010",
            "command_type": command_type, "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": engagement or self.engagement_id,
            "subject_type": subject_type, "subject_id": subject_id,
            "expected_record_version": expected,
            "requested_by": principal, "caller_type": caller_type,
            "caller_identity": {
                "subject": principal, "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": [capability], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "f4000000-0000-4000-8000-000000000011",
            "idempotency_key": key or f"phase5b-2f-{command_type.lower()}-0001",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{schemas[command_type]}:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }

    def ready_raw(self, expected=1, key="phase5b-2f-ready-0001", **kwargs):
        return self.raw("MarkOIAAssessmentReadyForDelivery", {"oia_assessment_id": self.assessment_id}, expected, key, **kwargs)

    def ready(self, **kwargs):
        raw = self.ready_raw(**kwargs)
        self.assertEqual(self.executor.execute(raw, self.context("MarkOIAAssessmentReadyForDelivery"))["result"], "ACCEPTED")
        return raw

    def delivery_payload(self, delivery_id=None, finding=None, ready_version=None):
        if finding is None:
            findings = UnitOfWork(self.store).oia_findings.list_current_by_assessment(
                self.tenant, self.assessment_id
            )
            finding = findings[0] if findings else None
        if finding is None:
            raise AssertionError("test setup has no current Finding")
        return {
            "oia_findings_delivery_id": delivery_id or self.delivery_id,
            "oia_assessment_id": self.assessment_id,
            "ready_record_version": ready_version or self.assessment()["record_version"],
            "finding_revisions": [{
                "oia_finding_id": finding["oia_finding_id"],
                "finding_revision": finding["finding_revision"],
                "content_digest": finding["content_digest"],
            }],
            "client_recipient_reference": "client-authority-001",
            "delivery_channel_reference": "portal-delivery-001",
        }

    def deliver(self, delivery_id=None, key="phase5b-2f-deliver-0001"):
        payload = self.delivery_payload(delivery_id)
        raw = self.raw("DeliverOIAFindings", payload, payload["ready_record_version"], key)
        self.assertEqual(self.executor.execute(raw, self.context("DeliverOIAFindings"))["result"], "ACCEPTED")
        return raw

    def revise(self, key="phase5b-2f-correction-0001"):
        payload = {
            "oia_finding_id": self.finding_id,
            "delivered_finding_revision": 1,
            "replacement_oia_finding_id": self.replacement_finding_id,
        }
        raw = self.raw("ReviseDeliveredOIAFinding", payload, 1, key)
        self.assertEqual(self.executor.execute(raw, self.context("ReviseDeliveredOIAFinding"))["result"], "ACCEPTED")
        return raw

    def close(self, key="phase5b-2f-close-0001"):
        raw = self.raw("CloseOIAAssessment", {"oia_assessment_id": self.assessment_id}, self.assessment()["record_version"], key)
        self.assertEqual(self.executor.execute(raw, self.context("CloseOIAAssessment"))["result"], "ACCEPTED")
        return raw

    def assert_rejected_without_effect(self, raw, context=None):
        before = copy.deepcopy((self.store.oia_assessments, self.store.oia_findings, self.store.oia_findings_deliveries, self.store.grants, self.store.events, self.store.outbox, self.store.idempotency))
        result = self.executor.execute(raw, context or self.context(raw["command_type"]))
        self.assertIn(result["result"], ("REJECTED", "VALIDATION_FAILED"))
        self.assertEqual((self.store.oia_assessments, self.store.oia_findings, self.store.oia_findings_deliveries, self.store.grants, self.store.events, self.store.outbox, self.store.idempotency), before)
        return result

    def assert_events_schema_valid(self):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker()
        formatter.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
        validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"),
            format_checker=formatter,
        )
        for event in self.store.events:
            self.assertFalse(list(validator.iter_errors(event)))

    def test_ready_happy_path_is_human_derived_and_schema_valid(self):
        self.ready()
        assessment = self.assessment()
        self.assertEqual((assessment["state"], assessment["record_version"], assessment["ready_for_delivery_at"]), ("READY_FOR_DELIVERY", 2, self.now))
        self.assertEqual((self.store.events[0]["event_type"], self.store.outbox[0]["status"]), ("oia.assessment_ready_for_delivery", "PENDING"))
        self.assertEqual(self.store.oia_findings_deliveries, {})
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        self.assertFalse(list(Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-assessment:v1")).iter_errors(assessment)))

    def test_ready_negatives_and_authority_fail_closed(self):
        self.store.oia_findings[(self.tenant, self.finding_id, 1)]["state"] = "DRAFT"
        self.assert_rejected_without_effect(self.ready_raw(key="phase5b-2f-ready-draft-0001"))
        self.setUp(); item = next(iter(self.store.oia_inspection_items.values())); item["coverage_state"] = "IN_PROGRESS"
        self.assert_rejected_without_effect(self.ready_raw(key="phase5b-2f-ready-unresolved-0001"))
        self.setUp(); raw = self.ready_raw(key="phase5b-2f-ready-workload-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(raw, self.context("MarkOIAAssessmentReadyForDelivery", "INTERNAL_SERVICE"))
        self.setUp(); other = self.base.base.base.base.other_tenant; raw = self.ready_raw(key="phase5b-2f-ready-cross-tenant-0001", tenant=other)
        self.assert_rejected_without_effect(raw, self.context("MarkOIAAssessmentReadyForDelivery", tenant=other))
        self.setUp(); result = self.assert_rejected_without_effect(self.ready_raw(expected=99, key="phase5b-2f-ready-stale-0001")); self.assertEqual(result["reason_code"], "VERSION_STALE")

    def test_delivery_happy_path_manifest_events_access_and_reads(self):
        diagnostic_before = copy.deepcopy((self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes, self.store.oia_findings))
        grant_before = copy.deepcopy(self.store.grants[(self.tenant, self.grant_id)])
        self.ready(); self.deliver()
        delivery = self.delivery(); assessment = self.assessment(); grant = self.store.grants[(self.tenant, self.grant_id)]
        self.assertEqual((assessment["state"], assessment["record_version"], assessment["findings_delivery_id"]), ("FINDINGS_DELIVERED", 3, self.delivery_id))
        self.assertEqual((delivery["delivery_sequence"], delivery["delivered_by"]), (1, "human.reviewer-001"))
        self.assertEqual(delivery["finding_revisions"][0]["content_digest"], self.finding()["content_digest"])
        self.assertTrue(delivery["manifest_digest"].startswith("sha256:"))
        self.assertEqual((grant["status"], grant["closure_reason"]), ("CLOSED", "FINDINGS_DELIVERED"))
        for field in ("active_from", "expires_at", "verified_at", "source_assessment_access_proposal_reference"):
            if field in grant_before:
                self.assertEqual(grant[field], grant_before[field])
        self.assertEqual([event["event_type"] for event in self.store.events], ["oia.assessment_ready_for_delivery", "oia.findings_delivered", "assessment_access.closed"])
        self.assertEqual(len(self.store.outbox), 3)
        self.assertEqual((self.store.oia_evidence_items, self.store.oia_observations, self.store.oia_root_causes, self.store.oia_findings), diagnostic_before)
        uow = UnitOfWork(self.store)
        status = uow.oia_findings_deliveries.status_view(self.tenant, self.assessment_id, assessment["state"], self.now)
        assessment_view = uow.oia_assessments.status_view(self.tenant, self.assessment_id, self.now)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
        for schema_id, value in (("urn:avuhz:schema:contracts:domain:oia-findings-delivery:v1", delivery), ("urn:avuhz:schema:contracts:read-models:oia-findings-delivery-status-view:v1", status), ("urn:avuhz:schema:contracts:read-models:oia-assessment-status-view:v1", assessment_view)):
            self.assertFalse(list(Draft202012Validator(registry.expanded(schema_id), format_checker=formatter).iter_errors(value)))
        event_schema = registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")
        for event in self.store.events:self.assertFalse(list(Draft202012Validator(event_schema, format_checker=formatter).iter_errors(event)))

    def test_delivery_after_expiry_preserves_terminal_access(self):
        grant = self.store.grants[(self.tenant, self.grant_id)]; grant["status"] = "EXPIRED"; grant["expires_at"] = self.now
        before = copy.deepcopy(grant)
        self.ready(); self.deliver()
        self.assertEqual(self.store.grants[(self.tenant, self.grant_id)], before)
        self.assertEqual([event["event_type"] for event in self.store.events], ["oia.assessment_ready_for_delivery", "oia.findings_delivered"])

    def test_delivery_rejects_stale_tampered_nonfinal_cherry_pick_and_spoof(self):
        self.ready(); payload = self.delivery_payload(); payload["finding_revisions"][0]["finding_revision"] = 99
        self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-stale-finding-0001"))
        payload = self.delivery_payload(); payload["finding_revisions"][0]["content_digest"] = "sha256:" + "f" * 64
        self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-tamper-0001"))
        payload = self.delivery_payload(); payload["finding_revisions"] = []
        self.assertEqual(self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-empty-0001"))["result"], "VALIDATION_FAILED")
        payload = self.delivery_payload(); payload["priority_override"] = "CRITICAL"
        self.assertEqual(self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-priority-spoof-0001"))["result"], "VALIDATION_FAILED")
        self.store.oia_findings[(self.tenant, self.finding_id, 1)]["state"] = "DRAFT"
        self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", self.delivery_payload(finding=self.store.oia_findings[(self.tenant, self.finding_id, 1)]), 2, "phase5b-2f-deliver-draft-0001"))
        self.setUp(); self.ready(); self.store.oia_findings[(self.tenant, self.finding_id, 1)]["state"] = "SUPERSEDED"
        payload = {"oia_findings_delivery_id":self.delivery_id,"oia_assessment_id":self.assessment_id,"ready_record_version":2,"finding_revisions":[{"oia_finding_id":self.finding_id,"finding_revision":1,"content_digest":"sha256:"+"a"*64}],"client_recipient_reference":"client-authority-001","delivery_channel_reference":"portal-delivery-001"}
        self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-superseded-0001"))

    def test_workload_delivery_and_role_spoofing_fail_closed(self):
        self.ready(); payload = self.delivery_payload()
        raw = self.raw("DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-workload-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(raw, self.context("DeliverOIAFindings", "INTERNAL_SERVICE"))
        for index, field in enumerate(("delivered_by", "human_approved", "client_accepted", "delivery_authorized"), 1):
            changed = self.delivery_payload(); changed[field] = "spoofed"
            result = self.assert_rejected_without_effect(self.raw("DeliverOIAFindings", changed, 2, f"phase5b-2f-delivery-role-spoof-{index:04d}"))
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_correction_update_finalize_and_redelivery_preserve_both_histories(self):
        self.ready(); self.deliver(); first = copy.deepcopy(self.delivery()); self.revise()
        original = self.finding(self.finding_id, 1); replacement = self.finding(self.replacement_finding_id)
        self.assertEqual((original["state"], replacement["state"], replacement["finding_revision"], self.assessment()["state"]), ("SUPERSEDED", "DRAFT", 2, "READY_FOR_DELIVERY"))
        changed = self.base.payload(finding_id=self.replacement_finding_id); changed.pop("oia_assessment_id"); changed["summary"] += " Corrected."
        update = self.base.raw("UpdateOIAFindingAnalysis", changed, 2, "phase5b-2f-correction-update-0001")
        self.assertEqual(self.base.executor.execute(update, self.base.context("UpdateOIAFindingAnalysis"))["result"], "ACCEPTED")
        final = self.base.raw("FinalizeOIAFinding", {"oia_finding_id":self.replacement_finding_id,"finding_revision":3}, 3, "phase5b-2f-correction-finalize-0001")
        self.assertEqual(self.base.executor.execute(final, self.base.context("FinalizeOIAFinding"))["result"], "ACCEPTED")
        self.deliver(self.second_delivery_id, "phase5b-2f-redeliver-0001")
        history = UnitOfWork(self.store).oia_findings_deliveries.list_by_assessment(self.tenant, self.assessment_id)
        self.assertEqual([delivery["delivery_sequence"] for delivery in history], [1, 2])
        self.assertEqual(history[0], first)
        self.assertEqual(history[1]["finding_revisions"][0]["oia_finding_id"], self.replacement_finding_id)
        self.assertEqual(self.finding(self.finding_id, 1)["state"], "SUPERSEDED")
        self.assertEqual(self.finding(self.replacement_finding_id)["state"], "FINAL")
        self.assertEqual(self.assessment()["state"], "FINDINGS_DELIVERED")
        self.assert_events_schema_valid()

    def test_close_happy_path_is_terminal_and_human_authoritative(self):
        self.ready(); self.deliver(); close = self.close()
        self.assertEqual((self.assessment()["state"], self.assessment()["record_version"], self.assessment()["closed_at"]), ("CLOSED", 4, self.now))
        self.assertEqual(self.store.events[-1]["event_type"], "oia.assessment_closed")
        self.assertEqual(self.executor.execute(close, self.context("CloseOIAAssessment"))["result"], "DUPLICATE")
        changed = copy.deepcopy(close); changed["engagement_id"] = self.unknown_id
        self.assertEqual(self.executor.execute(changed, self.context("CloseOIAAssessment"))["result"], "CONFLICT")
        self.assertEqual(self.store.grants[(self.tenant, self.grant_id)]["closure_reason"], "FINDINGS_DELIVERED")
        self.assert_events_schema_valid()

    def test_close_before_delivery_pending_correction_and_workload_reject(self):
        raw = self.raw("CloseOIAAssessment", {"oia_assessment_id":self.assessment_id}, 1, "phase5b-2f-close-in-progress-0001")
        self.assert_rejected_without_effect(raw)
        self.ready(); raw = self.raw("CloseOIAAssessment", {"oia_assessment_id":self.assessment_id}, 2, "phase5b-2f-close-ready-0001")
        self.assert_rejected_without_effect(raw)
        self.setUp(); self.ready(); self.deliver(); self.revise(); raw = self.raw("CloseOIAAssessment", {"oia_assessment_id":self.assessment_id}, 4, "phase5b-2f-close-pending-correction-0001")
        self.assert_rejected_without_effect(raw)
        self.setUp(); self.ready(); self.deliver(); raw = self.raw("CloseOIAAssessment", {"oia_assessment_id":self.assessment_id}, 3, "phase5b-2f-close-workload-0001", caller_type="INTERNAL_SERVICE")
        self.assert_rejected_without_effect(raw, self.context("CloseOIAAssessment", "INTERNAL_SERVICE"))

    def test_replay_conflict_uniqueness_stale_and_arbitrary_reopen(self):
        ready = self.ready(); before = copy.deepcopy((self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(ready, self.context("MarkOIAAssessmentReadyForDelivery"))["result"], "DUPLICATE")
        changed = copy.deepcopy(ready); changed["engagement_id"] = self.unknown_id
        self.assertEqual(self.executor.execute(changed, self.context("MarkOIAAssessmentReadyForDelivery"))["result"], "CONFLICT")
        self.assertEqual((self.store.events, self.store.outbox), before)
        delivery = self.deliver(); before = copy.deepcopy((self.store.oia_findings_deliveries, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(delivery, self.context("DeliverOIAFindings"))["result"], "DUPLICATE")
        changed = copy.deepcopy(delivery); changed["payload"]["client_recipient_reference"] = "client-authority-002"
        self.assertEqual(self.executor.execute(changed, self.context("DeliverOIAFindings"))["result"], "CONFLICT")
        duplicate = copy.deepcopy(delivery); duplicate["idempotency_key"] = "phase5b-2f-duplicate-delivery-identity-0001"; duplicate["command_id"] = self.unknown_id
        self.assertEqual(self.executor.execute(duplicate, self.context("DeliverOIAFindings"))["result"], "REJECTED")
        self.assertEqual((self.store.oia_findings_deliveries, self.store.events, self.store.outbox), before)
        correction = self.revise(); before = copy.deepcopy((self.store.oia_findings, self.store.oia_assessments, self.store.events, self.store.outbox))
        self.assertEqual(self.executor.execute(correction, self.context("ReviseDeliveredOIAFinding"))["result"], "DUPLICATE")
        changed = copy.deepcopy(correction); changed["payload"]["replacement_oia_finding_id"] = self.unknown_id
        self.assertEqual(self.executor.execute(changed, self.context("ReviseDeliveredOIAFinding"))["result"], "CONFLICT")
        arbitrary = self.ready_raw(expected=4, key="phase5b-2f-arbitrary-reopen-0001")
        self.assert_rejected_without_effect(arbitrary)

    def test_cross_tenant_unknown_finding_and_stale_lifecycle_versions_reject(self):
        other = self.base.base.base.base.other_tenant
        self.ready()
        payload = self.delivery_payload()
        cross_tenant = self.raw(
            "DeliverOIAFindings", payload, 2, "phase5b-2f-deliver-cross-tenant-0001",
            tenant=other,
        )
        self.assert_rejected_without_effect(
            cross_tenant, self.context("DeliverOIAFindings", tenant=other)
        )
        unknown = self.delivery_payload()
        unknown["finding_revisions"][0]["oia_finding_id"] = self.unknown_id
        self.assert_rejected_without_effect(
            self.raw("DeliverOIAFindings", unknown, 2, "phase5b-2f-deliver-unknown-finding-0001")
        )
        stale = self.delivery_payload(ready_version=99)
        result = self.assert_rejected_without_effect(
            self.raw("DeliverOIAFindings", stale, 99, "phase5b-2f-deliver-stale-assessment-0001")
        )
        self.assertEqual(result["reason_code"], "VERSION_STALE")

        self.deliver()
        stale_correction = {
            "oia_finding_id": self.finding_id,
            "delivered_finding_revision": 99,
            "replacement_oia_finding_id": self.replacement_finding_id,
        }
        result = self.assert_rejected_without_effect(
            self.raw("ReviseDeliveredOIAFinding", stale_correction, 99, "phase5b-2f-correction-stale-0001")
        )
        self.assertEqual(result["reason_code"], "VERSION_STALE")
        result = self.assert_rejected_without_effect(
            self.raw("CloseOIAAssessment", {"oia_assessment_id": self.assessment_id}, 99, "phase5b-2f-close-stale-0001")
        )
        self.assertEqual(result["reason_code"], "VERSION_STALE")

    def test_all_lifecycle_failpoints_roll_back_atomically(self):
        stages = ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT")
        for stage in stages:
            with self.subTest(command="ready", stage=stage):
                self.setUp(); self.store.fail_stage = stage
                before = copy.deepcopy(self.store.__dict__)
                self.assertEqual(self.executor.execute(self.ready_raw(key=f"phase5b-2f-ready-fail-{stage.lower()}"), self.context("MarkOIAAssessmentReadyForDelivery"))["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before)
            with self.subTest(command="delivery", stage=stage):
                self.setUp(); self.ready(); self.store.fail_stage = stage; payload = self.delivery_payload()
                before = copy.deepcopy(self.store.__dict__)
                raw = self.raw("DeliverOIAFindings", payload, 2, f"phase5b-2f-delivery-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(raw, self.context("DeliverOIAFindings"))["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before)
            with self.subTest(command="correction", stage=stage):
                self.setUp(); self.ready(); self.deliver(); self.store.fail_stage = stage
                before = copy.deepcopy(self.store.__dict__)
                payload = {"oia_finding_id":self.finding_id,"delivered_finding_revision":1,"replacement_oia_finding_id":self.replacement_finding_id}
                raw = self.raw("ReviseDeliveredOIAFinding", payload, 1, f"phase5b-2f-correction-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(raw, self.context("ReviseDeliveredOIAFinding"))["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before)
            with self.subTest(command="close", stage=stage):
                self.setUp(); self.ready(); self.deliver(); self.store.fail_stage = stage
                before = copy.deepcopy(self.store.__dict__)
                raw = self.raw("CloseOIAAssessment", {"oia_assessment_id":self.assessment_id}, 3, f"phase5b-2f-close-fail-{stage.lower()}")
                self.assertEqual(self.executor.execute(raw, self.context("CloseOIAAssessment"))["result"], "REJECTED")
                self.assertEqual(self.store.__dict__, before)


if __name__ == "__main__": unittest.main()
