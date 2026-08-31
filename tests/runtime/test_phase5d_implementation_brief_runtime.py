"""Phase 5D-B1 ImplementationBrief runtime, authority, and atomicity coverage."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from types import SimpleNamespace
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.implementation_handoff import ImplementationHandoffAcceptanceService, canonical_digest, handoff_reference
from avuhz_runtime.phase5d_brief import (
    IMPLEMENTATION_BRIEF_CAPABILITIES,
    ImplementationBriefReadService,
    implementation_brief_digest,
    implementation_brief_source_truth_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


BRIEF_ID = "d5100000-0000-4000-8000-000000000001"
FOREIGN_TENANT = "d5100000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
    return Draft202012Validator(registry.expanded(schema_id), format_checker=FormatChecker())


class ImplementationBriefRuntimeTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json").read_text())
        self.handoff = copy.deepcopy(fixture["positive"]["implementation_handoff"])
        self.store = MemoryStore()
        self.h = SimpleNamespace(now="2030-01-15T14:00:00Z")
        self._tenant = self.handoff["tenant_id"]
        self._engagement_id = self.handoff["source_engagement_reference"]
        uow = UnitOfWork(self.store)
        ImplementationHandoffAcceptanceService(uow).accept(self.handoff, self.handoff_context())
        uow.commit()
        self._number = 500
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.h.now, ids=self.next_id,
        )

    def handoff_context(self, tenant=None):
        return TrustedExecutionContext(
            True, "provider-adapter.fictional", "PROVIDER_ADAPTER", tenant or self._tenant,
            None, frozenset({"implementation_handoff:accept"}), frozenset(), "TEST",
            "avuhz-command-api", "STRONG", False, self.h.now, "2030-03-15T16:00:00Z",
        )

    @property
    def tenant(self):
        return self._tenant

    @property
    def engagement_id(self):
        return self._engagement_id

    def next_id(self):
        self._number += 1
        return f"d5190000-0000-4000-8000-{self._number:012d}"

    def context(self, command, *, caller_type=None, role=None, tenant=None, principal=None):
        caller_type = caller_type or (
            "HUMAN" if command == "RecordImplementationBriefApproval" else "INTERNAL_SERVICE"
        )
        principal = principal or (
            "human.client-implementation" if role == "CLIENT_IMPLEMENTATION_AUTHORITY"
            else "human.provider-implementation" if caller_type == "HUMAN"
            else "service.phase5d-brief"
        )
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({IMPLEMENTATION_BRIEF_CAPABILITIES[command]}),
            frozenset({role} if role else ()), "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if human else None,
            "organization.client" if role == "CLIENT_IMPLEMENTATION_AUTHORITY"
            else "organization.provider" if human else None,
            role,
        )

    def raw(self, command, payload, *, expected=None, key=None, command_id=None,
            caller_type=None, tenant=None, engagement=None):
        schemas = {
            "DraftImplementationBrief": "draft-implementation-brief",
            "ReviseImplementationBrief": "revise-implementation-brief",
            "RecordImplementationBriefApproval": "record-implementation-brief-approval",
            "ApproveImplementationBrief": "approve-implementation-brief",
        }
        caller_type = caller_type or (
            "HUMAN" if command == "RecordImplementationBriefApproval" else "INTERNAL_SERVICE"
        )
        tenant = tenant or self.tenant
        value = {
            "command_id": command_id or self.next_id(), "command_type": command,
            "command_schema_version": 1, "tenant_id": tenant,
            "engagement_id": engagement or self.engagement_id,
            "subject_type": "IMPLEMENTATION_BRIEF",
            "subject_id": payload.get("implementation_brief_id", BRIEF_ID),
            "requested_by": "trusted.phase5d", "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d", "audience": "avuhz-command-api",
                "caller_type": caller_type, "tenant_ids": [tenant],
                "capabilities": [IMPLEMENTATION_BRIEF_CAPABILITIES[command]],
                "environment": "TEST", "authentication_strength": "STRONG",
                "step_up_performed": False, "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5100000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5d-{command.lower()}-0001",
            "requested_at": self.h.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{schemas[command]}-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def payload(self, *, brief_id=BRIEF_ID, version=1):
        fixture = json.loads(
            (ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json").read_text()
        )["positive"]["implementation_brief"]
        omit = {
            "tenant_id", "engagement_id", "state", "client_approval_reference",
            "provider_approval_reference", "trusted_attribution", "approved_at",
            "record_version", "created_at", "updated_at",
        }
        payload = {key: copy.deepcopy(value) for key, value in fixture.items() if key not in omit}
        payload["implementation_brief_id"] = brief_id
        payload["implementation_brief_version"] = version
        if version > 1:
            payload["supersedes_implementation_brief_reference"] = {
                "reference_type": "IMPLEMENTATION_BRIEF", "reference_id": brief_id,
                "reference_version": version - 1,
            }
        payload["source_truth_digest"] = implementation_brief_source_truth_digest(payload)
        payload["implementation_brief_digest"] = implementation_brief_digest(payload)
        return payload

    def execute(self, command, payload, *, expected=None, role=None, caller_type=None,
                key=None, command_id=None):
        raw = self.raw(
            command, payload, expected=expected, caller_type=caller_type,
            key=key, command_id=command_id,
        )
        result = self.executor.execute(raw, self.context(command, caller_type=caller_type, role=role))
        self.assertEqual(result["result"], "ACCEPTED", (command, result))
        return raw

    def draft(self, payload=None, **kwargs):
        payload = payload or self.payload()
        return self.execute("DraftImplementationBrief", payload, **kwargs)

    def approve(self, payload):
        approval_ids = []
        for role, suffix in (
            ("CLIENT_IMPLEMENTATION_AUTHORITY", "client"),
            ("PROVIDER_IMPLEMENTATION_AUTHORITY", "provider"),
        ):
            command_id = self.next_id()
            self.execute(
                "RecordImplementationBriefApproval",
                {"subject_version": payload["implementation_brief_version"],
                 "authority_role": role, "authority_digest": payload["implementation_brief_digest"]},
                expected=1, role=role, command_id=command_id,
                key=f"phase5d-brief-approval-{suffix}-{payload['implementation_brief_version']}",
            )
            approval_ids.append(command_id)
        self.execute(
            "ApproveImplementationBrief",
            {
                "implementation_brief_id": payload["implementation_brief_id"],
                "implementation_brief_version": payload["implementation_brief_version"],
                "client_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL", "reference_id": approval_ids[0],
                    "reference_version": 1,
                },
                "provider_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL", "reference_id": approval_ids[1],
                    "reference_version": 1,
                },
                "implementation_brief_digest": payload["implementation_brief_digest"],
            }, expected=1,
            key=f"phase5d-brief-finalize-{payload['implementation_brief_version']}",
        )

    def assert_no_effects(self, before):
        self.assertEqual(
            (copy.deepcopy(self.store.implementation_briefs), copy.deepcopy(self.store.approvals),
             copy.deepcopy(self.store.events), copy.deepcopy(self.store.outbox),
             copy.deepcopy(self.store.idempotency)),
            before,
        )

    def test_happy_path_exact_sources_dual_human_approval_and_zero_authority(self):
        payload = self.payload()
        self.draft(payload)
        draft = UnitOfWork(self.store).implementation_briefs.get_version(self.tenant, BRIEF_ID, 1)
        self.assertEqual((draft["state"], draft["record_version"]), ("DRAFT", 1))
        self.assertEqual(draft["trusted_attribution"]["draft_assistance"], "AI_ASSISTED")
        self.approve(payload)
        uow = UnitOfWork(self.store)
        approved = uow.implementation_briefs.get_version(self.tenant, BRIEF_ID, 1)
        self.assertEqual((approved["state"], approved["record_version"]), ("APPROVED", 2))
        self.assertFalse(list(schema_validator(
            "urn:avuhz:schema:contracts:domain:implementation-brief:v1"
        ).iter_errors(approved)))
        readiness = ImplementationBriefReadService(uow).readiness(self.tenant, BRIEF_ID, 1, self.h.now)
        approval_validator = schema_validator(
            "urn:avuhz:schema:contracts:domain:human-approval:v1"
        )
        brief_approvals = [
            item for item in self.store.approvals.values()
            if item.get("subject_type") == "IMPLEMENTATION_BRIEF"
        ]
        self.assertEqual([list(approval_validator.iter_errors(item)) for item in brief_approvals], [[], []])
        self.assertTrue(readiness["implementation_brief_ready"])
        self.assertEqual(
            (readiness["implementation_authorized"], readiness["deployment_authorized"],
             readiness["production_change_authorized"]),
            (False, False, False),
        )
        self.assertFalse(list(schema_validator(
            "urn:avuhz:schema:contracts:read-models:implementation-brief-readiness-view:v1"
        ).iter_errors(readiness)))
        self.assertEqual(
            [event["event_type"] for event in self.store.events],
            ["implementation_brief.drafted", "implementation_brief.approval_recorded",
             "implementation_brief.approval_recorded", "implementation_brief.approved"],
        )
        event_validator = schema_validator(
            "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
        )
        self.assertTrue(all(not list(event_validator.iter_errors(event)) for event in self.store.events))
        self.assertTrue(all(intent == {"event_id": event["event_id"], "status": "PENDING"}
                            for intent, event in zip(self.store.outbox, self.store.events)))
        self.assertNotIn("implementation_authorization", self.store.__dict__)

    def test_revision_preserves_immutable_history_and_stale_write_fails(self):
        first = self.payload()
        self.draft(first)
        second = self.payload(version=2)
        denied = self.executor.execute(
            self.raw("ReviseImplementationBrief", second, expected=1,
                     key="phase5d-draft-revision-denied-0001"),
            self.context("ReviseImplementationBrief"),
        )
        self.assertEqual(denied["result"], "REJECTED")
        self.approve(first)
        self.execute("ReviseImplementationBrief", second, expected=2)
        uow = UnitOfWork(self.store)
        history = uow.implementation_briefs.list_versions(self.tenant, BRIEF_ID)
        self.assertEqual([(v["implementation_brief_version"], v["state"], v["record_version"])
                          for v in history], [(1, "SUPERSEDED", 3), (2, "DRAFT", 1)])
        self.assertEqual(history[0]["desired_business_outcome"], first["desired_business_outcome"])
        self.assertEqual(history[0]["implementation_brief_digest"], first["implementation_brief_digest"])
        stale = self.raw(
            "RecordImplementationBriefApproval",
            {"subject_version": 2, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY",
             "authority_digest": second["implementation_brief_digest"]},
            expected=2, key="phase5d-stale-approval-0001",
        )
        before = copy.deepcopy(self.store.implementation_briefs)
        result = self.executor.execute(
            stale, self.context("RecordImplementationBriefApproval",
                                role="CLIENT_IMPLEMENTATION_AUTHORITY")
        )
        self.assertEqual(result["reason_code"], "VERSION_STALE")
        self.assertEqual(self.store.implementation_briefs, before)

    def test_source_binding_negatives_fail_closed_without_side_effects(self):
        mutations = (
            lambda p: p["source_implementation_handoff_reference"].update(reference_version=99),
            lambda p: p["source_implementation_handoff_reference"].update(reference_digest="sha256:" + "f" * 64),
            lambda p: p["source_implementation_handoff_reference"].update(reference_id=self.next_id()),
            lambda p: p["approved_scope"][0]["source_traceability"][0].update(reference_digest="sha256:" + "f" * 64),
            lambda p: p.update(source_truth_digest="sha256:" + "f" * 64),
        )
        for index, mutate in enumerate(mutations):
            payload = self.payload(brief_id=f"d5100000-0000-4000-8000-{100 + index:012d}")
            mutate(payload)
            payload["implementation_brief_digest"] = implementation_brief_digest(payload)
            before = (copy.deepcopy(self.store.implementation_briefs), copy.deepcopy(self.store.approvals),
                      copy.deepcopy(self.store.events), copy.deepcopy(self.store.outbox),
                      copy.deepcopy(self.store.idempotency))
            raw = self.raw("DraftImplementationBrief", payload, key=f"phase5d-source-negative-{index}")
            self.assertEqual(self.executor.execute(raw, self.context("DraftImplementationBrief"))["result"], "REJECTED")
            self.assert_no_effects(before)
        payload = self.payload(brief_id="d5100000-0000-4000-8000-000000000200")
        raw = self.raw("DraftImplementationBrief", payload, tenant=FOREIGN_TENANT,
                       key="phase5d-cross-tenant-source-0001")
        before = (copy.deepcopy(self.store.implementation_briefs), copy.deepcopy(self.store.approvals),
                  copy.deepcopy(self.store.events), copy.deepcopy(self.store.outbox),
                  copy.deepcopy(self.store.idempotency))
        result = self.executor.execute(raw, self.context("DraftImplementationBrief", tenant=FOREIGN_TENANT))
        self.assertEqual(result["result"], "REJECTED")
        self.assert_no_effects(before)

    def test_upstream_invalidation_does_not_rebind_or_rewrite_draft(self):
        payload = self.payload()
        self.draft(payload)
        stored_before = copy.deepcopy(self.store.implementation_briefs)
        revoked = copy.deepcopy(self.handoff)
        revoked.update(
            handoff_version=2, state="REVOKED",
            supersedes_handoff_reference=handoff_reference(self.handoff),
            revoked_at="2030-01-15T14:01:00Z", revocation_reason="Provider approval withdrawn.",
        )
        revoked.pop("handoff_digest")
        revoked["handoff_digest"] = canonical_digest(revoked)
        uow = UnitOfWork(self.store)
        ImplementationHandoffAcceptanceService(uow).accept(revoked, self.handoff_context())
        uow.commit()
        readiness = ImplementationBriefReadService(UnitOfWork(self.store)).readiness(
            self.tenant, BRIEF_ID, 1, self.h.now
        )
        self.assertFalse(readiness["source_truth_exact"])
        self.assertFalse(readiness["implementation_brief_ready"])
        self.assertIn("HANDOFF_SOURCE_MISMATCH", readiness["reasons"])
        self.assertEqual(self.store.implementation_briefs, stored_before)
        approval = {
            "implementation_brief_id": BRIEF_ID, "implementation_brief_version": 1,
            "client_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": self.next_id(), "reference_version": 1},
            "provider_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": self.next_id(), "reference_version": 1},
            "implementation_brief_digest": payload["implementation_brief_digest"],
        }
        result = self.executor.execute(
            self.raw("ApproveImplementationBrief", approval, expected=1,
                     key="phase5d-invalidated-approval-0001"),
            self.context("ApproveImplementationBrief"),
        )
        self.assertEqual(result["result"], "REJECTED")
        self.assertEqual(self.store.implementation_briefs, stored_before)

    def test_human_workload_and_role_spoof_boundaries(self):
        payload = self.payload()
        self.draft(payload)
        approval_payload = {
            "subject_version": 1, "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY",
            "authority_digest": payload["implementation_brief_digest"],
        }
        for caller, role in (
            ("INTERNAL_SERVICE", None),
            ("HUMAN", "PROVIDER_IMPLEMENTATION_AUTHORITY"),
        ):
            raw = self.raw("RecordImplementationBriefApproval", approval_payload, expected=1,
                           caller_type=caller, key=f"phase5d-role-negative-{caller.lower()}")
            result = self.executor.execute(
                raw, self.context("RecordImplementationBriefApproval", caller_type=caller, role=role)
            )
            self.assertIn(result["result"], {"VALIDATION_FAILED", "REJECTED"})
        spoof = copy.deepcopy(approval_payload)
        spoof["approved_by"] = "human.spoofed"
        result = self.executor.execute(
            self.raw("RecordImplementationBriefApproval", spoof, expected=1,
                     key="phase5d-payload-role-spoof-0001"),
            self.context("RecordImplementationBriefApproval", role="CLIENT_IMPLEMENTATION_AUTHORITY"),
        )
        self.assertEqual(result["result"], "VALIDATION_FAILED")
        self.assertEqual(len(self.store.approvals), 0)

    def test_content_acceptance_prohibited_and_secret_boundaries(self):
        cases = []
        missing_prohibition = self.payload(brief_id="d5100000-0000-4000-8000-000000000301")
        missing_prohibition["prohibited_changes"].remove("PRODUCTION_DEPLOYMENT")
        cases.append(missing_prohibition)
        untraceable = self.payload(brief_id="d5100000-0000-4000-8000-000000000302")
        untraceable["acceptance_criteria"][0]["scope_item_ids"] = ["scope.not-approved"]
        cases.append(untraceable)
        secret = self.payload(brief_id="d5100000-0000-4000-8000-000000000303")
        secret_label = "api" + "_" + "key"
        secret["known_constraints"] = [secret_label + "=" + "fictional-prohibited-material"]
        secret["implementation_brief_digest"] = implementation_brief_digest(secret)
        cases.append(secret)
        authenticated_url = self.payload(brief_id="d5100000-0000-4000-8000-000000000304")
        authority = "user" + ":" + "pass"
        authenticated_url["dependencies"] = ["https" + "://" + authority + "@example.invalid/resource"]
        authenticated_url["implementation_brief_digest"] = implementation_brief_digest(authenticated_url)
        cases.append(authenticated_url)
        for index, payload in enumerate(cases):
            raw = self.raw("DraftImplementationBrief", payload, key=f"phase5d-content-negative-{index}")
            result = self.executor.execute(raw, self.context("DraftImplementationBrief"))
            self.assertIn(result["result"], {"VALIDATION_FAILED", "REJECTED"})
        self.assertFalse(self.store.implementation_briefs)
        self.assertFalse(self.store.events)
        self.assertFalse(self.store.outbox)

    def test_idempotency_duplicate_conflict_and_duplicate_identity(self):
        payload = self.payload()
        raw = self.raw("DraftImplementationBrief", payload, key="phase5d-idempotency-0001")
        context = self.context("DraftImplementationBrief")
        self.assertEqual(self.executor.execute(copy.deepcopy(raw), context)["result"], "ACCEPTED")
        counts = (len(self.store.implementation_briefs), len(self.store.events), len(self.store.outbox))
        self.assertEqual(self.executor.execute(copy.deepcopy(raw), context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["risks"] = ["A changed semantic request must conflict."]
        self.assertEqual(self.executor.execute(changed, context)["result"], "CONFLICT")
        duplicate_identity = self.raw("DraftImplementationBrief", payload,
                                      key="phase5d-duplicate-identity-0002")
        self.assertEqual(self.executor.execute(duplicate_identity, context)["result"], "REJECTED")
        self.assertEqual((len(self.store.implementation_briefs), len(self.store.events), len(self.store.outbox)), counts)

    def test_all_atomic_failpoints_rollback_state_event_outbox_and_idempotency(self):
        for index, stage in enumerate((
            "IDEMPOTENCY_RESERVE", "AUTHORITATIVE_WRITE", "LIFECYCLE_EVENT_APPEND",
            "OUTBOX_APPEND", "IDEMPOTENCY_COMPLETE", "COMMIT",
        )):
            payload = self.payload(brief_id=f"d5100000-0000-4000-8000-{400 + index:012d}")
            raw = self.raw("DraftImplementationBrief", payload, key=f"phase5d-failpoint-{stage.lower()}")
            self.store.fail_stage = stage
            before = (copy.deepcopy(self.store.implementation_briefs), copy.deepcopy(self.store.approvals),
                      copy.deepcopy(self.store.events), copy.deepcopy(self.store.outbox),
                      copy.deepcopy(self.store.idempotency))
            result = self.executor.execute(raw, self.context("DraftImplementationBrief"))
            self.assertEqual(result["result"], "REJECTED", stage)
            self.assert_no_effects(before)
            self.store.fail_stage = None


if __name__ == "__main__":
    unittest.main()
