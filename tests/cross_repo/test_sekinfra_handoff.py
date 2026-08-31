from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


AVUHZ = Path(__file__).resolve().parents[2]
SEKINFRA = Path("/home/network-p/sekinfra/consulting")
sys.path.insert(0, str(AVUHZ / "src"))
sys.path.insert(0, str(SEKINFRA / "src"))

from sekinfra_consulting.implementation_handoff import produce_implementation_handoff
from avuhz_runtime.implementation_handoff import (
    ImplementationHandoffAcceptanceService, canonical_digest as avuhz_digest,
    handoff_reference,
)
from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.phase5d_brief import implementation_brief_digest, implementation_brief_source_truth_digest
from tests.runtime.test_phase5d_implementation_brief_runtime import ImplementationBriefRuntimeTests


class CrossRepositoryImplementationHandoffTests(unittest.TestCase):
    def consulting_sources(self):
        tenant = "10000000-0000-4000-8000-000000000001"
        engagement = "60000000-0000-4000-8000-000000000001"
        finding = {
            "tenant_id": tenant, "oia_finding_id": "20000000-0000-4000-8000-000000000001",
            "oia_assessment_id": "30000000-0000-4000-8000-000000000001",
            "finding_revision": 2, "state": "FINAL",
            "verified_operational_problem": "Scheduling handoffs are inconsistent.",
            "desired_outcome": "Scheduling handoffs are deterministic and auditable.",
            "content_digest": "sha256:" + "1" * 64,
        }
        finding_ref = {
            "oia_finding_id": finding["oia_finding_id"], "finding_revision": 2,
            "content_digest": finding["content_digest"],
        }
        delivery = {
            "oia_findings_delivery_id": "40000000-0000-4000-8000-000000000001",
            "oia_assessment_id": finding["oia_assessment_id"], "delivery_sequence": 3,
            "finding_revisions": [finding_ref], "manifest_digest": "sha256:" + "2" * 64,
        }
        conversion = {
            "oia_conversion_decision_id": "50000000-0000-4000-8000-000000000001",
            "decision_version": 1, "tenant_id": tenant, "engagement_id": engagement,
            "oia_assessment_id": finding["oia_assessment_id"],
            "oia_findings_delivery_id": delivery["oia_findings_delivery_id"],
            "delivery_sequence": 3, "delivery_manifest_digest": delivery["manifest_digest"],
            "decision": "PROCEED", "state": "ACCEPTED", "selected_finding_revisions": [finding_ref],
            "conversion_authority_digest": "sha256:" + "3" * 64,
        }
        outcome = {
            "implementation_handoff_id": "70000000-0000-4000-8000-000000000001",
            "handoff_version": 1, "tenant_id": tenant, "engagement_id": engagement,
            "client_reference": "client.fictional.operations", "state": "APPROVED",
            "source_conversion_reference": {
                "reference_id": conversion["oia_conversion_decision_id"], "reference_version": 1,
                "reference_digest": conversion["conversion_authority_digest"],
            },
            "approved_scope": [{
                "scope_item_id": "scope.scheduling", "description": "Correct bounded scheduling handoffs.",
                "action_classes": ["MODIFY_CODE"],
                "target_references": [{"reference_type": "REPOSITORY", "reference_id": "repository.fictional.scheduler"}],
            }],
            "excluded_scope": ["Production deployment is excluded."],
            "constraints": ["Preserve existing client records."], "context_references": [],
            "integrations": [{"id": "integration.calendar", "statement": "Existing calendar API boundary."}],
            "allowed_access_level": "SANDBOX_ONLY",
            "risks": [{"id": "risk.concurrent-edits", "statement": "Concurrent edits may conflict."}],
            "implementation_requirements": [{"id": "requirement.atomic", "statement": "Apply scheduling updates atomically."}],
            "acceptance_criteria": [{"criterion_id": "criterion.audit", "expected_condition": "Every scheduling change is attributable.", "evidence_requirement": "Automated audit-trail test reference."}],
            "prohibited_changes": [
                "OUT_OF_SCOPE_SYSTEM_CHANGE", "PERMISSION_WIDENING", "DATA_DELETION",
                "CREDENTIAL_ROTATION", "PRODUCTION_DEPLOYMENT", "PRODUCTION_CHANGE",
                "BILLING_CHANGE", "OUT_OF_SCOPE_NETWORK_CHANGE", "OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE",
            ],
            "dependencies": [], "assumptions_limitations": ["Client calendar API remains available."],
            "upstream_approval_references": [
                {"approval_role": "CLIENT_APPROVER", "approval_reference": "approval.client.001", "approved_by": "human.client-authority", "approved_at": "2030-01-15T14:00:00Z"},
                {"approval_role": "PROVIDER_APPROVER", "approval_reference": "approval.provider.001", "approved_by": "human.provider-authority", "approved_at": "2030-01-15T14:01:00Z"},
            ],
            "approved_at": "2030-01-15T14:01:00Z", "created_at": "2030-01-15T14:01:00Z",
        }
        return outcome, conversion, delivery, [finding]

    def test_sekinfra_to_avuhz_to_implementation_brief_without_circular_import(self):
        outcome, conversion, delivery, findings = self.consulting_sources()
        handoff = produce_implementation_handoff(
            outcome=outcome, conversion=conversion, delivery=delivery, findings=findings
        )
        sekinfra_schema = SEKINFRA / "contracts/public/implementation-handoff.schema.json"
        avuhz_schema = AVUHZ / "contracts/schemas/v1/public/implementation-handoff.schema.json"
        self.assertEqual(sekinfra_schema.read_bytes(), avuhz_schema.read_bytes())
        validator = Draft202012Validator(json.loads(avuhz_schema.read_text()), format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(handoff)), [])

        flow = ImplementationBriefRuntimeTests(); flow.setUp()
        flow.store.implementation_handoffs.clear()
        flow.handoff = copy.deepcopy(handoff); flow._tenant = handoff["tenant_id"]
        flow._engagement_id = handoff["source_engagement_reference"]
        uow = UnitOfWork(flow.store)
        ImplementationHandoffAcceptanceService(uow).accept(handoff, flow.handoff_context())
        uow.commit()

        source = copy.deepcopy(handoff["source_artifact_references"])
        scope_ids = [item["scope_item_id"] for item in handoff["approved_scope"]]
        payload = flow.payload()
        payload.update(
            source_implementation_handoff_reference=handoff_reference(handoff),
            approved_business_problem=handoff["problem_statement"],
            desired_business_outcome=handoff["desired_outcome"],
            approved_scope=[{"scope_item_id": item["scope_item_id"], "statement": item["description"], "source_traceability": source} for item in handoff["approved_scope"]],
            excluded_scope=copy.deepcopy(handoff["excluded_scope"]),
            known_constraints=copy.deepcopy(handoff["constraints"]),
            current_state_context=[{"context_item_id": "context.provider-source", "statement": "Provider-approved source context.", "truth_class": "VERIFIED_SOURCE", "source_traceability": source}],
            approved_integrations=[{"integration_reference": item["id"], "purpose": item["statement"], "access_level": handoff["allowed_access_level"]} for item in handoff["integrations"]],
            allowed_access_level=handoff["allowed_access_level"], risks=[item["statement"] for item in handoff["risks"]],
            implementation_requirements=[{"scope_item_id": item["id"], "statement": item["statement"], "source_traceability": source} for item in handoff["implementation_requirements"]],
            acceptance_criteria=[{"criterion_id": item["criterion_id"], "category": "BUSINESS", "statement": item["expected_condition"], "verification_method": item["evidence_requirement"], "scope_item_ids": scope_ids, "source_traceability": source} for item in handoff["acceptance_criteria"]],
            prohibited_changes=copy.deepcopy(handoff["prohibited_changes"]), dependencies=[item["statement"] for item in handoff["dependencies"]],
            assumptions_and_limitations=[{"context_item_id": f"limitation.{index}", "statement": statement, "truth_class": "LIMITATION"} for index, statement in enumerate(handoff["assumptions_limitations"], 1)],
        )
        payload["source_truth_digest"] = implementation_brief_source_truth_digest(payload)
        payload["implementation_brief_digest"] = implementation_brief_digest(payload)
        flow.draft(payload)
        stored = UnitOfWork(flow.store).implementation_briefs.get_version(flow.tenant, payload["implementation_brief_id"], 1)
        self.assertEqual(stored["source_implementation_handoff_reference"], handoff_reference(handoff))
        self.assertNotIn("oia_assessment_id", stored)

    def test_avuhz_acceptance_rejects_leaks_spoofing_and_stale_history(self):
        outcome, conversion, delivery, findings = self.consulting_sources()
        first = produce_implementation_handoff(
            outcome=outcome, conversion=conversion, delivery=delivery, findings=findings
        )
        flow = ImplementationBriefRuntimeTests(); flow.setUp()
        flow.store.implementation_handoffs.clear()
        flow._tenant = first["tenant_id"]

        def accept(record, context=None):
            uow = UnitOfWork(flow.store)
            accepted = ImplementationHandoffAcceptanceService(uow).accept(
                record, context or flow.handoff_context()
            )
            uow.commit()
            return accepted

        accept(first)
        for mutate in (
            lambda value: value.update(oia_assessment_id="private-domain-leak"),
            lambda value: value["constraints"].append("api_key=fictional-but-prohibited"),
            lambda value: value["upstream_approval_references"].pop(),
        ):
            bad = copy.deepcopy(first); mutate(bad)
            bad.pop("handoff_digest", None); bad["handoff_digest"] = avuhz_digest(bad)
            with self.assertRaises(ValueError):
                accept(bad)

        revised_outcome = copy.deepcopy(outcome)
        revised_outcome["handoff_version"] = 2
        revised_outcome["constraints"].append("Retain exact audit attribution.")
        revised_outcome["supersedes_handoff_reference"] = handoff_reference(first)
        second = produce_implementation_handoff(
            outcome=revised_outcome, conversion=conversion, delivery=delivery, findings=findings
        )
        accept(second)
        self.assertEqual(
            len(UnitOfWork(flow.store).implementation_handoffs.list_versions(
                first["tenant_id"], first["implementation_handoff_id"]
            )), 2,
        )

        stale = copy.deepcopy(second)
        stale["constraints"].append("Conflicting stale revision.")
        stale.pop("handoff_digest"); stale["handoff_digest"] = avuhz_digest(stale)
        with self.assertRaises(ValueError):
            accept(stale)

        revoked = copy.deepcopy(second)
        revoked.update(
            handoff_version=3, state="REVOKED",
            supersedes_handoff_reference=handoff_reference(second),
            revoked_at="2030-01-16T14:00:00Z",
            revocation_reason="Provider approval was withdrawn.",
        )
        revoked.pop("handoff_digest"); revoked["handoff_digest"] = avuhz_digest(revoked)
        accept(revoked)
        after_revocation = copy.deepcopy(second)
        after_revocation.update(
            handoff_version=4,
            supersedes_handoff_reference=handoff_reference(revoked),
        )
        after_revocation.pop("handoff_digest"); after_revocation["handoff_digest"] = avuhz_digest(after_revocation)
        with self.assertRaises(ValueError):
            accept(after_revocation)


if __name__ == "__main__":
    unittest.main()
