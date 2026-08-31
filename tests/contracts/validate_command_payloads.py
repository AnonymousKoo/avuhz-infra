#!/usr/bin/env python3
"""Validate the active shared-system command payloads with local tooling."""
from __future__ import annotations
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.models import ValidationSuccess
from avuhz_runtime.validation import CommandValidator

PAYLOAD_IDS = {
    "AcceptAcquisitionHandoff": "urn:avuhz:schema:contracts:commands:accept-acquisition-handoff-payload:v1",
    "OpenEngagement": "urn:avuhz:schema:contracts:commands:open-engagement-payload:v1",
}
SUBJECTS = {"AcceptAcquisitionHandoff": "ACQUISITION_HANDOFF", "OpenEngagement": "ENGAGEMENT"}
TENANT = "a3000000-0000-4000-8000-000000000002"
HANDOFF = "a3000000-0000-4000-8000-000000000001"
ENGAGEMENT = "a3000000-0000-4000-8000-000000000004"


def handoff():
    source = "fictional-acquisition-provider"
    return {
        "handoff_id": HANDOFF, "handoff_version": 1, "tenant_id": TENANT,
        "canonical_account_reference": {"source_system": source, "object_type": "CANONICAL_ACCOUNT", "external_id": "account-001", "environment": "TEST"},
        "acquisition_opportunity_reference": {"source_system": source, "object_type": "ACQUISITION_OPPORTUNITY", "external_id": "opportunity-001", "environment": "TEST"},
        "qualification_status": "QUALIFIED", "target_outcome": "Fictional governed service outcome.",
        "validated_constraints": [], "stakeholder_context": [], "assumptions": [], "exclusions": [],
        "requested_engagement_type": "BUSINESS_REVIEW", "source_system": source,
        "source_record_version": "v1", "producer_identity": "acquisition.service-01",
        "produced_at": "2030-01-15T15:00:00Z", "correlation_id": "a3000000-0000-4000-8000-000000000003",
        "idempotency_key": "slice1-handoff-payload-0001",
    }


def payloads():
    source = handoff()
    return {
        "AcceptAcquisitionHandoff": {"acquisition_handoff": source},
        "OpenEngagement": {
            "proposed_engagement_id": ENGAGEMENT,
            "accepted_handoff_reference": {"reference_type": "ACQUISITION_HANDOFF", "reference_id": HANDOFF, "reference_version": 1},
            "canonical_account_reference": source["canonical_account_reference"],
            "acquisition_opportunity_reference": source["acquisition_opportunity_reference"],
            "engagement_type": "BUSINESS_REVIEW",
        },
    }


def envelope(command, payload):
    subject_id = HANDOFF if command == "AcceptAcquisitionHandoff" else ENGAGEMENT
    capability = "engagement:accept_handoff" if command == "AcceptAcquisitionHandoff" else "engagement:open"
    value = {
        "command_id": "a3000000-0000-4000-8000-000000000010", "command_type": command,
        "command_schema_version": 1, "tenant_id": TENANT, "subject_type": SUBJECTS[command],
        "subject_id": subject_id, "requested_by": "internal.service-01", "caller_type": "INTERNAL_SERVICE",
        "caller_identity": {"subject": "internal.service-01", "audience": "avuhz-command-api", "caller_type": "INTERNAL_SERVICE", "tenant_ids": [TENANT], "capabilities": [capability], "environment": "TEST", "authentication_strength": "STRONG", "step_up_performed": False, "authenticated_at": "2030-01-15T15:00:00Z", "expires_at": "2030-01-15T16:00:00Z"},
        "correlation_id": "a3000000-0000-4000-8000-000000000011", "idempotency_key": "slice1-executable-command-0001",
        "requested_at": "2030-01-15T15:00:00Z", "environment": "TEST", "payload_schema": PAYLOAD_IDS[command],
        "payload_version": 1, "payload": payload,
    }
    if command == "OpenEngagement":
        value["engagement_id"] = ENGAGEMENT
    return value


def main():
    validator = CommandValidator(ROOT / "contracts/schemas/v1")
    data = payloads()
    positives = [envelope(command, copy.deepcopy(payload)) for command, payload in data.items()]
    if any(not isinstance(validator.prepare(value), ValidationSuccess) for value in positives):
        raise SystemExit("command-payload validation: FAIL: active positive rejected")
    negatives = []
    wrong = copy.deepcopy(positives[0]); wrong["payload"]["credential"] = "forbidden"; negatives.append(wrong)
    wrong = copy.deepcopy(positives[1]); wrong["expected_record_version"] = 1; negatives.append(wrong)
    wrong = copy.deepcopy(positives[1]); wrong["payload"]["engagement_type"] = "company-specific"; negatives.append(wrong)
    if any(isinstance(validator.prepare(value), ValidationSuccess) for value in negatives):
        raise SystemExit("command-payload validation: FAIL: active negative accepted")
    print(f"command-payload validation: PASS ({len(positives)} positive, {len(negatives)} negative)")


if __name__ == "__main__":
    main()
