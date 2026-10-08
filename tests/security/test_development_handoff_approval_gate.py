"""Real-engine tests for the offline DEVELOPMENT handoff approval gate."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    approval_digest,
    initial_progress,
    plan_digest,
)
from avuhz_engineering.development_handoff_approval_gate import (
    EXPECTED_OPERATIONS,
    EXPECTED_STAGES,
    REQUIRED_PROHIBITIONS,
    DevelopmentHandoffSource,
    HandoffApprovalGateStop,
    StageAuthorizationDocuments,
    _bound_stage_resource_digest,
    prepare_handoff_stage_approval_state,
    stage_authorization_digest,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)

SCHEMAS = ROOT / "contracts/schemas/v1"
MAIN_SHA = "1" * 40
TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
AT = datetime(2030, 1, 15, 15, 0, 0, tzinfo=timezone.utc)
NOW = "2030-01-15T15:00:00Z"


class DevelopmentHandoffApprovalGateTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads(
            (ROOT / "contracts/fixtures/v1/phase5d-implementation-package.cases.json").read_text()
        )
        handoff = copy.deepcopy(fixture["positive"]["implementation_handoff"])
        handoff["tenant_id"] = TENANT
        handoff.pop("handoff_digest")
        handoff["handoff_digest"] = canonical_digest(handoff)
        self.command = {
            "command_id": "d5000000-0000-4000-8000-000000000090",
            "command_type": "AcceptImplementationHandoff",
            "command_schema_version": 1,
            "tenant_id": TENANT,
            "subject_type": "IMPLEMENTATION_HANDOFF",
            "subject_id": handoff["implementation_handoff_id"],
            "requested_by": "service.sekinfra-handoff-adapter",
            "caller_type": "PROVIDER_ADAPTER",
            "caller_identity": {
                "subject": "service.sekinfra-handoff-adapter",
                "audience": DEVELOPMENT_SERVICE_AUDIENCE,
                "caller_type": "PROVIDER_ADAPTER",
                "tenant_ids": [TENANT],
                "capabilities": ["implementation_handoff:accept"],
                "environment": "DEVELOPMENT",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "d5000000-0000-4000-8000-000000000091",
            "idempotency_key": "handoff.accept.approval-gate.0001",
            "requested_at": NOW,
            "environment": "DEVELOPMENT",
            "payload_schema": (
                "urn:avuhz:schema:contracts:commands:"
                "accept-implementation-handoff-payload:v1"
            ),
            "payload_version": 1,
            "payload": handoff,
        }
        self.base_source = DevelopmentHandoffSource(
            repository="AnonymousKoo/avuhz-infra",
            canonical_main_sha=MAIN_SHA,
            authorization_plan_digest="sha256:" + "0" * 64,
            command_digest=canonical_digest(self.command),
            tenant_id=TENANT,
            auth_project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            data_project_ref=DEVELOPMENT_DATA_PROJECT_REF,
            command_url="https://avuhz-command-dev.onrender.com/v1/commands",
        )
        self.stages = self._stage_documents(self.base_source)

    def _stage_documents(self, source):
        records = {}
        prohibitions = sorted(REQUIRED_PROHIBITIONS)
        for index, stage in enumerate(EXPECTED_STAGES, start=1):
            project = (
                DEVELOPMENT_DATA_PROJECT_REF
                if stage == "DATA_COMMAND"
                else DEVELOPMENT_AUTH_PROJECT_REF
            )
            responsibility = "DATA" if stage == "DATA_COMMAND" else "AUTH"
            identifier = f"{index:012d}"
            plan = {
                "plan_id": f"a7200000-0000-4000-8000-{identifier}",
                "plan_version": 1,
                "plan_digest": "sha256:" + "0" * 64,
                "definition_status": "READY_FOR_APPROVAL",
                "environment": "DEVELOPMENT",
                "target": {
                    "provider_class": "supabase",
                    "provider_reference": "supabase",
                    "project_reference": project,
                    "responsibility": responsibility,
                    "issuer_reference": DEVELOPMENT_AUTH_ISSUER,
                    "audience_reference": DEVELOPMENT_SERVICE_AUDIENCE,
                },
                "owner_identity": "github:AnonymousKoo",
                "created_at": "2030-01-15T14:00:00Z",
                "authorization_window": {
                    "binding_state": "BOUND",
                    "starts_at": "2030-01-15T14:30:00Z",
                    "expires_at": "2030-01-15T15:30:00Z",
                },
                "ordered_step_ids": [f"handoff.stage.{index}"],
                "steps": [{
                    "step_id": f"handoff.stage.{index}",
                    "ordinal": 1,
                    "resource": {
                        "resource_type": "provider.resource",
                        "resource_reference": f"handoff.resource.stage-{index}",
                        "binding_state": "BOUND",
                        "exact_version": "version.1",
                        "exact_digest": _bound_stage_resource_digest(source, stage),
                    },
                    "operation": EXPECTED_OPERATIONS[stage],
                    "dependency_step_ids": [],
                    "required_evidence": [{
                        "evidence_type": "handoff.preflight.trusted",
                        "source_step_id": None,
                        "binding_state": "BOUND",
                        "exact_digest": "sha256:" + "a" * 64,
                    }],
                    "expected_postcondition": "Offline state proposal prepared only.",
                    "prohibited_actions": prohibitions,
                    "stop_conditions": ["scope.drift", "evidence.mismatch"],
                    "correction_reference": "correction.forward-only",
                    "execution_class": "PROVIDER_MUTATION",
                    "credential_policy": {
                        "permitted": True,
                        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
                        "values_stored": False,
                    },
                    "unresolved_bindings": [],
                }],
                "prohibited_actions": prohibitions,
                "stop_conditions": [
                    "scope.drift",
                    "target.drift",
                    "evidence.missing",
                    "outcome.ambiguous",
                    "authorization.expired",
                ],
                "authority_effect": "NONE_UNTIL_SEPARATELY_APPROVED",
            }
            plan["plan_digest"] = plan_digest(plan)
            approval = {
                "approval_id": f"a7300000-0000-4000-8000-{identifier}",
                "plan_id": plan["plan_id"],
                "plan_version": plan["plan_version"],
                "plan_digest": plan["plan_digest"],
                "approval_digest": "sha256:" + "0" * 64,
                "owner_identity": "github:AnonymousKoo",
                "decision": "APPROVE",
                "environment": "DEVELOPMENT",
                "effective_at": "2030-01-15T14:30:00Z",
                "expires_at": "2030-01-15T15:30:00Z",
                "approved_at": "2030-01-15T14:20:00Z",
                "status": "ACTIVE",
                "authority_scope": "EXACT_PLAN_ONLY",
            }
            approval["approval_digest"] = approval_digest(approval)
            progress = initial_progress(
                plan,
                SCHEMAS,
                f"a7400000-0000-4000-8000-{identifier}",
                "2030-01-15T14:25:00Z",
            )
            records[stage] = StageAuthorizationDocuments(
                plan=plan,
                approval=approval,
                progress=progress,
                credential_class="OWNER_INTERACTIVE_SESSION",
            )
        return records

    def source_for(self, stage, documents=None):
        documents = documents or self.stages[stage]
        return replace(
            self.base_source,
            authorization_plan_digest=documents.plan["plan_digest"],
        )

    def invoke(self, stage="DATA_COMMAND", **changes):
        documents = changes.get("documents", self.stages[stage])
        source = changes.get("source", self.source_for(stage, documents))
        arguments = {
            "request": self.command,
            "source": source,
            "observed_main_sha": MAIN_SHA,
            "at_utc": AT,
            "stage": stage,
            "documents": documents,
            "owner_source_verified": True,
            "observed_owner_identity": "github:AnonymousKoo",
            "stage_authorization_attested_digest": stage_authorization_digest(
                stage, documents
            ),
        }
        arguments.update(changes)
        return prepare_handoff_stage_approval_state(**arguments)

    def test_real_engine_proposes_each_stage_individually_without_execution(self):
        for stage in EXPECTED_STAGES:
            with self.subTest(stage=stage):
                result = self.invoke(stage)
                self.assertEqual(
                    result.classification,
                    "OFFLINE_SINGLE_STAGE_AUTHORIZATION_PREPARED_PENDING_ATOMIC_CONSUMPTION",
                )
                self.assertEqual(result.command_digest, canonical_digest(self.command))
                self.assertEqual(result.stage.stage, stage)
                self.assertEqual(
                    result.stage.project_reference,
                    DEVELOPMENT_DATA_PROJECT_REF
                    if stage == "DATA_COMMAND"
                    else DEVELOPMENT_AUTH_PROJECT_REF,
                )
                self.assertFalse(result.remote_execution_authorized)
                self.assertFalse(result.credentials_resolved)
                self.assertFalse(result.data_write_attempted)
            record = self.stages[stage]
            self.assertEqual(
                record.progress["step_states"][0]["authorization_state"],
                "PENDING",
            )

    def test_unverified_owner_source_or_stage_binding_fails_closed(self):
        invalid_cases = (
            {"owner_source_verified": False},
            {"observed_owner_identity": "github:imposter"},
            {"observed_main_sha": "2" * 40},
            {"stage_authorization_attested_digest": "sha256:" + "f" * 64},
        )
        for changes in invalid_cases:
            with self.subTest(changes=changes), self.assertRaises(HandoffApprovalGateStop):
                self.invoke(**changes)

        wrong_url = replace(
            self.source_for("DATA_COMMAND"),
            command_url="https://wrong-development.example.invalid/v1/commands",
        )
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_SOURCE_BINDING_INVALID"
        ):
            self.invoke(source=wrong_url)

    def test_wrong_auth_data_project_or_resource_binding_fails_closed(self):
        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["target"]["project_reference"] = (
            DEVELOPMENT_AUTH_PROJECT_REF
        )
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke(documents=documents)

        documents = copy.deepcopy(self.stages["AUTH_VERIFY"])
        documents.plan["steps"][0]["resource"]["exact_digest"] = (
            "sha256:" + "f" * 64
        )
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke("AUTH_VERIFY", documents=documents)

    def test_malformed_stage_shapes_fail_with_bounded_errors(self):
        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["target"] = None
        with self.assertRaisesRegex(HandoffApprovalGateStop, "HANDOFF_APPROVAL_STAGE_INVALID"):
            self.invoke(documents=documents)

        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["steps"][0]["resource"] = None
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_APPROVAL_RESOURCE_MISMATCH"
        ):
            self.invoke(documents=documents)

    def test_expired_or_replayed_authorization_fails_closed(self):
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_AUTHORIZATION_ENGINE_DENIED"
        ):
            self.invoke(at_utc=datetime(2030, 1, 15, 16, 0, tzinfo=timezone.utc))

        documents = copy.deepcopy(self.stages["AUTH_GLOBAL_LOGOUT"])
        documents.progress["step_states"][0][
            "authorization_consumed"
        ] = True
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke("AUTH_GLOBAL_LOGOUT", documents=documents)

    def test_command_contract_tenant_and_digest_drift_fail_closed(self):
        command = copy.deepcopy(self.command)
        command["tenant_id"] = "d5000000-0000-4000-8000-000000000099"
        drifted_source = replace(
            self.source_for("DATA_COMMAND"), command_digest=canonical_digest(command)
        )
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_REQUEST_SOURCE_INVALID"
        ):
            self.invoke(request=command, source=drifted_source)

        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_REQUEST_SOURCE_INVALID"
        ):
            self.invoke(source=replace(
                self.source_for("DATA_COMMAND"),
                command_digest="sha256:" + "e" * 64,
            ))


if __name__ == "__main__":
    unittest.main()
