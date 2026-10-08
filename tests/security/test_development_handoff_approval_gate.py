"""Real-engine tests for the offline DEVELOPMENT handoff approval gate."""
from __future__ import annotations

import copy
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/service")]

from test_development_synthetic_handoff_offline_certification import (
    CANONICAL_DEVELOPMENT_TENANT,
    fictional_envelope,
)
from test_development_synthetic_handoff_preflight import CLOCK

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
    authorization_set_digest,
    prepare_handoff_stage_approval_state,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    COMMAND_URL,
    REPOSITORY,
)
from avuhz_engineering.development_synthetic_handoff_preflight import (
    certify_synthetic_command,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)

SCHEMAS = ROOT / "contracts/schemas/v1"
MAIN_SHA = "45e16b380b5d823b9527501f64e954258ccd1509"
TENANT = CANONICAL_DEVELOPMENT_TENANT
AT = CLOCK


class DevelopmentHandoffApprovalGateTests(unittest.TestCase):
    def setUp(self):
        self.command = fictional_envelope()
        self.base_source = DevelopmentHandoffSource(
            repository=REPOSITORY,
            canonical_main_sha=MAIN_SHA,
            authorization_plan_digest="sha256:" + "0" * 64,
            command_digest=certify_synthetic_command(
                self.command, at_utc=AT
            ).command_digest,
            tenant_id=TENANT,
            auth_project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            data_project_ref=DEVELOPMENT_DATA_PROJECT_REF,
            command_url=COMMAND_URL,
        )
        self.stages = self._stage_documents(self.base_source)
        self.source = replace(
            self.base_source,
            authorization_plan_digest=authorization_set_digest(self.stages),
        )

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
                "created_at": "2026-10-08T18:00:00Z",
                "authorization_window": {
                    "binding_state": "BOUND",
                    "starts_at": "2026-10-08T18:30:00Z",
                    "expires_at": "2026-10-08T19:20:00Z",
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
                "effective_at": "2026-10-08T18:30:00Z",
                "expires_at": "2026-10-08T19:20:00Z",
                "approved_at": "2026-10-08T18:20:00Z",
                "status": "ACTIVE",
                "authority_scope": "EXACT_PLAN_ONLY",
            }
            approval["approval_digest"] = approval_digest(approval)
            progress = initial_progress(
                plan,
                SCHEMAS,
                f"a7400000-0000-4000-8000-{identifier}",
                "2026-10-08T18:25:00Z",
            )
            records[stage] = StageAuthorizationDocuments(
                plan=plan,
                approval=approval,
                progress=progress,
                credential_class="OWNER_INTERACTIVE_SESSION",
            )
        return records

    def invoke(self, stage="DATA_COMMAND", **changes):
        stages = changes.get("stages", self.stages)
        source = changes.get("source", self.source)
        arguments = {
            "request": self.command,
            "source": source,
            "observed_main_sha": MAIN_SHA,
            "at_utc": AT,
            "stage": stage,
            "stages": stages,
            "owner_source_verified": True,
            "observed_owner_identity": "github:AnonymousKoo",
            "authorization_set_attested_digest": authorization_set_digest(stages),
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
            {"authorization_set_attested_digest": "sha256:" + "f" * 64},
        )
        for changes in invalid_cases:
            with self.subTest(changes=changes), self.assertRaises(HandoffApprovalGateStop):
                self.invoke(**changes)

        wrong_url = replace(
            self.source,
            command_url="https://wrong-development.example.invalid/v1/commands",
        )
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_REQUEST_SOURCE_INVALID"
        ):
            self.invoke(source=wrong_url)

    def test_wrong_auth_data_project_or_resource_binding_fails_closed(self):
        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["target"]["project_reference"] = (
            DEVELOPMENT_AUTH_PROJECT_REF
        )
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke(stages={**self.stages, "DATA_COMMAND": documents})

        documents = copy.deepcopy(self.stages["AUTH_VERIFY"])
        documents.plan["steps"][0]["resource"]["exact_digest"] = (
            "sha256:" + "f" * 64
        )
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke("AUTH_VERIFY", stages={**self.stages, "AUTH_VERIFY": documents})

    def test_malformed_stage_shapes_fail_with_bounded_errors(self):
        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["target"] = None
        with self.assertRaisesRegex(HandoffApprovalGateStop, "HANDOFF_APPROVAL_STAGE_INVALID"):
            self.invoke(stages={**self.stages, "DATA_COMMAND": documents})

        documents = copy.deepcopy(self.stages["DATA_COMMAND"])
        documents.plan["steps"][0]["resource"] = None
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_APPROVAL_RESOURCE_MISMATCH"
        ):
            self.invoke(stages={**self.stages, "DATA_COMMAND": documents})

    def test_expired_or_replayed_authorization_fails_closed(self):
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_AUTHORIZATION_ENGINE_DENIED"
        ):
            self.invoke(at_utc=datetime(2026, 10, 8, 19, 25, tzinfo=timezone.utc))

        documents = copy.deepcopy(self.stages["AUTH_GLOBAL_LOGOUT"])
        documents.progress["step_states"][0][
            "authorization_consumed"
        ] = True
        with self.assertRaises(HandoffApprovalGateStop):
            self.invoke(
                "AUTH_GLOBAL_LOGOUT",
                stages={**self.stages, "AUTH_GLOBAL_LOGOUT": documents},
            )

    def test_command_contract_tenant_and_digest_drift_fail_closed(self):
        command = copy.deepcopy(self.command)
        command["tenant_id"] = "d5000000-0000-4000-8000-000000000099"
        drifted_source = replace(
            self.source, command_digest=canonical_digest(command)
        )
        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_REQUEST_SOURCE_INVALID"
        ):
            self.invoke(request=command, source=drifted_source)

        with self.assertRaisesRegex(
            HandoffApprovalGateStop, "HANDOFF_REQUEST_SOURCE_INVALID"
        ):
            self.invoke(source=replace(
                self.source,
                command_digest="sha256:" + "e" * 64,
            ))


if __name__ == "__main__":
    unittest.main()
