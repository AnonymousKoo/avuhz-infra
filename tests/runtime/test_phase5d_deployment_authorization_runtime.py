"""Phase 5D-D4 exact deployment authority, dual-human approval, and history tests."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.phase5d_deployment_authorization import (
    DEPLOYMENT_AUTHORIZATION_CAPABILITIES,
    REQUIRED_PROHIBITED_DEPLOYMENT_ACTIONS,
    DeploymentAuthorizationReadService,
    deployment_authority_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_client_acceptance_runtime as acceptance_runtime


AUTHORIZATION_ID = "d5d40000-0000-4000-8000-000000000001"
FOREIGN_TENANT = "d5d40000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    return Draft202012Validator(
        SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(schema_id),
        format_checker=FormatChecker(),
    )


class DeploymentAuthorizationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.a = acceptance_runtime.ClientAcceptanceRuntimeTests()
        self.a.setUp()
        self.a.record()
        self.store = self.a.store
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self._number = 1480
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"),
            GuardPipeline(),
            self.store,
            clock=lambda: self.now,
            ids=self.next_id,
        )

    @property
    def tenant(self):
        return self.a.tenant

    @property
    def engagement_id(self):
        return self.a.engagement_id

    @property
    def now(self):
        return self.a.now

    def next_id(self):
        self._number += 1
        return f"d5d49000-0000-4000-8000-{self._number:012d}"

    def context(self, command, *, tenant=None, role=None, caller_type=None):
        default_callers = {
            "ProposeDeploymentAuthorization": "INTERNAL_SERVICE",
            "ReviseDeploymentAuthorization": "INTERNAL_SERVICE",
            "RecordDeploymentAuthorizationApproval": "HUMAN",
            "ActivateDeploymentAuthorization": "INTERNAL_SERVICE",
            "RevokeDeploymentAuthorization": "HUMAN",
        }
        caller_type = caller_type or default_callers[command]
        human = caller_type == "HUMAN"
        role = role if human else None
        principal = (
            f"human.{(role or 'deployment').lower()}"
            if human else "service.phase5d-deployment"
        )
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({DEPLOYMENT_AUTHORIZATION_CAPABILITIES[command]}),
            frozenset({role}) if role else frozenset(),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if human else None,
            "organization.client" if role == "CLIENT_DEPLOYMENT_AUTHORITY"
            else ("organization.provider" if human else None),
            role,
        )

    def raw(
        self, command, payload, *, expected=None, key=None, command_id=None,
        tenant=None, caller_type=None,
    ):
        context = self.context(command, tenant=tenant, caller_type=caller_type)
        value = {
            "command_id": command_id or self.next_id(),
            "command_type": command,
            "command_schema_version": 1,
            "tenant_id": tenant or self.tenant,
            "engagement_id": self.engagement_id,
            "subject_type": "DEPLOYMENT_AUTHORIZATION",
            "subject_id": payload.get("deployment_authorization_id", AUTHORIZATION_ID),
            "requested_by": "trusted.phase5d",
            "caller_type": context.caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d",
                "audience": "avuhz-command-api",
                "caller_type": context.caller_type,
                "tenant_ids": [tenant or self.tenant],
                "capabilities": [DEPLOYMENT_AUTHORIZATION_CAPABILITIES[command]],
                "environment": "TEST",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5d40000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5d-deployment-{command.lower()}-{self._number}",
            "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": (
                "urn:avuhz:schema:contracts:commands:"
                + {
                    "ProposeDeploymentAuthorization": "propose-deployment-authorization",
                    "ReviseDeploymentAuthorization": "revise-deployment-authorization",
                    "RecordDeploymentAuthorizationApproval": "record-deployment-authorization-approval",
                    "ActivateDeploymentAuthorization": "activate-deployment-authorization",
                    "RevokeDeploymentAuthorization": "revoke-deployment-authorization",
                }[command]
                + "-payload:v1"
            ),
            "payload_version": 1,
            "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def sources(self):
        acceptance = getattr(self, "source_acceptance", None)
        if acceptance is None:
            acceptance = UnitOfWork(self.store).client_acceptances.get_version(
                self.tenant, acceptance_runtime.ACCEPTANCE_ID, 1
            )
        build = getattr(self, "source_build", None)
        if build is None:
            build = UnitOfWork(self.store).build_execution_results.get(
                self.tenant, acceptance["build_execution_reference"]["reference_id"]
            )
        package_ref = acceptance["codex_build_package_reference"]
        package = getattr(self, "source_package", None)
        if package is None:
            package = UnitOfWork(self.store).codex_build_packages.get_version(
                self.tenant, package_ref["reference_id"], package_ref["reference_version"]
            )
        return acceptance, build, package

    def payload(self, *, version=1):
        acceptance, build, package = self.sources()
        value = {
            "deployment_authorization_id": AUTHORIZATION_ID,
            "authorization_version": version,
            "implementation_authorization_reference": copy.deepcopy(
                build["implementation_authorization_reference"]
            ),
            "implementation_authority_digest": build["implementation_authority_digest"],
            "codex_build_package_reference": copy.deepcopy(
                acceptance["codex_build_package_reference"]
            ),
            "package_digest": acceptance["package_digest"],
            "build_execution_reference": copy.deepcopy(
                acceptance["build_execution_reference"]
            ),
            "build_execution_digest": acceptance["build_execution_digest"],
            "qa_result_reference": copy.deepcopy(acceptance["qa_result_reference"]),
            "qa_result_digest": acceptance["qa_result_digest"],
            "client_acceptance_reference": {
                "reference_type": "CLIENT_ACCEPTANCE",
                "reference_id": acceptance["client_acceptance_id"],
                "reference_version": acceptance["acceptance_version"],
            },
            "client_acceptance_digest": acceptance["client_acceptance_digest"],
            "artifact_reference": copy.deepcopy(acceptance["artifact_reference"]),
            "target_environment": "PRODUCTION",
            "target_resources": [{
                "target_reference_id": package["allowed_targets"][0]["target_reference_id"],
                "target_class": "COMPONENT",
            }],
            "permitted_deployment_actions": [
                "DEPLOY_EXACT_ARTIFACT", "ROLLBACK_EXACT_ARTIFACT"
            ],
            "prohibited_deployment_actions": sorted(
                REQUIRED_PROHIBITED_DEPLOYMENT_ACTIONS
            ),
            "rollback_recovery_requirement": {
                "strategy": "Restore the exact preceding artifact and verify health.",
                "verification_reference": "verification.rollback",
            },
            "effective_at": "2030-01-15T13:30:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
            "deployment_authority_digest": "sha256:" + "0" * 64,
        }
        if version > 1:
            value["supersedes_deployment_authorization_reference"] = {
                "reference_type": "DEPLOYMENT_AUTHORIZATION",
                "reference_id": AUTHORIZATION_ID,
                "reference_version": version - 1,
            }
        value["deployment_authority_digest"] = deployment_authority_digest(value)
        return value

    def execute(self, raw, *, role=None, context=None):
        return self.executor.execute(
            raw,
            context or self.context(
                raw["command_type"], role=role, caller_type=raw["caller_type"]
            ),
        )

    def propose(self, payload=None, *, command="ProposeDeploymentAuthorization", expected=None, key=None):
        payload = payload or self.payload()
        raw = self.raw(command, payload, expected=expected, key=key)
        result = self.execute(raw)
        self.assertEqual(result["result"], "ACCEPTED", result)
        return raw

    def approval(self, role):
        payload = {
            "subject_version": 1,
            "authority_role": role,
            "authority_digest": self.payload()["deployment_authority_digest"],
        }
        raw = self.raw(
            "RecordDeploymentAuthorizationApproval", payload, expected=1,
            key=f"phase5d-deployment-approval-{role.lower()}",
        )
        result = self.execute(raw, role=role)
        self.assertEqual(result["result"], "ACCEPTED", result)
        return raw["command_id"]

    def activate(self, client_id, provider_id):
        payload = {
            "deployment_authorization_id": AUTHORIZATION_ID,
            "authorization_version": 1,
            "client_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": client_id,
                "reference_version": 1,
            },
            "provider_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": provider_id,
                "reference_version": 1,
            },
            "deployment_authority_digest": self.payload()["deployment_authority_digest"],
        }
        raw = self.raw(
            "ActivateDeploymentAuthorization", payload, expected=1,
            key="phase5d-deployment-activate-v1",
        )
        result = self.execute(raw)
        self.assertEqual(result["result"], "ACCEPTED", result)
        return raw

    def make_active(self):
        self.propose()
        client = self.approval("CLIENT_DEPLOYMENT_AUTHORITY")
        provider = self.approval("PROVIDER_DEPLOYMENT_AUTHORITY")
        self.activate(client, provider)
        return client, provider

    def test_client_acceptance_is_not_authority_then_exact_dual_activation(self):
        self.assertEqual(len(self.store.deployment_authorizations), 0)
        self.propose()
        uow = UnitOfWork(self.store)
        proposed = uow.deployment_authorizations.get_version(
            self.tenant, AUTHORIZATION_ID, 1
        )
        proposed_view = DeploymentAuthorizationReadService(uow).status(
            self.tenant, AUTHORIZATION_ID, 1, self.now
        )
        self.assertEqual(proposed["state"], "PROPOSED")
        self.assertFalse(proposed_view["deployment_authorized"])
        client = self.approval("CLIENT_DEPLOYMENT_AUTHORITY")
        self.assertFalse(DeploymentAuthorizationReadService(UnitOfWork(self.store)).status(
            self.tenant, AUTHORIZATION_ID, 1, self.now
        )["deployment_authorized"])
        provider = self.approval("PROVIDER_DEPLOYMENT_AUTHORITY")
        self.activate(client, provider)
        uow = UnitOfWork(self.store)
        active = uow.deployment_authorizations.get_version(
            self.tenant, AUTHORIZATION_ID, 1
        )
        view = DeploymentAuthorizationReadService(uow).status(
            self.tenant, AUTHORIZATION_ID, 1, self.now
        )
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:domain:deployment-authorization:v1"
            ).iter_errors(active)),
            [],
        )
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:read-models:deployment-authorization-status-view:v1"
            ).iter_errors(view)),
            [],
        )
        self.assertEqual(
            (view["state"], view["prerequisites_exact"], view["approvals_active"],
             view["deployment_authorized"], view["deployment_completed"]),
            ("ACTIVE", True, True, True, False),
        )
        self.assertEqual(
            [event["event_type"] for event in self.store.events],
            [
                "deployment_authorization.proposed",
                "deployment_authorization.approval_recorded",
                "deployment_authorization.approval_recorded",
                "deployment_authorization.activated",
            ],
        )
        self.assertEqual(len(self.store.outbox), 4)
        self.assertTrue(all(schema_validator(
            "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
        ).is_valid(event) for event in self.store.events))

    def test_exact_prerequisite_target_action_and_security_negatives(self):
        cases = (
            ("implementation-digest", lambda p: p.update(implementation_authority_digest="sha256:" + "9" * 64)),
            ("package-digest", lambda p: p.update(package_digest="sha256:" + "9" * 64)),
            ("build-digest", lambda p: p.update(build_execution_digest="sha256:" + "9" * 64)),
            ("qa-digest", lambda p: p.update(qa_result_digest="sha256:" + "9" * 64)),
            ("acceptance-digest", lambda p: p.update(client_acceptance_digest="sha256:" + "9" * 64)),
            ("artifact", lambda p: p["artifact_reference"].update(artifact_digest="sha256:" + "9" * 64)),
            ("target", lambda p: p["target_resources"][0].update(target_reference_id="component.unauthorized")),
        )
        for label, mutation in cases:
            payload = self.payload()
            mutation(payload)
            payload["deployment_authority_digest"] = deployment_authority_digest(payload)
            before = (
                len(self.store.deployment_authorizations), len(self.store.events),
                len(self.store.outbox), len(self.store.idempotency),
            )
            self.assertEqual(
                self.execute(self.raw(
                    "ProposeDeploymentAuthorization", payload,
                    key=f"phase5d-deployment-wrong-{label}",
                ))["result"],
                "REJECTED",
                label,
            )
            self.assertEqual(
                (
                    len(self.store.deployment_authorizations), len(self.store.events),
                    len(self.store.outbox), len(self.store.idempotency),
                ),
                before,
            )
        for field, value in (
            ("deployment_allowed", True),
            ("production_authorized", True),
            ("approved", True),
            ("actor_role", "CLIENT_DEPLOYMENT_AUTHORITY"),
            ("raw_provider_payload", {"result": "success"}),
        ):
            payload = self.payload()
            payload[field] = value
            self.assertEqual(
                self.execute(self.raw(
                    "ProposeDeploymentAuthorization", payload,
                    key=f"phase5d-deployment-spoof-{field}",
                ))["result"],
                "VALIDATION_FAILED",
                field,
            )
        weakened = self.payload()
        weakened["prohibited_deployment_actions"].pop()
        self.assertEqual(
            self.execute(self.raw(
                "ProposeDeploymentAuthorization", weakened,
                key="phase5d-deployment-weakened-prohibitions",
            ))["result"],
            "VALIDATION_FAILED",
        )
        secret = self.payload()
        secret["rollback_recovery_requirement"]["strategy"] = (
            "Use password=fictional-but-prohibited during rollback."
        )
        secret["deployment_authority_digest"] = deployment_authority_digest(secret)
        self.assertEqual(
            self.execute(self.raw(
                "ProposeDeploymentAuthorization", secret,
                key="phase5d-deployment-forbidden-content",
            ))["result"],
            "REJECTED",
        )

    def test_workload_cannot_approve_or_revoke_and_role_spoofing_fails(self):
        self.propose()
        approvals_before = len(self.store.approvals)
        approval = {
            "subject_version": 1,
            "authority_role": "CLIENT_DEPLOYMENT_AUTHORITY",
            "authority_digest": self.payload()["deployment_authority_digest"],
        }
        raw = self.raw(
            "RecordDeploymentAuthorizationApproval", approval, expected=1,
            caller_type="INTERNAL_SERVICE", key="phase5d-deployment-workload-approval",
        )
        self.assertEqual(self.execute(raw)["result"], "REJECTED")
        wrong = self.context(
            "RecordDeploymentAuthorizationApproval",
            role="PROVIDER_DEPLOYMENT_AUTHORITY",
        )
        self.assertEqual(
            self.execute(
                self.raw(
                    "RecordDeploymentAuthorizationApproval", approval, expected=1,
                    key="phase5d-deployment-role-spoof",
                ),
                context=wrong,
            )["result"],
            "REJECTED",
        )
        revoke = {
            "deployment_authorization_id": AUTHORIZATION_ID,
            "authorization_version": 1,
            "revocation_reason": "SECURITY_CONCERN",
            "deployment_authority_digest": self.payload()["deployment_authority_digest"],
        }
        workload_revoke = self.raw(
            "RevokeDeploymentAuthorization", revoke, expected=1,
            caller_type="INTERNAL_SERVICE", key="phase5d-deployment-workload-revoke",
        )
        self.assertEqual(self.execute(workload_revoke)["result"], "REJECTED")
        self.assertEqual(len(self.store.approvals), approvals_before)

    def test_version_supersession_revocation_expiry_and_stale_concurrency(self):
        self.make_active()
        version2 = self.payload(version=2)
        self.propose(
            version2,
            command="ReviseDeploymentAuthorization",
            expected=2,
            key="phase5d-deployment-revise-v2",
        )
        uow = UnitOfWork(self.store)
        history = uow.deployment_authorizations.list_versions(
            self.tenant, AUTHORIZATION_ID
        )
        self.assertEqual(
            [(item["authorization_version"], item["state"]) for item in history],
            [(1, "SUPERSEDED"), (2, "PROPOSED")],
        )
        self.assertEqual(
            history[1]["supersedes_deployment_authorization_reference"]["reference_version"], 1
        )
        stale = copy.deepcopy(version2)
        self.assertEqual(
            self.execute(self.raw(
                "ReviseDeploymentAuthorization", stale, expected=2,
                key="phase5d-deployment-stale-revision",
            ))["result"],
            "REJECTED",
        )
        revoke = {
            "deployment_authorization_id": AUTHORIZATION_ID,
            "authorization_version": 2,
            "revocation_reason": "CLIENT_WITHDRAWAL",
            "deployment_authority_digest": version2["deployment_authority_digest"],
        }
        result = self.execute(
            self.raw(
                "RevokeDeploymentAuthorization", revoke, expected=1,
                key="phase5d-deployment-revoke-v2",
            ),
            role="CLIENT_DEPLOYMENT_AUTHORITY",
        )
        self.assertEqual(result["result"], "ACCEPTED")
        revoked = DeploymentAuthorizationReadService(UnitOfWork(self.store)).status(
            self.tenant, AUTHORIZATION_ID, 2, self.now
        )
        self.assertEqual(revoked["state"], "REVOKED")
        self.assertFalse(revoked["deployment_authorized"])
        active_view = DeploymentAuthorizationReadService(UnitOfWork(self.store)).status(
            self.tenant, AUTHORIZATION_ID, 1, "2030-01-15T16:00:00Z"
        )
        self.assertFalse(active_view["deployment_authorized"])

    def test_idempotency_cross_tenant_activation_negatives_and_atomic_rollback(self):
        raw = self.propose()
        self.assertEqual(self.execute(copy.deepcopy(raw))["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["target_environment"] = "STAGING"
        self.assertEqual(self.execute(changed)["result"], "CONFLICT")
        foreign = self.raw(
            "ProposeDeploymentAuthorization", self.payload(),
            tenant=FOREIGN_TENANT, key="phase5d-deployment-cross-tenant",
        )
        self.assertEqual(self.execute(foreign)["result"], "REJECTED")
        client = self.approval("CLIENT_DEPLOYMENT_AUTHORITY")
        activation = {
            "deployment_authorization_id": AUTHORIZATION_ID,
            "authorization_version": 1,
            "client_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": client,
                "reference_version": 1,
            },
            "provider_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": client,
                "reference_version": 1,
            },
            "deployment_authority_digest": self.payload()["deployment_authority_digest"],
        }
        self.assertEqual(
            self.execute(self.raw(
                "ActivateDeploymentAuthorization", activation, expected=1,
                key="phase5d-deployment-one-approval",
            ))["result"],
            "VALIDATION_FAILED",
        )
        for stage in (
            "AUTHORITATIVE_WRITE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND",
            "IDEMPOTENCY_COMPLETE", "COMMIT",
        ):
            fresh = DeploymentAuthorizationRuntimeTests()
            fresh.setUp()
            fresh.store.fail_stage = stage
            before = copy.deepcopy(fresh.store)
            result = fresh.execute(fresh.raw(
                "ProposeDeploymentAuthorization", fresh.payload(),
                key=f"phase5d-deployment-fail-{stage.lower()}",
            ))
            self.assertEqual(result["result"], "REJECTED", stage)
            fresh.store.fail_stage = None
            self.assertEqual(
                fresh.store.deployment_authorizations,
                before.deployment_authorizations,
                stage,
            )
            self.assertEqual(fresh.store.events, before.events, stage)
            self.assertEqual(fresh.store.outbox, before.outbox, stage)
            self.assertEqual(fresh.store.idempotency, before.idempotency, stage)


if __name__ == "__main__":
    unittest.main()
