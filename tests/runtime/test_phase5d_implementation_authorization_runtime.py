"""Phase 5D-B2 ImplementationAuthorization runtime and authority coverage."""
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
from avuhz_runtime.phase5d_authorization import (
    IMPLEMENTATION_AUTHORIZATION_CAPABILITIES,
    ImplementationAuthorizationReadService,
    implementation_authority_digest,
    implementation_authorization_scope_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_implementation_brief_runtime as brief_runtime


AUTHORIZATION_ID = "d5200000-0000-4000-8000-000000000001"
FOREIGN_TENANT = "d5200000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
    return Draft202012Validator(
        registry.expanded(schema_id), format_checker=FormatChecker()
    )


class ImplementationAuthorizationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.b = brief_runtime.ImplementationBriefRuntimeTests()
        self.b.setUp()
        self.brief_payload = self.b.payload()
        self.b.draft(self.brief_payload)
        self.b.approve(self.brief_payload)
        self.store = self.b.store
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self._number = 700
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"),
            GuardPipeline(),
            self.store,
            clock=lambda: self.now,
            ids=self.next_id,
        )

    @property
    def tenant(self):
        return self.b.tenant

    @property
    def engagement_id(self):
        return self.b.engagement_id

    @property
    def now(self):
        return self.b.h.now

    def next_id(self):
        self._number += 1
        return f"d5290000-0000-4000-8000-{self._number:012d}"

    def context(self, command, *, caller_type=None, role=None, tenant=None, principal=None):
        caller_type = caller_type or (
            "HUMAN"
            if command in {
                "RecordImplementationAuthorizationApproval",
                "RevokeImplementationAuthorization",
            }
            else "INTERNAL_SERVICE"
        )
        principal = principal or (
            "human.client-implementation"
            if role == "CLIENT_IMPLEMENTATION_AUTHORITY"
            else "human.sekinfra-implementation"
            if caller_type == "HUMAN"
            else "service.phase5d-authorization"
        )
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True,
            principal,
            caller_type,
            tenant or self.tenant,
            None,
            frozenset({IMPLEMENTATION_AUTHORIZATION_CAPABILITIES[command]}),
            frozenset({role} if role else ()),
            "TEST",
            "avuhz-command-api",
            "STRONG",
            False,
            "2030-01-15T14:00:00Z",
            "2030-03-15T16:00:00Z",
            principal if human else None,
            (
                "organization.client"
                if role == "CLIENT_IMPLEMENTATION_AUTHORITY"
                else "organization.sekinfra"
                if human
                else None
            ),
            role,
        )

    def raw(
        self,
        command,
        payload,
        *,
        expected=None,
        key=None,
        command_id=None,
        caller_type=None,
        tenant=None,
        engagement=None,
    ):
        slugs = {
            "ProposeImplementationAuthorization": "propose-implementation-authorization",
            "ReviseImplementationAuthorization": "revise-implementation-authorization",
            "RecordImplementationAuthorizationApproval": "record-implementation-authorization-approval",
            "ActivateImplementationAuthorization": "activate-implementation-authorization",
            "RevokeImplementationAuthorization": "revoke-implementation-authorization",
        }
        caller_type = caller_type or (
            "HUMAN"
            if command in {
                "RecordImplementationAuthorizationApproval",
                "RevokeImplementationAuthorization",
            }
            else "INTERNAL_SERVICE"
        )
        tenant = tenant or self.tenant
        value = {
            "command_id": command_id or self.next_id(),
            "command_type": command,
            "command_schema_version": 1,
            "tenant_id": tenant,
            "engagement_id": engagement or self.engagement_id,
            "subject_type": "IMPLEMENTATION_AUTHORIZATION",
            "subject_id": payload.get("implementation_authorization_id", AUTHORIZATION_ID),
            "requested_by": "trusted.phase5d",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d",
                "audience": "avuhz-command-api",
                "caller_type": caller_type,
                "tenant_ids": [tenant],
                "capabilities": [IMPLEMENTATION_AUTHORIZATION_CAPABILITIES[command]],
                "environment": "TEST",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5200000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5d-{command.lower()}-0001",
            "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": (
                f"urn:avuhz:schema:contracts:commands:{slugs[command]}-payload:v1"
            ),
            "payload_version": 1,
            "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def payload(self, *, authorization_id=AUTHORIZATION_ID, version=1):
        brief = UnitOfWork(self.store).implementation_briefs.get_version(
            self.tenant, self.brief_payload["implementation_brief_id"], 1
        )
        payload = {
            "implementation_authorization_id": authorization_id,
            "authorization_version": version,
            "implementation_brief_reference": {
                "reference_type": "IMPLEMENTATION_BRIEF",
                "reference_id": brief["implementation_brief_id"],
                "reference_version": brief["implementation_brief_version"],
            },
            "implementation_brief_digest": brief["implementation_brief_digest"],
            "authorized_scope_digest": implementation_authorization_scope_digest(brief),
            "target_references": [
                {"target_reference_id": "scope.intake", "target_class": "COMPONENT"},
                {
                    "target_reference_id": "integration.fictional.sandbox",
                    "target_class": "NON_PRODUCTION_SYSTEM",
                },
            ],
            "permitted_action_classes": [
                "READ_REPOSITORY",
                "CREATE_CODE",
                "MODIFY_CODE",
                "CREATE_TEST",
                "MODIFY_TEST",
                "RUN_TEST",
                "CREATE_DOCUMENTATION",
                "MODIFY_DOCUMENTATION",
                "BUILD_NON_PRODUCTION_ARTIFACT",
            ],
            "prohibited_action_classes": copy.deepcopy(brief["prohibited_changes"]),
            "effective_at": self.now,
            "expires_at": "2030-02-15T14:59:59Z",
            "implementation_authority_digest": "sha256:" + "0" * 64,
        }
        if version > 1:
            payload["supersedes_implementation_authorization_reference"] = {
                "reference_type": "IMPLEMENTATION_AUTHORIZATION",
                "reference_id": authorization_id,
                "reference_version": version - 1,
            }
        payload["implementation_authority_digest"] = implementation_authority_digest(payload)
        return payload

    def execute(
        self,
        command,
        payload,
        *,
        expected=None,
        role=None,
        caller_type=None,
        key=None,
        command_id=None,
        context_role=None,
    ):
        raw = self.raw(
            command,
            payload,
            expected=expected,
            caller_type=caller_type,
            key=key,
            command_id=command_id,
        )
        result = self.executor.execute(
            raw,
            self.context(
                command,
                caller_type=caller_type,
                role=context_role if context_role is not None else role,
            ),
        )
        self.assertEqual(result["result"], "ACCEPTED", (command, result))
        return raw

    def approve(self, payload):
        approval_ids = []
        for role, suffix in (
            ("CLIENT_IMPLEMENTATION_AUTHORITY", "client"),
            ("SEKINFRA_IMPLEMENTATION_AUTHORITY", "sekinfra"),
        ):
            command_id = self.next_id()
            self.execute(
                "RecordImplementationAuthorizationApproval",
                {
                    "subject_version": payload["authorization_version"],
                    "authority_role": role,
                    "authority_digest": payload["implementation_authority_digest"],
                },
                expected=1,
                role=role,
                command_id=command_id,
                key=f"phase5d-auth-approval-{suffix}-{payload['authorization_version']}",
            )
            approval_ids.append(command_id)
        return approval_ids

    def activate(self, payload, approval_ids):
        self.execute(
            "ActivateImplementationAuthorization",
            {
                "implementation_authorization_id": payload["implementation_authorization_id"],
                "authorization_version": payload["authorization_version"],
                "client_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL",
                    "reference_id": approval_ids[0],
                    "reference_version": 1,
                },
                "sekinfra_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL",
                    "reference_id": approval_ids[1],
                    "reference_version": 1,
                },
                "implementation_authority_digest": payload[
                    "implementation_authority_digest"
                ],
            },
            expected=1,
        )

    def assert_no_effects(self, before):
        self.assertEqual(
            (
                copy.deepcopy(self.store.implementation_authorizations),
                copy.deepcopy(self.store.approvals),
                copy.deepcopy(self.store.events),
                copy.deepcopy(self.store.outbox),
                copy.deepcopy(self.store.idempotency),
            ),
            before,
        )

    def test_happy_path_exact_brief_dual_human_activation_and_zero_deployment(self):
        payload = self.payload()
        self.execute("ProposeImplementationAuthorization", payload)
        proposed = UnitOfWork(self.store).implementation_authorizations.get_version(
            self.tenant, AUTHORIZATION_ID, 1
        )
        self.assertEqual((proposed["state"], proposed["record_version"]), ("PROPOSED", 1))
        approval_ids = self.approve(payload)
        self.activate(payload, approval_ids)
        uow = UnitOfWork(self.store)
        active = uow.implementation_authorizations.get_version(
            self.tenant, AUTHORIZATION_ID, 1
        )
        self.assertEqual((active["state"], active["record_version"]), ("ACTIVE", 2))
        self.assertEqual(
            active["source_ongoing_access_reference"],
            self.brief_payload["source_ongoing_access_reference"],
        )
        self.assertFalse(list(schema_validator(
            "urn:avuhz:schema:contracts:domain:implementation-authorization:v1"
        ).iter_errors(active)))
        approval_validator = schema_validator(
            "urn:avuhz:schema:contracts:domain:human-approval:v1"
        )
        authorization_approvals = [
            approval for approval in self.store.approvals.values()
            if approval.get("subject_type") == "IMPLEMENTATION_AUTHORIZATION"
        ]
        self.assertEqual([list(approval_validator.iter_errors(approval)) for approval in authorization_approvals], [[], []])
        status = ImplementationAuthorizationReadService(uow).status(
            self.tenant, AUTHORIZATION_ID, 1, self.now
        )
        self.assertTrue(status["implementation_authorization_ready"])
        self.assertTrue(status["implementation_authorization_usable"])
        self.assertEqual(
            (status["deployment_authorized"], status["production_change_authorized"]),
            (False, False),
        )
        self.assertFalse(list(schema_validator(
            "urn:avuhz:schema:contracts:read-models:implementation-authorization-status-view:v1"
        ).iter_errors(status)))
        self.assertEqual(
            [event["event_type"] for event in self.store.events],
            [
                "implementation_authorization.proposed",
                "implementation_authorization.approval_recorded",
                "implementation_authorization.approval_recorded",
                "implementation_authorization.activated",
            ],
        )
        self.assertTrue(all(
            intent == {"event_id": event["event_id"], "status": "PENDING"}
            for intent, event in zip(self.store.outbox, self.store.events)
        ))

    def test_exact_brief_source_scope_target_and_prohibited_boundaries(self):
        mutations = (
            lambda p: p["implementation_brief_reference"].update(reference_version=2),
            lambda p: p.update(implementation_brief_digest="sha256:" + "f" * 64),
            lambda p: p.update(authorized_scope_digest="sha256:" + "e" * 64),
            lambda p: p["target_references"][0].update(
                target_reference_id="component.outside-approved-brief"
            ),
        )
        for index, mutate in enumerate(mutations):
            payload = self.payload(
                authorization_id=f"d5200000-0000-4000-8000-{100 + index:012d}"
            )
            mutate(payload)
            payload["implementation_authority_digest"] = implementation_authority_digest(payload)
            before = (
                copy.deepcopy(self.store.implementation_authorizations),
                copy.deepcopy(self.store.approvals),
                copy.deepcopy(self.store.events),
                copy.deepcopy(self.store.outbox),
                copy.deepcopy(self.store.idempotency),
            )
            result = self.executor.execute(
                self.raw(
                    "ProposeImplementationAuthorization",
                    payload,
                    key=f"phase5d-auth-source-negative-{index}",
                ),
                self.context("ProposeImplementationAuthorization"),
            )
            self.assertEqual(result["result"], "REJECTED")
            self.assert_no_effects(before)

        for field, value in (
            ("permitted_action_classes", ["PRODUCTION_CHANGE"]),
            ("prohibited_action_classes", ["PRODUCTION_DEPLOYMENT"]),
        ):
            payload = self.payload(authorization_id=self.next_id())
            payload[field] = value
            payload["implementation_authority_digest"] = implementation_authority_digest(payload)
            result = self.executor.execute(
                self.raw("ProposeImplementationAuthorization", payload, key=self.next_id()),
                self.context("ProposeImplementationAuthorization"),
            )
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_unapproved_superseded_and_cross_tenant_briefs_fail_closed(self):
        approved = self.store.implementation_briefs[
            (self.tenant, self.brief_payload["implementation_brief_id"], 1)
        ]
        approved["state"] = "DRAFT"
        payload = self.payload()
        payload["implementation_authority_digest"] = implementation_authority_digest(payload)
        result = self.executor.execute(
            self.raw("ProposeImplementationAuthorization", payload),
            self.context("ProposeImplementationAuthorization"),
        )
        self.assertEqual(result["result"], "REJECTED")
        approved["state"] = "APPROVED"

        result = self.executor.execute(
            self.raw(
                "ProposeImplementationAuthorization",
                self.payload(authorization_id=self.next_id()),
                tenant=FOREIGN_TENANT,
                key="phase5d-auth-cross-tenant-0001",
            ),
            self.context("ProposeImplementationAuthorization", tenant=FOREIGN_TENANT),
        )
        self.assertEqual(result["result"], "REJECTED")
        self.assertIsNone(UnitOfWork(self.store).implementation_authorizations.get_version(
            FOREIGN_TENANT, AUTHORIZATION_ID, 1
        ))

    def test_dual_human_workload_and_role_spoof_boundaries(self):
        payload = self.payload()
        self.execute("ProposeImplementationAuthorization", payload)
        client_id = self.next_id()
        self.execute(
            "RecordImplementationAuthorizationApproval",
            {
                "subject_version": 1,
                "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY",
                "authority_digest": payload["implementation_authority_digest"],
            },
            expected=1,
            role="CLIENT_IMPLEMENTATION_AUTHORITY",
            command_id=client_id,
        )
        missing = {
            "implementation_authorization_id": AUTHORIZATION_ID,
            "authorization_version": 1,
            "client_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": client_id,
                "reference_version": 1,
            },
            "sekinfra_approval_reference": {
                "reference_type": "HUMAN_APPROVAL",
                "reference_id": self.next_id(),
                "reference_version": 1,
            },
            "implementation_authority_digest": payload["implementation_authority_digest"],
        }
        result = self.executor.execute(
            self.raw("ActivateImplementationAuthorization", missing, expected=1),
            self.context("ActivateImplementationAuthorization"),
        )
        self.assertEqual(result["result"], "REJECTED")

        approval_payload = {
            "subject_version": 1,
            "authority_role": "SEKINFRA_IMPLEMENTATION_AUTHORITY",
            "authority_digest": payload["implementation_authority_digest"],
        }
        spoof = self.executor.execute(
            self.raw(
                "RecordImplementationAuthorizationApproval",
                approval_payload,
                expected=1,
                key="phase5d-auth-role-spoof-0001",
            ),
            self.context(
                "RecordImplementationAuthorizationApproval",
                role="CLIENT_IMPLEMENTATION_AUTHORITY",
            ),
        )
        self.assertEqual(spoof["result"], "REJECTED")
        workload = self.executor.execute(
            self.raw(
                "RecordImplementationAuthorizationApproval",
                approval_payload,
                expected=1,
                caller_type="WORKLOAD",
                key="phase5d-auth-workload-0001",
            ),
            self.context(
                "RecordImplementationAuthorizationApproval",
                caller_type="WORKLOAD",
            ),
        )
        self.assertEqual(workload["result"], "VALIDATION_FAILED")

    def test_payload_authority_spoof_and_deployment_claims_are_not_contract_fields(self):
        cases = (
            ("ProposeImplementationAuthorization", {**self.payload(), "deployment_allowed": True}),
            (
                "ActivateImplementationAuthorization",
                {
                    "implementation_authorization_id": AUTHORIZATION_ID,
                    "authorization_version": 1,
                    "client_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": self.next_id(), "reference_version": 1},
                    "sekinfra_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": self.next_id(), "reference_version": 1},
                    "implementation_authority_digest": "sha256:" + "a" * 64,
                    "authorized_by": "caller.spoof",
                },
            ),
        )
        for index, (command, payload) in enumerate(cases):
            result = self.executor.execute(
                self.raw(command, payload, expected=1 if index else None, key=self.next_id()),
                self.context(command),
            )
            self.assertEqual(result["result"], "VALIDATION_FAILED")

    def test_idempotency_identity_and_stale_concurrency(self):
        payload = self.payload()
        raw = self.raw(
            "ProposeImplementationAuthorization",
            payload,
            key="phase5d-auth-idempotency-0001",
            command_id=self.next_id(),
        )
        context = self.context("ProposeImplementationAuthorization")
        self.assertEqual(self.executor.execute(raw, context)["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(raw, context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["expires_at"] = "2030-02-14T14:59:59Z"
        changed["payload"]["implementation_authority_digest"] = implementation_authority_digest(
            changed["payload"]
        )
        self.assertEqual(self.executor.execute(changed, context)["result"], "CONFLICT")
        duplicate_identity = self.executor.execute(
            self.raw(
                "ProposeImplementationAuthorization",
                payload,
                key="phase5d-auth-duplicate-identity-0001",
            ),
            context,
        )
        self.assertEqual(duplicate_identity["result"], "REJECTED")
        stale = self.executor.execute(
            self.raw(
                "RecordImplementationAuthorizationApproval",
                {
                    "subject_version": 1,
                    "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY",
                    "authority_digest": payload["implementation_authority_digest"],
                },
                expected=2,
                key="phase5d-auth-stale-0001",
            ),
            self.context(
                "RecordImplementationAuthorizationApproval",
                role="CLIENT_IMPLEMENTATION_AUTHORITY",
            ),
        )
        self.assertEqual(stale["reason_code"], "VERSION_STALE")

    def test_revision_history_revocation_and_no_brief_mutation(self):
        first = self.payload()
        brief_before = copy.deepcopy(self.store.implementation_briefs)
        self.execute("ProposeImplementationAuthorization", first)
        self.activate(first, self.approve(first))
        second = self.payload(version=2)
        second["permitted_action_classes"] = ["READ_REPOSITORY", "CREATE_TEST", "RUN_TEST"]
        second["implementation_authority_digest"] = implementation_authority_digest(second)
        self.execute("ReviseImplementationAuthorization", second, expected=2)
        history = UnitOfWork(self.store).implementation_authorizations.list_versions(
            self.tenant, AUTHORIZATION_ID
        )
        self.assertEqual(
            [(record["authorization_version"], record["state"], record["record_version"]) for record in history],
            [(1, "SUPERSEDED", 3), (2, "PROPOSED", 1)],
        )
        self.assertEqual(history[0]["implementation_authority_digest"], first["implementation_authority_digest"])
        self.execute(
            "RevokeImplementationAuthorization",
            {
                "implementation_authorization_id": AUTHORIZATION_ID,
                "revocation_reason": "SECURITY_CONCERN",
            },
            expected=1,
            role="SEKINFRA_IMPLEMENTATION_AUTHORITY",
        )
        revoked = UnitOfWork(self.store).implementation_authorizations.get_version(
            self.tenant, AUTHORIZATION_ID, 2
        )
        self.assertEqual((revoked["state"], revoked["record_version"]), ("REVOKED", 2))
        self.assertEqual(self.store.implementation_briefs, brief_before)

    def test_atomic_rollback_for_each_uow_stage(self):
        for index, stage in enumerate((
            "IDEMPOTENCY_RESERVE",
            "AUTHORITATIVE_WRITE",
            "LIFECYCLE_EVENT_APPEND",
            "OUTBOX_APPEND",
            "IDEMPOTENCY_COMPLETE",
            "COMMIT",
        )):
            payload = self.payload(
                authorization_id=f"d5200000-0000-4000-8000-{300 + index:012d}"
            )
            before = (
                copy.deepcopy(self.store.implementation_authorizations),
                copy.deepcopy(self.store.approvals),
                copy.deepcopy(self.store.events),
                copy.deepcopy(self.store.outbox),
                copy.deepcopy(self.store.idempotency),
            )
            self.store.fail_stage = stage
            result = self.executor.execute(
                self.raw(
                    "ProposeImplementationAuthorization",
                    payload,
                    key=f"phase5d-auth-failpoint-{index}",
                ),
                self.context("ProposeImplementationAuthorization"),
            )
            self.store.fail_stage = None
            self.assertEqual(result["result"], "REJECTED", stage)
            self.assert_no_effects(before)

    def test_ongoing_access_is_prerequisite_not_implementation_authority(self):
        self.assertTrue(self.store.ongoing_access_grants)
        self.assertFalse(self.store.implementation_authorizations)
        payload = self.payload()
        self.execute("ProposeImplementationAuthorization", payload)
        self.activate(payload, self.approve(payload))
        stored_before = copy.deepcopy(self.store.implementation_authorizations)
        grant_key = (self.tenant, self.b.h.ongoing_grant_id)
        self.store.ongoing_access_grants[grant_key]["state"] = "REVOKED"
        status = ImplementationAuthorizationReadService(UnitOfWork(self.store)).status(
            self.tenant, AUTHORIZATION_ID, 1, self.now
        )
        self.assertFalse(status["ongoing_access_usable"])
        self.assertFalse(status["implementation_authorization_usable"])
        self.assertEqual(self.store.implementation_authorizations, stored_before)


if __name__ == "__main__":
    unittest.main()
