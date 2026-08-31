"""Phase 5D-B3 CodexBuildPackage runtime, authority, and atomicity coverage."""
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
from avuhz_runtime.phase5d_package import (
    CODEX_BUILD_PACKAGE_CAPABILITIES,
    CodexBuildPackageReadService,
    codex_build_package_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_implementation_authorization_runtime as auth_runtime


PACKAGE_ID = "d5300000-0000-4000-8000-000000000001"
FOREIGN_TENANT = "d5300000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
    return Draft202012Validator(
        registry.expanded(schema_id), format_checker=FormatChecker()
    )


class CodexBuildPackageRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.a = auth_runtime.ImplementationAuthorizationRuntimeTests()
        self.a.setUp()
        implementation_authority = self.a.payload()
        self.a.execute("ProposeImplementationAuthorization", implementation_authority)
        self.a.activate(implementation_authority, self.a.approve(implementation_authority))
        self.authorization_payload = implementation_authority
        self.store = self.a.store
        self.store.events.clear()
        self.store.outbox.clear()
        self.store.idempotency.clear()
        self._number = 900
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
        return f"d5390000-0000-4000-8000-{self._number:012d}"

    def context(self, command, *, caller_type=None, role=None, tenant=None):
        caller_type = caller_type or (
            "HUMAN" if command == "RecordCodexBuildPackageApproval" else "INTERNAL_SERVICE"
        )
        principal = (
            "human.client-package"
            if role == "CLIENT_IMPLEMENTATION_AUTHORITY"
            else "human.sekinfra-package"
            if caller_type == "HUMAN"
            else "service.phase5d-package"
        )
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True,
            principal,
            caller_type,
            tenant or self.tenant,
            None,
            frozenset({CODEX_BUILD_PACKAGE_CAPABILITIES[command]}),
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
        package_id=None,
        expected=None,
        caller_type=None,
        tenant=None,
        engagement=None,
        key=None,
        command_id=None,
    ):
        slugs = {
            "DraftCodexBuildPackage": "draft-codex-build-package",
            "ReviseCodexBuildPackage": "revise-codex-build-package",
            "RecordCodexBuildPackageApproval": "record-codex-build-package-approval",
            "ReleaseCodexBuildPackage": "release-codex-build-package",
        }
        caller_type = caller_type or (
            "HUMAN" if command == "RecordCodexBuildPackageApproval" else "INTERNAL_SERVICE"
        )
        tenant = tenant or self.tenant
        command_id = command_id or self.next_id()
        value = {
            "command_id": command_id,
            "command_type": command,
            "command_schema_version": 1,
            "tenant_id": tenant,
            "engagement_id": engagement or self.engagement_id,
            "subject_type": "CODEX_BUILD_PACKAGE",
            "subject_id": package_id or payload.get("codex_build_package_id", PACKAGE_ID),
            "requested_by": "trusted.phase5d",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5d",
                "audience": "avuhz-command-api",
                "caller_type": caller_type,
                "tenant_ids": [tenant],
                "capabilities": [CODEX_BUILD_PACKAGE_CAPABILITIES[command]],
                "environment": "TEST",
                "authentication_strength": "STRONG",
                "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "d5300000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5d-package-{command.lower()}-{self._number}",
            "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{slugs[command]}-payload:v1",
            "payload_version": 1,
            "payload": copy.deepcopy(payload),
        }
        if expected is not None:
            value["expected_record_version"] = expected
        return value

    def payload(self, *, package_id=PACKAGE_ID, version=1):
        uow = UnitOfWork(self.store)
        brief = uow.implementation_briefs.get_version(
            self.tenant,
            self.authorization_payload["implementation_brief_reference"]["reference_id"],
            self.authorization_payload["implementation_brief_reference"]["reference_version"],
        )
        implementation_authority = uow.implementation_authorizations.get_version(
            self.tenant,
            self.authorization_payload["implementation_authorization_id"],
            self.authorization_payload["authorization_version"],
        )
        value = {
            "codex_build_package_id": package_id,
            "package_version": version,
            "implementation_brief_reference": copy.deepcopy(
                implementation_authority["implementation_brief_reference"]
            ),
            "implementation_brief_digest": implementation_authority["implementation_brief_digest"],
            "implementation_authorization_reference": {
                "reference_type": "IMPLEMENTATION_AUTHORIZATION",
                "reference_id": implementation_authority["implementation_authorization_id"],
                "reference_version": implementation_authority["authorization_version"],
            },
            "implementation_authority_digest": implementation_authority[
                "implementation_authority_digest"
            ],
            "authorized_build_scope": copy.deepcopy(brief["approved_scope"]),
            "problem_statement": brief["approved_business_problem"],
            "desired_outcome": brief["desired_business_outcome"],
            "current_architecture_context": copy.deepcopy(brief["current_state_context"]),
            "required_integrations": copy.deepcopy(brief["approved_integrations"]),
            "implementation_requirements": copy.deepcopy(
                brief["implementation_requirements"]
            ),
            "acceptance_criteria": copy.deepcopy(brief["acceptance_criteria"]),
            "constraints": copy.deepcopy(brief["known_constraints"]),
            "prohibited_changes": copy.deepcopy(brief["prohibited_changes"]),
            "allowed_targets": copy.deepcopy(implementation_authority["target_references"]),
            "test_obligations": [
                "Run positive, negative, traceability, concurrency, and regression fixtures."
            ],
            "rollback_recovery_expectations": [
                "Keep all pre-deployment changes reviewable and revertible."
            ],
            "package_digest": "sha256:" + "0" * 64,
        }
        if version > 1:
            value["supersedes_codex_build_package_reference"] = {
                "reference_type": "CODEX_BUILD_PACKAGE",
                "reference_id": package_id,
                "reference_version": version - 1,
            }
        value["package_digest"] = codex_build_package_digest(value)
        return value

    def execute(
        self,
        command,
        payload,
        *,
        package_id=None,
        expected=None,
        role=None,
        caller_type=None,
        key=None,
        command_id=None,
    ):
        raw = self.raw(
            command,
            payload,
            package_id=package_id,
            expected=expected,
            caller_type=caller_type,
            key=key,
            command_id=command_id,
        )
        result = self.executor.execute(
            raw, self.context(command, caller_type=caller_type, role=role)
        )
        self.assertEqual(result["result"], "ACCEPTED", (command, result))
        return raw

    def draft(self, payload):
        return self.execute("DraftCodexBuildPackage", payload)

    def approve(self, payload):
        approval_ids = []
        for role, suffix in (
            ("CLIENT_IMPLEMENTATION_AUTHORITY", "client"),
            ("PROVIDER_IMPLEMENTATION_AUTHORITY", "sekinfra"),
        ):
            approval_id = self.next_id()
            self.execute(
                "RecordCodexBuildPackageApproval",
                {
                    "subject_version": payload["package_version"],
                    "authority_role": role,
                    "authority_digest": payload["package_digest"],
                },
                package_id=payload["codex_build_package_id"],
                expected=1,
                role=role,
                command_id=approval_id,
                key=f"phase5d-package-approval-{suffix}-{payload['package_version']}",
            )
            approval_ids.append(approval_id)
        return approval_ids

    def release(self, payload, approval_ids):
        return self.execute(
            "ReleaseCodexBuildPackage",
            {
                "codex_build_package_id": payload["codex_build_package_id"],
                "package_version": payload["package_version"],
                "client_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL",
                    "reference_id": approval_ids[0],
                    "reference_version": 1,
                },
                "provider_approval_reference": {
                    "reference_type": "HUMAN_APPROVAL",
                    "reference_id": approval_ids[1],
                    "reference_version": 1,
                },
                "package_digest": payload["package_digest"],
            },
            expected=1,
        )

    def effects(self):
        return (
            copy.deepcopy(self.store.codex_build_packages),
            copy.deepcopy(self.store.approvals),
            copy.deepcopy(self.store.events),
            copy.deepcopy(self.store.outbox),
            copy.deepcopy(self.store.idempotency),
        )

    def assert_rejected_without_effects(self, raw, context):
        before = self.effects()
        result = self.executor.execute(raw, context)
        self.assertIn(result["result"], {"REJECTED", "VALIDATION_FAILED"}, result)
        self.assertEqual(self.effects(), before)
        return result

    def test_happy_path_exact_bindings_dual_human_release_and_zero_authority(self):
        payload = self.payload()
        draft_raw = self.draft(payload)
        duplicate = self.executor.execute(
            copy.deepcopy(draft_raw), self.context("DraftCodexBuildPackage")
        )
        self.assertEqual(duplicate["result"], "DUPLICATE")
        conflict_raw = copy.deepcopy(draft_raw)
        conflict_raw["payload"]["problem_statement"] += " Changed."
        conflict = self.executor.execute(
            conflict_raw, self.context("DraftCodexBuildPackage")
        )
        self.assertEqual(conflict["result"], "CONFLICT")

        approvals = self.approve(payload)
        self.release(payload, approvals)
        package = UnitOfWork(self.store).codex_build_packages.get_version(
            self.tenant, PACKAGE_ID, 1
        )
        self.assertEqual((package["state"], package["record_version"]), ("RELEASED", 2))
        self.assertEqual(package["implementation_brief_reference"], payload["implementation_brief_reference"])
        self.assertEqual(
            package["implementation_authorization_reference"],
            payload["implementation_authorization_reference"],
        )
        self.assertEqual(package["package_digest"], payload["package_digest"])
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:domain:codex-build-package:v1"
            ).iter_errors(package)),
            [],
        )

        readiness = CodexBuildPackageReadService(UnitOfWork(self.store)).readiness(
            self.tenant, PACKAGE_ID, 1, self.now
        )
        self.assertTrue(readiness["codex_build_package_ready"])
        self.assertFalse(readiness["package_grants_authority"])
        self.assertFalse(readiness["deployment_authorized"])
        self.assertFalse(readiness["production_change_authorized"])
        self.assertEqual(
            list(schema_validator(
                "urn:avuhz:schema:contracts:read-models:codex-build-package-readiness-view:v1"
            ).iter_errors(readiness)),
            [],
        )
        self.assertEqual(
            [event["event_type"] for event in self.store.events],
            [
                "codex_build_package.drafted",
                "codex_build_package.approval_recorded",
                "codex_build_package.approval_recorded",
                "codex_build_package.released",
            ],
        )
        self.assertTrue(all(row["status"] == "PENDING" for row in self.store.outbox))
        self.assertEqual(
            {row["event_id"] for row in self.store.outbox},
            {event["event_id"] for event in self.store.events},
        )
        self.assertTrue(all("authorized_build_scope" not in event["sanitized_metadata"] for event in self.store.events))

    def test_exact_brief_authorization_scope_target_and_security_negatives(self):
        mutations = [
            lambda p: p["implementation_brief_reference"].update(reference_version=2),
            lambda p: p.update(implementation_brief_digest="sha256:" + "a" * 64),
            lambda p: p["implementation_authorization_reference"].update(reference_version=2),
            lambda p: p.update(implementation_authority_digest="sha256:" + "b" * 64),
            lambda p: p["authorized_build_scope"].append({
                "scope_item_id": "scope.outside",
                "statement": "Attempt work outside the approved brief.",
                "source_traceability": copy.deepcopy(p["authorized_build_scope"][0]["source_traceability"]),
            }),
            lambda p: p["allowed_targets"].append({
                "target_reference_id": "component.unauthorized",
                "target_class": "COMPONENT",
            }),
            lambda p: p["test_obligations"].append("Deploy to production after tests."),
            lambda p: p["test_obligations"].append(
                "Deploy the package to a staging environment."
            ),
            lambda p: p["rollback_recovery_expectations"].append("Rotate credentials after build completion."),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                payload = self.payload(
                    package_id=f"d5300000-0000-4000-8000-{100 + index:012d}"
                )
                mutate(payload)
                if index >= 4:
                    payload["package_digest"] = codex_build_package_digest(payload)
                raw = self.raw("DraftCodexBuildPackage", payload)
                self.assert_rejected_without_effects(
                    raw, self.context("DraftCodexBuildPackage")
                )

        for extra in (
            {"deployment_authorized": True},
            {"production_change_authorized": True},
            {"raw_provider_payload": {"unrestricted": True}},
            {"credential": "fictional-but-prohibited"},
        ):
            payload = self.payload(package_id=self.next_id())
            payload.update(extra)
            raw = self.raw("DraftCodexBuildPackage", payload)
            self.assert_rejected_without_effects(
                raw, self.context("DraftCodexBuildPackage")
            )

        payload = self.payload(package_id=self.next_id())
        payload["prohibited_changes"].remove("PERMISSION_WIDENING")
        payload["package_digest"] = codex_build_package_digest(payload)
        self.assert_rejected_without_effects(
            self.raw("DraftCodexBuildPackage", payload),
            self.context("DraftCodexBuildPackage"),
        )
        payload = self.payload(package_id=self.next_id())
        mismatched_subject = self.raw(
            "DraftCodexBuildPackage",
            payload,
            package_id=self.next_id(),
        )
        result = self.assert_rejected_without_effects(
            mismatched_subject,
            self.context("DraftCodexBuildPackage"),
        )
        self.assertEqual(result["reason_code"], "PAYLOAD_INVALID")

        authorization_key = (
            self.tenant,
            self.authorization_payload["implementation_authorization_id"],
            self.authorization_payload["authorization_version"],
        )
        self.store.implementation_authorizations[authorization_key]["state"] = "REVOKED"
        payload = self.payload(package_id=self.next_id())
        self.assert_rejected_without_effects(
            self.raw("DraftCodexBuildPackage", payload),
            self.context("DraftCodexBuildPackage"),
        )
        self.store.implementation_authorizations[authorization_key]["state"] = "ACTIVE"

        payload = self.payload(package_id=self.next_id())
        self.assert_rejected_without_effects(
            self.raw(
                "DraftCodexBuildPackage",
                payload,
                tenant=FOREIGN_TENANT,
            ),
            self.context("DraftCodexBuildPackage", tenant=FOREIGN_TENANT),
        )

    def test_human_ai_boundary_stale_version_duplicate_identity_and_atomic_rollback(self):
        payload = self.payload()
        self.draft(payload)

        approval_payload = {
            "subject_version": 1,
            "authority_role": "CLIENT_IMPLEMENTATION_AUTHORITY",
            "authority_digest": payload["package_digest"],
        }
        wrong_engagement = self.raw(
            "RecordCodexBuildPackageApproval",
            approval_payload,
            package_id=PACKAGE_ID,
            expected=1,
            engagement=FOREIGN_TENANT,
        )
        result = self.assert_rejected_without_effects(
            wrong_engagement,
            self.context(
                "RecordCodexBuildPackageApproval", role="CLIENT_IMPLEMENTATION_AUTHORITY"
            ),
        )
        self.assertEqual(result["reason_code"], "CROSS_TENANT_ATTEMPT")

        workload_raw = self.raw(
            "RecordCodexBuildPackageApproval",
            approval_payload,
            package_id=PACKAGE_ID,
            expected=1,
            caller_type="INTERNAL_SERVICE",
        )
        self.assert_rejected_without_effects(
            workload_raw,
            self.context(
                "RecordCodexBuildPackageApproval", caller_type="INTERNAL_SERVICE"
            ),
        )

        spoofed_raw = self.raw(
            "RecordCodexBuildPackageApproval",
            approval_payload,
            package_id=PACKAGE_ID,
            expected=1,
        )
        self.assert_rejected_without_effects(
            spoofed_raw,
            self.context(
                "RecordCodexBuildPackageApproval",
                role="PROVIDER_IMPLEMENTATION_AUTHORITY",
            ),
        )

        duplicate_identity = self.raw(
            "DraftCodexBuildPackage",
            payload,
            key="phase5d-package-duplicate-identity-0001",
        )
        self.assert_rejected_without_effects(
            duplicate_identity, self.context("DraftCodexBuildPackage")
        )

        stale = self.raw(
            "RecordCodexBuildPackageApproval",
            approval_payload,
            package_id=PACKAGE_ID,
            expected=2,
        )
        result = self.assert_rejected_without_effects(
            stale,
            self.context(
                "RecordCodexBuildPackageApproval",
                role="CLIENT_IMPLEMENTATION_AUTHORITY",
            ),
        )
        self.assertEqual(result["reason_code"], "VERSION_STALE")

        baseline = copy.deepcopy(self.store)
        for stage in (
            "AUTHORITATIVE_WRITE",
            "LIFECYCLE_EVENT_APPEND",
            "OUTBOX_APPEND",
            "IDEMPOTENCY_COMPLETE",
            "COMMIT",
        ):
            self.store.__dict__.update(copy.deepcopy(baseline.__dict__))
            self.store.fail_stage = stage
            atomic_payload = self.payload(package_id=self.next_id())
            result = self.executor.execute(
                self.raw("DraftCodexBuildPackage", atomic_payload),
                self.context("DraftCodexBuildPackage"),
            )
            self.assertEqual(result["result"], "REJECTED", stage)
            self.store.fail_stage = None
            self.assertEqual(self.store.codex_build_packages, baseline.codex_build_packages)
            self.assertEqual(self.store.events, baseline.events)
            self.assertEqual(self.store.outbox, baseline.outbox)
            self.assertEqual(self.store.idempotency, baseline.idempotency)

    def test_revision_preserves_immutable_history_and_exact_bindings(self):
        v1 = self.payload()
        self.draft(v1)
        self.release(v1, self.approve(v1))
        v1_record = copy.deepcopy(
            UnitOfWork(self.store).codex_build_packages.get_version(
                self.tenant, PACKAGE_ID, 1
            )
        )
        v2 = self.payload(version=2)
        v2["test_obligations"].append("Run immutable-history regression checks.")
        v2["package_digest"] = codex_build_package_digest(v2)
        self.execute("ReviseCodexBuildPackage", v2, expected=2)
        history = UnitOfWork(self.store).codex_build_packages.list_versions(
            self.tenant, PACKAGE_ID
        )
        self.assertEqual(
            [(row["package_version"], row["state"], row["record_version"]) for row in history],
            [(1, "SUPERSEDED", 3), (2, "DRAFT", 1)],
        )
        self.assertEqual(history[0]["package_digest"], v1_record["package_digest"])
        self.assertEqual(
            history[0]["implementation_brief_reference"],
            v1_record["implementation_brief_reference"],
        )
        self.assertEqual(
            history[0]["implementation_authorization_reference"],
            v1_record["implementation_authorization_reference"],
        )
        self.release(v2, self.approve(v2))
        self.assertEqual(
            UnitOfWork(self.store).codex_build_packages.get_version(
                self.tenant, PACKAGE_ID, 2
            )["state"],
            "RELEASED",
        )


if __name__ == "__main__":
    unittest.main()
