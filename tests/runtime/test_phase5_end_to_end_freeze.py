"""Phase 5 provider-neutral chain freeze certification."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_deployment_verification_runtime as verification_runtime


class Phase5EndToEndFreezeTests(unittest.TestCase):
    def setUp(self):
        self.flow = verification_runtime.DeploymentVerificationRuntimeTests(); self.flow.setUp()
        raw, context = self.flow.raw(self.flow.payload())
        self.assertEqual(self.flow.execute(raw, context)["result"], "ACCEPTED")
        def only(name):
            values = list(getattr(self.flow.store, name).values())
            self.assertEqual(len(values), 1, name)
            return values[0]
        names = ("implementation_handoffs", "implementation_briefs", "implementation_authorizations",
                 "codex_build_packages", "build_execution_results", "qa_results", "client_acceptances",
                 "deployment_authorizations", "deployment_executions", "deployment_verifications")
        (self.handoff, self.brief, self.authorization, self.package, self.build, self.qa,
         self.acceptance, self.deployment_authorization, self.execution, self.verification) = map(only, names)

    def assert_reference(self, value, reference_type, record_id, version):
        self.assertEqual(value, {"reference_type": reference_type, "reference_id": record_id,
                                 "reference_version": version})

    def test_complete_chain_has_exact_identity_version_and_digest_bindings(self):
        handoff_ref = {"reference_type": "IMPLEMENTATION_HANDOFF",
                       "reference_id": self.handoff["implementation_handoff_id"],
                       "reference_version": self.handoff["handoff_version"],
                       "reference_digest": self.handoff["handoff_digest"]}
        self.assertEqual(self.brief["source_implementation_handoff_reference"], handoff_ref)
        self.assertEqual(self.authorization["source_implementation_handoff_reference"], handoff_ref)
        self.assert_reference(self.authorization["implementation_brief_reference"], "IMPLEMENTATION_BRIEF",
                              self.brief["implementation_brief_id"], self.brief["implementation_brief_version"])
        self.assertEqual(self.authorization["implementation_brief_digest"], self.brief["implementation_brief_digest"])
        self.assert_reference(self.package["implementation_authorization_reference"], "IMPLEMENTATION_AUTHORIZATION",
                              self.authorization["implementation_authorization_id"], self.authorization["authorization_version"])
        self.assertEqual(self.package["implementation_authority_digest"], self.authorization["implementation_authority_digest"])
        self.assertEqual(self.package["implementation_brief_reference"], self.authorization["implementation_brief_reference"])
        self.assertEqual(self.package["implementation_brief_digest"], self.brief["implementation_brief_digest"])
        self.assert_reference(self.build["codex_build_package_reference"], "CODEX_BUILD_PACKAGE",
                              self.package["codex_build_package_id"], self.package["package_version"])
        self.assertEqual(self.build["package_digest"], self.package["package_digest"])
        self.assertEqual(self.build["implementation_authorization_reference"], self.package["implementation_authorization_reference"])
        self.assertEqual(self.build["implementation_authority_digest"], self.authorization["implementation_authority_digest"])
        self.assert_reference(self.qa["build_execution_reference"], "BUILD_EXECUTION_RESULT",
                              self.build["build_execution_result_id"], self.build["record_version"])
        self.assertEqual(self.qa["build_execution_digest"], self.build["execution_digest"])
        self.assertEqual(self.qa["codex_build_package_reference"], self.build["codex_build_package_reference"])
        self.assertEqual(self.qa["package_digest"], self.package["package_digest"])
        self.assert_reference(self.acceptance["qa_result_reference"], "QA_RESULT",
                              self.qa["qa_result_id"], self.qa["record_version"])
        self.assertEqual(self.acceptance["qa_result_digest"], self.qa["qa_digest"])
        self.assertEqual(self.acceptance["build_execution_reference"], self.qa["build_execution_reference"])
        self.assertEqual(self.acceptance["build_execution_digest"], self.build["execution_digest"])
        self.assertEqual(self.acceptance["codex_build_package_reference"], self.qa["codex_build_package_reference"])
        self.assertEqual(self.acceptance["package_digest"], self.package["package_digest"])

        deployment = self.deployment_authorization
        expected = (
            ("implementation_authorization_reference", "implementation_authority_digest", self.package["implementation_authorization_reference"], self.authorization["implementation_authority_digest"]),
            ("codex_build_package_reference", "package_digest", self.build["codex_build_package_reference"], self.package["package_digest"]),
            ("build_execution_reference", "build_execution_digest", self.qa["build_execution_reference"], self.build["execution_digest"]),
            ("qa_result_reference", "qa_result_digest", self.acceptance["qa_result_reference"], self.qa["qa_digest"]),
            ("client_acceptance_reference", "client_acceptance_digest",
             {"reference_type": "CLIENT_ACCEPTANCE", "reference_id": self.acceptance["client_acceptance_id"],
              "reference_version": self.acceptance["acceptance_version"]}, self.acceptance["client_acceptance_digest"]),
        )
        for reference_field, digest_field, source_reference, source_digest in expected:
            self.assertEqual(deployment[reference_field], source_reference)
            self.assertEqual(deployment[digest_field], source_digest)
        self.assertEqual(deployment["artifact_reference"], self.acceptance["artifact_reference"])

        binding = self.execution["authority_binding"]
        self.assert_reference(binding["deployment_authorization_reference"], "DEPLOYMENT_AUTHORIZATION",
                              deployment["deployment_authorization_id"], deployment["authorization_version"])
        self.assertEqual(binding["deployment_authority_digest"], deployment["deployment_authority_digest"])
        for field in ("implementation_authorization_reference", "implementation_authority_digest",
                      "codex_build_package_reference", "package_digest", "build_execution_reference",
                      "build_execution_digest", "qa_result_reference", "qa_result_digest",
                      "client_acceptance_reference", "client_acceptance_digest", "artifact_reference",
                      "target_environment", "target_resources"):
            self.assertEqual(binding[field], deployment[field], field)
        self.assert_reference(self.verification["deployment_execution_reference"], "DEPLOYMENT_EXECUTION",
                              self.execution["deployment_execution_id"], self.execution["record_version"])
        self.assertEqual(self.verification["deployment_execution_digest"], self.execution["execution_digest"])
        self.assertEqual(self.verification["authority_binding"], binding)

    def test_all_authoritative_records_are_schema_valid_and_tenant_bound(self):
        records = (
            ("urn:avuhz:public-contract:implementation-handoff:v1", self.handoff),
            ("urn:avuhz:schema:contracts:domain:implementation-brief:v1", self.brief),
            ("urn:avuhz:schema:contracts:domain:implementation-authorization:v1", self.authorization),
            ("urn:avuhz:schema:contracts:domain:codex-build-package:v1", self.package),
            ("urn:avuhz:schema:contracts:domain:build-execution-result:v1", self.build),
            ("urn:avuhz:schema:contracts:domain:qa-result:v1", self.qa),
            ("urn:avuhz:schema:contracts:domain:client-acceptance:v1", self.acceptance),
            ("urn:avuhz:schema:contracts:domain:deployment-authorization:v1", self.deployment_authorization),
            ("urn:avuhz:schema:contracts:domain:deployment-execution:v1", self.execution),
            ("urn:avuhz:schema:contracts:domain:deployment-verification:v1", self.verification),
        )
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        for schema_id, record in records:
            validator = Draft202012Validator(registry.expanded(schema_id), format_checker=FormatChecker())
            self.assertEqual(list(validator.iter_errors(record)), [], schema_id)
            self.assertEqual(record["tenant_id"], self.flow.tenant, schema_id)
        for _, record in records[1:]: self.assertEqual(record["engagement_id"], self.flow.engagement_id)
        self.assertEqual(self.handoff["source_engagement_reference"], self.flow.engagement_id)

    def test_protected_truth_is_human_attributable_and_final_write_is_atomic(self):
        self.assertEqual(self.acceptance["attribution"]["authority_role"], "CLIENT_ACCEPTANCE_AUTHORITY")
        self.assertTrue(self.acceptance["attribution"]["principal_reference"].startswith("human."))
        approvals = list(self.flow.store.approvals.values())
        self.assertEqual(len(approvals), 8)
        self.assertTrue(all(value["actor_identity"].startswith("human.") for value in approvals))
        deployment_roles = {value["actor_role"] for value in approvals
                            if value["subject_type"] == "DEPLOYMENT_AUTHORIZATION"}
        self.assertEqual(deployment_roles, {"CLIENT_DEPLOYMENT_AUTHORITY", "PROVIDER_DEPLOYMENT_AUTHORITY"})
        self.assertEqual(self.execution["status"], "SUCCEEDED")
        self.assertNotIn("deployment_verified", self.execution)
        self.assertEqual(self.verification["overall_status"], "VERIFIED")
        self.assertTrue(self.verification["attribution"]["principal_reference"].startswith("service."))
        self.assertEqual((len(self.flow.store.events), len(self.flow.store.outbox), len(self.flow.store.idempotency)), (1, 1, 1))
        self.assertEqual(self.flow.store.events[0]["event_type"], "deployment_verification.recorded")
        self.assertEqual(self.flow.store.outbox[0]["status"], "PENDING")


if __name__ == "__main__": unittest.main()
