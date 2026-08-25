import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS, resolve_command
from avuhz_runtime.schema_registry import SchemaRegistry


class CommandRegistryTests(unittest.TestCase):
    def test_registry_is_exactly_slice_one(self):
        self.assertEqual(set(COMMANDS), {"AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope", "CanonicalizeDiagnosticScope", "RecordAssessmentAccessApproval", "CreateAssessmentAccessProposal", "IssueAssessmentAccessGrant", "VerifyAssessmentAccess", "ExpireAssessmentAccess", "RevokeAssessmentAccess", "CloseAssessmentAccessForAgreementEnd"})
        self.assertEqual([entry.executable for entry in COMMANDS.values()], [False, False, False, False, True, True, True, False, True, True, True, True, False])
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].subject_type, "ASSESSMENT_ACCESS_PROPOSAL")
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].payload_schema_id, "urn:avuhz:schema:contracts:commands:create-assessment-access-proposal-payload:v1")
        self.assertTrue(all(entry.validatable for entry in COMMANDS.values()))
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].required_capability, "assessment_access:propose")
        self.assertEqual(COMMANDS["VerifyAssessmentAccess"].subject_type, "ASSESSMENT_ACCESS_GRANT")
        self.assertEqual(COMMANDS["VerifyAssessmentAccess"].required_capability, "assessment_access:verify")
        self.assertTrue(COMMANDS["VerifyAssessmentAccess"].executable)
        for command, capability in (("ExpireAssessmentAccess", "assessment_access:expire"), ("RevokeAssessmentAccess", "assessment_access:revoke"), ("CloseAssessmentAccessForAgreementEnd", "assessment_access:close")):
            self.assertEqual(COMMANDS[command].subject_type, "ASSESSMENT_ACCESS_GRANT")
            self.assertEqual(COMMANDS[command].required_capability, capability)
            self.assertTrue(COMMANDS[command].executable)
        self.assertIsNone(resolve_command("DeployEverything"))

    def test_schema_catalog_is_fixed_and_local(self):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        self.assertEqual(len(registry.schema_ids), 37)
        with self.assertRaises(KeyError): registry.resolve("https://example.invalid/schema")
        with self.assertRaises(KeyError): registry.resolve("../outside.schema.json")


if __name__ == "__main__": unittest.main()
