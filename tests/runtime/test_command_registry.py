import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS, resolve_command
from avuhz_runtime.schema_registry import SchemaRegistry


class CommandRegistryTests(unittest.TestCase):
    def test_registry_is_exactly_slice_one(self):
        self.assertEqual(set(COMMANDS), {"AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope", "CanonicalizeDiagnosticScope", "RecordAssessmentAccessApproval", "CreateAssessmentAccessProposal"})
        self.assertEqual([entry.executable for entry in COMMANDS.values()], [False] * 8)
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].subject_type, "ASSESSMENT_ACCESS_PROPOSAL")
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].payload_schema_id, "urn:avuhz:schema:contracts:commands:create-assessment-access-proposal-payload:v1")
        self.assertTrue(all(entry.validatable for entry in COMMANDS.values()))
        self.assertEqual(COMMANDS["CreateAssessmentAccessProposal"].required_capability, "assessment_access:propose")
        self.assertIsNone(resolve_command("DeployEverything"))

    def test_schema_catalog_is_fixed_and_local(self):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        self.assertEqual(len(registry.schema_ids), 32)
        with self.assertRaises(KeyError): registry.resolve("https://example.invalid/schema")
        with self.assertRaises(KeyError): registry.resolve("../outside.schema.json")


if __name__ == "__main__": unittest.main()
