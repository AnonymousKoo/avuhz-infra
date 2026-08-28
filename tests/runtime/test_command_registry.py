import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS, resolve_command
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.phase5c import PHASE5C_COMMANDS
from avuhz_runtime.phase5d_brief import IMPLEMENTATION_BRIEF_COMMANDS
from avuhz_runtime.phase5d_authorization import IMPLEMENTATION_AUTHORIZATION_COMMANDS


class CommandRegistryTests(unittest.TestCase):
    def test_registry_is_exactly_slice_one(self):
        self.assertEqual(set(COMMANDS), {"AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope", "CanonicalizeDiagnosticScope", "RecordAssessmentAccessApproval", "CreateAssessmentAccessProposal", "IssueAssessmentAccessGrant", "VerifyAssessmentAccess", "ExpireAssessmentAccess", "RevokeAssessmentAccess", "CloseAssessmentAccessForAgreementEnd", "RecordDiagnosticAgreementAuthority", "RecordDiagnosticPaymentVerification", "InvalidateDiagnosticPaymentVerification", "OpenOIAAssessment", "RecordOIAEvidence", "RecordOIAObservation", "SupersedeOIAObservation", "RecordOIARootCause", "CreateOIAFinding", "UpdateOIAFindingAnalysis", "FinalizeOIAFinding", "MarkOIAAssessmentReadyForDelivery", "DeliverOIAFindings", "ReviseDeliveredOIAFinding", "CloseOIAAssessment", "CreateOIAAssessmentPlan", "ReviseOIAAssessmentPlan", "ReviewOIAAssessmentPlan", "ApproveOIAAssessmentPlan", "CreateOIAInspectionItem", "UpdateOIAInspectionItem", "MarkOIAInspectionItemBlocked"} | set(PHASE5C_COMMANDS) | set(IMPLEMENTATION_BRIEF_COMMANDS) | set(IMPLEMENTATION_AUTHORIZATION_COMMANDS))
        self.assertEqual(sum(entry.executable for entry in COMMANDS.values()), 55)
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
        for command, subject, capability in (("RecordDiagnosticAgreementAuthority", "DIAGNOSTIC_AGREEMENT_AUTHORITY", "diagnostic_agreement:record"), ("RecordDiagnosticPaymentVerification", "DIAGNOSTIC_PAYMENT_VERIFICATION", "diagnostic_payment:record"), ("InvalidateDiagnosticPaymentVerification", "DIAGNOSTIC_PAYMENT_VERIFICATION", "diagnostic_payment:invalidate")):
            self.assertEqual(COMMANDS[command].subject_type, subject)
            self.assertEqual(COMMANDS[command].required_capability, capability)
            self.assertTrue(COMMANDS[command].executable)
        self.assertEqual(COMMANDS["OpenOIAAssessment"].subject_type, "OIA_ASSESSMENT")
        self.assertEqual(COMMANDS["OpenOIAAssessment"].required_capability, "oia:open")
        self.assertTrue(COMMANDS["OpenOIAAssessment"].executable)
        self.assertEqual(COMMANDS["RecordOIAEvidence"].subject_type, "OIA_EVIDENCE_ITEM")
        self.assertEqual(COMMANDS["RecordOIAEvidence"].required_capability, "oia:evidence:record")
        self.assertTrue(COMMANDS["RecordOIAEvidence"].executable)
        for command in ("RecordOIAObservation", "SupersedeOIAObservation"):
            self.assertEqual(COMMANDS[command].subject_type, "OIA_OBSERVATION")
            self.assertEqual(COMMANDS[command].required_capability, "oia:observation:record")
            self.assertTrue(COMMANDS[command].executable)
        self.assertEqual(COMMANDS["RecordOIARootCause"].subject_type, "OIA_ROOT_CAUSE")
        self.assertEqual(COMMANDS["RecordOIARootCause"].required_capability, "oia:root_cause:record")
        self.assertTrue(COMMANDS["RecordOIARootCause"].executable)
        for command, capability in (("CreateOIAFinding", "oia:finding:write"), ("UpdateOIAFindingAnalysis", "oia:finding:write"), ("FinalizeOIAFinding", "oia:finding:finalize")):
            self.assertEqual(COMMANDS[command].subject_type, "OIA_FINDING")
            self.assertEqual(COMMANDS[command].required_capability, capability)
            self.assertTrue(COMMANDS[command].executable)
        for command, subject, capability in (("MarkOIAAssessmentReadyForDelivery", "OIA_ASSESSMENT", "oia:assessment:review"), ("DeliverOIAFindings", "OIA_FINDINGS_DELIVERY", "oia:findings:deliver"), ("ReviseDeliveredOIAFinding", "OIA_FINDING", "oia:finding:finalize"), ("CloseOIAAssessment", "OIA_ASSESSMENT", "oia:assessment:close")):
            self.assertEqual(COMMANDS[command].subject_type, subject)
            self.assertEqual(COMMANDS[command].required_capability, capability)
            self.assertTrue(COMMANDS[command].executable)
        for command, capability in (("CreateOIAAssessmentPlan", "oia:plan:write"), ("ReviseOIAAssessmentPlan", "oia:plan:write"), ("ReviewOIAAssessmentPlan", "oia:plan:review"), ("ApproveOIAAssessmentPlan", "oia:plan:approve")):
            self.assertEqual(COMMANDS[command].subject_type, "OIA_ASSESSMENT_PLAN")
            self.assertEqual(COMMANDS[command].required_capability, capability)
            self.assertTrue(COMMANDS[command].executable)

        for command in ("CreateOIAInspectionItem", "UpdateOIAInspectionItem", "MarkOIAInspectionItemBlocked"):
            self.assertEqual(COMMANDS[command].subject_type, "OIA_INSPECTION_ITEM")
            self.assertEqual(COMMANDS[command].required_capability, "oia:inspection:manage")
            self.assertTrue(COMMANDS[command].executable)

        self.assertIsNone(resolve_command("DeployEverything"))

    def test_schema_catalog_is_fixed_and_local(self):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        self.assertEqual(len(registry.schema_ids), 118)
        with self.assertRaises(KeyError): registry.resolve("https://example.invalid/schema")
        with self.assertRaises(KeyError): registry.resolve("../outside.schema.json")


if __name__ == "__main__": unittest.main()
