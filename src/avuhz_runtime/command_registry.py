"""Closed command registry. Adding files cannot activate commands."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandDefinition:
    command_type: str
    subject_type: str
    envelope_version: int
    payload_schema_id: str
    payload_version: int
    validatable: bool = True
    required_capability: str = ""
    executable: bool = False


COMMANDS = {
    "AcceptAcquisitionHandoff": CommandDefinition("AcceptAcquisitionHandoff", "ACQUISITION_HANDOFF", 1, "urn:avuhz:schema:contracts:commands:accept-acquisition-handoff-payload:v1", 1),
    "OpenEngagement": CommandDefinition("OpenEngagement", "ENGAGEMENT", 1, "urn:avuhz:schema:contracts:commands:open-engagement-payload:v1", 1),
    "SubmitDiagnosticScope": CommandDefinition("SubmitDiagnosticScope", "ENGAGEMENT", 1, "urn:avuhz:schema:contracts:commands:submit-diagnostic-scope-payload:v1", 1),
    "RecordHumanApproval": CommandDefinition("RecordHumanApproval", "DIAGNOSTIC_SCOPE", 1, "urn:avuhz:schema:contracts:commands:record-human-approval-payload:v1", 1),
    "RecordAssessmentAccessApproval": CommandDefinition("RecordAssessmentAccessApproval", "ASSESSMENT_ACCESS_PROPOSAL", 1, "urn:avuhz:schema:contracts:commands:record-assessment-access-approval-payload:v1", 1, required_capability="assessment_access:approve", executable=True),
    "CreateAssessmentAccessProposal": CommandDefinition("CreateAssessmentAccessProposal", "ASSESSMENT_ACCESS_PROPOSAL", 1, "urn:avuhz:schema:contracts:commands:create-assessment-access-proposal-payload:v1", 1, required_capability="assessment_access:propose", executable=True),
    "IssueAssessmentAccessGrant": CommandDefinition("IssueAssessmentAccessGrant", "ASSESSMENT_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:issue-assessment-access-grant-payload:v1", 1, required_capability="assessment_access:issue", executable=True),
    "ApproveDiagnosticScope": CommandDefinition("ApproveDiagnosticScope", "DIAGNOSTIC_SCOPE", 1, "urn:avuhz:schema:contracts:commands:approve-diagnostic-scope-payload:v1", 1),
    "VerifyAssessmentAccess": CommandDefinition("VerifyAssessmentAccess", "ASSESSMENT_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:verify-assessment-access-payload:v1", 1, required_capability="assessment_access:verify", executable=True),
    "ExpireAssessmentAccess": CommandDefinition("ExpireAssessmentAccess", "ASSESSMENT_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:expire-assessment-access-payload:v1", 1, required_capability="assessment_access:expire", executable=True),
    "RevokeAssessmentAccess": CommandDefinition("RevokeAssessmentAccess", "ASSESSMENT_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:revoke-assessment-access-payload:v1", 1, required_capability="assessment_access:revoke", executable=True),
    "CloseAssessmentAccessForAgreementEnd": CommandDefinition("CloseAssessmentAccessForAgreementEnd", "ASSESSMENT_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:close-assessment-access-for-agreement-end-payload:v1", 1, required_capability="assessment_access:close", executable=True),
    "RecordDiagnosticAgreementAuthority": CommandDefinition("RecordDiagnosticAgreementAuthority", "DIAGNOSTIC_AGREEMENT_AUTHORITY", 1, "urn:avuhz:schema:contracts:commands:record-diagnostic-agreement-authority-payload:v1", 1, required_capability="diagnostic_agreement:record", executable=True),
    "RecordDiagnosticPaymentVerification": CommandDefinition("RecordDiagnosticPaymentVerification", "DIAGNOSTIC_PAYMENT_VERIFICATION", 1, "urn:avuhz:schema:contracts:commands:record-diagnostic-payment-verification-payload:v1", 1, required_capability="diagnostic_payment:record", executable=True),
    "InvalidateDiagnosticPaymentVerification": CommandDefinition("InvalidateDiagnosticPaymentVerification", "DIAGNOSTIC_PAYMENT_VERIFICATION", 1, "urn:avuhz:schema:contracts:commands:invalidate-diagnostic-payment-verification-payload:v1", 1, required_capability="diagnostic_payment:invalidate", executable=True),
    "CanonicalizeDiagnosticScope": CommandDefinition("CanonicalizeDiagnosticScope", "DIAGNOSTIC_SCOPE", 1, "urn:avuhz:schema:contracts:commands:canonicalize-diagnostic-scope-payload:v1", 1),
    "OpenOIAAssessment": CommandDefinition("OpenOIAAssessment", "OIA_ASSESSMENT", 1, "urn:avuhz:schema:contracts:commands:open-oia-assessment-payload:v1", 1, required_capability="oia:open", executable=True),
    "RecordOIAEvidence": CommandDefinition("RecordOIAEvidence", "OIA_EVIDENCE_ITEM", 1, "urn:avuhz:schema:contracts:commands:record-oia-evidence-payload:v1", 1, required_capability="oia:evidence:record", executable=True),
    "RecordOIAObservation": CommandDefinition("RecordOIAObservation", "OIA_OBSERVATION", 1, "urn:avuhz:schema:contracts:commands:record-oia-observation-payload:v1", 1, required_capability="oia:observation:record", executable=True),
    "SupersedeOIAObservation": CommandDefinition("SupersedeOIAObservation", "OIA_OBSERVATION", 1, "urn:avuhz:schema:contracts:commands:supersede-oia-observation-payload:v1", 1, required_capability="oia:observation:record", executable=True),
    "RecordOIARootCause": CommandDefinition("RecordOIARootCause", "OIA_ROOT_CAUSE", 1, "urn:avuhz:schema:contracts:commands:record-oia-root-cause-payload:v1", 1, required_capability="oia:root_cause:record", executable=True),
    "CreateOIAFinding": CommandDefinition("CreateOIAFinding", "OIA_FINDING", 1, "urn:avuhz:schema:contracts:commands:create-oia-finding-payload:v1", 1, required_capability="oia:finding:write", executable=True),
    "UpdateOIAFindingAnalysis": CommandDefinition("UpdateOIAFindingAnalysis", "OIA_FINDING", 1, "urn:avuhz:schema:contracts:commands:update-oia-finding-analysis-payload:v1", 1, required_capability="oia:finding:write", executable=True),
    "FinalizeOIAFinding": CommandDefinition("FinalizeOIAFinding", "OIA_FINDING", 1, "urn:avuhz:schema:contracts:commands:finalize-oia-finding-payload:v1", 1, required_capability="oia:finding:finalize", executable=True),
    "MarkOIAAssessmentReadyForDelivery": CommandDefinition("MarkOIAAssessmentReadyForDelivery", "OIA_ASSESSMENT", 1, "urn:avuhz:schema:contracts:commands:mark-oia-assessment-ready-for-delivery-payload:v1", 1, required_capability="oia:assessment:review", executable=True),
    "DeliverOIAFindings": CommandDefinition("DeliverOIAFindings", "OIA_FINDINGS_DELIVERY", 1, "urn:avuhz:schema:contracts:commands:deliver-oia-findings-payload:v1", 1, required_capability="oia:findings:deliver", executable=True),
    "ReviseDeliveredOIAFinding": CommandDefinition("ReviseDeliveredOIAFinding", "OIA_FINDING", 1, "urn:avuhz:schema:contracts:commands:revise-delivered-oia-finding-payload:v1", 1, required_capability="oia:finding:finalize", executable=True),
    "CloseOIAAssessment": CommandDefinition("CloseOIAAssessment", "OIA_ASSESSMENT", 1, "urn:avuhz:schema:contracts:commands:close-oia-assessment-payload:v1", 1, required_capability="oia:assessment:close", executable=True),
    "CreateOIAAssessmentPlan": CommandDefinition("CreateOIAAssessmentPlan", "OIA_ASSESSMENT_PLAN", 1, "urn:avuhz:schema:contracts:commands:create-oia-assessment-plan-payload:v1", 1, required_capability="oia:plan:write", executable=True),
    "ReviseOIAAssessmentPlan": CommandDefinition("ReviseOIAAssessmentPlan", "OIA_ASSESSMENT_PLAN", 1, "urn:avuhz:schema:contracts:commands:revise-oia-assessment-plan-payload:v1", 1, required_capability="oia:plan:write", executable=True),
    "ReviewOIAAssessmentPlan": CommandDefinition("ReviewOIAAssessmentPlan", "OIA_ASSESSMENT_PLAN", 1, "urn:avuhz:schema:contracts:commands:review-oia-assessment-plan-payload:v1", 1, required_capability="oia:plan:review", executable=True),
    "ApproveOIAAssessmentPlan": CommandDefinition("ApproveOIAAssessmentPlan", "OIA_ASSESSMENT_PLAN", 1, "urn:avuhz:schema:contracts:commands:approve-oia-assessment-plan-payload:v1", 1, required_capability="oia:plan:approve", executable=True),
    "CreateOIAInspectionItem": CommandDefinition("CreateOIAInspectionItem", "OIA_INSPECTION_ITEM", 1, "urn:avuhz:schema:contracts:commands:create-oia-inspection-item-payload:v1", 1, required_capability="oia:inspection:manage", executable=True),
    "UpdateOIAInspectionItem": CommandDefinition("UpdateOIAInspectionItem", "OIA_INSPECTION_ITEM", 1, "urn:avuhz:schema:contracts:commands:update-oia-inspection-item-payload:v1", 1, required_capability="oia:inspection:manage", executable=True),
    "MarkOIAInspectionItemBlocked": CommandDefinition("MarkOIAInspectionItemBlocked", "OIA_INSPECTION_ITEM", 1, "urn:avuhz:schema:contracts:commands:mark-oia-inspection-item-blocked-payload:v1", 1, required_capability="oia:inspection:manage", executable=True),
    "RecordOIAConversionDecision": CommandDefinition("RecordOIAConversionDecision", "OIA_CONVERSION_DECISION", 1, "urn:avuhz:schema:contracts:commands:record-oia-conversion-decision-payload:v1", 1, required_capability="conversion:decide", executable=True),
    "AcceptOIAConversion": CommandDefinition("AcceptOIAConversion", "OIA_CONVERSION_DECISION", 1, "urn:avuhz:schema:contracts:commands:accept-oia-conversion-payload:v1", 1, required_capability="conversion:accept", executable=True),
    "ProposeOngoingAgreement": CommandDefinition("ProposeOngoingAgreement", "ONGOING_AGREEMENT_AUTHORITY", 1, "urn:avuhz:schema:contracts:commands:propose-ongoing-agreement-payload:v1", 1, required_capability="ongoing_agreement:propose", executable=True),
    "RecordOngoingAgreementApproval": CommandDefinition("RecordOngoingAgreementApproval", "ONGOING_AGREEMENT_AUTHORITY", 1, "urn:avuhz:schema:contracts:commands:record-ongoing-agreement-approval-payload:v1", 1, required_capability="ongoing_agreement:approve", executable=True),
    "ActivateOngoingAgreement": CommandDefinition("ActivateOngoingAgreement", "ONGOING_AGREEMENT_AUTHORITY", 1, "urn:avuhz:schema:contracts:commands:activate-ongoing-agreement-payload:v1", 1, required_capability="ongoing_agreement:activate", executable=True),
    "TerminateOngoingAgreement": CommandDefinition("TerminateOngoingAgreement", "ONGOING_AGREEMENT_AUTHORITY", 1, "urn:avuhz:schema:contracts:commands:terminate-ongoing-agreement-payload:v1", 1, required_capability="ongoing_agreement:terminate", executable=True),
    "RecordOngoingPaymentVerification": CommandDefinition("RecordOngoingPaymentVerification", "ONGOING_PAYMENT_VERIFICATION", 1, "urn:avuhz:schema:contracts:commands:record-ongoing-payment-verification-payload:v1", 1, required_capability="ongoing_payment:record", executable=True),
    "InvalidateOngoingPaymentVerification": CommandDefinition("InvalidateOngoingPaymentVerification", "ONGOING_PAYMENT_VERIFICATION", 1, "urn:avuhz:schema:contracts:commands:invalidate-ongoing-payment-verification-payload:v1", 1, required_capability="ongoing_payment:invalidate", executable=True),
    "ProposeOngoingAccessGrant": CommandDefinition("ProposeOngoingAccessGrant", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:propose-ongoing-access-grant-payload:v1", 1, required_capability="ongoing_access:propose", executable=True),
    "RecordOngoingAccessApproval": CommandDefinition("RecordOngoingAccessApproval", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:record-ongoing-access-approval-payload:v1", 1, required_capability="ongoing_access:approve", executable=True),
    "ApproveOngoingAccessGrant": CommandDefinition("ApproveOngoingAccessGrant", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:approve-ongoing-access-grant-payload:v1", 1, required_capability="ongoing_access:approve", executable=True),
    "VerifyOngoingAccess": CommandDefinition("VerifyOngoingAccess", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:verify-ongoing-access-payload:v1", 1, required_capability="ongoing_access:activate", executable=True),
    "RevokeOngoingAccess": CommandDefinition("RevokeOngoingAccess", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:revoke-ongoing-access-payload:v1", 1, required_capability="ongoing_access:revoke", executable=True),
    "CloseOngoingAccess": CommandDefinition("CloseOngoingAccess", "ONGOING_ACCESS_GRANT", 1, "urn:avuhz:schema:contracts:commands:close-ongoing-access-payload:v1", 1, required_capability="ongoing_access:close", executable=True),
    "InitiateOngoingOffboarding": CommandDefinition("InitiateOngoingOffboarding", "ONGOING_OFFBOARDING", 1, "urn:avuhz:schema:contracts:commands:initiate-ongoing-offboarding-payload:v1", 1, required_capability="offboarding:initiate", executable=True),
    "VerifyOngoingAccessRevocation": CommandDefinition("VerifyOngoingAccessRevocation", "ONGOING_ACCESS_REVOCATION_VERIFICATION", 1, "urn:avuhz:schema:contracts:commands:verify-ongoing-access-revocation-payload:v1", 1, required_capability="offboarding:verify_revocation", executable=True),
    "CompleteOngoingOffboarding": CommandDefinition("CompleteOngoingOffboarding", "ONGOING_OFFBOARDING", 1, "urn:avuhz:schema:contracts:commands:complete-ongoing-offboarding-payload:v1", 1, required_capability="offboarding:complete", executable=True),
    "DraftImplementationBrief": CommandDefinition("DraftImplementationBrief", "IMPLEMENTATION_BRIEF", 1, "urn:avuhz:schema:contracts:commands:draft-implementation-brief-payload:v1", 1, required_capability="implementation_brief:draft", executable=True),
    "ReviseImplementationBrief": CommandDefinition("ReviseImplementationBrief", "IMPLEMENTATION_BRIEF", 1, "urn:avuhz:schema:contracts:commands:revise-implementation-brief-payload:v1", 1, required_capability="implementation_brief:draft", executable=True),
    "RecordImplementationBriefApproval": CommandDefinition("RecordImplementationBriefApproval", "IMPLEMENTATION_BRIEF", 1, "urn:avuhz:schema:contracts:commands:record-implementation-brief-approval-payload:v1", 1, required_capability="implementation_brief:approve", executable=True),
    "ApproveImplementationBrief": CommandDefinition("ApproveImplementationBrief", "IMPLEMENTATION_BRIEF", 1, "urn:avuhz:schema:contracts:commands:approve-implementation-brief-payload:v1", 1, required_capability="implementation_brief:approve", executable=True),
    "ProposeImplementationAuthorization": CommandDefinition("ProposeImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", 1, "urn:avuhz:schema:contracts:commands:propose-implementation-authorization-payload:v1", 1, required_capability="implementation_authorization:propose", executable=True),
    "ReviseImplementationAuthorization": CommandDefinition("ReviseImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", 1, "urn:avuhz:schema:contracts:commands:revise-implementation-authorization-payload:v1", 1, required_capability="implementation_authorization:propose", executable=True),
    "RecordImplementationAuthorizationApproval": CommandDefinition("RecordImplementationAuthorizationApproval", "IMPLEMENTATION_AUTHORIZATION", 1, "urn:avuhz:schema:contracts:commands:record-implementation-authorization-approval-payload:v1", 1, required_capability="implementation_authorization:approve", executable=True),
    "ActivateImplementationAuthorization": CommandDefinition("ActivateImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", 1, "urn:avuhz:schema:contracts:commands:activate-implementation-authorization-payload:v1", 1, required_capability="implementation_authorization:activate", executable=True),
    "RevokeImplementationAuthorization": CommandDefinition("RevokeImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", 1, "urn:avuhz:schema:contracts:commands:revoke-implementation-authorization-payload:v1", 1, required_capability="implementation_authorization:revoke", executable=True),
    "DraftCodexBuildPackage": CommandDefinition("DraftCodexBuildPackage", "CODEX_BUILD_PACKAGE", 1, "urn:avuhz:schema:contracts:commands:draft-codex-build-package-payload:v1", 1, required_capability="codex_build_package:draft", executable=True),
    "ReviseCodexBuildPackage": CommandDefinition("ReviseCodexBuildPackage", "CODEX_BUILD_PACKAGE", 1, "urn:avuhz:schema:contracts:commands:revise-codex-build-package-payload:v1", 1, required_capability="codex_build_package:draft", executable=True),
    "RecordCodexBuildPackageApproval": CommandDefinition("RecordCodexBuildPackageApproval", "CODEX_BUILD_PACKAGE", 1, "urn:avuhz:schema:contracts:commands:record-codex-build-package-approval-payload:v1", 1, required_capability="codex_build_package:approve", executable=True),
    "ReleaseCodexBuildPackage": CommandDefinition("ReleaseCodexBuildPackage", "CODEX_BUILD_PACKAGE", 1, "urn:avuhz:schema:contracts:commands:release-codex-build-package-payload:v1", 1, required_capability="codex_build_package:release", executable=True),
    "StartBuildExecution": CommandDefinition("StartBuildExecution", "BUILD_EXECUTION_RESULT", 1, "urn:avuhz:schema:contracts:commands:start-build-execution-payload:v1", 1, required_capability="build_execution:start", executable=True),
    "CompleteBuildExecution": CommandDefinition("CompleteBuildExecution", "BUILD_EXECUTION_RESULT", 1, "urn:avuhz:schema:contracts:commands:complete-build-execution-payload:v1", 1, required_capability="build_execution:complete", executable=True),
    "RecordQAResult": CommandDefinition("RecordQAResult", "QA_RESULT", 1, "urn:avuhz:schema:contracts:commands:record-qa-result-payload:v1", 1, required_capability="qa_result:record", executable=True),
}


def resolve_command(command_type: object) -> CommandDefinition | None:
    return COMMANDS.get(command_type) if isinstance(command_type, str) else None
