"""Pure deterministic guards; no I/O, persistence, or state mutation."""
from dataclasses import dataclass
from .errors import RuntimeReason
from .phase5c import PHASE5C_CAPABILITIES
from .phase5d_brief import IMPLEMENTATION_BRIEF_CAPABILITIES, IMPLEMENTATION_BRIEF_COMMANDS
from .phase5d_authorization import IMPLEMENTATION_AUTHORIZATION_CAPABILITIES, IMPLEMENTATION_AUTHORIZATION_COMMANDS

COMMAND_CAPABILITIES={"AcceptAcquisitionHandoff":"engagement:accept_handoff","OpenEngagement":"engagement:open","SubmitDiagnosticScope":"scope:submit","RecordHumanApproval":"scope:approve","RecordAssessmentAccessApproval":"assessment_access:approve","CreateAssessmentAccessProposal":"assessment_access:propose","IssueAssessmentAccessGrant":"assessment_access:issue","VerifyAssessmentAccess":"assessment_access:verify","ExpireAssessmentAccess":"assessment_access:expire","RevokeAssessmentAccess":"assessment_access:revoke","CloseAssessmentAccessForAgreementEnd":"assessment_access:close","RecordDiagnosticAgreementAuthority":"diagnostic_agreement:record","RecordDiagnosticPaymentVerification":"diagnostic_payment:record","InvalidateDiagnosticPaymentVerification":"diagnostic_payment:invalidate","ApproveDiagnosticScope":"scope:approve","CanonicalizeDiagnosticScope":"scope:submit","OpenOIAAssessment":"oia:open","RecordOIAEvidence":"oia:evidence:record","RecordOIAObservation":"oia:observation:record","SupersedeOIAObservation":"oia:observation:record","RecordOIARootCause":"oia:root_cause:record","CreateOIAFinding":"oia:finding:write","UpdateOIAFindingAnalysis":"oia:finding:write","FinalizeOIAFinding":"oia:finding:finalize","MarkOIAAssessmentReadyForDelivery":"oia:assessment:review","DeliverOIAFindings":"oia:findings:deliver","ReviseDeliveredOIAFinding":"oia:finding:finalize","CloseOIAAssessment":"oia:assessment:close","CreateOIAAssessmentPlan":"oia:plan:write","ReviseOIAAssessmentPlan":"oia:plan:write","ReviewOIAAssessmentPlan":"oia:plan:review","ApproveOIAAssessmentPlan":"oia:plan:approve","CreateOIAInspectionItem":"oia:inspection:manage","UpdateOIAInspectionItem":"oia:inspection:manage","MarkOIAInspectionItemBlocked":"oia:inspection:manage"}
COMMAND_CAPABILITIES.update(PHASE5C_CAPABILITIES)
COMMAND_CAPABILITIES.update(IMPLEMENTATION_BRIEF_CAPABILITIES)
COMMAND_CAPABILITIES.update(IMPLEMENTATION_AUTHORIZATION_CAPABILITIES)
PHASE5C_TRANSITIONS=frozenset(PHASE5C_CAPABILITIES)-frozenset({"RecordOIAConversionDecision","ProposeOngoingAgreement","RecordOngoingPaymentVerification","ProposeOngoingAccessGrant","InitiateOngoingOffboarding"})
IMPLEMENTATION_BRIEF_TRANSITIONS=frozenset(IMPLEMENTATION_BRIEF_COMMANDS)-{"DraftImplementationBrief"}
IMPLEMENTATION_AUTHORIZATION_TRANSITIONS=frozenset(IMPLEMENTATION_AUTHORIZATION_COMMANDS)-{"ProposeImplementationAuthorization"}
HUMAN_AUTHORITY_ROLES=frozenset({"CLIENT_DECISION_AUTHORITY","SEKINFRA_ENGAGEMENT_AUTHORITY","CLIENT_IMPLEMENTATION_AUTHORITY","SEKINFRA_IMPLEMENTATION_AUTHORITY"})

@dataclass(frozen=True)
class TrustedExecutionContext:
    authenticated: bool; principal_id: str|None; caller_type: str|None; tenant_id: str|None; organization_id: str|None; capabilities: frozenset[str]; authority_roles: frozenset[str]; environment: str|None; audience: str|None; authentication_strength: str|None; step_up_satisfied: bool; authenticated_at: str|None; expires_at: str|None=None; human_principal_reference: str|None=None; human_organization_reference: str|None=None; human_authority_role: str|None=None
@dataclass(frozen=True)
class AuthoritativeSubjectSnapshot:
    subject_type: str; subject_id: str; tenant_id: str; record_version: int; exists: bool; engagement_id: str|None=None; state: str|None=None
@dataclass(frozen=True)
class GuardFailure:
    reason: RuntimeReason; message: str; guard_name: str
@dataclass(frozen=True)
class GuardedCommand:
    prepared: object; trusted_principal_id: str; trusted_caller_type: str; trusted_tenant_id: str; effective_capabilities: frozenset[str]; subject_snapshot: AuthoritativeSubjectSnapshot|None
@dataclass(frozen=True)
class GuardSuccess: guarded: GuardedCommand

class GuardPipeline:
    """Order: authentication, environment, tenant, capability, subject, version."""
    def evaluate(self,p,c,s,evaluated_at):
        for name,fn in (("authentication",self.auth),("environment",self.env),("tenant",self.tenant),("capability",self.cap),("subject",self.subject),("version",self.version)):
            r=fn(p,c,s,evaluated_at)
            if r:return r
        return GuardSuccess(GuardedCommand(p,c.principal_id or "",c.caller_type or "",c.tenant_id or "",c.capabilities,s))
    def fail(self,r,m,n):return GuardFailure(r,m,n)
    def human_approval_authority(self,c,requested_role):
        if c.caller_type!="HUMAN":return self.fail(RuntimeReason.AUTH_INVALID,"human caller is required","human_authority")
        if not c.human_principal_reference:return self.fail(RuntimeReason.AUTH_INVALID,"trusted human principal is required","human_authority")
        if not c.human_organization_reference:return self.fail(RuntimeReason.AUTH_INVALID,"trusted human organization is required","human_authority")
        if not c.tenant_id:return self.fail(RuntimeReason.TENANT_CONTEXT_MISSING,"trusted tenant context is required","human_authority")
        if c.human_authority_role not in HUMAN_AUTHORITY_ROLES:return self.fail(RuntimeReason.AUTH_INVALID,"trusted human authority is invalid","human_authority")
        if requested_role!=c.human_authority_role:return self.fail(RuntimeReason.AUTH_INVALID,"requested authority does not match trusted authority","human_authority")
    def auth(self,p,c,s,t):
        if not c.authenticated:return self.fail(RuntimeReason.AUTH_MISSING,"trusted authentication is required","authentication")
        if not c.principal_id or not c.caller_type or not c.authenticated_at or c.caller_type!=p.caller_identity_claim.get("caller_type"):return self.fail(RuntimeReason.AUTH_INVALID,"trusted identity context is invalid","authentication")
        if c.audience!="avuhz-command-api":return self.fail(RuntimeReason.AUTH_AUDIENCE_INVALID,"trusted audience is not accepted","authentication")
        if c.expires_at and c.expires_at<=t:return self.fail(RuntimeReason.AUTH_EXPIRED,"trusted identity is expired","authentication")
    def env(self,p,c,s,t):
        if not c.environment or c.environment!=p.environment:return self.fail(RuntimeReason.AUTH_INVALID,"trusted environment does not match command","environment")
    def tenant(self,p,c,s,t):
        if not c.tenant_id:return self.fail(RuntimeReason.TENANT_CONTEXT_MISSING,"trusted tenant context is required","tenant")
        if c.tenant_id!=p.tenant_id:return self.fail(RuntimeReason.TENANT_ACCESS_DENIED,"trusted tenant cannot act for command tenant","tenant")
        if s and s.tenant_id!=p.tenant_id:return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"subject tenant does not match command","tenant")
        if s and p.engagement_id and s.engagement_id and s.engagement_id!=p.engagement_id:return self.fail(RuntimeReason.CROSS_TENANT_ATTEMPT,"engagement context does not match subject","tenant")
    def cap(self,p,c,s,t):
        need=COMMAND_CAPABILITIES.get(p.command_type)
        if not need:return self.fail(RuntimeReason.INTERNAL_INVARIANT_VIOLATION,"registered command policy is incomplete","capability")
        if need not in c.capabilities:return self.fail(RuntimeReason.AUTH_CAPABILITY_MISSING,"trusted capability is required","capability")
    def subject(self,p,c,s,t):
        if p.command_type=="OpenEngagement" and s and s.exists:return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"proposed engagement already exists","subject")
        if p.command_type in PHASE5C_TRANSITIONS and (not s or not s.exists or s.subject_type!=p.subject_type or s.subject_id!=p.subject_id):
            return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"authoritative Phase 5C subject is required and must match","subject")
        if p.command_type in IMPLEMENTATION_BRIEF_TRANSITIONS and (not s or not s.exists or s.subject_type!=p.subject_type or s.subject_id!=p.subject_id):
            return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"authoritative ImplementationBrief is required and must match","subject")
        if p.command_type in IMPLEMENTATION_AUTHORIZATION_TRANSITIONS and (not s or not s.exists or s.subject_type!=p.subject_type or s.subject_id!=p.subject_id):
            return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"authoritative ImplementationAuthorization is required and must match","subject")
        if p.command_type in ("SubmitDiagnosticScope","RecordHumanApproval","ApproveDiagnosticScope","CanonicalizeDiagnosticScope","RecordAssessmentAccessApproval","ReviseOIAAssessmentPlan","ReviewOIAAssessmentPlan","ApproveOIAAssessmentPlan","UpdateOIAInspectionItem","MarkOIAInspectionItemBlocked","SupersedeOIAObservation","UpdateOIAFindingAnalysis","FinalizeOIAFinding","MarkOIAAssessmentReadyForDelivery","ReviseDeliveredOIAFinding","CloseOIAAssessment"):
            if not s or not s.exists or s.subject_type!=p.subject_type or s.subject_id!=p.subject_id:return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"authoritative subject is required and must match","subject")
        if p.command_type=="RecordOIARootCause" and p.expected_record_version is not None:
            if not s or not s.exists or s.subject_type!=p.subject_type or s.subject_id!=p.subject_id:return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH,"authoritative subject is required and must match","subject")
    def version(self,p,c,s,t):
        if p.command_type in PHASE5C_TRANSITIONS and (not s or p.expected_record_version!=s.record_version):
            return self.fail(RuntimeReason.VERSION_STALE,"authoritative Phase 5C record version is stale","version")
        if p.command_type in IMPLEMENTATION_BRIEF_TRANSITIONS and (not s or p.expected_record_version!=s.record_version):
            return self.fail(RuntimeReason.VERSION_STALE,"authoritative ImplementationBrief record version is stale","version")
        if p.command_type in IMPLEMENTATION_AUTHORIZATION_TRANSITIONS and (not s or p.expected_record_version!=s.record_version):
            return self.fail(RuntimeReason.VERSION_STALE,"authoritative ImplementationAuthorization record version is stale","version")
        if p.command_type in ("SubmitDiagnosticScope","RecordHumanApproval","ApproveDiagnosticScope","CanonicalizeDiagnosticScope","RecordAssessmentAccessApproval","ReviseOIAAssessmentPlan","ReviewOIAAssessmentPlan","ApproveOIAAssessmentPlan","UpdateOIAInspectionItem","MarkOIAInspectionItemBlocked","SupersedeOIAObservation","UpdateOIAFindingAnalysis","FinalizeOIAFinding","MarkOIAAssessmentReadyForDelivery","ReviseDeliveredOIAFinding","CloseOIAAssessment","DeliverOIAFindings") and (not s or p.expected_record_version!=s.record_version):return self.fail(RuntimeReason.VERSION_STALE,"authoritative record version is stale","version")
        if p.command_type=="RecordOIARootCause" and p.expected_record_version is not None and (not s or p.expected_record_version!=s.record_version):return self.fail(RuntimeReason.VERSION_STALE,"authoritative record version is stale","version")
