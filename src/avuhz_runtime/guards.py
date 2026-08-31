"""Pure deterministic governance guards; no I/O or state mutation."""
from dataclasses import dataclass

from .errors import RuntimeReason
from .phase5d_brief import IMPLEMENTATION_BRIEF_CAPABILITIES, IMPLEMENTATION_BRIEF_COMMANDS
from .phase5d_authorization import IMPLEMENTATION_AUTHORIZATION_CAPABILITIES, IMPLEMENTATION_AUTHORIZATION_COMMANDS
from .phase5d_package import CODEX_BUILD_PACKAGE_CAPABILITIES, CODEX_BUILD_PACKAGE_COMMANDS
from .phase5d_build_execution import BUILD_EXECUTION_CAPABILITIES, BUILD_EXECUTION_COMMANDS
from .phase5d_qa_result import QA_RESULT_CAPABILITIES
from .phase5d_client_acceptance import CLIENT_ACCEPTANCE_CAPABILITIES
from .phase5d_deployment_authorization import DEPLOYMENT_AUTHORIZATION_CAPABILITIES, DEPLOYMENT_AUTHORIZATION_COMMANDS


COMMAND_CAPABILITIES = {"AcceptAcquisitionHandoff": "engagement:accept_handoff", "OpenEngagement": "engagement:open"}
COMMAND_CAPABILITIES.update(IMPLEMENTATION_BRIEF_CAPABILITIES)
COMMAND_CAPABILITIES.update(IMPLEMENTATION_AUTHORIZATION_CAPABILITIES)
COMMAND_CAPABILITIES.update(CODEX_BUILD_PACKAGE_CAPABILITIES)
COMMAND_CAPABILITIES.update(BUILD_EXECUTION_CAPABILITIES)
COMMAND_CAPABILITIES.update(QA_RESULT_CAPABILITIES)
COMMAND_CAPABILITIES.update(CLIENT_ACCEPTANCE_CAPABILITIES)
COMMAND_CAPABILITIES.update(DEPLOYMENT_AUTHORIZATION_CAPABILITIES)

IMPLEMENTATION_BRIEF_TRANSITIONS = frozenset(IMPLEMENTATION_BRIEF_COMMANDS) - {"DraftImplementationBrief"}
IMPLEMENTATION_AUTHORIZATION_TRANSITIONS = frozenset(IMPLEMENTATION_AUTHORIZATION_COMMANDS) - {"ProposeImplementationAuthorization"}
CODEX_BUILD_PACKAGE_TRANSITIONS = frozenset(CODEX_BUILD_PACKAGE_COMMANDS) - {"DraftCodexBuildPackage"}
BUILD_EXECUTION_TRANSITIONS = frozenset(BUILD_EXECUTION_COMMANDS) - {"StartBuildExecution"}
DEPLOYMENT_AUTHORIZATION_TRANSITIONS = frozenset(DEPLOYMENT_AUTHORIZATION_COMMANDS) - {"ProposeDeploymentAuthorization"}
HUMAN_AUTHORITY_ROLES = frozenset({"CLIENT_IMPLEMENTATION_AUTHORITY", "PROVIDER_IMPLEMENTATION_AUTHORITY", "CLIENT_DEPLOYMENT_AUTHORITY", "PROVIDER_DEPLOYMENT_AUTHORITY"})


@dataclass(frozen=True)
class TrustedExecutionContext:
    authenticated: bool; principal_id: str | None; caller_type: str | None; tenant_id: str | None
    organization_id: str | None; capabilities: frozenset[str]; authority_roles: frozenset[str]
    environment: str | None; audience: str | None; authentication_strength: str | None
    step_up_satisfied: bool; authenticated_at: str | None; expires_at: str | None = None
    human_principal_reference: str | None = None; human_organization_reference: str | None = None
    human_authority_role: str | None = None


@dataclass(frozen=True)
class AuthoritativeSubjectSnapshot:
    subject_type: str; subject_id: str; tenant_id: str; record_version: int; exists: bool
    engagement_id: str | None = None; state: str | None = None


@dataclass(frozen=True)
class GuardFailure:
    reason: RuntimeReason; message: str; guard_name: str


@dataclass(frozen=True)
class GuardedCommand:
    prepared: object; trusted_principal_id: str; trusted_caller_type: str
    trusted_tenant_id: str; effective_capabilities: frozenset[str]
    subject_snapshot: AuthoritativeSubjectSnapshot | None


@dataclass(frozen=True)
class GuardSuccess:
    guarded: GuardedCommand


class GuardPipeline:
    """Order: authentication, environment, tenant, capability, subject, version."""
    def evaluate(self, prepared, context, snapshot, evaluated_at):
        for name, guard in (("authentication", self.auth), ("environment", self.env), ("tenant", self.tenant), ("capability", self.cap), ("subject", self.subject), ("version", self.version)):
            failure = guard(prepared, context, snapshot, evaluated_at)
            if failure: return failure
        return GuardSuccess(GuardedCommand(prepared, context.principal_id or "", context.caller_type or "", context.tenant_id or "", context.capabilities, snapshot))
    @staticmethod
    def fail(reason, message, name): return GuardFailure(reason, message, name)
    def human_approval_authority(self, context, requested_role):
        if context.caller_type != "HUMAN" or not context.human_principal_reference or not context.human_organization_reference:
            return self.fail(RuntimeReason.AUTH_INVALID, "trusted human caller is required", "human_authority")
        if not context.tenant_id: return self.fail(RuntimeReason.TENANT_CONTEXT_MISSING, "trusted tenant context is required", "human_authority")
        if context.human_authority_role not in HUMAN_AUTHORITY_ROLES or requested_role != context.human_authority_role:
            return self.fail(RuntimeReason.AUTH_INVALID, "trusted human authority role does not match", "human_authority")
    def auth(self, prepared, context, snapshot, evaluated_at):
        if not context.authenticated: return self.fail(RuntimeReason.AUTH_MISSING, "trusted authentication is required", "authentication")
        if not context.principal_id or not context.caller_type or not context.authenticated_at or context.caller_type != prepared.caller_identity_claim.get("caller_type"):
            return self.fail(RuntimeReason.AUTH_INVALID, "trusted identity context is invalid", "authentication")
        if context.audience != "avuhz-command-api": return self.fail(RuntimeReason.AUTH_AUDIENCE_INVALID, "trusted audience is not accepted", "authentication")
        if context.expires_at and context.expires_at <= evaluated_at: return self.fail(RuntimeReason.AUTH_EXPIRED, "trusted identity is expired", "authentication")
    def env(self, prepared, context, snapshot, evaluated_at):
        if not context.environment or context.environment != prepared.environment: return self.fail(RuntimeReason.AUTH_INVALID, "trusted environment does not match command", "environment")
    def tenant(self, prepared, context, snapshot, evaluated_at):
        if not context.tenant_id: return self.fail(RuntimeReason.TENANT_CONTEXT_MISSING, "trusted tenant context is required", "tenant")
        if context.tenant_id != prepared.tenant_id: return self.fail(RuntimeReason.TENANT_ACCESS_DENIED, "trusted tenant cannot act for command tenant", "tenant")
        if snapshot and snapshot.tenant_id != prepared.tenant_id: return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH, "subject tenant does not match command", "tenant")
        if snapshot and prepared.engagement_id and snapshot.engagement_id and snapshot.engagement_id != prepared.engagement_id: return self.fail(RuntimeReason.CROSS_TENANT_ATTEMPT, "engagement context does not match subject", "tenant")
    def cap(self, prepared, context, snapshot, evaluated_at):
        required = COMMAND_CAPABILITIES.get(prepared.command_type)
        if not required: return self.fail(RuntimeReason.INTERNAL_INVARIANT_VIOLATION, "registered command policy is incomplete", "capability")
        if required not in context.capabilities: return self.fail(RuntimeReason.AUTH_CAPABILITY_MISSING, "trusted capability is required", "capability")
    def subject(self, prepared, context, snapshot, evaluated_at):
        transitions = IMPLEMENTATION_BRIEF_TRANSITIONS | IMPLEMENTATION_AUTHORIZATION_TRANSITIONS | CODEX_BUILD_PACKAGE_TRANSITIONS | BUILD_EXECUTION_TRANSITIONS | DEPLOYMENT_AUTHORIZATION_TRANSITIONS
        if prepared.command_type == "OpenEngagement" and snapshot and snapshot.exists:
            return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH, "proposed engagement already exists", "subject")
        if prepared.command_type in transitions and (not snapshot or not snapshot.exists or snapshot.subject_type != prepared.subject_type or snapshot.subject_id != prepared.subject_id):
            return self.fail(RuntimeReason.TENANT_SUBJECT_MISMATCH, "exact authoritative subject is required", "subject")
    def version(self, prepared, context, snapshot, evaluated_at):
        transitions = IMPLEMENTATION_BRIEF_TRANSITIONS | IMPLEMENTATION_AUTHORIZATION_TRANSITIONS | CODEX_BUILD_PACKAGE_TRANSITIONS | BUILD_EXECUTION_TRANSITIONS | DEPLOYMENT_AUTHORIZATION_TRANSITIONS
        if prepared.command_type in transitions and (not snapshot or prepared.expected_record_version != snapshot.record_version):
            return self.fail(RuntimeReason.VERSION_STALE, "authoritative record version is stale", "version")
