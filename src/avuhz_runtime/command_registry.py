"""Closed command registry. Adding files cannot activate commands."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandDefinition:
    command_type: str; subject_type: str; envelope_version: int
    payload_schema_id: str; payload_version: int; validatable: bool = True
    required_capability: str = ""; executable: bool = False


def command(name, subject, slug, capability):
    return CommandDefinition(name, subject, 1, f"urn:avuhz:schema:contracts:commands:{slug}-payload:v1", 1, required_capability=capability, executable=True)


COMMANDS = {
    "AcceptAcquisitionHandoff": command("AcceptAcquisitionHandoff", "ACQUISITION_HANDOFF", "accept-acquisition-handoff", "engagement:accept_handoff"),
    "OpenEngagement": command("OpenEngagement", "ENGAGEMENT", "open-engagement", "engagement:open"),
    "DraftImplementationBrief": command("DraftImplementationBrief", "IMPLEMENTATION_BRIEF", "draft-implementation-brief", "implementation_brief:draft"),
    "ReviseImplementationBrief": command("ReviseImplementationBrief", "IMPLEMENTATION_BRIEF", "revise-implementation-brief", "implementation_brief:draft"),
    "RecordImplementationBriefApproval": command("RecordImplementationBriefApproval", "IMPLEMENTATION_BRIEF", "record-implementation-brief-approval", "implementation_brief:approve"),
    "ApproveImplementationBrief": command("ApproveImplementationBrief", "IMPLEMENTATION_BRIEF", "approve-implementation-brief", "implementation_brief:approve"),
    "ProposeImplementationAuthorization": command("ProposeImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", "propose-implementation-authorization", "implementation_authorization:propose"),
    "ReviseImplementationAuthorization": command("ReviseImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", "revise-implementation-authorization", "implementation_authorization:propose"),
    "RecordImplementationAuthorizationApproval": command("RecordImplementationAuthorizationApproval", "IMPLEMENTATION_AUTHORIZATION", "record-implementation-authorization-approval", "implementation_authorization:approve"),
    "ActivateImplementationAuthorization": command("ActivateImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", "activate-implementation-authorization", "implementation_authorization:activate"),
    "RevokeImplementationAuthorization": command("RevokeImplementationAuthorization", "IMPLEMENTATION_AUTHORIZATION", "revoke-implementation-authorization", "implementation_authorization:revoke"),
    "DraftCodexBuildPackage": command("DraftCodexBuildPackage", "CODEX_BUILD_PACKAGE", "draft-codex-build-package", "codex_build_package:draft"),
    "ReviseCodexBuildPackage": command("ReviseCodexBuildPackage", "CODEX_BUILD_PACKAGE", "revise-codex-build-package", "codex_build_package:draft"),
    "RecordCodexBuildPackageApproval": command("RecordCodexBuildPackageApproval", "CODEX_BUILD_PACKAGE", "record-codex-build-package-approval", "codex_build_package:approve"),
    "ReleaseCodexBuildPackage": command("ReleaseCodexBuildPackage", "CODEX_BUILD_PACKAGE", "release-codex-build-package", "codex_build_package:release"),
    "StartBuildExecution": command("StartBuildExecution", "BUILD_EXECUTION_RESULT", "start-build-execution", "build_execution:start"),
    "CompleteBuildExecution": command("CompleteBuildExecution", "BUILD_EXECUTION_RESULT", "complete-build-execution", "build_execution:complete"),
    "RecordQAResult": command("RecordQAResult", "QA_RESULT", "record-qa-result", "qa_result:record"),
}


def resolve_command(command_type): return COMMANDS.get(command_type) if isinstance(command_type, str) else None
