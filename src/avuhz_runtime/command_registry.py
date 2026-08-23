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
    executable: bool = False


COMMANDS = {
    "AcceptAcquisitionHandoff": CommandDefinition("AcceptAcquisitionHandoff", "ACQUISITION_HANDOFF", 1, "urn:avuhz:schema:contracts:commands:accept-acquisition-handoff-payload:v1", 1),
    "OpenEngagement": CommandDefinition("OpenEngagement", "ENGAGEMENT", 1, "urn:avuhz:schema:contracts:commands:open-engagement-payload:v1", 1),
    "SubmitDiagnosticScope": CommandDefinition("SubmitDiagnosticScope", "ENGAGEMENT", 1, "urn:avuhz:schema:contracts:commands:submit-diagnostic-scope-payload:v1", 1),
    "ApproveDiagnosticScope": CommandDefinition("ApproveDiagnosticScope", "DIAGNOSTIC_SCOPE", 1, "urn:avuhz:schema:contracts:commands:approve-diagnostic-scope-payload:v1", 1),
    "CanonicalizeDiagnosticScope": CommandDefinition("CanonicalizeDiagnosticScope", "DIAGNOSTIC_SCOPE", 1, "urn:avuhz:schema:contracts:commands:canonicalize-diagnostic-scope-payload:v1", 1),
}


def resolve_command(command_type: object) -> CommandDefinition | None:
    return COMMANDS.get(command_type) if isinstance(command_type, str) else None
