"""Provider-neutral DEVELOPMENT trusted-identity resolution boundary."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from avuhz_runtime.guards import COMMAND_CAPABILITIES, TrustedExecutionContext

from .application import QUERY_READ_CAPABILITY
from .development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_ENVIRONMENT,
    DEVELOPMENT_SERVICE_AUDIENCE,
)


_INTERNAL_RUNTIME_AUDIENCE = "avuhz-command-api"
_CALLER_TYPES = frozenset({
    "HUMAN", "WORKLOAD", "INTERNAL_SERVICE", "PROVIDER_ADAPTER",
    "SCHEDULED_AUTOMATION", "SECURITY_AUTOMATION",
})
_AUTHENTICATION_STRENGTHS = frozenset({"STANDARD", "STRONG", "STEP_UP"})
_COMMAND_QUERY_CAPABILITIES = frozenset({QUERY_READ_CAPABILITY, *COMMAND_CAPABILITIES.values()})
_OPAQUE_REFERENCE = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$"
)


@dataclass(frozen=True)
class VerifiedDevelopmentIdentityEvidence:
    """Bounded output of a trusted verifier; never a raw token or provider payload."""

    issuer: str
    audience: str
    subject: str
    tenant_id: str
    caller_type: str
    capabilities: frozenset[str]
    authority_roles: frozenset[str]
    environment: str
    authentication_strength: str
    step_up_performed: bool
    authenticated_at: str
    expires_at: str


class DevelopmentIdentityVerifier(Protocol):
    def verify(self, untrusted_identity: object) -> VerifiedDevelopmentIdentityEvidence: ...


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or not 20 <= len(value) <= 30 or not _UTC_TIMESTAMP.fullmatch(value):
        raise PermissionError("trusted development identity evidence is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PermissionError("trusted development identity evidence is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise PermissionError("trusted development identity evidence is invalid")
    return parsed


def _canonical_tenant(value: object) -> bool:
    return isinstance(value, str) and _CANONICAL_UUID.fullmatch(value) is not None


class DevelopmentTrustedIdentityResolver:
    """Resolve verified DEVELOPMENT evidence into the frozen trusted context."""

    def __init__(
        self,
        verifier: DevelopmentIdentityVerifier,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if verifier is None or not callable(getattr(verifier, "verify", None)) or not callable(clock):
            raise ValueError("trusted DEVELOPMENT verifier boundary is required")
        self._verifier = verifier
        self._clock = clock

    def resolve(self, authenticated_identity: object) -> TrustedExecutionContext:
        try:
            evidence = self._verifier.verify(authenticated_identity)
            if type(evidence) is not VerifiedDevelopmentIdentityEvidence:
                raise PermissionError
            authenticated_at = _utc(evidence.authenticated_at)
            expires_at = _utc(evidence.expires_at)
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise PermissionError
            now = now.astimezone(timezone.utc)
            if evidence.issuer != DEVELOPMENT_AUTH_ISSUER:
                raise PermissionError
            if evidence.audience != DEVELOPMENT_SERVICE_AUDIENCE:
                raise PermissionError
            if evidence.environment != DEVELOPMENT_ENVIRONMENT:
                raise PermissionError
            if not isinstance(evidence.subject, str) or not 3 <= len(evidence.subject) <= 128:
                raise PermissionError
            if not _OPAQUE_REFERENCE.fullmatch(evidence.subject):
                raise PermissionError
            if not _canonical_tenant(evidence.tenant_id):
                raise PermissionError
            if evidence.caller_type not in _CALLER_TYPES:
                raise PermissionError
            if type(evidence.capabilities) is not frozenset or len(evidence.capabilities) > 16:
                raise PermissionError
            if not evidence.capabilities <= _COMMAND_QUERY_CAPABILITIES:
                raise PermissionError
            if type(evidence.authority_roles) is not frozenset or evidence.authority_roles:
                raise PermissionError
            if evidence.authentication_strength not in _AUTHENTICATION_STRENGTHS:
                raise PermissionError
            if type(evidence.step_up_performed) is not bool:
                raise PermissionError
            if (evidence.authentication_strength == "STEP_UP") != evidence.step_up_performed:
                raise PermissionError
            if authenticated_at > now or expires_at <= now or expires_at <= authenticated_at:
                raise PermissionError
        except Exception:
            raise PermissionError("trusted development identity evidence is invalid") from None

        return TrustedExecutionContext(
            authenticated=True,
            principal_id=evidence.subject,
            caller_type=evidence.caller_type,
            tenant_id=evidence.tenant_id,
            organization_id=None,
            capabilities=evidence.capabilities,
            authority_roles=frozenset(),
            environment=DEVELOPMENT_ENVIRONMENT,
            audience=_INTERNAL_RUNTIME_AUDIENCE,
            authentication_strength=evidence.authentication_strength,
            step_up_satisfied=evidence.step_up_performed,
            authenticated_at=evidence.authenticated_at,
            expires_at=evidence.expires_at,
            human_principal_reference=None,
            human_organization_reference=None,
            human_authority_role=None,
        )
