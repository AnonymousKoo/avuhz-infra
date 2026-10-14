"""Offline-only candidate for a distinct shared Avuhz acquisition service identity.

The historical DEVELOPMENT Supabase allowlist source is checksum-bound and must
NOT be edited under this proposal. This module reuses the existing AUTH-signed
JWT interface and DevelopmentTrustedIdentityResolver evidence format, but is
NOT wired into the hosted command service or an intake HTTP route. No service
subject, credential, AUTH account, capability grant or DATA permission exists
as a result of this module.

A live implementation requires separately approved provider registration,
server-managed JWT app_metadata, trusted verifier composition, verified
active tenant/owner binding, rate limits and RLS-limited DATA grants.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Protocol

from .development import (
    DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_ENVIRONMENT,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from .development_identity import VerifiedDevelopmentIdentityEvidence
from .development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINCIPAL = re.compile(r"^service\.[a-z][a-z0-9._:-]{2,120}$")
_SERVICE_CLASS = "acquisition_intake"
_CAPABILITIES = frozenset({"acquisition_intake:receive"})
# Bound future acquisition workload credentials to one typical Supabase
# access-token window. This is a verifier cap, not a provider-side issuer
# configuration change or approval to enroll/issue a workload credential.
MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS = 60 * 60
_DENIED = "acquisition_service_identity_invalid"


class AuthSignedJwtVerifier(Protocol):
    """Existing shared AUTH verifier interface, not a second JWT issuer."""

    def verify(self, token: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class DevelopmentAcquisitionServicePolicy:
    """One future enrolled, non-human AUTH identity (no secret material)."""

    subject_digest: str
    principal_reference: str
    tenant_id: str

    def __post_init__(self) -> None:
        if (
            type(self.subject_digest) is not str
            or _SHA.fullmatch(self.subject_digest) is None
            or type(self.principal_reference) is not str
            or _PRINCIPAL.fullmatch(self.principal_reference) is None
            or type(self.tenant_id) is not str
            or _UUID.fullmatch(self.tenant_id) is None
        ):
            raise ValueError("invalid acquisition service policy")
        # Never re-label the already-approved HUMAN or PROVIDER_ADAPTER
        # subjects as an acquisition service with broader privileges.
        if any(
            entry.subject_digest == self.subject_digest
            or entry.principal_reference == self.principal_reference
            for entry in DEVELOPMENT_IDENTITY_ALLOWLIST
        ):
            raise ValueError("existing development identity cannot be reclassified")


def _utc_timestamp(value: object) -> str:
    if type(value) is not int or value < 0:
        raise ValueError
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (ValueError, OverflowError, OSError):
        raise ValueError from None


class DevelopmentAcquisitionServiceIdentityCandidate:
    """Verifier adapter for injection-only offline certification.

    The real hosting composition must use the existing cryptographic
    DevelopmentSupabaseEs256JwtVerifier, not an in-memory testing verifier.
    This class itself registers no handler, route, entitlement or allowlist.
    """

    def __init__(
        self, jwt_verifier: AuthSignedJwtVerifier,
        policy: DevelopmentAcquisitionServicePolicy,
    ) -> None:
        if (
            not callable(getattr(jwt_verifier, "verify", None))
            or type(policy) is not DevelopmentAcquisitionServicePolicy
        ):
            raise ValueError("valid shared AUTH verifier and service policy required")
        self._jwt_verifier = jwt_verifier
        self._policy = policy

    def verify(self, untrusted_identity: object) -> VerifiedDevelopmentIdentityEvidence:
        try:
            if (
                type(untrusted_identity) is not str
                or not 32 <= len(untrusted_identity) <= 16384
            ):
                raise ValueError
            claims = self._jwt_verifier.verify(untrusted_identity)
            if not isinstance(claims, Mapping):
                raise ValueError
            subject = claims.get("sub")
            tenant = claims.get("avuhz_tenant_id")
            metadata = claims.get("app_metadata")

            if (
                claims.get("iss") != DEVELOPMENT_AUTH_ISSUER
                or claims.get("aud") != DEVELOPMENT_SERVICE_AUDIENCE
                or claims.get("role") != "authenticated"
                or claims.get("aal") != "aal1"
                or claims.get("is_anonymous") is not False
                or type(subject) is not str or _UUID.fullmatch(subject) is None
                or type(tenant) is not str or tenant != self._policy.tenant_id
                or not isinstance(metadata, Mapping)
                or metadata.get("avuhz_workload") != _SERVICE_CLASS
                or metadata.get("avuhz_tenant_id") != self._policy.tenant_id
            ):
                raise ValueError
            digest = "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()
            if not hmac.compare_digest(digest, self._policy.subject_digest):
                raise ValueError

            issued = claims.get("iat")
            expires = claims.get("exp")
            issued_at = _utc_timestamp(issued)
            expires_at = _utc_timestamp(expires)
            if (
                expires <= issued
                or expires - issued > MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS
            ):
                raise ValueError
        except Exception:
            # No credential, subject, private provider payload, PII, or
            # exception text is ever exposed through this boundary.
            raise PermissionError(_DENIED) from None

        return VerifiedDevelopmentIdentityEvidence(
            issuer=DEVELOPMENT_AUTH_ISSUER,
            audience=DEVELOPMENT_SERVICE_AUDIENCE,
            subject=self._policy.principal_reference,
            tenant_id=self._policy.tenant_id,
            caller_type="INTERNAL_SERVICE",
            capabilities=_CAPABILITIES,
            authority_roles=frozenset(),
            environment=DEVELOPMENT_ENVIRONMENT,
            authentication_strength="STANDARD",
            step_up_performed=False,
            authenticated_at=issued_at,
            expires_at=expires_at,
        )
