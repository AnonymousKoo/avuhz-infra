"Provider-specific DEVELOPMENT Supabase identity verification policy boundary."
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Protocol

from .development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_ENVIRONMENT,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from .development_identity import VerifiedDevelopmentIdentityEvidence


_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_OPAQUE_REFERENCE = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_READ_ONLY_CAPABILITIES = frozenset({"engagement:read"})
_SYNTHETIC_CALLER_TYPE = "HUMAN"


class DevelopmentSupabaseJwtVerifier(Protocol):
    """Cryptographically verify an untrusted JWT and return verified claims only."""

    def verify(self, token: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class DevelopmentIdentityAllowlistEntry:
    """Server-owned mapping from one provider subject digest to bounded Avuhz authority."""

    subject_digest: str
    principal_reference: str
    tenant_id: str

    def __post_init__(self):
        if not isinstance(self.subject_digest, str) or not _SHA256.fullmatch(self.subject_digest):
            raise ValueError("valid provider subject digest is required")
        if (
            not isinstance(self.principal_reference, str)
            or not _OPAQUE_REFERENCE.fullmatch(self.principal_reference)
        ):
            raise ValueError("valid provider-neutral principal reference is required")
        if not isinstance(self.tenant_id, str) or not _CANONICAL_UUID.fullmatch(self.tenant_id):
            raise ValueError("valid canonical tenant id is required")


def _subject_digest(subject: str) -> str:
    return "sha256:" + hashlib.sha256(subject.encode("utf-8")).hexdigest()


def _utc_timestamp(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PermissionError
    if value < 0:
        raise PermissionError
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise PermissionError from None


class DevelopmentSupabaseIdentityVerifier:
    """Translate one verified Supabase JWT into bounded provider-neutral Avuhz evidence."""

    def __init__(
        self,
        jwt_verifier: DevelopmentSupabaseJwtVerifier,
        *,
        allowlist: tuple[DevelopmentIdentityAllowlistEntry, ...],
    ):
        if jwt_verifier is None or not callable(getattr(jwt_verifier, "verify", None)):
            raise ValueError("trusted Supabase JWT verifier is required")
        if type(allowlist) is not tuple or len(allowlist) != 1:
            raise ValueError("exactly one DEVELOPMENT identity allowlist entry is required")
        if type(allowlist[0]) is not DevelopmentIdentityAllowlistEntry:
            raise ValueError("valid DEVELOPMENT identity allowlist entry is required")
        self._jwt_verifier = jwt_verifier
        self._allowlist = allowlist

    def verify(self, untrusted_identity: object) -> VerifiedDevelopmentIdentityEvidence:
        try:
            if not isinstance(untrusted_identity, str) or not 32 <= len(untrusted_identity) <= 16384:
                raise PermissionError
            claims = self._jwt_verifier.verify(untrusted_identity)
            if not isinstance(claims, Mapping):
                raise PermissionError

            issuer = claims.get("iss")
            audience = claims.get("aud")
            provider_subject = claims.get("sub")
            tenant_id = claims.get("avuhz_tenant_id")
            role = claims.get("role")
            aal = claims.get("aal")
            is_anonymous = claims.get("is_anonymous")
            issued_at = claims.get("iat")
            expires_at = claims.get("exp")

            if issuer != DEVELOPMENT_AUTH_ISSUER:
                raise PermissionError
            if audience != DEVELOPMENT_SERVICE_AUDIENCE:
                raise PermissionError
            if not isinstance(provider_subject, str) or not _CANONICAL_UUID.fullmatch(provider_subject):
                raise PermissionError
            if not isinstance(tenant_id, str) or not _CANONICAL_UUID.fullmatch(tenant_id):
                raise PermissionError
            if role != "authenticated" or aal != "aal1" or is_anonymous is not False:
                raise PermissionError

            digest = _subject_digest(provider_subject)
            matches = tuple(
                entry
                for entry in self._allowlist
                if hmac.compare_digest(entry.subject_digest, digest)
                and entry.tenant_id == tenant_id
            )
            if len(matches) != 1:
                raise PermissionError
            entry = matches[0]

            authenticated_at = _utc_timestamp(issued_at)
            expires_at_text = _utc_timestamp(expires_at)
        except Exception:
            raise PermissionError("trusted development identity evidence is invalid") from None

        return VerifiedDevelopmentIdentityEvidence(
            issuer=DEVELOPMENT_AUTH_ISSUER,
            audience=DEVELOPMENT_SERVICE_AUDIENCE,
            subject=entry.principal_reference,
            tenant_id=entry.tenant_id,
            caller_type=_SYNTHETIC_CALLER_TYPE,
            capabilities=_READ_ONLY_CAPABILITIES,
            authority_roles=frozenset(),
            environment=DEVELOPMENT_ENVIRONMENT,
            authentication_strength="STANDARD",
            step_up_performed=False,
            authenticated_at=authenticated_at,
            expires_at=expires_at_text,
        )
