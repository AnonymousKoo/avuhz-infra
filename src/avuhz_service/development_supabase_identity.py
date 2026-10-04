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
_PROVIDER_ADAPTER_CAPABILITIES = frozenset({"implementation_handoff:accept"})
_SYNTHETIC_CALLER_TYPE = "HUMAN"
_PROVIDER_ADAPTER_CALLER_TYPE = "PROVIDER_ADAPTER"
_ALLOWED_POLICY_CALLER_TYPES = frozenset({_SYNTHETIC_CALLER_TYPE, _PROVIDER_ADAPTER_CALLER_TYPE})


class DevelopmentSupabaseJwtVerifier(Protocol):
    """Cryptographically verify an untrusted JWT and return verified claims only."""

    def verify(self, token: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class DevelopmentIdentityAllowlistEntry:
    """Server-owned mapping from one provider subject digest to bounded Avuhz authority."""

    subject_digest: str
    principal_reference: str
    tenant_id: str
    caller_type: str = _SYNTHETIC_CALLER_TYPE
    capabilities: frozenset[str] = _READ_ONLY_CAPABILITIES

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
        if self.caller_type not in _ALLOWED_POLICY_CALLER_TYPES:
            raise ValueError("bounded DEVELOPMENT caller type is required")
        if type(self.capabilities) is not frozenset:
            raise ValueError("bounded DEVELOPMENT capabilities are required")
        expected = (
            _READ_ONLY_CAPABILITIES
            if self.caller_type == _SYNTHETIC_CALLER_TYPE
            else _PROVIDER_ADAPTER_CAPABILITIES
        )
        if self.capabilities != expected:
            raise ValueError("exact caller capability policy is required")


DEVELOPMENT_SYNTHETIC_READ_ONLY_POLICY_DIGEST = "sha256:864019b6d904f790fab298f0142989e067af65fa735094edc28ffa756de406f6"
DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST = (
    DevelopmentIdentityAllowlistEntry(
        subject_digest="sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5",
        principal_reference="subject.development-synthetic-user",
        tenant_id="1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0",
    ),
)
DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_POLICY_DIGEST = "sha256:e82ca947658c1366e468ff9b0d069f148c175c3b1f7b896c8bb5683ecb9ce483"
DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY = DevelopmentIdentityAllowlistEntry(
    subject_digest="sha256:21ae3658908a20bb95e6440850180d699bba96da97ee1556e0574d1b12293e7a",
    principal_reference="provider-adapter.implementation-handoff-development",
    tenant_id="1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0",
    caller_type=_PROVIDER_ADAPTER_CALLER_TYPE,
    capabilities=_PROVIDER_ADAPTER_CAPABILITIES,
)
DEVELOPMENT_IDENTITY_ALLOWLIST = (
    *DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)


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
        if type(allowlist) is not tuple or not 1 <= len(allowlist) <= 2:
            raise ValueError("one or two DEVELOPMENT identity allowlist entries are required")
        if any(type(entry) is not DevelopmentIdentityAllowlistEntry for entry in allowlist):
            raise ValueError("valid DEVELOPMENT identity allowlist entries are required")
        if len({entry.subject_digest for entry in allowlist}) != len(allowlist):
            raise ValueError("DEVELOPMENT provider subjects must be unique")
        if len({entry.principal_reference for entry in allowlist}) != len(allowlist):
            raise ValueError("DEVELOPMENT principal references must be unique")
        if len({(entry.tenant_id, entry.caller_type) for entry in allowlist}) != len(allowlist):
            raise ValueError("DEVELOPMENT tenant/caller policies must be unique")
        synthetic_entries = tuple(
            entry for entry in allowlist if entry.caller_type == _SYNTHETIC_CALLER_TYPE
        )
        provider_adapter_entries = tuple(
            entry for entry in allowlist if entry.caller_type == _PROVIDER_ADAPTER_CALLER_TYPE
        )
        if len(synthetic_entries) != 1 or len(provider_adapter_entries) > 1:
            raise ValueError("exact DEVELOPMENT identity policy composition is required")
        if len(allowlist) == 2 and len(provider_adapter_entries) != 1:
            raise ValueError("second DEVELOPMENT identity must be a provider adapter")
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
            caller_type=entry.caller_type,
            capabilities=entry.capabilities,
            authority_roles=frozenset(),
            environment=DEVELOPMENT_ENVIRONMENT,
            authentication_strength="STANDARD",
            step_up_performed=False,
            authenticated_at=authenticated_at,
            expires_at=expires_at_text,
        )
