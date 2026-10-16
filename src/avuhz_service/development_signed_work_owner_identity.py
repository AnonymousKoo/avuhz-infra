"""Dormant shared DEVELOPMENT owner -> opaque Work Item principal boundary.

AUTH verifies human identity + a fresh MFA ceremony and live session. Existing
DATA RLS/membership proves this digest belongs to an ACTIVE OWNER at the
exact tenant and organization. An *independent*, trusted, signed principal
registry then binds that same digest to an opaque Avuhz principal.

Does not issue tokens or sign decisions; contains NO signing key, credential,
hosted route, identity enrollment, table, or vertical-specific authorization.
Synthetic test signing keys are NEVER acceptable for a hosted connection.

DO NOT mount for hosted use until trusted binding issuer/provenance, key
custody, scope selection, historical identity enrollment, revocation and the
acquisition transaction admission have been independently certified.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from avuhz_runtime.guards import TrustedExecutionContext
from .development import DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF
from .development_active_owner_membership import DevelopmentActiveOwnerMembershipCheck, _uuid
from .development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint, ProvisionalOwnerAuthentication,
)
from .development_owner_mfa_freshness import DevelopmentOwnerMfaFreshnessCheck
from .shared_work_intake_candidate import _opaque

PURPOSE = "AVUHZ_DEVELOPMENT_WORK_OWNER_PRINCIPAL_BINDING_V1"
ISSUER = "AUTHORITATIVE_SHARED_PRINCIPAL_REGISTRY"
_FIELDS = frozenset({
    "purpose", "issuer", "environment", "auth_project_ref", "data_project_ref",
    "tenant_id", "organization_id", "subject_digest", "principal_reference",
    "issued_at", "expires_at",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class SignedWorkOwnerPrincipalBinding:
    statement: dict[str, object]
    signature: bytes


def _utc(value: object) -> datetime | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        dt = datetime.fromisoformat(value[:-1] + "+00:00")
        return dt if dt.tzinfo == timezone.utc else None
    except (ValueError, OverflowError):
        return None


class DevelopmentSignedWorkOwnerIdentityResolver:
    """Source-only callable usable by existing shared writer's identity hook.

    Runtime bearer is the ONLY caller-supplied argument. The tenant and org
    must be selected by a trusted server-side composition, not by request
    parameters or a workflow event. Only an independently pinned issuer's
    exact subject+scope+principal assertion may establish an opaque mapping.
    """

    def __init__(
        self, *,
        tenant_id: str,
        organization_id: str,
        auth_checkpoint: DevelopmentOwnerAuthenticationCheckpoint,
        mfa_check: DevelopmentOwnerMfaFreshnessCheck,
        active_owner_membership: DevelopmentActiveOwnerMembershipCheck,
        principal_public_key: Ed25519PublicKey,
        pinned_fingerprint: str,
        fetch_signed_binding: Callable[
            [str, str, str], SignedWorkOwnerPrincipalBinding
        ],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if (
            not _uuid(tenant_id) or not _uuid(organization_id)
            or type(auth_checkpoint) is not DevelopmentOwnerAuthenticationCheckpoint
            or type(mfa_check) is not DevelopmentOwnerMfaFreshnessCheck
            or type(active_owner_membership) is not DevelopmentActiveOwnerMembershipCheck
            or not isinstance(principal_public_key, Ed25519PublicKey)
            or type(pinned_fingerprint) is not str
            or not _DIGEST.fullmatch(pinned_fingerprint)
            or not callable(fetch_signed_binding)
            or not callable(clock)
        ):
            raise ValueError("trusted owner principal boundary required")
        digest = "sha256:" + hashlib.sha256(
            principal_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        if not hmac.compare_digest(digest, pinned_fingerprint):
            raise ValueError("pinned principal registry signing key mismatch")
        self._tenant_id = tenant_id
        self._organization_id = organization_id
        self._auth = auth_checkpoint
        self._mfa = mfa_check
        self._active_member = active_owner_membership
        self._public_key = principal_public_key
        self._fetch = fetch_signed_binding
        self._clock = clock

    def resolve(self, untrusted_bearer: object) -> TrustedExecutionContext:
        try:
            provisional = self._auth.inspect(untrusted_bearer)
            if (
                type(provisional) is not ProvisionalOwnerAuthentication
                or provisional.environment != "DEVELOPMENT"
                or provisional.auth_project_verified is not True
                or provisional.aal2_token_verified is not True
                or provisional.registration_authorized is not False
                or type(provisional.subject_digest) is not str
                or not _DIGEST.fullmatch(provisional.subject_digest)
            ):
                raise PermissionError
            now = self._clock()
            if (
                type(now) is not datetime or now.tzinfo != timezone.utc
                or _utc(provisional.verified_at) is None
                or _utc(provisional.verified_at) > now
                or now - _utc(provisional.verified_at) > timedelta(minutes=5)
            ):
                raise PermissionError
            if self._mfa(untrusted_bearer, provisional.subject_digest) is not True:
                raise PermissionError
            if self._active_member(
                untrusted_bearer, self._tenant_id, self._organization_id,
            ) is not True:
                raise PermissionError
            # Never trust a callback result unless it is signed by an
            # independently provisioned, pinned registry signing authority.
            signed = self._fetch(
                provisional.subject_digest, self._tenant_id, self._organization_id,
            )
            if type(signed) is not SignedWorkOwnerPrincipalBinding:
                raise PermissionError
            statement = signed.statement
            if (
                type(statement) is not dict or set(statement) != _FIELDS
                or statement["purpose"] != PURPOSE
                or statement["issuer"] != ISSUER
                or statement["environment"] != "DEVELOPMENT"
                or statement["auth_project_ref"] != DEVELOPMENT_AUTH_PROJECT_REF
                or statement["data_project_ref"] != DEVELOPMENT_DATA_PROJECT_REF
                or statement["auth_project_ref"] == statement["data_project_ref"]
                or statement["tenant_id"] != self._tenant_id
                or statement["organization_id"] != self._organization_id
                or type(statement["subject_digest"]) is not str
                or not hmac.compare_digest(
                    statement["subject_digest"], provisional.subject_digest,
                )
                or not _opaque(statement["principal_reference"])
                or _DIGEST.fullmatch(statement["principal_reference"]) is not None
                or type(signed.signature) is not bytes
                or len(signed.signature) != 64
            ):
                raise PermissionError
            issued = _utc(statement["issued_at"])
            expires = _utc(statement["expires_at"])
            if (
                issued is None or expires is None
                or issued > now or now - issued > timedelta(seconds=60)
                or expires <= now or expires <= issued
                or expires - issued > timedelta(seconds=90)
            ):
                raise PermissionError
            canonical = json.dumps(
                statement, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
            self._public_key.verify(signed.signature, canonical)
            return TrustedExecutionContext(
                authenticated=True,
                principal_id=statement["principal_reference"],
                caller_type="HUMAN", tenant_id=self._tenant_id,
                organization_id=self._organization_id,
                capabilities=frozenset({"work_intake:create"}),
                authority_roles=frozenset(), environment="DEVELOPMENT",
                audience="avuhz-command-api",
                authentication_strength="STRONG", step_up_satisfied=False,
                authenticated_at=provisional.verified_at,
                expires_at=statement["expires_at"],
            )
        except Exception:
            # No JWT, subject digest, signing material, tenant existence,
            # PII, issuer response, or SQL details leave this boundary.
            raise PermissionError("work owner identity unavailable") from None
