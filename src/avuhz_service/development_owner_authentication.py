"""Dormant DEVELOPMENT owner-authentication checkpoint for shared tenant onboarding.

This module does NOT register a tenant, verify business ownership, establish
recent MFA enrollment, grant an onboarding capability, or write to DATA.
It is NOT connected to HTTP routing, the DEVELOPMENT identity allowlist, the
owner-directory port, or a hosted provider action.

Only the existing, cryptographically validating, project-pinned Supabase ES256
JWKS verifier is accepted. A cryptographically verified aal2 token proves a
token's assurance claim, NOT that the user owns a business or that MFA
occurred recently. Token iat indicates token issuance, not step-up time.
Any later registration writer must separately resolve:
- a fresh AUTH-owned MFA ceremony / assurance attestation;
- independent proof that this AUTH subject owns this business;
- the user's trusted authorization to register exactly one DATA tenant;
- atomic organization + owner membership registration under RLS.
Never take those facts from this result or from caller input.

The only output of this checkpoint is a non-authorizing opaque subject digest
that matches the installed DATA membership storage shape.

Local focused test (no providers): PYTHONPATH=src python3 -m doctest -v
src/avuhz_service/development_owner_authentication.py

>>> import time
>>> from types import SimpleNamespace
>>> import jwt
>>> from cryptography.hazmat.primitives.asymmetric import ec
>>> private_key = ec.generate_private_key(ec.SECP256R1())
>>> class TestOnlyJwks:
...     def get_signing_key_from_jwt(self, _token):
...         return SimpleNamespace(key=private_key.public_key())
>>> verifier = DevelopmentSupabaseEs256JwtVerifier(TestOnlyJwks())
>>> checkpoint = DevelopmentOwnerAuthenticationCheckpoint(verifier)
>>> now = int(time.time())
>>> claims = dict(iss=DEVELOPMENT_AUTH_ISSUER, aud="authenticated",
...     sub="11111111-1111-4111-8111-111111111111", role="authenticated",
...     is_anonymous=False, aal="aal2", iat=now-5, exp=now+300)
>>> signed = jwt.encode(claims, private_key, algorithm="ES256")
>>> proof = checkpoint.inspect(signed)
>>> proof.subject_digest.startswith("sha256:") and len(proof.subject_digest) == 71
True
>>> (proof.auth_project_verified, proof.aal2_token_verified, proof.fresh_step_up_verified, proof.business_owner_verified, proof.registration_authorized)
(True, True, False, False, False)
>>> checkpoint.inspect(jwt.encode(dict(claims, aal="aal1"), private_key, algorithm="ES256"))
Traceback (most recent call last):
...
PermissionError: development owner authentication checkpoint denied
>>> checkpoint.inspect(jwt.encode(dict(claims, avuhz_tenant_id="22222222-2222-4222-8222-222222222222"), private_key, algorithm="ES256"))
Traceback (most recent call last):
...
PermissionError: development owner authentication checkpoint denied
>>> impostor = ec.generate_private_key(ec.SECP256R1())
>>> checkpoint.inspect(jwt.encode(claims, impostor, algorithm="ES256"))
Traceback (most recent call last):
...
PermissionError: development owner authentication checkpoint denied
>>> checkpoint.inspect(jwt.encode(dict(claims, iss="https://wrong.example/auth/v1"), private_key, algorithm="ES256"))
Traceback (most recent call last):
...
PermissionError: development owner authentication checkpoint denied
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping

from .development import (
    DEVELOPMENT_AUTH_ISSUER,
)
from .development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
from .development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier


_CANONICAL_SUBJECT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_KNOWN_TEST_SUBJECT_DIGESTS = frozenset(
    entry.subject_digest for entry in DEVELOPMENT_IDENTITY_ALLOWLIST
)
_MAX_TOKEN_AGE_SECONDS = 900
_MAX_TOKEN_LIFETIME_SECONDS = 3600
# The installed AUTH hook rewrites aud to the command-service value only
# AFTER provider-owned app_metadata contains a tenant binding. A first owner
# cannot have that binding yet, so require the standard pre-tenant audience.
# No command capability or tenant RLS authority is ever granted here.
_PRE_TENANT_AUTH_AUDIENCE = "authenticated"
_DENIED = "development owner authentication checkpoint denied"


@dataclass(frozen=True)
class ProvisionalOwnerAuthentication:
    """Internal, non-authorizing evidence. Never serialize to a public client."""

    subject_digest: str = field(repr=False)
    verified_at: str
    environment: str = "DEVELOPMENT"
    auth_project_verified: bool = True
    aal2_token_verified: bool = True
    fresh_step_up_verified: bool = False
    business_owner_verified: bool = False
    registration_authorized: bool = False


class DevelopmentOwnerAuthenticationCheckpoint:
    """Verify DEVELOPMENT AUTH JWT; never translate it into enrollment authority."""

    def __init__(self, jwt_verifier: DevelopmentSupabaseEs256JwtVerifier):
        # Prevent accidental substitution with a caller-supplied verifier
        # that trusts decoded-but-unsigned or other-project JWT claims.
        if type(jwt_verifier) is not DevelopmentSupabaseEs256JwtVerifier:
            raise ValueError("approved DEVELOPMENT AUTH JWT verifier required")
        self._verifier = jwt_verifier

    def inspect(self, untrusted_bearer: object) -> ProvisionalOwnerAuthentication:
        """Return sanitized internal ID only; any uncertainty denies access."""
        try:
            if not isinstance(untrusted_bearer, str) or not 32 <= len(untrusted_bearer) <= 16384:
                raise PermissionError
            claims = self._verifier.verify(untrusted_bearer)
            if not isinstance(claims, Mapping):
                raise PermissionError

            if (claims.get("iss") != DEVELOPMENT_AUTH_ISSUER
                    or claims.get("aud") != _PRE_TENANT_AUTH_AUDIENCE
                    or claims.get("role") != "authenticated"
                    or claims.get("aal") != "aal2"
                    or claims.get("is_anonymous") is not False):
                raise PermissionError

            # Never permit the existing tenant-bound synthetic/provider JWT to
            # bootstrap an independent, real-business organization.
            if "avuhz_tenant_id" in claims:
                raise PermissionError
            app_metadata = claims.get("app_metadata")
            if isinstance(app_metadata, Mapping) and "avuhz_tenant_id" in app_metadata:
                raise PermissionError
            subject = claims.get("sub")
            if not isinstance(subject, str) or not _CANONICAL_SUBJECT.fullmatch(subject):
                raise PermissionError

            issued = claims.get("iat")
            expiry = claims.get("exp")
            if type(issued) is not int or type(expiry) is not int:
                raise PermissionError
            now = datetime.now(timezone.utc)
            now_timestamp = now.timestamp()
            if (issued <= 0 or issued > now_timestamp or expiry <= now_timestamp
                    or now_timestamp - issued > _MAX_TOKEN_AGE_SECONDS
                    or expiry - issued > _MAX_TOKEN_LIFETIME_SECONDS):
                raise PermissionError

            digest = "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()
            if any(hmac.compare_digest(digest, item) for item in _KNOWN_TEST_SUBJECT_DIGESTS):
                raise PermissionError
        except Exception:
            # Never log or surface bearer, claims, subject, evidence, or exceptions.
            raise PermissionError(_DENIED) from None

        return ProvisionalOwnerAuthentication(
            subject_digest=digest,
            verified_at=now.isoformat().replace("+00:00", "Z"),
        )


if __name__ == "__main__":
    import doctest
    failed, _ = doctest.testmod()
    raise SystemExit(1 if failed else 0)
