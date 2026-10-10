"""Dedicated pre-tenant DEVELOPMENT AUTH ES256 verifier for first-owner proof.

A pre-tenant human's Supabase token has the provider's native
`aud=authenticated`. It is NOT an Avuhz command-service JWT and must never
authorize Avuhz commands, tenant RLS, a business registration, or API actions.

Keep the historical command-service-only verifier unchanged; the separate
exact-type owner checkpoint is the only consumer permitted here. All claims
remain untrusted until signature, exact AUTH project issuer, and audience pass.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

import jwt
from jwt import PyJWKClient

from .development import DEVELOPMENT_AUTH_ISSUER
from .development_supabase_jwt import DEVELOPMENT_AUTH_JWKS_URL

_PRE_TENANT_AUDIENCE = "authenticated"
_ALLOWED_ALGORITHMS = ("ES256",)
_REQUIRED_CLAIMS = ("exp", "iat", "sub", "iss", "aud")


class DevelopmentPreTenantEs256JwtVerifier:
    """Exact-purpose, fail-closed JWT verifier for pre-registration owner MFA."""

    audience = _PRE_TENANT_AUDIENCE

    def __init__(self, jwk_client: object | None = None):
        client = (
            PyJWKClient(
                DEVELOPMENT_AUTH_JWKS_URL,
                cache_keys=True,
                max_cached_keys=8,
                cache_jwk_set=True,
                lifespan=300,
                timeout=5,
            )
            if jwk_client is None
            else jwk_client
        )
        if not callable(getattr(client, "get_signing_key_from_jwt", None)):
            raise ValueError("approved DEVELOPMENT AUTH JWK resolver required")
        self._jwk_client = client

    def verify(self, token: str) -> Mapping[str, object]:
        try:
            if type(token) is not str or not 32 <= len(token) <= 16384:
                raise PermissionError
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            key = getattr(signing_key, "key", None)
            if key is None:
                raise PermissionError
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(_ALLOWED_ALGORITHMS),
                audience=_PRE_TENANT_AUDIENCE,
                issuer=DEVELOPMENT_AUTH_ISSUER,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
            if type(claims) is not dict:
                raise PermissionError
        except Exception:
            raise PermissionError("pre-tenant DEVELOPMENT AUTH JWT verification failed") from None
        return MappingProxyType(dict(claims))
