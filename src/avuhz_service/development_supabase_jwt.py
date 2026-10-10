"""Concrete DEVELOPMENT Supabase JWT cryptographic verification adapter."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

import jwt
from jwt import PyJWKClient

from .development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE


DEVELOPMENT_AUTH_JWKS_URL = f"{DEVELOPMENT_AUTH_ISSUER}/.well-known/jwks.json"
_ALLOWED_ALGORITHMS = ("ES256",)
# The deployed custom access-token hook only rewrites aud after tenant
# assignment. The unbound first-owner flow must accept the native Supabase
# audience, while normal Avuhz command/query verification keeps its existing
# command-service-only default.
_PRE_TENANT_AUTH_AUDIENCE = "authenticated"
_ALLOWED_EXACT_AUDIENCES = (DEVELOPMENT_SERVICE_AUDIENCE, _PRE_TENANT_AUTH_AUDIENCE)
_REQUIRED_CLAIMS = ("exp", "iat", "sub", "iss", "aud")


class DevelopmentSupabaseEs256JwtVerifier:
    """Verify one Supabase access token with the approved DEVELOPMENT JWKS boundary."""

    def __init__(
        self, jwk_client: object | None = None,
        *, audience: str = DEVELOPMENT_SERVICE_AUDIENCE,
    ):
        if type(audience) is not str or audience not in _ALLOWED_EXACT_AUDIENCES:
            raise ValueError("approved DEVELOPMENT JWT audience is required")
        self._audience = audience
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
            raise ValueError("valid JWKS client is required")
        self._jwk_client = client

    @property
    def audience(self) -> str:
        return self._audience

    def verify(self, token: str) -> Mapping[str, object]:
        try:
            if not isinstance(token, str) or not 32 <= len(token) <= 16384:
                raise PermissionError

            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            key = getattr(signing_key, "key", None)
            if key is None:
                raise PermissionError

            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(_ALLOWED_ALGORITHMS),
                audience=self._audience,
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
            raise PermissionError("development Supabase JWT verification failed") from None

        return MappingProxyType(dict(claims))
