"""Dormant DEVELOPMENT AUTH MFA freshness boundary for Avuhz owner onboarding.

Uses the existing project-pinned ES256 Supabase JWT verifier. A signed aal2
token and a recently issued JWT alone do NOT prove a fresh second factor.
Require a signed recent TOTP `amr` event tied to the token subject/session
AND an independent, authenticated, live AUTH session read. Supabase JWTs may
remain cryptographically valid after session revocation.

The live-session dependency is intentionally unimplemented here; its caller
must be an approved AUTH-owned verifier for exactly the DEVELOPMENT AUTH
project. A synthetic always-True test callback is NOT provider evidence.
No registration route or grant is connected. No browser-authored claim is
accepted as ownership or tenant authority.

This callable matches PR #611's check_fresh_auth_mfa(bearer, subject_digest)
injection point but does not verify business ownership or authorize writes.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
import uuid
from typing import Callable, Mapping

from .development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier
from .development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_MAX_MFA_AGE = 300
_MAX_TOKEN_AGE = 900


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


class DevelopmentOwnerMfaFreshnessCheck:
    """Fail-closed, PII-free signed-factor check with an AUTH session proof port.

    confirm_live_session(auth_subject, session_id) MUST fetch independently
    authoritative *current* DEVELOPMENT AUTH session state and return exactly
    True only when that session is active and belongs to that subject. It
    must never trust user JSON or reuse a decoded JWT as its session proof.
    """

    def __init__(
        self,
        verifier: DevelopmentSupabaseEs256JwtVerifier,
        *,
        confirm_live_session: Callable[[str, str], bool],
    ):
        if type(verifier) is not DevelopmentSupabaseEs256JwtVerifier:
            raise ValueError("approved DEVELOPMENT AUTH JWT verifier required")
        if not callable(confirm_live_session):
            raise ValueError("independent AUTH session verifier required")
        self._verifier = verifier
        self._confirm_live_session = confirm_live_session

    def __call__(self, bearer: object, subject_digest: object) -> bool:
        try:
            if not isinstance(bearer, str) or not isinstance(subject_digest, str):
                return False
            if not _DIGEST.fullmatch(subject_digest):
                return False

            # Cryptographic verification precedes any interpretation of
            # authentication-method claims. No unverified jwt.decode().
            claims = self._verifier.verify(bearer)
            if not isinstance(claims, Mapping):
                return False
            if (
                claims.get("iss") != DEVELOPMENT_AUTH_ISSUER
                or claims.get("aud") != DEVELOPMENT_SERVICE_AUDIENCE
                or claims.get("role") != "authenticated"
                or claims.get("is_anonymous") is not False
                or claims.get("aal") != "aal2"
                or "avuhz_tenant_id" in claims
            ):
                return False

            subject = claims.get("sub")
            session_id = claims.get("session_id")
            if not _canonical_uuid(subject) or not _canonical_uuid(session_id):
                return False
            expected = "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()
            if not hmac.compare_digest(expected, subject_digest):
                return False

            now = int(time.time())
            iat = claims.get("iat")
            exp = claims.get("exp")
            if (
                type(iat) is not int or type(exp) is not int
                or iat > now or now - iat > _MAX_TOKEN_AGE
                or exp <= now or exp - iat > 3600
            ):
                return False

            amr = claims.get("amr")
            if type(amr) is not list or not amr:
                return False
            # "otp" can be a first-factor login; only a documented TOTP
            # second-factor event is accepted as MFA freshness evidence.
            recent_totp = any(
                type(method) is dict
                and method.get("method") == "totp"
                and type(method.get("timestamp")) is int
                and 0 <= now - method["timestamp"] <= _MAX_MFA_AGE
                and method["timestamp"] <= iat
                for method in amr
            )
            if not recent_totp:
                return False

            # An active signed token is not proof of an active Supabase session.
            # Fail closed if the independently authenticated provider check
            # fails, is missing, or raises an exception.
            return self._confirm_live_session(subject, session_id) is True
        except Exception:
            # Never emit claims, subject, bearer, session IDs or provider errors.
            return False
