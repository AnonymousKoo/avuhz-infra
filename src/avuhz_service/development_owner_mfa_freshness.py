"""Dormant DEVELOPMENT AUTH MFA freshness boundary for Avuhz owner onboarding.

Uses the existing project-pinned ES256 Supabase JWT verifier. A signed aal2
token and a recently issued JWT alone do NOT prove a fresh second factor.
Require a signed recent TOTP `amr` event tied to the token subject/session
AND an independent, authenticated, live AUTH user/session check. Supabase JWTs may
remain cryptographically valid after session revocation.

The new HTTPS live-session checker remains disconnected from hosted
composition. Its publishable key must be injected by an approved server-only
configuration (never committed), and no owner data can be submitted until the
other independent business ownership and DATA writer boundaries are approved.
No registration route or grant is connected. No browser-authored claim is
accepted as ownership or tenant authority.

This callable matches PR #611's check_fresh_auth_mfa(bearer, subject_digest)
injection point but does not verify business ownership or authorize writes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Callable, Mapping
from urllib import request as url_request

from .development_pretenant_supabase_jwt import DevelopmentPreTenantEs256JwtVerifier
from .development import DEVELOPMENT_AUTH_ISSUER

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_MAX_MFA_AGE = 300
_MAX_TOKEN_AGE = 900
# The AUTH hook preserves this audience until a tenant is registered.
_PRE_TENANT_AUTH_AUDIENCE = "authenticated"


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


class DevelopmentOwnerMfaFreshnessCheck:
    """Fail-closed, PII-free signed-factor check with an AUTH session proof port.

    confirm_live_session(auth_subject, session_id, bearer) MUST perform a
    separate request to the exact DEVELOPMENT AUTH server and return True
    only for a current, authenticated user matching the signed JWT subject.
    The session ID is verified in the signed JWT, and the injected check
    MUST independently establish that the exact subject/session record remains
    active in DEVELOPMENT AUTH. A /auth/v1/user lookup alone CANNOT satisfy
    that requirement, even if it returns the expected user ID.
    """

    def __init__(
        self,
        verifier: DevelopmentPreTenantEs256JwtVerifier,
        *,
        confirm_live_session: Callable[[str, str, str], bool],
    ):
        if (
            type(verifier) is not DevelopmentPreTenantEs256JwtVerifier
            or verifier.audience != _PRE_TENANT_AUTH_AUDIENCE
        ):
            raise ValueError("approved pre-tenant DEVELOPMENT AUTH JWT verifier required")
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
                or claims.get("aud") != _PRE_TENANT_AUTH_AUDIENCE
                or claims.get("role") != "authenticated"
                or claims.get("is_anonymous") is not False
                or claims.get("aal") != "aal2"
                or "avuhz_tenant_id" in claims
            ):
                return False
            app_metadata = claims.get("app_metadata")
            if isinstance(app_metadata, Mapping) and "avuhz_tenant_id" in app_metadata:
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
            return self._confirm_live_session(subject, session_id, bearer) is True
        except Exception:
            # Never emit claims, subject, bearer, session IDs or provider errors.
            return False



_AUTH_USER_URL = "https://pwlhruwutoitnieactol.supabase.co/auth/v1/user"
_MAX_AUTH_RESPONSE_BYTES = 8192


class _NoBearerRedirects(url_request.HTTPRedirectHandler):
    """Never forward the access token or publishable key to a redirect URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DevelopmentAuthUserSessionCheck:
    """Server-side, read-only, exact-project Supabase Auth /user probe.

    This is not user enrollment, a privileged Auth-admin API, or a substitute
    for JWT TOTP verification. The token is cryptographically checked by
    DevelopmentOwnerMfaFreshnessCheck before this class is invoked.

    Supabase's Auth `getUser` request independently checks the signed bearer
    and user ID, but DOES NOT prove that the token's session_id remains active.
    To avoid accepting a signed JWT after logout/session revocation, this
    checker ALWAYS denies if confirm_session_record is absent. A configured
    callback must query authoritative, current DEVELOPMENT AUTH session state
    by *both* verified subject and signed session UUID. A synthetic callback,
    a copied token, or a /user response cannot authorize hosted onboarding.

    The callback must be a separately approved, server-only, read-only
    AUTH session-record source with revocation support. Never use client data,
    a DATA-project session, service_role in public code, or synthetic callbacks
    in hosted composition. This checker is still dormant and issues no session
    credential or tenant/registration authority.
    """

    def __init__(
        self,
        publishable_key: str,
        *,
        confirm_session_record: Callable[[str, str], bool] | None = None,
    ):
        if (
            not isinstance(publishable_key, str)
            or not publishable_key.startswith("sb_publishable_")
            or not 25 <= len(publishable_key) <= 512
            or not re.fullmatch(r"[a-zA-Z0-9_]+", publishable_key)
        ):
            raise ValueError("DEVELOPMENT AUTH publishable key required")
        if confirm_session_record is not None and not callable(confirm_session_record):
            raise ValueError("independent DEVELOPMENT AUTH session record checker required")
        self._publishable_key = publishable_key
        # Missing authoritative session proof is deliberately NOT accepted.
        # Do not silently replace this with a /user lookup or a JWT claim.
        self._confirm_session_record = confirm_session_record
        # Ignore process-controlled HTTP proxies, and disallow HTTPS redirects.
        # No request is issued until the callable is invoked by the MFA gate.
        self._opener = url_request.build_opener(
            url_request.ProxyHandler({}), _NoBearerRedirects()
        )

    def __call__(self, subject: object, session_id: object, bearer: object) -> bool:
        try:
            if (
                not _canonical_uuid(subject)
                or not _canonical_uuid(session_id)
                or not isinstance(bearer, str)
                or not 32 <= len(bearer) <= 16384
                # Compact Supabase JWTs contain three base64url segments.
                # Backslashes, whitespace, quoting and control characters
                # must be rejected locally before any provider contact.
                or re.fullmatch(
                    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                    bearer,
                    flags=re.ASCII,
                ) is None
            ):
                return False
            req = url_request.Request(
                _AUTH_USER_URL,
                headers={
                    "apikey": self._publishable_key,
                    "Authorization": "Bearer " + bearer,
                    "Accept": "application/json",
                    "Cache-Control": "no-store",
                },
                method="GET",
            )
            with self._opener.open(req, timeout=5) as response:
                if response.status != 200 or response.geturl() != _AUTH_USER_URL:
                    return False
                body = response.read(_MAX_AUTH_RESPONSE_BYTES + 1)
                if len(body) > _MAX_AUTH_RESPONSE_BYTES:
                    return False
            user = json.loads(body.decode("utf-8"))
            if type(user) is not dict or user.get("id") != subject:
                return False
            # getUser can succeed without validating this JWT's signed
            # session_id against a current non-revoked AUTH session record.
            # The protected, authoritative record proof is a separate gate.
            if self._confirm_session_record is None:
                return False
            return self._confirm_session_record(subject, session_id) is True
        except Exception:
            # No network diagnostics, provider payload or bearer leaks.
            return False
