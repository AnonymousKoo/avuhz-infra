"""Deterministic DEVELOPMENT AUTH synthetic-token lifecycle primitives.

This module is the forward-only replacement for the browser redirect handling in
the historical v29-v32 executors.  It is deliberately plan/version neutral: a
future, separately authorized executor may compose these primitives, but this
module does not create authority or contact a provider by itself.

Public contract evidence checked 2026-09-17:

* Supabase auth-js ``GenerateLinkProperties`` names the raw Admin generate-link
  field ``hashed_token`` and ``VerifyTokenHashParams`` submits it as
  ``token_hash`` with an email verification type.
* auth-js ``verifyOtp`` posts to ``/verify`` and applies ``_sessionResponse``.
* Supabase Auth ``VerifyParams`` accepts exactly ``type`` plus ``token_hash`` for
  that POST; ``verifyPost`` returns ``AccessTokenResponse`` as JSON.
* ``AccessTokenResponse`` has top-level access/refresh tokens, token type,
  expiry fields, and user.  auth-js recognizes a session from those top-level
  fields rather than from a redirect fragment.

Authoritative sources:
https://github.com/supabase/auth-js/blob/master/src/lib/types.ts
https://github.com/supabase/auth-js/blob/master/src/GoTrueClient.ts
https://github.com/supabase/auth-js/blob/master/src/lib/fetch.ts
https://github.com/supabase/auth/blob/master/internal/api/verify.go
https://github.com/supabase/auth/blob/master/internal/tokens/service.go

Credential-bearing values remain process-memory-only.  Exceptions expose only
fixed safe codes and sanitized state classifications; response bodies and
credentials are never included in messages or representations.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn

import jwt

from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
    DevelopmentSupabaseIdentityVerifier,
)
from avuhz_service.development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier


VERIFY_PATH = "/auth/v1/verify"
VERIFY_METHOD = "POST"
VERIFY_TYPE = "recovery"
LOCAL_LOGOUT_PATH = "/auth/v1/logout?scope=local"
GLOBAL_LOGOUT_PATH = "/auth/v1/logout?scope=global"
MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024

_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PROJECT_REF = re.compile(r"^[a-z]{20}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9_]{3,80}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class SessionState(str, Enum):
    """Sanitized state classifications; none imply more than readback proved."""

    NO_SESSION_OBSERVED = "NO_SESSION_OBSERVED"
    SESSION_PRESENT = "SESSION_PRESENT"
    SESSION_CLEANUP_VERIFIED = "SESSION_CLEANUP_VERIFIED"
    SESSION_STATE_UNVERIFIED = "SESSION_STATE_UNVERIFIED"
    SESSION_CLEANUP_UNAVAILABLE = "SESSION_CLEANUP_UNAVAILABLE"


class SafeLifecycleStop(RuntimeError):
    """Fail closed without retaining or rendering provider material."""

    def __init__(
        self,
        code: str,
        *,
        session_state: SessionState | None = None,
        cleanup_state: SessionState | None = None,
    ) -> None:
        safe_code = code if _SAFE_CODE.fullmatch(code) else "AUTH_TOKEN_LIFECYCLE_STOPPED"
        super().__init__(safe_code)
        self.code = safe_code
        self.session_state = session_state
        self.cleanup_state = cleanup_state

    def __repr__(self) -> str:
        return (
            "SafeLifecycleStop("
            f"code={self.code!r}, session_state={self.session_state!r}, "
            f"cleanup_state={self.cleanup_state!r})"
        )


def _stop(code: str) -> NoReturn:
    raise SafeLifecycleStop(code)


class RecoveryVerificationCredential:
    """One-time credential with a redacted representation and explicit clearing."""

    __slots__ = ("_user_id", "_value")

    def __init__(self, value: str, *, user_id: str | None = None) -> None:
        if not isinstance(value, str) or not 16 <= len(value) <= 4096:
            _stop("RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID")
        if user_id is not None and (
            not isinstance(user_id, str) or not _CANONICAL_UUID.fullmatch(user_id)
        ):
            _stop("RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID")
        self._value = bytearray(value, "utf-8")
        self._user_id = None if user_id is None else bytearray(user_id, "utf-8")

    def _text(self) -> str:
        if not self._value:
            _stop("RECOVERY_CREDENTIAL_UNAVAILABLE")
        return self._value.decode("utf-8")

    def _user_id_text(self) -> str:
        if not self._user_id:
            _stop("EXPECTED_SYNTHETIC_IDENTITY_INVALID")
        return self._user_id.decode("utf-8")

    @property
    def is_cleared(self) -> bool:
        return not self._value and not self._user_id

    def clear(self) -> None:
        for value in (self._value, self._user_id):
            if value is None:
                continue
            for index in range(len(value)):
                value[index] = 0
            value.clear()

    def __repr__(self) -> str:
        return "RecoveryVerificationCredential(<redacted>)"


class IssuedSession:
    """An in-memory session whose credential fields never appear in repr."""

    __slots__ = (
        "_access_token",
        "_refresh_token",
        "expires_at",
        "expires_in",
        "token_type",
        "user_id",
    )

    def __init__(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_in: int,
        expires_at: int,
        token_type: str,
        user_id: str,
    ) -> None:
        self._access_token = bytearray(access_token, "utf-8")
        self._refresh_token = bytearray(refresh_token, "utf-8")
        self.expires_in = expires_in
        self.expires_at = expires_at
        self.token_type = token_type
        self.user_id = user_id

    def _access_text(self) -> str:
        if not self._access_token:
            _stop("SESSION_ACCESS_TOKEN_UNAVAILABLE")
        return self._access_token.decode("utf-8")

    @property
    def has_access_token(self) -> bool:
        return bool(self._access_token)

    @property
    def has_refresh_token(self) -> bool:
        return bool(self._refresh_token)

    @property
    def is_cleared(self) -> bool:
        return not self._access_token and not self._refresh_token

    def clear(self) -> None:
        for value in (self._access_token, self._refresh_token):
            for index in range(len(value)):
                value[index] = 0
            value.clear()

    def __repr__(self) -> str:
        return (
            "IssuedSession(access_token=<redacted>, refresh_token=<redacted>, "
            f"expires_in={self.expires_in!r}, expires_at={self.expires_at!r}, "
            f"token_type={self.token_type!r}, user_id=<redacted>)"
        )


@dataclass(frozen=True)
class ProviderSessionCounts:
    session_count: int
    refresh_token_count: int

    @property
    def is_zero(self) -> bool:
        return self.session_count == 0 and self.refresh_token_count == 0

    @property
    def is_exactly_one(self) -> bool:
        return self.session_count == 1 and self.refresh_token_count == 1


@dataclass(frozen=True)
class JwtValidationResult:
    algorithm: str
    issuer: str
    audience: str
    subject_digest: str
    tenant_id: str
    role: str
    aal: str
    is_anonymous: bool
    caller_type: str
    capabilities: tuple[str, ...]
    authority_roles: tuple[str, ...]


@dataclass(frozen=True)
class LifecycleResult:
    session_count_after_issue: int
    refresh_token_count_after_issue: int
    session_count_after_cleanup: int
    refresh_token_count_after_cleanup: int
    session_state: SessionState
    cleanup_state: SessionState
    jwt_validated: bool


def _validate_project_ref(project_ref: str) -> None:
    if project_ref != DEVELOPMENT_AUTH_PROJECT_REF or not _PROJECT_REF.fullmatch(project_ref):
        _stop("DEVELOPMENT_AUTH_PROJECT_MISMATCH")


def _provider_headers(api_key: str, *, access_token: str | None = None) -> dict[str, str]:
    if not isinstance(api_key, str) or not api_key:
        _stop("PROVIDER_CREDENTIAL_UNAVAILABLE")
    bearer = api_key if access_token is None else access_token
    if not isinstance(bearer, str) or not bearer:
        _stop("PROVIDER_CREDENTIAL_UNAVAILABLE")
    # This matches the current Supabase client boundary: hosted requests carry
    # the project key in ``apikey`` and its unauthenticated bearer fallback;
    # local logout replaces the bearer value with the exact issued JWT.
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _post_json(
    url: str,
    *,
    headers: Mapping[str, str],
    body: Mapping[str, Any],
    provider_rejected_code: str,
    request_failed_code: str,
    response_invalid_code: str,
    accepted_statuses: tuple[int, ...] = (200,),
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any] | None:
    encoded = bytearray(
        json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
    )
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers=dict(headers),
    )
    raw = bytearray()
    try:
        try:
            with urlopen(request, timeout=30) as response:
                if response.status not in accepted_statuses:
                    _stop(provider_rejected_code)
                raw.extend(response.read(MAX_PROVIDER_RESPONSE_BYTES + 1))
        except SafeLifecycleStop:
            raise
        except urllib.error.HTTPError:
            # Never read the rejection body: it may echo credential material.
            _stop(provider_rejected_code)
        except Exception:
            _stop(request_failed_code)
        if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            _stop(response_invalid_code)
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except Exception:
            _stop(response_invalid_code)
        if not isinstance(payload, dict):
            _stop(response_invalid_code)
        return payload
    finally:
        for index in range(len(encoded)):
            encoded[index] = 0
        encoded.clear()
        for index in range(len(raw)):
            raw[index] = 0
        raw.clear()


def request_generate_recovery_credential(
    *,
    project_ref: str,
    admin_secret: str,
    existing_user_email: str,
    expected_user_id: str | None,
    expected_subject_digest: str,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> RecoveryVerificationCredential:
    """Generate a recovery credential only; this API does not create a user or send mail."""

    _validate_project_ref(project_ref)
    if not isinstance(existing_user_email, str) or not existing_user_email:
        _stop("EXISTING_USER_REFERENCE_INVALID")
    payload = _post_json(
        f"https://{project_ref}.supabase.co/auth/v1/admin/generate_link",
        headers=_provider_headers(admin_secret),
        body={"type": VERIFY_TYPE, "email": existing_user_email},
        provider_rejected_code="RECOVERY_GENERATE_PROVIDER_REJECTED",
        request_failed_code="RECOVERY_GENERATE_REQUEST_FAILED",
        response_invalid_code="RECOVERY_GENERATE_RESPONSE_INVALID",
        urlopen=urlopen,
    )
    if payload is None:
        _stop("RECOVERY_GENERATE_RESPONSE_INVALID")
    try:
        return extract_recovery_verification_credential(
            payload,
            expected_user_id=expected_user_id,
            expected_subject_digest=expected_subject_digest,
        )
    finally:
        for field in ("action_link", "email_otp", "hashed_token"):
            if field in payload:
                payload[field] = None


def extract_recovery_verification_credential(
    payload: Mapping[str, Any],
    *,
    expected_user_id: str | None,
    expected_subject_digest: str,
) -> RecoveryVerificationCredential:
    """Extract only raw ``hashed_token`` for POST ``token_hash`` verification."""

    if not isinstance(payload, Mapping):
        _stop("RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID")
    if expected_user_id is not None and (
        not isinstance(expected_user_id, str)
        or not _CANONICAL_UUID.fullmatch(expected_user_id)
    ):
        _stop("EXPECTED_SYNTHETIC_IDENTITY_INVALID")
    if (
        not isinstance(expected_subject_digest, str)
        or not _SHA256.fullmatch(expected_subject_digest)
    ):
        _stop("EXPECTED_SYNTHETIC_IDENTITY_INVALID")
    generated_id = payload.get("id")
    credential = payload.get("hashed_token")
    if (
        payload.get("verification_type") != VERIFY_TYPE
        or not isinstance(generated_id, str)
        or not _CANONICAL_UUID.fullmatch(generated_id)
        or not isinstance(credential, str)
    ):
        _stop("RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID")
    digest = "sha256:" + hashlib.sha256(generated_id.encode("utf-8")).hexdigest()
    if (
        (expected_user_id is not None and generated_id != expected_user_id)
        or not hmac.compare_digest(digest, expected_subject_digest)
    ):
        _stop("RECOVERY_GENERATE_IDENTITY_MISMATCH")
    result = RecoveryVerificationCredential(credential, user_id=generated_id)
    if isinstance(payload, dict):
        for field in ("action_link", "email_otp", "hashed_token"):
            if field in payload:
                payload[field] = None
    return result


def request_direct_recovery_verification(
    *,
    project_ref: str,
    publishable_key: str,
    credential: RecoveryVerificationCredential,
    expected_user_id: str | None,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> IssuedSession:
    """POST recovery verification and return only a redacted in-memory session."""

    _validate_project_ref(project_ref)
    if not isinstance(credential, RecoveryVerificationCredential):
        _stop("RECOVERY_CREDENTIAL_UNAVAILABLE")
    payload = _post_json(
        f"https://{project_ref}.supabase.co{VERIFY_PATH}",
        headers=_provider_headers(publishable_key),
        body={"type": VERIFY_TYPE, "token_hash": credential._text()},
        provider_rejected_code="RECOVERY_VERIFICATION_PROVIDER_REJECTED",
        request_failed_code="RECOVERY_VERIFICATION_REQUEST_FAILED",
        response_invalid_code="RECOVERY_VERIFICATION_RESPONSE_INVALID",
        urlopen=urlopen,
    )
    if payload is None:
        _stop("RECOVERY_VERIFICATION_RESPONSE_INVALID")
    try:
        bound_user_id = (
            credential._user_id_text()
            if expected_user_id is None
            else expected_user_id
        )
        return parse_recovery_verification_response(
            payload,
            expected_user_id=bound_user_id,
        )
    finally:
        payload["access_token"] = None
        payload["refresh_token"] = None


def parse_recovery_verification_response(
    payload: Mapping[str, Any],
    *,
    expected_user_id: str,
) -> IssuedSession:
    """Parse the current raw Auth ``AccessTokenResponse`` top-level shape."""

    if not isinstance(payload, Mapping):
        _stop("RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID")
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    token_type = payload.get("token_type")
    expires_in = payload.get("expires_in")
    expires_at = payload.get("expires_at")
    user = payload.get("user")
    user_id = user.get("id") if isinstance(user, Mapping) else None
    if (
        not isinstance(access_token, str)
        or not 32 <= len(access_token) <= 16384
        or not isinstance(refresh_token, str)
        or not 16 <= len(refresh_token) <= 4096
        or token_type != "bearer"
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
        or not 1 <= expires_in <= 3600
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= 0
        or not isinstance(user_id, str)
        or not _CANONICAL_UUID.fullmatch(user_id)
        or user_id != expected_user_id
    ):
        _stop("RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID")
    result = IssuedSession(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        expires_at=expires_at,
        token_type=token_type,
        user_id=user_id,
    )
    if isinstance(payload, dict):
        payload["access_token"] = None
        payload["refresh_token"] = None
    return result


def request_local_session_logout(
    *,
    project_ref: str,
    publishable_key: str,
    access_token: str,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> None:
    """Revoke only the session named by the issued access JWT."""

    _validate_project_ref(project_ref)
    response = _post_json(
        f"https://{project_ref}.supabase.co{LOCAL_LOGOUT_PATH}",
        headers=_provider_headers(publishable_key, access_token=access_token),
        body={},
        provider_rejected_code="LOCAL_SESSION_LOGOUT_PROVIDER_REJECTED",
        request_failed_code="LOCAL_SESSION_LOGOUT_REQUEST_FAILED",
        response_invalid_code="LOCAL_SESSION_LOGOUT_RESPONSE_INVALID",
        accepted_statuses=(200, 204),
        urlopen=urlopen,
    )
    if response not in (None, {}):
        _stop("LOCAL_SESSION_LOGOUT_RESPONSE_INVALID")


def request_global_session_logout(
    *,
    project_ref: str,
    publishable_key: str,
    bearer_token: str,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> None:
    """Revoke every session for the exact user authenticated by the JWT.

    Supabase Auth documents ``global`` as revoking all refresh tokens/sessions
    for the bearer user.  Acceptance is not cleanup verification; callers must
    require an independent provider readback before claiming a clean state.
    """

    _validate_project_ref(project_ref)
    response = _post_json(
        f"https://{project_ref}.supabase.co{GLOBAL_LOGOUT_PATH}",
        headers=_provider_headers(publishable_key, access_token=bearer_token),
        body={},
        provider_rejected_code="GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
        request_failed_code="GLOBAL_SESSION_LOGOUT_REQUEST_FAILED",
        response_invalid_code="GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
        accepted_statuses=(204,),
        urlopen=urlopen,
    )
    if response is not None:
        _stop("GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID")


def parse_provider_session_counts(
    value: Mapping[str, Any] | ProviderSessionCounts,
) -> ProviderSessionCounts:
    if isinstance(value, ProviderSessionCounts):
        return value
    if not isinstance(value, Mapping):
        _stop("SESSION_STATE_RESPONSE_INVALID")

    def count(name: str) -> int:
        raw = value.get(name)
        if isinstance(raw, bool):
            _stop("SESSION_STATE_RESPONSE_INVALID")
        if isinstance(raw, int):
            result = raw
        elif isinstance(raw, str) and raw.isdigit():
            result = int(raw)
        else:
            _stop("SESSION_STATE_RESPONSE_INVALID")
        if result < 0:
            _stop("SESSION_STATE_RESPONSE_INVALID")
        return result

    return ProviderSessionCounts(
        session_count=count("session_count"),
        refresh_token_count=count("refresh_token_count"),
    )


class _VerifiedClaimsAdapter:
    def __init__(self, claims: Mapping[str, object]) -> None:
        self._claims = claims

    def verify(self, _token: str) -> Mapping[str, object]:
        return self._claims


def validate_development_synthetic_access_jwt(
    access_token: str,
    *,
    verifier: Any | None = None,
) -> JwtValidationResult:
    """Apply the exact DEVELOPMENT cryptographic and allowlist policy boundary."""

    try:
        header = jwt.get_unverified_header(access_token)
        if not isinstance(header, dict) or header.get("alg") != "ES256":
            raise PermissionError
        cryptographic_verifier = (
            DevelopmentSupabaseEs256JwtVerifier()
            if verifier is None
            else verifier
        )
        claims = cryptographic_verifier.verify(access_token)
        identity = DevelopmentSupabaseIdentityVerifier(
            _VerifiedClaimsAdapter(claims),
            allowlist=DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
        ).verify(access_token)
        provider_subject = claims.get("sub")
        session_id = claims.get("session_id")
        if not isinstance(provider_subject, str) or not _CANONICAL_UUID.fullmatch(provider_subject):
            raise PermissionError
        if not isinstance(session_id, str):
            raise PermissionError
        uuid.UUID(session_id)
        if identity.caller_type != "HUMAN":
            raise PermissionError
        if identity.capabilities != frozenset({"engagement:read"}):
            raise PermissionError
        if identity.authority_roles != frozenset():
            raise PermissionError
        entry = DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0]
        digest = "sha256:" + hashlib.sha256(provider_subject.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, entry.subject_digest):
            raise PermissionError
        if claims.get("iss") != DEVELOPMENT_AUTH_ISSUER:
            raise PermissionError
        if claims.get("aud") != DEVELOPMENT_SERVICE_AUDIENCE:
            raise PermissionError
        if claims.get("avuhz_tenant_id") != entry.tenant_id:
            raise PermissionError
        if claims.get("role") != "authenticated" or claims.get("aal") != "aal1":
            raise PermissionError
        if claims.get("is_anonymous") is not False:
            raise PermissionError
    except Exception:
        _stop("ACCESS_JWT_VALIDATION_FAILED")

    return JwtValidationResult(
        algorithm="ES256",
        issuer=DEVELOPMENT_AUTH_ISSUER,
        audience=DEVELOPMENT_SERVICE_AUDIENCE,
        subject_digest=entry.subject_digest,
        tenant_id=entry.tenant_id,
        role="authenticated",
        aal="aal1",
        is_anonymous=False,
        caller_type=identity.caller_type,
        capabilities=tuple(sorted(identity.capabilities)),
        authority_roles=tuple(sorted(identity.authority_roles)),
    )


def _read_counts(
    read_session_state: Callable[[], Mapping[str, Any] | ProviderSessionCounts],
) -> ProviderSessionCounts | None:
    try:
        return parse_provider_session_counts(read_session_state())
    except Exception:
        return None


def _raise_after_possible_session(
    code: str,
    *,
    session: IssuedSession | None,
    read_session_state: Callable[[], Mapping[str, Any] | ProviderSessionCounts],
    logout_local: Callable[[str], None],
    observed: ProviderSessionCounts | None = None,
    logout_already_attempted: bool = False,
) -> NoReturn:
    """Reconcile after a possibly session-creating operation, then fail closed."""

    state = observed if observed is not None else _read_counts(read_session_state)
    if state is None:
        if session is not None and not logout_already_attempted:
            try:
                logout_local(session._access_text())
                logout_already_attempted = True
            except Exception:
                pass
            state = _read_counts(read_session_state)
        if state is None:
            raise SafeLifecycleStop(
                code,
                session_state=SessionState.SESSION_STATE_UNVERIFIED,
                cleanup_state=SessionState.SESSION_STATE_UNVERIFIED,
            )

    if state.is_zero:
        classification = (
            SessionState.SESSION_CLEANUP_VERIFIED
            if logout_already_attempted
            else SessionState.NO_SESSION_OBSERVED
        )
        raise SafeLifecycleStop(
            code,
            session_state=classification,
            cleanup_state=classification,
        )

    if session is None:
        raise SafeLifecycleStop(
            code,
            session_state=SessionState.SESSION_PRESENT,
            cleanup_state=SessionState.SESSION_CLEANUP_UNAVAILABLE,
        )

    if not logout_already_attempted:
        try:
            logout_local(session._access_text())
            logout_already_attempted = True
        except Exception:
            pass
    final_state = _read_counts(read_session_state)
    if final_state is None:
        raise SafeLifecycleStop(
            code,
            session_state=SessionState.SESSION_STATE_UNVERIFIED,
            cleanup_state=SessionState.SESSION_STATE_UNVERIFIED,
        )
    if final_state.is_zero:
        raise SafeLifecycleStop(
            code,
            session_state=SessionState.SESSION_CLEANUP_VERIFIED,
            cleanup_state=SessionState.SESSION_CLEANUP_VERIFIED,
        )
    raise SafeLifecycleStop(
        code,
        session_state=SessionState.SESSION_PRESENT,
        cleanup_state=SessionState.SESSION_PRESENT,
    )


def run_recovery_session_lifecycle(
    *,
    generate_recovery: Callable[[str, str], RecoveryVerificationCredential],
    verify_recovery: Callable[[RecoveryVerificationCredential, str], IssuedSession],
    read_session_state: Callable[[], Mapping[str, Any] | ProviderSessionCounts],
    logout_local: Callable[[str], None],
    validate_access_jwt: Callable[[str], Any],
    expected_user_id: str,
    expected_subject_digest: str,
) -> LifecycleResult:
    """Issue, prove, revoke, prove 0/0, validate, and discard one session.

    Verification is attempted once.  Every failure after that attempt invokes
    independent readback, even if response parsing never captured an access JWT.
    No session issuance retry or broad/admin session deletion exists here.
    """

    credential: RecoveryVerificationCredential | None = None
    session: IssuedSession | None = None
    try:
        try:
            credential = generate_recovery(
                expected_user_id,
                expected_subject_digest,
            )
            if not isinstance(credential, RecoveryVerificationCredential):
                _stop("RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID")
        except SafeLifecycleStop:
            raise
        except Exception:
            _stop("RECOVERY_GENERATE_REQUEST_FAILED")

        try:
            session = verify_recovery(credential, expected_user_id)
            if not isinstance(session, IssuedSession):
                _stop("RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID")
        except SafeLifecycleStop as exc:
            _raise_after_possible_session(
                exc.code,
                session=None,
                read_session_state=read_session_state,
                logout_local=logout_local,
            )
        except Exception:
            _raise_after_possible_session(
                "RECOVERY_VERIFICATION_REQUEST_FAILED",
                session=None,
                read_session_state=read_session_state,
                logout_local=logout_local,
            )

        issued = _read_counts(read_session_state)
        if issued is None:
            _raise_after_possible_session(
                "SESSION_STATE_READBACK_FAILED",
                session=session,
                read_session_state=read_session_state,
                logout_local=logout_local,
            )
        if not issued.is_exactly_one:
            _raise_after_possible_session(
                "SESSION_ISSUANCE_COUNT_MISMATCH",
                session=session,
                read_session_state=read_session_state,
                logout_local=logout_local,
                observed=issued,
            )

        try:
            logout_local(session._access_text())
        except Exception:
            _raise_after_possible_session(
                "LOCAL_SESSION_LOGOUT_FAILED",
                session=session,
                read_session_state=read_session_state,
                logout_local=logout_local,
                logout_already_attempted=True,
            )

        cleaned = _read_counts(read_session_state)
        if cleaned is None:
            raise SafeLifecycleStop(
                "SESSION_STATE_READBACK_FAILED",
                session_state=SessionState.SESSION_STATE_UNVERIFIED,
                cleanup_state=SessionState.SESSION_STATE_UNVERIFIED,
            )
        if not cleaned.is_zero:
            raise SafeLifecycleStop(
                "SESSION_CLEANUP_NOT_VERIFIED",
                session_state=SessionState.SESSION_PRESENT,
                cleanup_state=SessionState.SESSION_PRESENT,
            )

        try:
            validate_access_jwt(session._access_text())
        except SafeLifecycleStop as exc:
            raise SafeLifecycleStop(
                exc.code,
                session_state=SessionState.SESSION_CLEANUP_VERIFIED,
                cleanup_state=SessionState.SESSION_CLEANUP_VERIFIED,
            ) from None
        except Exception:
            raise SafeLifecycleStop(
                "ACCESS_JWT_VALIDATION_FAILED",
                session_state=SessionState.SESSION_CLEANUP_VERIFIED,
                cleanup_state=SessionState.SESSION_CLEANUP_VERIFIED,
            ) from None

        return LifecycleResult(
            session_count_after_issue=issued.session_count,
            refresh_token_count_after_issue=issued.refresh_token_count,
            session_count_after_cleanup=cleaned.session_count,
            refresh_token_count_after_cleanup=cleaned.refresh_token_count,
            session_state=SessionState.SESSION_CLEANUP_VERIFIED,
            cleanup_state=SessionState.SESSION_CLEANUP_VERIFIED,
            jwt_validated=True,
        )
    finally:
        if credential is not None:
            credential.clear()
        if session is not None:
            session.clear()
