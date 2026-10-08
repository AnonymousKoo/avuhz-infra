"""Injection-only, one-attempt DEVELOPMENT synthetic handoff dispatch core.

Repository-only capability: this module has no default HTTP opener, network
access, Supabase credential lookup, login, session creation or cleanup. It is not
an authorization executor. A future separately approved owner-bound executor
must provide a trusted authorization callback and an approved transport.
Never reuse the retired v15 credential or treat this module as live permission.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Mapping

from avuhz_engineering.development_synthetic_handoff_preflight import (
    CertifiedSyntheticCommand,
    SyntheticCommandPreflightStop,
    certify_accepted_response,
    certify_synthetic_command,
)

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class OneShotHandoffDispatchOutcome:
    """Safe terminal record; never includes access tokens or HTTP bodies."""

    classification: str
    command_digest: str
    handoff_id: str
    send_attempted: bool
    data_readback_required: bool
    session_cleanup_readback_required: bool
    credential_retirement_required: bool
    retry_authorized: bool
    safe_error_code: str | None = None
    token_material_retained: bool = False
    pii_retained: bool = False


def _check(condition: bool, code: str) -> None:
    if not condition:
        raise SyntheticCommandPreflightStop(code)


def dispatch_one_synthetic_handoff(
    request: Mapping[str, object],
    *,
    at_utc: datetime,
    approved_command_digest: str,
    authorization_check: Callable[[CertifiedSyntheticCommand], bool],
    access_token: str,
    send_once: Callable[[dict, str], tuple[int, bytes]],
) -> OneShotHandoffDispatchOutcome:
    """Call an injected sender at most once, only after strict local checks.

    authorization_check must be supplied by a separately reviewed and
    authenticated exact-plan executor. A truthy callback supplied by a caller
    is NOT intrinsically owner authorization; this module cannot verify owner
    identity, provider state, or an approval record by itself.

    No resend is ever attempted. Once send_once is called, transport errors and
    any unexpected response are classified as outcome-UNVERIFIED and require
    independent tenant-scoped DATA readback before any further action. A 202
    response remains pending DATA readback and independent session cleanup.
    """
    candidate = certify_synthetic_command(request, at_utc=at_utc)
    _check(
        type(approved_command_digest) is str
        and _SHA256.fullmatch(approved_command_digest) is not None
        and candidate.command_digest == approved_command_digest,
        "SYNTHETIC_SOURCE_BINDING_MISMATCH",
    )
    _check(callable(authorization_check), "SYNTHETIC_EXECUTOR_AUTHORIZATION_MISSING")
    try:
        authorized = authorization_check(candidate)
    except Exception:
        raise SyntheticCommandPreflightStop("SYNTHETIC_EXECUTOR_AUTHORIZATION_UNVERIFIED") from None
    _check(authorized is True, "SYNTHETIC_EXECUTOR_AUTHORIZATION_UNVERIFIED")
    _check(
        type(access_token) is str
        and 32 <= len(access_token) <= 16384
        and not any(character.isspace() for character in access_token),
        "SYNTHETIC_SESSION_UNAVAILABLE",
    )
    _check(callable(send_once), "SYNTHETIC_TRANSPORT_UNAVAILABLE")

    # No retry: at this point even an exception might follow a committed write.
    try:
        status, body = send_once(copy.deepcopy(dict(request)), access_token)
    except Exception:
        return OneShotHandoffDispatchOutcome(
            classification="SYNTHETIC_COMMAND_OUTCOME_UNVERIFIED",
            command_digest=candidate.command_digest,
            handoff_id=candidate.handoff_id,
            send_attempted=True,
            data_readback_required=True,
            session_cleanup_readback_required=True,
            credential_retirement_required=True,
            retry_authorized=False,
            safe_error_code="SYNTHETIC_TRANSPORT_UNVERIFIED",
        )
    try:
        classification = certify_accepted_response(
            http_status=status, response_bytes=body, candidate=candidate
        )
        return OneShotHandoffDispatchOutcome(
            classification=classification,
            command_digest=candidate.command_digest,
            handoff_id=candidate.handoff_id,
            send_attempted=True,
            data_readback_required=True,
            session_cleanup_readback_required=True,
            credential_retirement_required=True,
            retry_authorized=False,
        )
    except SyntheticCommandPreflightStop as error:
        return OneShotHandoffDispatchOutcome(
            classification="SYNTHETIC_COMMAND_OUTCOME_UNVERIFIED",
            command_digest=candidate.command_digest,
            handoff_id=candidate.handoff_id,
            send_attempted=True,
            data_readback_required=True,
            session_cleanup_readback_required=True,
            credential_retirement_required=True,
            retry_authorized=False,
            safe_error_code=str(error),
        )
