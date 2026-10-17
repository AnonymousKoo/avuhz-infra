"""LOCAL/TEST-only Cal.com raw webhook signature gate for shared Avuhz ingress.

Does NOT expose an HTTP listener, create/authorize a lead, map a tenant, create
a Work Item, de-duplicate replay, schedule notifications, or touch n8n.
The caller must pass the exact, unmodified raw HTTP request-body bytes and a
secret resolved inside its separately authorized server-side credential boundary.
A valid signature establishes only payload integrity under that secret; it
is NOT evidence of freshness, unique delivery, consent, booking status, owner
identity, organization membership or authorized tenant binding.
"""
from __future__ import annotations

import hashlib
import hmac
import re

_HEADER_HEX = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MAX_RAW_BYTES = 65_536
_DENIAL = "calcom_signature_unverified"


class CalcomSignatureDenied(PermissionError):
    """Generic, deliberately non-revealing signature denial."""


def verify_calcom_signature(
    raw_body: object,
    signature_header: object,
    *,
    secret: object,
) -> None:
    """Validate only Cal.com's SHA-256 HMAC over original unmodified body.

    An accepted signature header may be 64 lowercase hex characters or that
    exact value prefixed by 'sha256='. No header folding, repeated headers,
    body re-serialization, upper hex, alternate hash or digest algorithm.
    Never return the raw body, secret, or signature to a caller.
    """
    if (
        type(raw_body) is not bytes
        or not (1 <= len(raw_body) <= _MAX_RAW_BYTES)
        or type(secret) is not bytes
        or not (32 <= len(secret) <= 4096)
        or type(signature_header) is not str
    ):
        raise CalcomSignatureDenied(_DENIAL)
    given = signature_header.removeprefix("sha256=")
    if not _HEADER_HEX.fullmatch(given):
        raise CalcomSignatureDenied(_DENIAL)

    received = bytes.fromhex(given)
    expected = hmac.new(secret, raw_body, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received):
        raise CalcomSignatureDenied(_DENIAL)
    # Successful verification carries no authority or replay decision.
    return None
