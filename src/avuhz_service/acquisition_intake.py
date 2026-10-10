"""Shared, side-effect-free validation for an *unqualified* website prospect intake.

The authoritative persistence shape is the installed DEVELOPMENT DATA table
public.avuhz_acquisition_intake_requests. This module validates only customer
data fields against that table. It does not authenticate the website, grant
tenant or business ownership, authorize an engagement, connect an HTTP route,
perform SQL, send notifications, or activate public submissions.

SECURITY: never accept tenant_id, organization_id, intake_id, database state,
timestamps or access authority from a browser. A future governed command MUST
derive tenant and organization from a server-verified ACTIVE business binding,
then use an explicitly granted tenant-RLS-limited writer. The external request
UUID is merely an untrusted *idempotency reference*, not proof of identity.

PII is retained in this immutable in-process object for eventual guarded DATA
storage only; it must not be serialized into logs/events/outbox/error responses.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

# Mirrors the installed intake-table column checks; source and route are
# non-authoritative categorization labels, not a credential or policy decision.
_SLUG = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", re.ASCII)
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", re.UNICODE)
_PHONE = re.compile(r"^[+0-9(). -]+$", re.ASCII)
# The diagnostic summary is human text, not a secrets transmission channel.
_CREDENTIAL_MARKER = re.compile(
    r"(?i)\b(?:bearer\s+\S+|"
    r"(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret)\s*[:=]\s*\S+|"
    r"(?:https?|postgres(?:ql)?)://[^\s/:]+:[^\s/@]+@)"
)
_ALLOWED = frozenset({
    "external_request_id", "source_system", "route_reference", "business_name",
    "contact_name", "contact_email", "contact_phone", "preferred_contact_method",
    "contact_requested", "diagnostic_summary",
})
_REQUIRED = _ALLOWED - {"contact_phone"}
_REJECTED = "invalid_acquisition_intake"


@dataclass(frozen=True, slots=True)
class ValidatedAcquisitionIntake:
    """Non-authorizing candidate. Hidden fields prevent accidental repr PII."""

    external_request_id: str
    source_system: str
    route_reference: str
    business_name: str = field(repr=False)
    contact_name: str = field(repr=False)
    contact_email: str = field(repr=False)
    contact_phone: str | None = field(repr=False)
    preferred_contact_method: str
    diagnostic_summary: str = field(repr=False)
    contact_requested: bool = field(default=True, repr=False)


def _clean(raw: object, minimum: int, maximum: int) -> str:
    if not isinstance(raw, str):
        raise ValueError
    value = raw.strip()
    if not minimum <= len(value) <= maximum:
        raise ValueError
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError
    return value


def validate_acquisition_intake(payload: object) -> ValidatedAcquisitionIntake:
    """Normalize only intake content; do NOT bind tenant or perform writes.

    Returns a PII-bearing internal value for a future governed command. All
    validation errors use the same non-disclosing code and no raw input logs.
    """
    try:
        if type(payload) is not dict:
            raise ValueError
        keys = set(payload)
        if not _REQUIRED <= keys or not keys <= _ALLOWED:
            raise ValueError

        untrusted_id = payload["external_request_id"]
        if not isinstance(untrusted_id, str):
            raise ValueError
        request_id = str(uuid.UUID(untrusted_id))
        if request_id != untrusted_id:
            raise ValueError

        source = _clean(payload["source_system"], 3, 128)
        route = _clean(payload["route_reference"], 3, 128)
        if not _SLUG.fullmatch(source) or not _SLUG.fullmatch(route):
            raise ValueError

        business = _clean(payload["business_name"], 2, 160)
        person = _clean(payload["contact_name"], 2, 120)
        email = _clean(payload["contact_email"], 5, 254).lower()
        if not _EMAIL.fullmatch(email):
            raise ValueError

        phone = payload.get("contact_phone")
        if phone is not None:
            phone = _clean(phone, 7, 30)
            if not _PHONE.fullmatch(phone):
                raise ValueError

        method = payload["preferred_contact_method"]
        if method not in ("EMAIL", "PHONE") or (
            method == "PHONE" and phone is None
        ):
            raise ValueError
        if payload["contact_requested"] is not True:
            raise ValueError

        summary = _clean(payload["diagnostic_summary"], 1, 500)
        if _CREDENTIAL_MARKER.search(summary):
            raise ValueError
    except (TypeError, ValueError, KeyError, AttributeError):
        raise ValueError(_REJECTED) from None

    return ValidatedAcquisitionIntake(
        external_request_id=request_id,
        source_system=source,
        route_reference=route,
        business_name=business,
        contact_name=person,
        contact_email=email,
        contact_phone=phone,
        preferred_contact_method=method,
        diagnostic_summary=summary,
    )
