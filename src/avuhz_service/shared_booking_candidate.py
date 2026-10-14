"""System #001 shared booking-PREFERENCE validation; LOCAL/TEST only.

This module validates untrusted *time preferences*, never tenant identity,
operator/owner claims, calendar availability, a booking state transition or a
provider commitment. It contains no endpoint, database, idempotency ledger,
email/SMS, webhook, n8n connection or background scheduler.

A separate authorized shared Work Item command, using the existing Avuhz
identity/tenant/idempotency/event/outbox implementation, must establish
ownership and persist any work. Never treat the return value as a reservation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", re.ASCII)
_CODE = re.compile(r"^[a-z][a-z0-9_]{1,39}$", re.ASCII)
_FIELDS = frozenset({"start_at", "end_at", "next_action_due_at", "booking_type"})


class BookingPreferenceDenied(ValueError):
    """Safe validation failure with no request values echoed."""


@dataclass(frozen=True)
class BookingPolicy:
    """Must come from server-owned, reviewed tenant configuration, not HTTP."""
    allowed_booking_types: frozenset[str]
    min_notice_minutes: int
    max_duration_minutes: int
    max_horizon_days: int
    max_followup_hours: int

    def __post_init__(self):
        if (type(self.allowed_booking_types) is not frozenset
            or not self.allowed_booking_types
            or any(type(code) is not str or not _CODE.fullmatch(code)
                   for code in self.allowed_booking_types)
            or any(type(getattr(self, key)) is not int
                   for key in ("min_notice_minutes", "max_duration_minutes",
                               "max_horizon_days", "max_followup_hours"))
            or not (1 <= self.min_notice_minutes <= 43200)
            or not (1 <= self.max_duration_minutes <= 1440)
            or not (1 <= self.max_horizon_days <= 365)
            or not (1 <= self.max_followup_hours <= 168)):
            raise BookingPreferenceDenied("invalid server booking policy")


@dataclass(frozen=True)
class ValidatedBookingPreference:
    booking_type: str
    start_at: str
    end_at: str
    next_action_due_at: str


def _timestamp(value: object) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise BookingPreferenceDenied("invalid booking window")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
        if instant.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
            raise ValueError
        return instant
    except (ValueError, OverflowError):
        raise BookingPreferenceDenied("invalid booking window") from None


def _clock(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise BookingPreferenceDenied("trusted UTC clock required")
    return value


def validate_booking_preference(
    untrusted: object, *, policy: BookingPolicy, now: datetime,
) -> ValidatedBookingPreference:
    """Pure request validation; an accepted preference is NOT a booked slot.

    Reject contact text and browser-provided tenant, organization, owner,
    work-item, role or confirmation fields; these belong to other authorized
    shared service boundaries.
    """
    at = _clock(now)
    if (type(policy) is not BookingPolicy or type(untrusted) is not dict
        or frozenset(untrusted.keys()) != _FIELDS):
        raise BookingPreferenceDenied("invalid booking request")
    code = untrusted.get("booking_type")
    if type(code) is not str or code not in policy.allowed_booking_types:
        raise BookingPreferenceDenied("booking type unavailable")
    start = _timestamp(untrusted.get("start_at"))
    end = _timestamp(untrusted.get("end_at"))
    due = _timestamp(untrusted.get("next_action_due_at"))
    if not (
        at + timedelta(minutes=policy.min_notice_minutes) <= start
        and start < end
        and end <= at + timedelta(days=policy.max_horizon_days)
        and end - start <= timedelta(minutes=policy.max_duration_minutes)
        and at < due < start
        and due <= at + timedelta(hours=policy.max_followup_hours)
    ):
        raise BookingPreferenceDenied("booking window or follow-up invalid")
    return ValidatedBookingPreference(
        booking_type=code, start_at=untrusted["start_at"],
        end_at=untrusted["end_at"],
        next_action_due_at=untrusted["next_action_due_at"],
    )


def next_action_is_due(
    preference: ValidatedBookingPreference, *, now: datetime,
) -> bool:
    """Time predicate only; not a worker, a tenant query, or contact authority."""
    at = _clock(now)
    if type(preference) is not ValidatedBookingPreference:
        raise BookingPreferenceDenied("validated booking preference required")
    return _timestamp(preference.next_action_due_at) <= at
