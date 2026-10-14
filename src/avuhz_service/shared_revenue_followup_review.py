"""Shared System #001 follow-up/overdue decisions; pure LOCAL/TEST candidate.

Receives only already-authorized tenant-scoped Work Item snapshots with
persisted due-time evidence supplied by an independent trusted query. It
cannot authenticate a caller, read DATA, persist obligations, run a scheduler,
message contacts, acknowledge receipts or create another automation engine.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from .shared_work_intake_candidate import WorkItem

_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_MEMBER = re.compile(r"[a-z][a-z0-9._:-]{1,95}\Z", re.ASCII)
_STATUS = frozenset(("OPEN", "BLOCKED", "RESOLVED"))
_SOURCE = frozenset(("phone", "email", "web", "internal", "api", "other"))
_CLASSIFICATION = frozenset((
    "service_request", "work_order", "support_request", "incident",
    "approval_request", "internal_task", "customer_question", "other",
))
_KIND = Literal[
    "FOLLOWUP_DUE", "FOLLOWUP_ESCALATION_REVIEW_REQUIRED",
    "BLOCKED_OWNER_REVIEW_REQUIRED",
]
_MAX_BATCH = 100


class FollowupReviewDenied(ValueError):
    """Generic denial without echoing tenant, contact or work details."""


@dataclass(frozen=True, slots=True)
class FollowupReviewPolicy:
    """Server-owned policy; never construct this from browser/n8n payloads."""

    escalation_after_minutes: int

    def __post_init__(self) -> None:
        if type(self.escalation_after_minutes) is not int or not 15 <= self.escalation_after_minutes <= 10080:
            raise FollowupReviewDenied("invalid shared follow-up policy")


@dataclass(frozen=True, slots=True)
class FollowupObservation:
    """Trusted Work Item snapshot plus separate authoritative due-time read."""

    item: WorkItem
    next_action_due_at: str


@dataclass(frozen=True, slots=True)
class FollowupReviewCandidate:
    """Non-authoritative decision; NOT an instruction to n8n to send."""

    work_item_id: str
    record_version: int
    owner_reference: str
    next_action_due_at: str
    kind: _KIND


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _instant(value: object) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise FollowupReviewDenied("invalid follow-up snapshot")
    try:
        at = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        if at.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
            raise ValueError
        return at.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        raise FollowupReviewDenied("invalid follow-up snapshot") from None


def review_followup_due(
    observations: tuple[FollowupObservation, ...],
    *, trusted_tenant_id: str, policy: FollowupReviewPolicy, now: datetime,
) -> tuple[FollowupReviewCandidate, ...]:
    """Return due/overdue REVIEW CANDIDATES for an authorized snapshot batch.

    No side effects. Caller must prove tenant authorization, owner eligibility,
    actual persisted due times, versioned work state and replay-safe commands
    before converting a candidate into a real Work Item action.
    """
    if (
        type(observations) is not tuple
        or not 1 <= len(observations) <= _MAX_BATCH
        or not _uuid(trusted_tenant_id)
        or type(policy) is not FollowupReviewPolicy
        or type(now) is not datetime
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
    ):
        raise FollowupReviewDenied("trusted follow-up review context required")
    seen: set[str] = set()
    candidates: list[FollowupReviewCandidate] = []
    for row in observations:
        if type(row) is not FollowupObservation or type(row.item) is not WorkItem:
            raise FollowupReviewDenied("invalid follow-up snapshot")
        item = row.item
        if (
            item.tenant_id != trusted_tenant_id
            or not _uuid(item.work_item_id)
            or type(item.owner_reference) is not str
            or _MEMBER.fullmatch(item.owner_reference) is None
            or type(item.record_version) is not int
            or not 1 <= item.record_version < 2**31
            or type(item.state) is not str or item.state not in _STATUS
            or type(item.source) is not str or item.source not in _SOURCE
            or type(item.classification) is not str or item.classification not in _CLASSIFICATION
            or item.work_item_id in seen
        ):
            raise FollowupReviewDenied("invalid follow-up snapshot")
        seen.add(item.work_item_id)
        due = _instant(row.next_action_due_at)
        if item.state == "RESOLVED" or now < due:
            continue
        if item.state == "BLOCKED":
            kind: _KIND = "BLOCKED_OWNER_REVIEW_REQUIRED"
        elif (now - due) >= timedelta(minutes=policy.escalation_after_minutes):
            kind = "FOLLOWUP_ESCALATION_REVIEW_REQUIRED"
        else:
            kind = "FOLLOWUP_DUE"
        candidates.append(FollowupReviewCandidate(
            work_item_id=item.work_item_id,
            record_version=item.record_version,
            owner_reference=item.owner_reference,
            next_action_due_at=row.next_action_due_at,
            kind=kind,
        ))
    return tuple(candidates)
