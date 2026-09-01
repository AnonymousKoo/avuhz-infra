"""Pure bounded state transitions for operational outbox delivery records."""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone

SAFE_FAILURE_CODES = frozenset({"DELIVERY_UNAVAILABLE", "DELIVERY_REJECTED", "EVENT_UNAVAILABLE"})
TERMINAL_STATUSES = frozenset({"PUBLISHED", "FAILED_TERMINAL"})


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone-aware timestamp required")
    return parsed.astimezone(timezone.utc)


def normalize_delivery(intent: dict, event: dict, destination_reference: str, now: str) -> dict:
    """Translate the existing minimal command intent into its canonical delivery record."""
    event_id = intent.get("event_id") or intent.get("event_reference", {}).get("reference_id")
    if not event_id or event.get("event_id") != event_id:
        raise ValueError("exact lifecycle event is required")
    tenant_id = event.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant-bound lifecycle event is required")
    if "outbox_delivery_id" in intent:
        return copy.deepcopy(intent)
    delivery_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:avuhz:outbox:" + tenant_id + ":" + event_id))
    return {
        "outbox_delivery_id": delivery_id,
        "event_reference": {"reference_type": "LIFECYCLE_EVENT", "reference_id": event_id},
        "destination_reference": destination_reference,
        "status": intent.get("status", "PENDING"),
        "attempt_count": 0,
        "attempt_history": [],
        "last_safe_error_code": None,
        "delivery_idempotency_key": "outbox-delivery:" + event_id,
        "record_version": 1,
        "created_at": event.get("occurred_at") or now,
        "updated_at": event.get("occurred_at") or now,
    }


def _clear_lease(record: dict) -> None:
    for field in ("lease_owner_reference", "lease_token", "lease_expires_at"):
        record.pop(field, None)


def _append_attempt(record: dict, completed_at: str, outcome: str, safe_error_code: str | None) -> None:
    history = record.setdefault("attempt_history", [])
    if len(history) >= 32:
        raise ValueError("outbox attempt history limit reached")
    history.append({
        "attempt_number": record["attempt_count"],
        "worker_reference": record["lease_owner_reference"],
        "started_at": record["last_attempt_at"],
        "completed_at": completed_at,
        "outcome": outcome,
        "safe_error_code": safe_error_code,
    })


def claim_delivery(record: dict, worker_reference: str, destination_reference: str, now: str,
                   lease_expires_at: str, max_attempts: int, lease_token: str) -> tuple[str, dict]:
    """Return NONE, CLAIMED, or DEAD_LETTERED plus a transition-safe copy."""
    candidate = copy.deepcopy(record)
    status = candidate["status"]
    if status in TERMINAL_STATUSES or candidate["destination_reference"] != destination_reference:
        return "NONE", candidate
    due = status == "PENDING"
    due = due or (status == "FAILED_RETRYABLE" and parse_utc(candidate["next_attempt_at"]) <= parse_utc(now))
    expired = status == "PUBLISHING" and parse_utc(candidate["lease_expires_at"]) <= parse_utc(now)
    if not due and not expired:
        return "NONE", candidate
    if expired:
        _append_attempt(candidate, now, "LEASE_EXPIRED", "LEASE_EXPIRED")
        candidate["last_safe_error_code"] = "LEASE_EXPIRED"
        _clear_lease(candidate)
        if candidate["attempt_count"] >= max_attempts:
            candidate["status"] = "FAILED_TERMINAL"
            candidate.pop("next_attempt_at", None)
            candidate["updated_at"] = now
            candidate["record_version"] += 1
            return "DEAD_LETTERED", candidate
    if candidate["attempt_count"] >= max_attempts:
        return "NONE", candidate
    candidate["status"] = "PUBLISHING"
    candidate["attempt_count"] += 1
    candidate["last_attempt_at"] = now
    candidate["lease_owner_reference"] = worker_reference
    candidate["lease_token"] = lease_token
    candidate["lease_expires_at"] = lease_expires_at
    candidate.pop("next_attempt_at", None)
    candidate.pop("published_at", None)
    candidate["updated_at"] = now
    candidate["record_version"] += 1
    return "CLAIMED", candidate


def publish_delivery(record: dict, lease_token: str, published_at: str) -> dict:
    candidate = copy.deepcopy(record)
    if candidate["status"] != "PUBLISHING" or candidate.get("lease_token") != lease_token:
        raise ValueError("outbox lease is stale")
    _append_attempt(candidate, published_at, "PUBLISHED", None)
    candidate["status"] = "PUBLISHED"
    candidate["published_at"] = published_at
    candidate["last_safe_error_code"] = None
    candidate.pop("next_attempt_at", None)
    _clear_lease(candidate)
    candidate["updated_at"] = published_at
    candidate["record_version"] += 1
    return candidate


def fail_delivery(record: dict, lease_token: str, failed_at: str, safe_error_code: str,
                  next_attempt_at: str | None) -> dict:
    if safe_error_code not in SAFE_FAILURE_CODES:
        raise ValueError("safe outbox error code is required")
    candidate = copy.deepcopy(record)
    if candidate["status"] != "PUBLISHING" or candidate.get("lease_token") != lease_token:
        raise ValueError("outbox lease is stale")
    outcome = "FAILED_RETRYABLE" if next_attempt_at else "FAILED_TERMINAL"
    _append_attempt(candidate, failed_at, outcome, safe_error_code)
    candidate["status"] = outcome
    candidate["last_safe_error_code"] = safe_error_code
    if next_attempt_at:
        candidate["next_attempt_at"] = next_attempt_at
    else:
        candidate.pop("next_attempt_at", None)
    candidate.pop("published_at", None)
    _clear_lease(candidate)
    candidate["updated_at"] = failed_at
    candidate["record_version"] += 1
    return candidate
