"""LOCAL/TEST projection of System #001 intents into Avuhz's EXISTING event contract.

This pure adapter DOES NOT persist, claim a transaction committed, enqueue a
delivery, publish to n8n or grant client-system authority. The existing shared
Avuhz unit-of-work must atomically commit authoritative work state, lifecycle
event and outbox reference before any later hosted use. No parallel event bus,
workflow runtime, credential, auth path, or billing engine is introduced.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.schema_registry import SchemaRegistry
from .shared_work_intake_candidate import WorkIntakeResult

_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
_ROOT = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"

_WORK_EVENTS = {
    "work_intake.opened": "OPEN",
    "work_intake.handoff_offered": "OPEN",
    "work_intake.handoff_accepted": "OPEN",
    "work_intake.handoff_cancelled": "OPEN",
    "work_intake.blocked": "BLOCKED",
    "work_intake.resumed": "OPEN",
    "work_intake.resolved": "RESOLVED",
}


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _utc(value: object) -> bool:
    if type(value) is not str or not value.endswith("Z"):
        return False
    try:
        ts = datetime.fromisoformat(value[:-1] + "+00:00")
        return ts.utcoffset() == timezone.utc.utcoffset(ts)
    except (ValueError, OverflowError):
        return False


def project_test_work_intake_lifecycle_event(
    outcome: WorkIntakeResult,
    *,
    environment: str,
    event_id: str,
    correlation_id: str,
    idempotency_key: str,
    occurred_at: str,
) -> dict:
    """Build a schema-valid, minimal event for a synthetic WORK_ITEM change.

    It is intentionally restricted to LOCAL/TEST because the current
    WorkIntakeCandidate is in-memory and has no shared transactional persistence.
    Retries produce no second event. The caller cannot supply tenant, subject,
    event type, state, version or metadata separately from the accepted result.
    """
    if (
        environment not in {"LOCAL", "TEST"}
        or type(outcome) is not WorkIntakeResult
        or outcome.replayed is not False
        or outcome.intent is None
        or not _uuid(event_id)
        or not _uuid(correlation_id)
        or not _utc(occurred_at)
        or type(idempotency_key) is not str
        or not 8 <= len(idempotency_key) <= 128
        or not idempotency_key.isascii()
        or not all(ch.isalnum() or ch in "._:-" for ch in idempotency_key)
    ):
        raise ValueError("work intake event projection unavailable")
    item = outcome.item
    intent = outcome.intent
    if (
        not _uuid(item.tenant_id)
        or not _uuid(item.work_item_id)
        or intent.tenant_id != item.tenant_id
        or intent.work_item_id != item.work_item_id
        or intent.record_version != item.record_version
        or type(item.record_version) is not int
        or item.record_version < 1
        or intent.state != item.state
        or _WORK_EVENTS.get(intent.event_type) != item.state
    ):
        raise ValueError("work intake event projection unavailable")

    event = {
        "event_id": event_id,
        "event_type": intent.event_type,
        "event_schema_version": 1,
        "tenant_id": item.tenant_id,
        "authoritative_subject_reference": {
            "reference_type": "WORK_ITEM",
            "reference_id": item.work_item_id,
        },
        "authoritative_subject_version": item.record_version,
        "occurred_at": occurred_at,
        "producer_reference": "command.service-01",
        "correlation_id": correlation_id,
        "subject_id": item.work_item_id,
        "idempotency_key": idempotency_key,
        "visibility": "TENANT_OPERATIONAL",
        "sanitized_metadata": {
            "work_item_id": item.work_item_id,
            "state": item.state,
        },
    }
    validator = Draft202012Validator(
        SchemaRegistry(_ROOT).expanded(_SCHEMA_ID),
        format_checker=FormatChecker(),
    )
    if not validator.is_valid(event):
        raise ValueError("work intake event projection unavailable")
    return event
