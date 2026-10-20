"""Shared usage-metering port and deterministic LOCAL/TEST billing fake.

This module records only a non-authoritative measurement of one allowlisted,
sanitized lifecycle event.  It never calculates a price, creates a bill or
invoice, moves money, contacts a provider, or grants authoritative work.
Outbox events and these in-memory records are evidence of delivery only; they
are not authoritative business state or billable charges.

The fake is intended to be composed only behind the canonical
:class:`OutboxWorker`.  Its sink protocol cannot attest its caller or prove
that an event was committed before delivery.  Passing the same trusted worker
context to the constructor and OutboxWorker is therefore a LOCAL/TEST
composition invariant, not an authorization boundary.  Direct Python calls
remain possible and must never be treated as consumption authority.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.schema_registry import SchemaRegistry, schema_root
from .outbox import DeliveryRejected, DeliveryUnavailable, PUBLISH_CAPABILITY


_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
_MAX_EVENT_BYTES = 16_384
_ALLOWED_METRICS = {
    "engagement.opened": "engagement_opened",
    "work_intake.opened": "work_item_opened",
}
_UNIT = "governed_event"


@dataclass(frozen=True, slots=True)
class LocalUsageRecord:
    """Immutable, non-authoritative measurement; never a billable charge."""

    usage_record_id: str
    tenant_id: str
    event_id: str
    correlation_id: str
    subject_reference_type: str
    subject_reference_id: str
    metric: str
    unit: str
    measured_quantity: int
    delivery_idempotency_key: str
    event_semantic_digest: str
    measured_at: str
    billing_effect: str = "NONE"


@dataclass(frozen=True, slots=True)
class UsageMeteringResult:
    disposition: str
    record: LocalUsageRecord


@runtime_checkable
class SharedUsageMeteringAdapter(Protocol):
    """Avuhz-owned metering port intended for OutboxWorker composition."""

    def deliver(
        self, idempotency_key: str, event: dict, delivered_at: str
    ) -> UsageMeteringResult: ...


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError):
        return False


def _utc_timestamp(value: object) -> bool:
    if type(value) is not str or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0


def _validate_worker_context(context, tenant_id: str, environment: str) -> None:
    """Defensively mirror the canonical worker's LOCAL/TEST requirements."""
    valid = (
        getattr(context, "authenticated", False) is True
        and bool(getattr(context, "principal_id", None))
        and getattr(context, "caller_type", None) == "INTERNAL_SERVICE"
        and getattr(context, "tenant_id", None) == tenant_id
        and getattr(context, "environment", None) == environment
        and environment in {"LOCAL", "TEST"}
        and getattr(context, "audience", None) == "avuhz-command-api"
        and PUBLISH_CAPABILITY in getattr(context, "capabilities", frozenset())
        and not getattr(context, "authority_roles", frozenset())
        and getattr(context, "human_authority_role", None) is None
        and bool(getattr(context, "authenticated_at", None))
    )
    if not valid:
        raise ValueError("trusted local outbox worker context is required")
    expires_at = getattr(context, "expires_at", None)
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ValueError("trusted local outbox worker context is required") from error
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise ValueError("trusted local outbox worker context is required")


class DeterministicLocalUsageBillingFake:
    """Thread-safe fake retaining one unpriced measurement per event identity.

    Quantity is fixed internally at one governed event.  No event or caller
    field can supply a quantity, price, currency, customer, invoice, payment,
    recipient, or provider destination.
    """

    def __init__(
        self, *, tenant_id: str, environment: str, trusted_context, outcomes=(),
    ) -> None:
        if not _canonical_uuid(tenant_id):
            raise ValueError("canonical usage tenant is required")
        _validate_worker_context(trusted_context, tenant_id, environment)
        bounded_outcomes = tuple(outcomes)
        if any(outcome not in {"RECORDED", "DELIVERY_UNAVAILABLE"} for outcome in bounded_outcomes):
            raise ValueError("bounded local usage outcome is required")
        self._tenant_id = tenant_id
        self._outcomes = list(bounded_outcomes)
        self._records: dict[str, LocalUsageRecord] = {}
        self._lock = threading.Lock()
        registry = SchemaRegistry(schema_root())
        self._validator = Draft202012Validator(
            registry.expanded(_SCHEMA_ID), format_checker=FormatChecker()
        )

    @property
    def records(self) -> tuple[LocalUsageRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def _validated_semantics(
        self, idempotency_key: object, event: object,
    ) -> tuple[str, dict, str]:
        if type(event) is not dict or type(idempotency_key) is not str:
            raise DeliveryRejected("USAGE_EVENT_REJECTED")
        try:
            encoded = json.dumps(
                event, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        except (TypeError, ValueError, RecursionError):
            raise DeliveryRejected("USAGE_EVENT_REJECTED") from None
        if len(encoded) > _MAX_EVENT_BYTES or not self._validator.is_valid(event):
            raise DeliveryRejected("USAGE_EVENT_REJECTED")
        reference = event.get("authoritative_subject_reference")
        metadata = event.get("sanitized_metadata")
        event_type = event.get("event_type")
        common_valid = (
            event.get("tenant_id") == self._tenant_id
            and event_type in _ALLOWED_METRICS
            and event.get("event_schema_version") == 1
            and event.get("visibility") == "TENANT_OPERATIONAL"
            and _canonical_uuid(event.get("event_id"))
            and _canonical_uuid(event.get("correlation_id"))
            and idempotency_key == "outbox-delivery:" + event["event_id"]
            and type(reference) is dict
            and set(reference) == {"reference_type", "reference_id"}
            and _canonical_uuid(reference.get("reference_id"))
            and type(metadata) is dict
        )
        engagement_valid = (
            event_type == "engagement.opened"
            and reference.get("reference_type") == "ENGAGEMENT"
            and event.get("engagement_id") == reference.get("reference_id")
            and event.get("subject_id") == reference.get("reference_id")
            and set(metadata) == {"engagement_id"}
            and metadata.get("engagement_id") == reference.get("reference_id")
        )
        work_item_valid = (
            event_type == "work_intake.opened"
            and reference.get("reference_type") == "WORK_ITEM"
            and "engagement_id" not in event
            and "subject_id" not in event
            and set(metadata) == {"work_item_id", "state"}
            and metadata.get("work_item_id") == reference.get("reference_id")
            and metadata.get("state") == "OPEN"
        )
        if not common_valid or not (engagement_valid or work_item_valid):
            raise DeliveryRejected("USAGE_EVENT_REJECTED")
        return hashlib.sha256(encoded).hexdigest(), reference, _ALLOWED_METRICS[event_type]

    def deliver(
        self, idempotency_key: str, event: dict, delivered_at: str
    ) -> UsageMeteringResult:
        digest, reference, metric = self._validated_semantics(idempotency_key, event)
        if not _utc_timestamp(delivered_at):
            raise DeliveryRejected("USAGE_EVENT_REJECTED")
        with self._lock:
            prior = self._records.get(idempotency_key)
            if prior is not None:
                if prior.tenant_id != event["tenant_id"] or prior.event_semantic_digest != digest:
                    raise DeliveryRejected("USAGE_IDENTITY_COLLISION")
                return UsageMeteringResult("DUPLICATE", prior)
            outcome = self._outcomes.pop(0) if self._outcomes else "RECORDED"
            if outcome == "DELIVERY_UNAVAILABLE":
                raise DeliveryUnavailable("USAGE_METERING_TEMPORARILY_UNAVAILABLE")
            record_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                "urn:avuhz:local-usage:" + self._tenant_id + ":" + event["event_id"],
            ))
            record = LocalUsageRecord(
                usage_record_id=record_id,
                tenant_id=self._tenant_id,
                event_id=event["event_id"],
                correlation_id=event["correlation_id"],
                subject_reference_type=reference["reference_type"],
                subject_reference_id=reference["reference_id"],
                metric=metric,
                unit=_UNIT,
                measured_quantity=1,
                delivery_idempotency_key=idempotency_key,
                event_semantic_digest=digest,
                measured_at=event["occurred_at"],
            )
            self._records[idempotency_key] = record
            return UsageMeteringResult("RECORDED", record)

    def validate(self, idempotency_key: str, event: dict, delivered_at: str) -> None:
        """Validate a prospective LOCAL measurement without recording it."""
        digest, _reference, _metric = self._validated_semantics(idempotency_key, event)
        if not _utc_timestamp(delivered_at):
            raise DeliveryRejected("USAGE_EVENT_REJECTED")
        with self._lock:
            prior = self._records.get(idempotency_key)
            if prior is not None and (
                prior.tenant_id != event["tenant_id"]
                or prior.event_semantic_digest != digest
            ):
                raise DeliveryRejected("USAGE_IDENTITY_COLLISION")
