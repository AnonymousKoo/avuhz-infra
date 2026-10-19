"""Provider-neutral shared communications port and deterministic LOCAL fake.

This module performs no external send and stores no authoritative state.  The
fake is intended to be composed only as an :class:`OutboxWorker` sink.  Its
protocol carries neither trusted context nor claim/commit attestation, so the
sink cannot prove its caller or that an event came from a committed outbox
claim.  LOCAL/TEST composition is therefore a trusted in-process assumption:
constructor context checks reject accidental misconfiguration, but are not an
authorization boundary and cannot prevent direct Python invocation.

Receipts live only for the lifetime of this object.  They are deterministic,
immutable, non-authoritative records of a fictional internal-notification
effect, not a durable acknowledgment, hosted delivery, or permitted send.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.schema_registry import SchemaRegistry
from .outbox import DeliveryRejected, DeliveryUnavailable, PUBLISH_CAPABILITY


_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"
_MAX_EVENT_BYTES = 16_384
_CHANNEL = "INTERNAL_NOTIFICATION"
_ALLOWED_EVENT = "engagement.opened"
_ALLOWED_REFERENCE = "ENGAGEMENT"


@dataclass(frozen=True, slots=True)
class CommunicationReceipt:
    """Immutable, non-authoritative receipt for one fictional local effect."""

    tenant_id: str
    event_id: str
    correlation_id: str
    subject_reference_type: str
    subject_reference_id: str
    channel: str
    delivery_idempotency_key: str
    event_semantic_digest: str
    delivered_at: str


@dataclass(frozen=True, slots=True)
class CommunicationDeliveryResult:
    disposition: str
    receipt: CommunicationReceipt


@runtime_checkable
class SharedCommunicationsAdapter(Protocol):
    """Avuhz-owned provider-neutral port intended for OutboxWorker composition."""

    def deliver(
        self, idempotency_key: str, event: dict, delivered_at: str
    ) -> CommunicationDeliveryResult: ...


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
    """Defensively mirror the worker's LOCAL/TEST composition requirements."""
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


class DeterministicLocalCommunicationsFake:
    """Thread-safe, in-memory fake with one effect per delivery identity.

    The caller must pass the same server-derived `trusted_context` to this fake
    and the canonical OutboxWorker.  The sink interface cannot verify that
    identity or call path, so this is a composition invariant rather than an
    authorization guarantee.  The fixed channel has no external destination
    or provider address.
    """

    def __init__(
        self, *, tenant_id: str, environment: str, trusted_context,
        channel: str = _CHANNEL, outcomes=(),
    ) -> None:
        if not _canonical_uuid(tenant_id):
            raise ValueError("canonical communications tenant is required")
        _validate_worker_context(trusted_context, tenant_id, environment)
        if channel != _CHANNEL:
            raise ValueError("allowlisted local communications channel is required")
        bounded_outcomes = tuple(outcomes)
        if any(outcome not in {"PUBLISHED", "DELIVERY_UNAVAILABLE"} for outcome in bounded_outcomes):
            raise ValueError("bounded local communications outcome is required")
        self._tenant_id = tenant_id
        self._channel = channel
        self._outcomes = list(bounded_outcomes)
        self._receipts: dict[str, CommunicationReceipt] = {}
        self._lock = threading.Lock()
        registry = SchemaRegistry(_SCHEMA_ROOT)
        self._validator = Draft202012Validator(
            registry.expanded(_SCHEMA_ID), format_checker=FormatChecker()
        )

    @property
    def receipts(self) -> tuple[CommunicationReceipt, ...]:
        with self._lock:
            return tuple(self._receipts.values())

    def _validated_semantics(self, idempotency_key: object, event: object) -> tuple[str, dict]:
        if type(event) is not dict or type(idempotency_key) is not str:
            raise DeliveryRejected("COMMUNICATION_EVENT_REJECTED")
        try:
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        except (TypeError, ValueError):
            raise DeliveryRejected("COMMUNICATION_EVENT_REJECTED") from None
        if len(encoded) > _MAX_EVENT_BYTES or not self._validator.is_valid(event):
            raise DeliveryRejected("COMMUNICATION_EVENT_REJECTED")
        reference = event.get("authoritative_subject_reference")
        metadata = event.get("sanitized_metadata")
        valid = (
            event.get("tenant_id") == self._tenant_id
            and event.get("event_type") == _ALLOWED_EVENT
            and event.get("event_schema_version") == 1
            and _canonical_uuid(event.get("event_id"))
            and _canonical_uuid(event.get("correlation_id"))
            and idempotency_key == "outbox-delivery:" + event["event_id"]
            and type(reference) is dict
            and set(reference) == {"reference_type", "reference_id"}
            and reference.get("reference_type") == _ALLOWED_REFERENCE
            and _canonical_uuid(reference.get("reference_id"))
            and event.get("engagement_id") == reference.get("reference_id")
            and event.get("subject_id") == reference.get("reference_id")
            and type(metadata) is dict
            and set(metadata) == {"engagement_id"}
            and metadata.get("engagement_id") == reference.get("reference_id")
        )
        if not valid:
            raise DeliveryRejected("COMMUNICATION_EVENT_REJECTED")
        return hashlib.sha256(encoded).hexdigest(), reference

    def deliver(
        self, idempotency_key: str, event: dict, delivered_at: str
    ) -> CommunicationDeliveryResult:
        digest, reference = self._validated_semantics(idempotency_key, event)
        if not _utc_timestamp(delivered_at):
            raise DeliveryRejected("COMMUNICATION_EVENT_REJECTED")
        with self._lock:
            prior = self._receipts.get(idempotency_key)
            if prior is not None:
                if prior.tenant_id != event["tenant_id"] or prior.event_semantic_digest != digest:
                    raise DeliveryRejected("COMMUNICATION_IDENTITY_COLLISION")
                return CommunicationDeliveryResult("DUPLICATE", prior)
            outcome = self._outcomes.pop(0) if self._outcomes else "PUBLISHED"
            if outcome == "DELIVERY_UNAVAILABLE":
                raise DeliveryUnavailable("COMMUNICATION_TEMPORARILY_UNAVAILABLE")
            receipt = CommunicationReceipt(
                tenant_id=self._tenant_id,
                event_id=event["event_id"],
                correlation_id=event["correlation_id"],
                subject_reference_type=reference["reference_type"],
                subject_reference_id=reference["reference_id"],
                channel=self._channel,
                delivery_idempotency_key=idempotency_key,
                event_semantic_digest=digest,
                delivered_at=delivered_at,
            )
            self._receipts[idempotency_key] = receipt
            return CommunicationDeliveryResult("PUBLISHED", receipt)
