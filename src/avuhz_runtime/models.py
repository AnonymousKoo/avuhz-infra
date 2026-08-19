"""Internal validation results. Claimed caller identity is never authenticated here."""

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import RuntimeReason


@dataclass(frozen=True)
class PreparedCommand:
    command_type: str
    command_id: str
    tenant_id: str
    subject_type: str
    subject_id: str
    caller_identity_claim: Mapping[str, Any]
    correlation_id: str
    idempotency_key: str
    environment: str
    payload: Mapping[str, Any]
    payload_schema: str
    payload_version: int
    engagement_id: str | None = None
    expected_record_version: int | None = None
    causation_id: str | None = None


@dataclass(frozen=True)
class ValidationFailure:
    reason: RuntimeReason
    message: str


@dataclass(frozen=True)
class ValidationSuccess:
    prepared: PreparedCommand


ValidationResult = ValidationSuccess | ValidationFailure
