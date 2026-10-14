"""Infrastructure V1: side-effect-free LOCAL/TEST Phase-5D target-state assessment.

Only trusted, independently collected/authorized provider observations may
feed this module. It does NOT authenticate, discover, authorize, mutate,
rollback, verify a deployment, or call a provider.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_TARGET_REF = re.compile(r"[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_FINGERPRINT = re.compile(r"fpv[1-9][0-9]*:[A-Za-z0-9._-]{16,200}\Z", re.ASCII)
_CLASSES = frozenset(("SYSTEM", "SERVICE", "COMPONENT", "HOST_GROUP"))
_EVIDENCE_CLASSES = frozenset(("TARGET_STATE", "HEALTH_CHECK", "AUDIT_RECORD"))
_MAX_TARGETS = 50


class InfrastructureStateReviewDenied(ValueError):
    """Fail closed with a fixed, non-PII diagnostic."""


@dataclass(frozen=True, slots=True)
class DesiredResource:
    """V1 must be bound to an existing approved Phase-5D target manifest."""

    tenant_id: str
    target_reference_id: str
    target_class: str
    target_environment: str
    expected_artifact_digest: str


@dataclass(frozen=True, slots=True)
class ObservedResource:
    """Supplier-provided claim, never trusted without separate attestation."""

    tenant_id: str
    target_reference_id: str
    target_class: str
    target_environment: str
    observed_artifact_digest: str
    observed_state_fingerprint: str
    evidence_reference_id: str
    evidence_class: str
    provenance_reference: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class ResourceAssessment:
    """A review candidate, NOT Phase-5D DeploymentVerification truth."""

    target_reference_id: str
    target_class: str
    result: str
    evidence_reference_id: str | None


def _valid_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


def _valid_ref(value: object) -> bool:
    return type(value) is str and 3 <= len(value) <= 128 and bool(_TARGET_REF.fullmatch(value))


def _valid_digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _valid_clock(value: object) -> bool:
    # Reject custom/mutable tzinfo objects before calling attacker-defined
    # utcoffset(), equality, comparison or arithmetic.
    return type(value) is datetime and value.tzinfo is timezone.utc


def assess_development_resources(
    desired: tuple[DesiredResource, ...],
    observed: tuple[ObservedResource, ...],
    *,
    trusted_tenant_id: str,
    now: datetime,
    max_observation_age_minutes: int,
) -> tuple[ResourceAssessment, ...]:
    """Pure inventory completeness/drift review for an injected DEVELOPMENT set.

    Caller must authenticate tenant, bind approved resource manifest, and
    independently verify provider evidence, freshness and provenance before
    trusting any returned result. MISMATCHED never means 'fix automatically'.
    """
    if (
        type(desired) is not tuple
        or not 1 <= len(desired) <= _MAX_TARGETS
        or type(observed) is not tuple
        or len(observed) > _MAX_TARGETS
        or not _valid_uuid(trusted_tenant_id)
        or not _valid_clock(now)
        or type(max_observation_age_minutes) is not int
        or not 1 <= max_observation_age_minutes <= 1440
    ):
        raise InfrastructureStateReviewDenied("trusted infrastructure context required")

    items: dict[tuple[str, str], DesiredResource] = {}
    for d in desired:
        if (
            type(d) is not DesiredResource
            or not _valid_uuid(d.tenant_id)
            or d.tenant_id != trusted_tenant_id
            or type(d.target_environment) is not str
            or d.target_environment != "DEVELOPMENT"
            or type(d.target_class) is not str or d.target_class not in _CLASSES
            or not _valid_ref(d.target_reference_id)
            or not _valid_digest(d.expected_artifact_digest)
        ):
            raise InfrastructureStateReviewDenied("invalid desired resource scope")
        key = (d.target_reference_id, d.target_class)
        if key in items:
            raise InfrastructureStateReviewDenied("duplicate resource scope")
        items[key] = d

    actual: dict[tuple[str, str], ObservedResource] = {}
    for o in observed:
        if (
            type(o) is not ObservedResource
            or not _valid_uuid(o.tenant_id)
            or o.tenant_id != trusted_tenant_id
            or type(o.target_environment) is not str
            or o.target_environment != "DEVELOPMENT"
            or type(o.target_class) is not str or o.target_class not in _CLASSES
            or not _valid_ref(o.target_reference_id)
            or not _valid_digest(o.observed_artifact_digest)
            or type(o.observed_state_fingerprint) is not str
            or not 20 <= len(o.observed_state_fingerprint) <= 220
            or not _FINGERPRINT.fullmatch(o.observed_state_fingerprint)
            or not _valid_ref(o.evidence_reference_id)
            or not _valid_ref(o.provenance_reference)
            or type(o.evidence_class) is not str or o.evidence_class not in _EVIDENCE_CLASSES
            or not _valid_clock(o.observed_at)
        ):
            raise InfrastructureStateReviewDenied("invalid observed resource scope")
        key = (o.target_reference_id, o.target_class)
        if key not in items or key in actual:
            raise InfrastructureStateReviewDenied("unexpected or duplicate observed resource")
        actual[key] = o

    result: list[ResourceAssessment] = []
    for key, d in items.items():
        o = actual.get(key)
        if o is None or o.observed_at > now or now-o.observed_at > timedelta(minutes=max_observation_age_minutes):
            code = "BLOCKED"
            evidence = None
        else:
            code = "MATCHED" if d.expected_artifact_digest == o.observed_artifact_digest else "MISMATCHED"
            evidence = o.evidence_reference_id
        result.append(ResourceAssessment(
            target_reference_id=d.target_reference_id,
            target_class=d.target_class, result=code, evidence_reference_id=evidence,
        ))
    return tuple(result)
