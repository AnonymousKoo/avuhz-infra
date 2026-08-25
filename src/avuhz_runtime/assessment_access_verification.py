"""Credential-free provider-neutral technical verification boundary.

Provider or vault adapters may resolve credentials internally, but this module
accepts and returns only immutable authority identifiers and sanitized outcomes.
"""

from dataclasses import dataclass
from enum import Enum


class VerificationFailureReason(str, Enum):
    CONNECTIVITY_FAILED = "CONNECTIVITY_FAILED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    PERMISSION_CHECK_FAILED = "PERMISSION_CHECK_FAILED"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    VERIFIER_UNAVAILABLE = "VERIFIER_UNAVAILABLE"


@dataclass(frozen=True)
class AssessmentAccessVerificationRequest:
    assessment_access_grant_id: str
    tenant_id: str
    engagement_id: str
    target_system_references: tuple[str, ...]
    permitted_actions: tuple[str, ...]

    @classmethod
    def from_grant(cls, grant: dict) -> "AssessmentAccessVerificationRequest":
        return cls(
            assessment_access_grant_id=grant["assessment_access_grant_id"],
            tenant_id=grant["tenant_id"],
            engagement_id=grant["engagement_id"],
            target_system_references=tuple(target["system_reference_id"] for target in grant["target_system_references"]),
            permitted_actions=tuple(grant["permitted_actions"]),
        )


@dataclass(frozen=True)
class TargetVerificationResult:
    target_system_reference: str
    success: bool
    failure_reason: VerificationFailureReason | None = None

    def __post_init__(self) -> None:
        if self.success != (self.failure_reason is None):
            raise ValueError("target verification result must be a sanitized success or failure")


@dataclass(frozen=True)
class AssessmentAccessVerificationResult:
    success: bool
    target_results: tuple[TargetVerificationResult, ...]

    @classmethod
    def for_request(
        cls,
        request: AssessmentAccessVerificationRequest,
        target_results: tuple[TargetVerificationResult, ...],
    ) -> "AssessmentAccessVerificationResult":
        expected = request.target_system_references
        actual = tuple(result.target_system_reference for result in target_results)
        if len(expected) != len(set(expected)) or len(actual) != len(set(actual)) or set(actual) != set(expected):
            raise ValueError("verification results must cover each authoritative target exactly once")
        return cls(success=all(result.success for result in target_results), target_results=target_results)


class InMemoryAssessmentAccessVerifier:
    """Deterministic test verifier; it is not a provider integration."""

    def __init__(self, outcomes: dict[str, VerificationFailureReason | None] | None = None):
        self._outcomes = dict(outcomes or {})

    def verify(self, request: AssessmentAccessVerificationRequest) -> AssessmentAccessVerificationResult:
        results = tuple(
            TargetVerificationResult(target, self._outcomes.get(target) is None, self._outcomes.get(target))
            for target in request.target_system_references
        )
        return AssessmentAccessVerificationResult.for_request(request, results)
