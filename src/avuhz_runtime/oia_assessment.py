"""Trusted runtime core for opening one OIAAssessment from current Phase 5A authority."""

from __future__ import annotations

from dataclasses import dataclass

from .assessment_access_usability import evaluate_assessment_access_usability


@dataclass(frozen=True)
class OIAAssessmentEntryEligibilityResult:
    eligible: bool
    reason: str | None = None


class OIAAssessmentRejected(ValueError):
    """Current authoritative truth cannot open the requested OIAAssessment."""


def evaluate_oia_assessment_entry_eligibility(repositories, trusted_tenant_id, payload, trusted_now):
    """Evaluate current Phase 5A truth without granting or caching access authority."""
    if not trusted_tenant_id:
        return OIAAssessmentEntryEligibilityResult(False, "TENANT_CONTEXT_MISSING")
    engagement = repositories.engagements.get(trusted_tenant_id, payload["engagement_id"])
    if not engagement or engagement.get("engagement_state") != "OPEN":
        return OIAAssessmentEntryEligibilityResult(False, "ENGAGEMENT_NOT_ELIGIBLE")
    scope = repositories.diagnostic_scopes.get(trusted_tenant_id, payload["diagnostic_scope_id"])
    if not scope or scope.get("engagement_id") != engagement.get("engagement_id") or scope.get("status") != "APPROVED":
        return OIAAssessmentEntryEligibilityResult(False, "SCOPE_NOT_APPROVED")
    if scope.get("scope_version") != payload["diagnostic_scope_version"] or scope.get("canonical_scope_digest") != payload["canonical_scope_digest"]:
        return OIAAssessmentEntryEligibilityResult(False, "SCOPE_AUTHORITY_MISMATCH")
    grant = repositories.assessment_access_grants.get(trusted_tenant_id, payload["assessment_access_grant_id"])
    if not grant:
        return OIAAssessmentEntryEligibilityResult(False, "GRANT_NOT_FOUND")
    scope_reference = grant.get("diagnostic_scope_reference", {})
    if (
        grant.get("engagement_id") != engagement.get("engagement_id")
        or scope_reference.get("reference_type") != "DIAGNOSTIC_SCOPE"
        or scope_reference.get("reference_id") != scope.get("diagnostic_scope_id")
        or scope_reference.get("reference_version") != scope.get("scope_version")
        or grant.get("canonical_scope_digest") != scope.get("canonical_scope_digest")
        or grant.get("action_set_version") != scope.get("action_set_version")
    ):
        return OIAAssessmentEntryEligibilityResult(False, "GRANT_SCOPE_BINDING_MISMATCH")
    usability = evaluate_assessment_access_usability(
        repositories, trusted_tenant_id, payload["assessment_access_grant_id"], trusted_now
    )
    if not usability.usable:
        return OIAAssessmentEntryEligibilityResult(False, usability.reason)
    return OIAAssessmentEntryEligibilityResult(True)


class OpenOIAAssessmentHandler:
    def __init__(self, repositories):
        self.repositories = repositories

    def open(self, trusted_context, payload, opened_at):
        if (
            not trusted_context.tenant_id
            or "oia:open" not in trusted_context.capabilities
            or trusted_context.caller_type not in ("INTERNAL_SERVICE", "HUMAN")
        ):
            raise OIAAssessmentRejected("trusted OIA opening authority is required")
        eligibility = evaluate_oia_assessment_entry_eligibility(
            self.repositories, trusted_context.tenant_id, payload, opened_at
        )
        if not eligibility.eligible:
            raise OIAAssessmentRejected("current Phase 5A authority does not permit OIA entry")
        assessment = {
            "tenant_id": trusted_context.tenant_id,
            "oia_assessment_id": payload["oia_assessment_id"],
            "engagement_id": payload["engagement_id"],
            "diagnostic_scope_id": payload["diagnostic_scope_id"],
            "diagnostic_scope_version": payload["diagnostic_scope_version"],
            "canonical_scope_digest": payload["canonical_scope_digest"],
            "assessment_access_grant_id": payload["assessment_access_grant_id"],
            "state": "IN_PROGRESS",
            "record_version": 1,
            "opened_at": opened_at,
            "created_at": opened_at,
            "updated_at": opened_at,
        }
        return self.repositories.oia_assessments.create(assessment)
