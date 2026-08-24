"""Pure read-only predicate for exact assessment-access dual human approval."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AssessmentAccessDualApprovalResult:
    satisfied: bool
    reason: str | None = None


def _attributed(approval, proposal_id, digest, role):
    return bool(
        approval
        and approval.get("subject_type") == "ASSESSMENT_ACCESS_PROPOSAL"
        and approval.get("subject_id") == proposal_id
        and approval.get("actor_role") == role
        and approval.get("actor_identity")
        and approval.get("actor_organization")
        and approval.get("assessment_access", {}).get("assessment_access_proposal_id") == proposal_id
        and approval.get("assessment_access", {}).get("assessment_access_authority_digest") == digest
    )


def evaluate_assessment_access_dual_approval(repositories, tenant_id, assessment_access_proposal_id):
    """Return whether an OPEN proposal has its two exact active human approvals."""
    proposal = repositories.assessment_access_proposals.get(tenant_id, assessment_access_proposal_id)
    if not proposal:
        return AssessmentAccessDualApprovalResult(False, "PROPOSAL_NOT_FOUND")
    if proposal.get("status") != "OPEN":
        return AssessmentAccessDualApprovalResult(False, "PROPOSAL_NOT_OPEN")
    digest = proposal.get("assessment_access_authority_digest")
    client = repositories.human_approvals.list_active_assessment_access_bindings(tenant_id, assessment_access_proposal_id, digest, "CLIENT_DECISION_AUTHORITY")
    if not client:
        return AssessmentAccessDualApprovalResult(False, "CLIENT_APPROVAL_MISSING")
    sekinfra = repositories.human_approvals.list_active_assessment_access_bindings(tenant_id, assessment_access_proposal_id, digest, "SEKINFRA_ENGAGEMENT_AUTHORITY")
    if not sekinfra:
        return AssessmentAccessDualApprovalResult(False, "SEKINFRA_APPROVAL_MISSING")
    if len(client) != 1 or len(sekinfra) != 1 or not _attributed(client[0], assessment_access_proposal_id, digest, "CLIENT_DECISION_AUTHORITY") or not _attributed(sekinfra[0], assessment_access_proposal_id, digest, "SEKINFRA_ENGAGEMENT_AUTHORITY"):
        return AssessmentAccessDualApprovalResult(False, "APPROVAL_BINDING_MISMATCH")
    return AssessmentAccessDualApprovalResult(True)
