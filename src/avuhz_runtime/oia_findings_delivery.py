"""Immutable OIA findings delivery, governed correction, and assessment closure."""

from __future__ import annotations

import copy
import hashlib
import json

from .oia_finding import ANALYSIS_FIELDS, derive_finding_set_readiness


class OIAFindingsDeliveryRejected(ValueError):
    """Current authoritative truth cannot accept the delivery lifecycle transition."""


def findings_delivery_manifest_digest(delivery):
    """Digest the exact immutable delivery receipt without self-referencing its digest."""
    projection = {
        name: delivery[name]
        for name in (
            "tenant_id",
            "oia_findings_delivery_id",
            "oia_assessment_id",
            "delivery_sequence",
            "finding_revisions",
            "delivered_at",
            "delivered_by",
            "client_recipient_reference",
            "delivery_channel_reference",
        )
    }
    encoded = json.dumps(projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


class OIAFindingsLifecycleHandler:
    """Advance only the frozen READY, delivery, correction, and closure lifecycle."""

    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _human_actor(trusted_context, capability):
        if (
            not trusted_context.tenant_id
            or capability not in trusted_context.capabilities
            or trusted_context.caller_type != "HUMAN"
            or not trusted_context.principal_id
            or not trusted_context.human_principal_reference
        ):
            raise OIAFindingsDeliveryRejected("trusted human OIA lifecycle authority is required")
        return trusted_context.human_principal_reference

    def _assessment(self, tenant_id, assessment_id, engagement_id, state):
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        if (
            not assessment
            or assessment.get("tenant_id") != tenant_id
            or assessment.get("engagement_id") != engagement_id
            or assessment.get("state") != state
            or not engagement
            or engagement.get("engagement_state") != "OPEN"
        ):
            raise OIAFindingsDeliveryRejected("a correlated assessment in the required state is required")
        return assessment

    def _validate_current_finding_set(self, tenant_id, assessment):
        readiness = derive_finding_set_readiness(
            self.repositories, tenant_id, assessment["oia_assessment_id"]
        )
        if readiness["readiness"] != "READY":
            raise OIAFindingsDeliveryRejected("the authoritative Finding set is not ready")
        findings = self.repositories.oia_findings.list_current_by_assessment(
            tenant_id, assessment["oia_assessment_id"]
        )
        if not findings or any(
            finding.get("state") != "FINAL" or not finding.get("content_digest")
            for finding in findings
        ):
            raise OIAFindingsDeliveryRejected("only current FINAL Finding revisions are deliverable")
        return findings

    @staticmethod
    def _authoritative_revisions(findings):
        return tuple(
            {
                "oia_finding_id": finding["oia_finding_id"],
                "finding_revision": finding["finding_revision"],
                "content_digest": finding["content_digest"],
            }
            for finding in findings
        )

    def mark_ready(self, trusted_context, payload, engagement_id, expected_version, ready_at):
        self._human_actor(trusted_context, "oia:assessment:review")
        assessment = self._assessment(
            trusted_context.tenant_id, payload["oia_assessment_id"], engagement_id, "IN_PROGRESS"
        )
        if assessment.get("record_version") != expected_version:
            raise OIAFindingsDeliveryRejected("assessment record version is stale")
        self._validate_current_finding_set(trusted_context.tenant_id, assessment)
        return self.repositories.oia_assessments.mark_ready(assessment, ready_at)

    def deliver(self, trusted_context, payload, engagement_id, expected_version, delivered_at):
        actor = self._human_actor(trusted_context, "oia:findings:deliver")
        tenant_id = trusted_context.tenant_id
        assessment = self._assessment(
            tenant_id, payload["oia_assessment_id"], engagement_id, "READY_FOR_DELIVERY"
        )
        if (
            assessment.get("record_version") != expected_version
            or payload["ready_record_version"] != expected_version
        ):
            raise OIAFindingsDeliveryRejected("ready assessment record version is stale")
        findings = self._validate_current_finding_set(tenant_id, assessment)
        authoritative = self._authoritative_revisions(findings)
        submitted = tuple(copy.deepcopy(payload["finding_revisions"]))
        if len(submitted) != len(authoritative) or {
            (item["oia_finding_id"], item["finding_revision"], item["content_digest"])
            for item in submitted
        } != {
            (item["oia_finding_id"], item["finding_revision"], item["content_digest"])
            for item in authoritative
        }:
            raise OIAFindingsDeliveryRejected("delivery must match the exact current FINAL Finding set")
        sequence = len(
            self.repositories.oia_findings_deliveries.list_by_assessment(
                tenant_id, assessment["oia_assessment_id"]
            )
        ) + 1
        delivery = {
            "tenant_id": tenant_id,
            "oia_findings_delivery_id": payload["oia_findings_delivery_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "delivery_sequence": sequence,
            "finding_revisions": list(submitted),
            "delivered_at": delivered_at,
            "delivered_by": actor,
            "client_recipient_reference": payload["client_recipient_reference"],
            "delivery_channel_reference": payload["delivery_channel_reference"],
        }
        delivery["manifest_digest"] = findings_delivery_manifest_digest(delivery)
        stored_delivery = self.repositories.oia_findings_deliveries.create(delivery)
        updated_assessment = self.repositories.oia_assessments.mark_delivered(
            assessment, stored_delivery, delivered_at
        )
        access_closed = self.repositories.assessment_access_grants.close_for_lifecycle(
            tenant_id,
            assessment["assessment_access_grant_id"],
            delivered_at,
            "FINDINGS_DELIVERED",
        )
        return {
            "assessment": updated_assessment,
            "delivery": stored_delivery,
            "access_closed": access_closed,
        }

    def revise_delivered(self, trusted_context, payload, engagement_id, expected_revision, opened_at):
        actor = self._human_actor(trusted_context, "oia:finding:finalize")
        tenant_id = trusted_context.tenant_id
        original = self.repositories.oia_findings.get_revision(
            tenant_id, payload["oia_finding_id"], payload["delivered_finding_revision"]
        )
        if (
            not original
            or original.get("state") != "FINAL"
            or original.get("finding_revision") != expected_revision
            or self.repositories.oia_findings.get(tenant_id, payload["oia_finding_id"]) != original
        ):
            raise OIAFindingsDeliveryRejected("the exact current delivered FINAL Finding is required")
        assessment = self._assessment(
            tenant_id, original["oia_assessment_id"], engagement_id, "FINDINGS_DELIVERED"
        )
        latest = self.repositories.oia_findings_deliveries.latest_by_assessment(
            tenant_id, assessment["oia_assessment_id"]
        )
        exact = (
            original["oia_finding_id"], original["finding_revision"], original["content_digest"]
        )
        if not latest or exact not in {
            (item["oia_finding_id"], item["finding_revision"], item["content_digest"])
            for item in latest["finding_revisions"]
        }:
            raise OIAFindingsDeliveryRejected("Finding revision is not part of the current delivery")
        replacement = {
            "tenant_id": tenant_id,
            "oia_finding_id": payload["replacement_oia_finding_id"],
            "oia_assessment_id": assessment["oia_assessment_id"],
            "finding_revision": original["finding_revision"] + 1,
            "state": "DRAFT",
            **{
                name: copy.deepcopy(original[name])
                for name in ANALYSIS_FIELDS
                if name in original
            },
            "priority": original["priority"],
            "supersedes_finding_revision": {
                "oia_finding_id": original["oia_finding_id"],
                "finding_revision": original["finding_revision"],
            },
            "created_by": actor,
            "created_at": opened_at,
            "updated_at": opened_at,
        }
        stored_replacement = self.repositories.oia_findings.open_delivered_correction(
            original, replacement, opened_at
        )
        updated_assessment = self.repositories.oia_assessments.reopen_for_correction(
            assessment, opened_at
        )
        return {"assessment": updated_assessment, "replacement": stored_replacement}

    def close(self, trusted_context, payload, engagement_id, expected_version, closed_at):
        self._human_actor(trusted_context, "oia:assessment:close")
        tenant_id = trusted_context.tenant_id
        assessment = self._assessment(
            tenant_id, payload["oia_assessment_id"], engagement_id, "FINDINGS_DELIVERED"
        )
        if assessment.get("record_version") != expected_version:
            raise OIAFindingsDeliveryRejected("assessment record version is stale")
        latest = self.repositories.oia_findings_deliveries.latest_by_assessment(
            tenant_id, assessment["oia_assessment_id"]
        )
        findings = self.repositories.oia_findings.list_current_by_assessment(
            tenant_id, assessment["oia_assessment_id"]
        )
        current = set(
            (finding["oia_finding_id"], finding["finding_revision"], finding.get("content_digest"))
            for finding in findings
            if finding.get("state") == "FINAL"
        )
        delivered = set(
            (item["oia_finding_id"], item["finding_revision"], item["content_digest"])
            for item in (latest or {}).get("finding_revisions", ())
        )
        if (
            not latest
            or assessment.get("findings_delivery_id") != latest["oia_findings_delivery_id"]
            or not findings
            or any(finding.get("state") != "FINAL" for finding in findings)
            or current != delivered
        ):
            raise OIAFindingsDeliveryRejected("current delivered truth is incomplete or has a pending correction")
        updated_assessment = self.repositories.oia_assessments.close(assessment, closed_at)
        access_closed = self.repositories.assessment_access_grants.close_for_lifecycle(
            tenant_id,
            assessment["assessment_access_grant_id"],
            closed_at,
            "ASSESSMENT_CLOSED",
        )
        return {"assessment": updated_assessment, "access_closed": access_closed}
