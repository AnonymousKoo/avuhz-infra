"""Authoritative, human-accepted OIA root-cause confidence semantics."""

from __future__ import annotations

from .oia_observation import OIAObservationHandler


class OIARootCauseRejected(ValueError):
    """Current authoritative analytical truth cannot accept the causal transition."""


class OIARootCauseHandler:
    """Advance bounded causal confidence without creating findings or new evidence."""

    _TRANSITIONS = {"HYPOTHESIS": "SUPPORTED", "SUPPORTED": "VERIFIED"}

    def __init__(self, repositories):
        self.repositories = repositories

    @staticmethod
    def _actor(trusted_context):
        if (
            not trusted_context.tenant_id
            or "oia:root_cause:record" not in trusted_context.capabilities
            or trusted_context.caller_type != "HUMAN"
            or not trusted_context.principal_id
            or not trusted_context.human_principal_reference
        ):
            raise OIARootCauseRejected("trusted human root-cause authority is required")
        return trusted_context.human_principal_reference

    def _assessment(self, tenant_id, assessment_id, engagement_id):
        assessment = self.repositories.oia_assessments.get(tenant_id, assessment_id)
        engagement = self.repositories.engagements.get(tenant_id, engagement_id)
        if (
            not assessment
            or assessment.get("tenant_id") != tenant_id
            or assessment.get("engagement_id") != engagement_id
            or assessment.get("state") != "IN_PROGRESS"
            or not engagement
            or engagement.get("engagement_state") != "OPEN"
        ):
            raise OIARootCauseRejected("an in-progress correlated assessment is required")
        return assessment

    def _observations(self, tenant_id, assessment, observation_ids):
        observations = []
        for observation_id in observation_ids:
            observation = self.repositories.oia_observations.get(tenant_id, observation_id)
            if (
                not observation
                or observation.get("tenant_id") != tenant_id
                or observation.get("oia_assessment_id") != assessment["oia_assessment_id"]
                or observation.get("state") != "RECORDED"
            ):
                raise OIARootCauseRejected(
                    "root-cause observations must be current and correlated to this assessment"
                )
            observations.append(observation)
        return tuple(observations)

    def _evidence(self, tenant_id, assessment, observations, payload):
        evidence_ids = tuple(payload.get("supporting_evidence_ids", ()))
        if payload["confidence"] != "HYPOTHESIS" and not evidence_ids:
            raise OIARootCauseRejected("consequential causal confidence requires evidence support")
        cited_by_observation = {
            evidence_id
            for observation in observations
            for evidence_id in observation.get("evidence_ids", ())
        }
        evidence_records = []
        for evidence_id in evidence_ids:
            evidence = self.repositories.oia_evidence_items.get(tenant_id, evidence_id)
            if (
                not evidence
                or evidence.get("tenant_id") != tenant_id
                or evidence.get("oia_assessment_id") != assessment["oia_assessment_id"]
                or evidence_id not in cited_by_observation
            ):
                raise OIARootCauseRejected(
                    "root-cause evidence must be authoritative support cited by an observation"
                )
            evidence_records.append(evidence)
        if evidence_ids and any(
            not set(observation.get("evidence_ids", ())).intersection(evidence_ids)
            for observation in observations
        ):
            raise OIARootCauseRejected("every causal observation requires exact evidence support")
        if payload["confidence"] == "VERIFIED" and all(
            evidence.get("evidence_type") == "HUMAN_INTERVIEW_CORROBORATION"
            for evidence in evidence_records
        ):
            raise OIARootCauseRejected("human statements alone cannot verify causation")
        return evidence_ids

    def _governed_support(self, tenant_id, assessment, observations):
        observation_handler = OIAObservationHandler(self.repositories)
        plan = observation_handler._approved_plan(tenant_id, assessment)
        for observation in observations:
            observation_handler._supporting_items(
                tenant_id, assessment, plan, observation
            )

    @staticmethod
    def _preserves(existing, replacement):
        return all(value in replacement for value in existing)

    def record(
        self,
        trusted_context,
        payload,
        engagement_id,
        expected_record_version,
        recorded_at,
    ):
        actor = self._actor(trusted_context)
        tenant_id = trusted_context.tenant_id
        assessment = self._assessment(
            tenant_id, payload["oia_assessment_id"], engagement_id
        )
        observations = self._observations(
            tenant_id, assessment, payload["supporting_observation_ids"]
        )
        evidence_ids = self._evidence(
            tenant_id, assessment, observations, payload
        )
        current = self.repositories.oia_root_causes.get(
            tenant_id, payload["oia_root_cause_id"]
        )
        if current is None:
            if expected_record_version is not None or payload["confidence"] != "HYPOTHESIS":
                raise OIARootCauseRejected("a root cause must begin as a hypothesis")
            root_cause = {
                "tenant_id": tenant_id,
                "oia_root_cause_id": payload["oia_root_cause_id"],
                "oia_assessment_id": assessment["oia_assessment_id"],
                "cause_statement": payload["cause_statement"],
                "confidence": "HYPOTHESIS",
                "supporting_observation_ids": list(payload["supporting_observation_ids"]),
                "record_version": 1,
                "created_by": actor,
                "created_at": recorded_at,
                "updated_at": recorded_at,
            }
            if evidence_ids:
                root_cause["supporting_evidence_ids"] = list(evidence_ids)
            return self.repositories.oia_root_causes.create(root_cause)

        if (
            current.get("tenant_id") != tenant_id
            or current.get("oia_assessment_id") != assessment["oia_assessment_id"]
            or expected_record_version is None
            or current.get("record_version") != expected_record_version
            or self._TRANSITIONS.get(current.get("confidence")) != payload["confidence"]
            or current.get("cause_statement") != payload["cause_statement"]
            or not self._preserves(
                current.get("supporting_observation_ids", ()),
                payload["supporting_observation_ids"],
            )
            or not self._preserves(
                current.get("supporting_evidence_ids", ()), evidence_ids
            )
        ):
            raise OIARootCauseRejected("root-cause confidence transition is invalid")
        self._governed_support(tenant_id, assessment, observations)
        return self.repositories.oia_root_causes.transition(
            current, payload, recorded_at
        )
