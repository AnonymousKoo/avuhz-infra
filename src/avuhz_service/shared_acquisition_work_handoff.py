"""Dormant, governed System #001 acquisition -> shared Work Item composition.

Only connect EXISTING shared acquisition and Work Item components; no new
storage, workflow, API auth, capability, billing, or tenant infrastructure.

The acquisition receipt has five metadata fields, NOT a verified owner,
source/classification, business deadline or assignment authority. A trusted
server-owned planner must supply a bounded OPEN plan separately. The
Work Item writer independently re-authenticates the same human evidence,
checks the current tenant membership and writes its authoritative transaction.

LOCAL/TEST ONLY. The initial reader and final writer remain separate transactions.
The writer now rechecks admission inside its own Work Item transaction,
but this does NOT serialize future privileged acquisition mutations.
Never claim hosted acceptance from this source-only adapter.
Do not mount it in hosted services or n8n without a separately reviewed
same-transaction acquisition admission guard and real identity binding.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from .shared_acquisition_metadata_lookup import (
    SharedAcquisitionMetadataLookup, VerifiedAcquisitionMetadata, _uuid,
)
from .shared_work_intake_candidate import (
    WorkIntakeCommand, _canonical_due, _SOURCE, _CLASSIFICATION,
)
from .shared_work_intake_postgres_candidate import (
    DurableWorkReceipt, SharedWorkIntakePostgresCandidate,
)


class GovernedAcquisitionHandoffDenied(PermissionError):
    """One safe response, including when a row or authorization is missing."""


@dataclass(frozen=True, slots=True)
class GovernedAcquisitionWorkPlan:
    """An INTERNAL planner's decision; never a public request or n8n payload.

    Work Item ID is exactly the canonical intake ID (1 item per intake).
    Requires a separate governed source/category and deadline decision,
    independently of the acquisition metadata or consumer-provided fields.
    The writer, not this plan, determines the actual authenticated owner.
    """
    tenant_id: str
    organization_id: str
    intake_id: str
    intake_record_version: int
    work_item_id: str
    source: str
    classification: str
    next_action_due_at: str


class SharedAcquisitionWorkHandoff:
    """Compose existing independent read and writer; LOCAL/TEST only.

    The caller supplies ONLY authenticated evidence and an intake UUID.
    The plan provider must be server-owned and derive/approve business due
    policy and classification independently of HTTP, events and n8n.
    Merely passing a callback does not certify its trust provenance.
    """

    def __init__(
        self, reader: SharedAcquisitionMetadataLookup,
        writer: SharedWorkIntakePostgresCandidate, *,
        resolve_governed_plan: Callable[
            [VerifiedAcquisitionMetadata], GovernedAcquisitionWorkPlan
        ],
    ) -> None:
        if (
            type(reader) is not SharedAcquisitionMetadataLookup
            or type(writer) is not SharedWorkIntakePostgresCandidate
            or not callable(resolve_governed_plan)
        ):
            raise ValueError("existing shared components and server-owned plan required")
        self._reader = reader
        self._writer = writer
        self._resolve_plan = resolve_governed_plan

    def open(self, identity_evidence: object, intake_id: object) -> DurableWorkReceipt:
        # No raw context, caller-supplied plan, owner, due, business classification
        # or n8n receipt can establish authority here.
        if type(identity_evidence) is TrustedExecutionContext or not _uuid(intake_id):
            raise GovernedAcquisitionHandoffDenied("acquisition handoff unavailable")
        try:
            metadata = self._reader.lookup(identity_evidence, intake_id)
            if (
                type(metadata) is not VerifiedAcquisitionMetadata
                or metadata.intake_state != "RECEIVED"
                or not _uuid(metadata.intake_id)
                or not _uuid(metadata.tenant_id)
                or not _uuid(metadata.organization_id)
                or metadata.intake_id != intake_id
                or type(metadata.record_version) is not int
                or metadata.record_version < 1
            ):
                raise PermissionError
            plan = self._resolve_plan(metadata)
            if (
                type(plan) is not GovernedAcquisitionWorkPlan
                or plan.tenant_id != metadata.tenant_id
                or plan.organization_id != metadata.organization_id
                or plan.intake_id != metadata.intake_id
                or plan.work_item_id != metadata.intake_id
                or type(plan.intake_record_version) is not int
                or plan.intake_record_version != metadata.record_version
                or type(plan.source) is not str
                or plan.source not in _SOURCE
                or type(plan.classification) is not str
                or plan.classification not in _CLASSIFICATION
                or not _canonical_due(plan.next_action_due_at)
            ):
                raise PermissionError

            # One stable key for one canonical intake; the real writer's
            # caller/tenant-scoped idempotency ledger handles safe replay.
            # Existing WorkItem OPEN transaction enforces deadline 1m..30d.
            cmd = WorkIntakeCommand(
                kind="OPEN",
                work_item_id=metadata.intake_id,
                idempotency_key="Acq" + metadata.intake_id.replace("-", ""),
                source=plan.source,
                classification=plan.classification,
                next_action_due_at=plan.next_action_due_at,
            )
            # The prior acquisition reader is NOT the commit authority.
            # The existing writer re-reads this exact snapshot under tenant
            # RLS in its own Work Item/outbox transaction, twice.
            result = self._writer.execute(
                identity_evidence, cmd, acquisition_admission=metadata,
            )
            if (type(result) is not DurableWorkReceipt
                    or result.work_item_id != metadata.intake_id
                    or type(result.accepted_version) is not int
                    or result.accepted_version < 1
                    or type(result.replayed) is not bool):
                raise PermissionError
            return result
        except Exception:
            # Hide row existence, assignment, token, SQL, policy and PII.
            raise GovernedAcquisitionHandoffDenied(
                "acquisition handoff unavailable"
            ) from None
