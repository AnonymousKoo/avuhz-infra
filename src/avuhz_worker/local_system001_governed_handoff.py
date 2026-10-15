"""Dormant LOCAL/TEST System #001 receipt -> shared Work Item command boundary.

The only authority to OPEN a work item is independently verified source
ownership plus the existing shared Work Intake PostgreSQL writer. This is not
a hosted endpoint, n8n node or new authentication mechanism. No network, key,
schema, provider or workflow change is made by importing this module.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping

from avuhz_service.shared_work_intake_candidate import WorkIntakeCommand, _fresh
from avuhz_runtime.guards import TrustedExecutionContext
from .local_n8n_receipt_store import LocalN8nReceiptStore, ReceiptStoreUnavailable


class LocalSystem001HandoffDenied(PermissionError):
    """Safe error: no tenant, source, owner or PII information is echoed."""


@dataclass(frozen=True, slots=True)
class AuthorizedAcquisitionSnapshot:
    """Result ONLY of independent server-owned authoritative acquisition lookup.

    An intake/event payload, n8n node, or receipt itself cannot produce this
    snapshot. Only the configured server-controlled resolver may return one.
    This type is not proof of enrollment and does not grant a capability.
    """

    tenant_id: str
    intake_id: str
    work_item_id: str
    state: str
    source: str
    classification: str
    next_action_due_at: str
    owner_identity_evidence: object = field(repr=False)


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


class LocalSystem001GovernedHandoff:
    """LOCAL-only sequencing for receipt proof and shared Work Item authority.

    The *independent* lookup receives only an opaque intake UUID. It MUST read
    the underlying, tenant-bound acquisition record and owner assignment
    from the server-controlled DATA boundary; it must not transform the
    n8n envelope into proof of ownership. The Work Item writer then
    independently validates authenticated identity, live membership,
    scoped PostgreSQL RLS, and idempotency in its existing transaction.

    A scripted/synthetic lookup is permitted ONLY in isolated LOCAL/TEST
    certification. No hosted or production route may instantiate this adapter.
    """

    def __init__(
        self,
        *,
        receipt_store: LocalN8nReceiptStore,
        resolve_acquisition: Callable[[str], AuthorizedAcquisitionSnapshot],
        resolve_owner_identity: Callable[[object], TrustedExecutionContext],
        work_writer: object,
    ) -> None:
        if (
            type(receipt_store) is not LocalN8nReceiptStore
            or not callable(resolve_acquisition)
            or not callable(resolve_owner_identity)
            or not callable(getattr(work_writer, "execute", None))
        ):
            raise ValueError("local shared handoff dependencies required")
        self._receipts = receipt_store
        self._lookup = resolve_acquisition
        self._resolve_owner = resolve_owner_identity
        self._work = work_writer

    def open_receipted_intake(
        self, envelope: Mapping[str, object], *, delivery_header: object,
    ) -> object:
        """Return the existing shared writer receipt; NO alternative ledger.

        A missing, changed, or uncommitted receipt FAILS CLOSED without an
        owner lookup or Work Item write. Replayed exact receipts call the
        shared writer with the same deterministic idempotency key.
        """
        try:
            if not self._receipts.committed(envelope, delivery_header=delivery_header):
                raise LocalSystem001HandoffDenied("local handoff denied")
        except (TypeError, ValueError, PermissionError, ReceiptStoreUnavailable):
            raise LocalSystem001HandoffDenied("local handoff denied") from None

        reference = envelope["authoritative_subject_reference"]
        if (
            envelope["event_type"] != "acquisition.intake.received"
            or envelope["authoritative_subject_version"] != 1
            or reference["reference_type"] != "ACQUISITION_INTAKE"
        ):
            raise LocalSystem001HandoffDenied("local handoff denied")

        try:
            # Resolve source from the authoritative store, never from the
            # untrusted event fields, browser, n8n or a synthetic owner claim.
            source = self._lookup(reference["reference_id"])
        except Exception:
            raise LocalSystem001HandoffDenied("local handoff denied") from None

        if (
            type(source) is not AuthorizedAcquisitionSnapshot
            or source.tenant_id != envelope["tenant_id"]
            or source.intake_id != reference["reference_id"]
            or source.state != "RECEIVED"
            or not _uuid(source.tenant_id)
            or not _uuid(source.intake_id)
            or not _uuid(source.work_item_id)
            or source.work_item_id == source.intake_id
            or source.source not in {"web", "phone", "email", "api", "internal", "other"}
            or source.classification not in {
                "service_request", "work_order", "support_request", "incident",
                "approval_request", "internal_task", "customer_question", "other",
            }
            or type(source.next_action_due_at) is not str
        ):
            raise LocalSystem001HandoffDenied("local handoff denied")

        # Independent owner identity MUST be the same tenant as the persisted
        # acquisition. Merely passing a different tenant's valid HUMAN
        # credential to the shared writer would otherwise OPEN in that tenant.
        # The writer still revalidates identity, membership, RLS and command.
        try:
            owner = self._resolve_owner(source.owner_identity_evidence)
            if (
                type(owner) is not TrustedExecutionContext
                or owner.authenticated is not True
                or owner.environment != "DEVELOPMENT"
                or owner.audience != "avuhz-command-api"
                or owner.caller_type != "HUMAN"
                or owner.tenant_id != source.tenant_id
                or owner.authentication_strength != "STRONG"
                or type(owner.capabilities) is not frozenset
                or "work_intake:create" not in owner.capabilities
                or type(owner.authority_roles) is not frozenset
                or owner.authority_roles
                or not _fresh(owner)
            ):
                raise PermissionError
        except Exception:
            raise LocalSystem001HandoffDenied("local handoff denied") from None

        # No business owner, Work Item ID, deadline or assignment is taken
        # from the receipt; all are from the independently looked-up DATA
        # record and fresh trusted identity. The real shared PG writer then
        # checks live member eligibility and tenant RLS again.
        fingerprint = hashlib.sha256(
            (source.tenant_id + ":" + source.intake_id).encode("ascii")
        ).hexdigest()[:40]
        command = WorkIntakeCommand(
            "OPEN",
            source.work_item_id,
            "qa-work-open-" + fingerprint,
            source=source.source,
            classification=source.classification,
            next_action_due_at=source.next_action_due_at,
        )
        return self._work.execute(source.owner_identity_evidence, command)
