"""Client-neutral LOCAL/TEST governed Work Item delivery composition.

This composes the existing acquisition handoff and tenant-bound n8n dispatcher.
The handoff returns only after its authoritative Work Item, idempotency record,
lifecycle event and outbox intent commit.  Dispatch therefore cannot run before
that commit.  Delivery and a durable n8n receipt remain a later, non-authoritative
operation and are not atomic with the business transaction.

No identity, tenant, owner, schema, receipt store, network transport or workflow
is created here.  In particular, a lifecycle event, outbox row or n8n receipt can
never grant authority.  Future privileged acquisition writers must participate
in the advisory-lock protocol documented by shared_acquisition_commit_admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Callable

from avuhz_worker.local_unattended_n8n_dispatch import (
    LocalN8nDispatchSummary,
    LocalN8nOutboxDispatcher,
)

from .shared_acquisition_work_handoff import SharedAcquisitionWorkHandoff
from .shared_work_intake_postgres_candidate import DurableWorkReceipt


class SharedGovernedWorkLocalProofUnavailable(RuntimeError):
    """Bounded failure that does not disclose identity, SQL or event data."""


@dataclass(frozen=True, slots=True)
class SharedGovernedWorkLocalOutcome:
    work: DurableWorkReceipt
    dispatch: LocalN8nDispatchSummary


class SharedGovernedWorkLocalProof:
    """Run one governed handoff before an existing LOCAL/TEST dispatcher.

    Dispatch also runs after an exact command replay.  That is required when a
    previous invocation committed the authoritative transaction but delivery
    stopped afterward.  Existing outbox and receiver idempotency, not this
    coordinator, prevent duplicate publication and durable receipts.
    """

    def __init__(
        self,
        handoff: SharedAcquisitionWorkHandoff,
        dispatcher: LocalN8nOutboxDispatcher,
        *,
        receipt_committed: Callable[[DurableWorkReceipt], bool],
    ) -> None:
        if (
            type(handoff) is not SharedAcquisitionWorkHandoff
            or type(dispatcher) is not LocalN8nOutboxDispatcher
            or not callable(receipt_committed)
        ):
            raise ValueError("existing governed local components and receipt proof required")
        self._handoff = handoff
        self._dispatcher = dispatcher
        self._receipt_committed = receipt_committed

    def run(
        self, identity_evidence: object, intake_id: object, *, stop: Event
    ) -> SharedGovernedWorkLocalOutcome:
        if type(stop) is not Event or stop.is_set():
            raise SharedGovernedWorkLocalProofUnavailable(
                "governed work local proof unavailable"
            )
        try:
            # This is the only business mutation.  It returns after commit;
            # denial or rollback prevents the dispatcher call below.
            work = self._handoff.open(identity_evidence, intake_id)
            if (
                type(work) is not DurableWorkReceipt
                or type(work.replayed) is not bool
                or (work.replayed and work.event_id is not None)
                or (not work.replayed and type(work.event_id) is not str)
            ):
                raise RuntimeError
            dispatch = self._dispatcher.run_until_stopped(stop)
            if (
                type(dispatch) is not LocalN8nDispatchSummary
                or (not work.replayed and dispatch.published < 1)
                or self._receipt_committed(work) is not True
            ):
                raise RuntimeError
            return SharedGovernedWorkLocalOutcome(work, dispatch)
        except Exception:
            # The authoritative commit may already exist if dispatch failed.
            # A caller may safely replay; never expose internal diagnostics.
            raise SharedGovernedWorkLocalProofUnavailable(
                "governed work local proof unavailable"
            ) from None
