"""LOCAL/TEST fanout for two shared allowlisted lifecycle-event fakes.

This is a sink behind the canonical :class:`OutboxWorker`, not a delivery
loop, authority writer, durable delivery ledger, or provider adapter.  The
communications and usage fakes retain their own idempotency identities, so a
retry after a partial failure repeats no completed effect.  The canonical
outbox delivery is published only after both local effects complete.

The sinks independently validate exact ``engagement.opened`` and
``work_intake.opened`` shapes.  This module performs no event translation and
does not create a Work Item-to-Engagement authority transition.
"""
from __future__ import annotations

from dataclasses import dataclass

from .shared_communications_local import (
    CommunicationDeliveryResult,
    DeterministicLocalCommunicationsFake,
)
from .shared_usage_billing_local import (
    DeterministicLocalUsageBillingFake,
    UsageMeteringResult,
)


@dataclass(frozen=True, slots=True)
class LocalLifecycleDeliveryResult:
    """Non-authoritative result from both deterministic local effects."""

    communication: CommunicationDeliveryResult
    usage: UsageMeteringResult


class SharedLifecycleDeliveryLocalFanout:
    """Deliver one canonical event to both exact shared LOCAL/TEST fakes."""

    def __init__(
        self,
        communications: DeterministicLocalCommunicationsFake,
        usage: DeterministicLocalUsageBillingFake,
    ) -> None:
        if (
            type(communications) is not DeterministicLocalCommunicationsFake
            or type(usage) is not DeterministicLocalUsageBillingFake
        ):
            raise ValueError("exact shared local delivery fakes required")
        self._communications = communications
        self._usage = usage

    def deliver(
        self, idempotency_key: str, event: dict, delivered_at: str,
    ) -> LocalLifecycleDeliveryResult:
        # Both exact consumers must accept the event and any existing replay
        # identity before either fake records an effect.  This prevents the
        # stricter usage contract from terminally rejecting after a
        # communications receipt has already been created.
        self.validate(idempotency_key, event, delivered_at)
        communication = self._communications.deliver(
            idempotency_key, event, delivered_at,
        )
        usage = self._usage.deliver(idempotency_key, event, delivered_at)
        return LocalLifecycleDeliveryResult(communication, usage)

    def validate(self, idempotency_key: str, event: dict, delivered_at: str) -> None:
        """Preflight both sinks without creating a local effect."""
        self._communications.validate(idempotency_key, event, delivered_at)
        self._usage.validate(idempotency_key, event, delivered_at)


# Compatibility names for the initial uncommitted Batch5 composition.  They
# do not narrow or translate the exact event contracts validated by the sinks.
LocalEngagementDeliveryResult = LocalLifecycleDeliveryResult
SharedEngagementDeliveryLocalFanout = SharedLifecycleDeliveryLocalFanout
