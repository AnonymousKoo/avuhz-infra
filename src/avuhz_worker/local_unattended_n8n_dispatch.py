"""Bounded unattended LOCAL/TEST Avuhz lifecycle-outbox -> n8n polling.

Composition of EXISTING OutboxWorker and N8nOutboxSink, never a new event
ledger, data writer, owner verifier, provider credential path or n8n workflow.

A server-owned caller must already supply a tenant-scoped repository, trusted
INTERNAL_SERVICE identity and guarded n8n sink; this component ONLY repeats
the existing single-cycle worker at an approved interval. No network client,
token, n8n activation, database DSN or background process is started on import.
The installed n8n receiver remains INACTIVE until separately authorized.

Output contains aggregate non-PII counters only. Unexpected errors fail closed
with one safe category; no credential or provider exception is echoed.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Event

from .n8n_event_sink import N8nOutboxSink
from .outbox import OutboxWorker

_FIELDS = frozenset({"claimed", "published", "retry_scheduled", "dead_lettered"})


class LocalN8nDispatchUnavailable(RuntimeError):
    """No unsafe exception, source payload or credential details are relayed."""


@dataclass(frozen=True, slots=True)
class LocalN8nDispatchConfig:
    """Limits apply per session; nothing runs persistently unless started.

    A session may run without an operator advancing each event, but the
    explicit hard cycle limit and stop Event prevent hidden infinite loops.
    The retry delay remains owned by OutboxWorker/outbox record state.
    """
    tenant_id: str
    poll_interval_seconds: int = 5
    max_cycles: int = 720

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not str
            or type(self.poll_interval_seconds) is not int
            or type(self.max_cycles) is not int
            or not 1 <= self.poll_interval_seconds <= 300
            or not 1 <= self.max_cycles <= 17280
        ):
            raise ValueError("bounded local dispatch configuration required")
        # Canonical UUID check must not be approximated by string patterns.
        import uuid
        try:
            if str(uuid.UUID(self.tenant_id)) != self.tenant_id:
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise ValueError("bounded local dispatch configuration required") from None


@dataclass(frozen=True, slots=True)
class LocalN8nDispatchSummary:
    cycles: int
    claimed: int
    published: int
    retry_scheduled: int
    dead_lettered: int
    termination: str


class LocalN8nOutboxDispatcher:
    """Drains new and now-due retryable events without manual cycle triggers.

    The OutboxWorker still performs tenant-scoped claims, leases,
    at-least-once/idempotent delivery and backoff. N8nOutboxSink still
    validates event contract and projects only non-PII opaque event fields.
    Nothing in a receipt grants owner or business-command authority.
    """

    def __init__(self, worker: OutboxWorker, config: LocalN8nDispatchConfig):
        if (
            type(worker) is not OutboxWorker
            or type(config) is not LocalN8nDispatchConfig
            or type(worker.sink) is not N8nOutboxSink
            or worker.settings.tenant_id != config.tenant_id
            or worker.context.tenant_id != config.tenant_id
            or worker.sink._tenant_id != config.tenant_id
            or worker.context.environment not in ("LOCAL", "TEST")
        ):
            raise ValueError("shared tenant-bound local n8n worker required")
        # Existing authority gate, unchanged. Never trust an event's tenant,
        # a n8n receipt or the caller-supplied config as independent authority.
        worker._validate_context()
        self._worker = worker
        self._config = config

    def run_until_stopped(self, stop: Event) -> LocalN8nDispatchSummary:
        """Poll autonomously until stop or the hard cycle bound.

        No implicit retries for unexpected provider/store failures. The worker
        alone handles the explicitly retryable, persistently recorded statuses.
        """
        if type(stop) is not Event:
            raise ValueError("explicit local stop event required")

        cycles = 0
        counts = {field: 0 for field in _FIELDS}
        while cycles < self._config.max_cycles:
            if stop.is_set():
                return LocalN8nDispatchSummary(
                    cycles, counts["claimed"], counts["published"],
                    counts["retry_scheduled"], counts["dead_lettered"],
                    "STOP_REQUESTED",
                )
            try:
                self._worker._validate_context()  # recheck each cycle
                result = self._worker.run_once()
            except Exception:
                raise LocalN8nDispatchUnavailable("local_outbox_cycle_unavailable") from None
            if (
                type(result) is not dict
                or set(result) != _FIELDS
                or any(type(v) is not int or v < 0 or
                       v > self._worker.settings.batch_size for v in result.values())
                or result["published"] + result["retry_scheduled"] > result["claimed"]
            ):
                raise LocalN8nDispatchUnavailable("local_outbox_cycle_unavailable")
            cycles += 1
            for key in _FIELDS:
                counts[key] += result[key]
            # Wait even for a busy queue so one source cannot bypass cadence.
            # Event.wait wakes immediately upon shutdown; no hand-stepped
            # polling and no busy-loop, worker backoff still controls retries.
            if stop.wait(self._config.poll_interval_seconds):
                return LocalN8nDispatchSummary(
                    cycles, counts["claimed"], counts["published"],
                    counts["retry_scheduled"], counts["dead_lettered"],
                    "STOP_REQUESTED",
                )
        return LocalN8nDispatchSummary(
            cycles, counts["claimed"], counts["published"],
            counts["retry_scheduled"], counts["dead_lettered"],
            "CYCLE_LIMIT",
        )
