"""Bounded at-least-once delivery of committed Avuhz lifecycle events."""
from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from avuhz_runtime.in_memory import OutboxMemoryRepository

PUBLISH_CAPABILITY = "event:publish_internal"


class DeliveryUnavailable(RuntimeError):
    """A safe retryable sink outcome; its message is never persisted."""


class DeliveryRejected(RuntimeError):
    """A safe terminal sink outcome; its message is never persisted."""


@dataclass(frozen=True)
class WorkerSettings:
    tenant_id: str
    worker_reference: str = "outbox.worker-local"
    destination_reference: str = "internal.lifecycle-events"
    batch_size: int = 10
    max_attempts: int = 5
    lease_seconds: int = 30
    base_backoff_seconds: int = 5
    max_backoff_seconds: int = 300

    def __post_init__(self):
        import uuid
        try:
            if str(uuid.UUID(self.tenant_id)) != self.tenant_id:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise ValueError("canonical worker tenant is required") from error
        if not 1 <= self.batch_size <= 100:
            raise ValueError("bounded worker batch is required")
        if not 1 <= self.max_attempts <= 16:
            raise ValueError("bounded worker attempts are required")
        if not 5 <= self.lease_seconds <= 900:
            raise ValueError("bounded lease duration is required")
        if not 1 <= self.base_backoff_seconds <= self.max_backoff_seconds <= 3600:
            raise ValueError("bounded retry backoff is required")
        for value in (self.worker_reference, self.destination_reference):
            if not isinstance(value, str) or not 3 <= len(value) <= 128:
                raise ValueError("bounded worker references are required")


class FakeLocalSink:
    """Thread-safe idempotent local sink retaining only bounded sanitized events."""
    def __init__(self, outcomes=()):
        self._lock = threading.Lock()
        self._outcomes = list(outcomes)
        self._receipts = {}

    @property
    def receipts(self):
        with self._lock:
            return copy.deepcopy(tuple(self._receipts.values()))

    def deliver(self, idempotency_key: str, event: dict, delivered_at: str):
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 262144:
            raise DeliveryRejected("event exceeds local sink boundary")
        required = {"event_id", "tenant_id", "correlation_id", "idempotency_key", "sanitized_metadata"}
        if not required <= set(event):
            raise DeliveryRejected("event contract is incomplete")
        with self._lock:
            prior = self._receipts.get(idempotency_key)
            if prior:
                if prior["event_id"] != event["event_id"]:
                    raise DeliveryRejected("idempotency semantic mismatch")
                return {"result": "DUPLICATE", **copy.deepcopy(prior)}
            outcome = self._outcomes.pop(0) if self._outcomes else "PUBLISHED"
            if outcome == "DELIVERY_UNAVAILABLE":
                raise DeliveryUnavailable("fictional local sink unavailable")
            if outcome == "DELIVERY_REJECTED":
                raise DeliveryRejected("fictional local sink rejected event")
            if outcome != "PUBLISHED":
                raise DeliveryRejected("unknown fake sink outcome")
            receipt = {
                "event_id": event["event_id"], "tenant_id": event["tenant_id"],
                "correlation_id": event["correlation_id"],
                "delivery_idempotency_key": idempotency_key, "delivered_at": delivered_at,
                "event": copy.deepcopy(event),
            }
            self._receipts[idempotency_key] = receipt
            return {"result": "PUBLISHED", **copy.deepcopy(receipt)}


_MEMORY_LOCKS = {}
_MEMORY_LOCKS_GUARD = threading.Lock()


def _memory_lock(store):
    identity = id(store)
    with _MEMORY_LOCKS_GUARD:
        entry = _MEMORY_LOCKS.get(identity)
        if entry and entry[0] is store:
            return entry[1]
        lock = threading.RLock()
        _MEMORY_LOCKS[identity] = (store, lock)
        return lock


class MemoryOutboxUnitOfWork:
    """Operational UoW that can commit outbox state but never domain aggregates."""
    def __init__(self, store):
        self.store = store
        self._lock = _memory_lock(store)
        self._lock.acquire()
        self._closed = False
        self.working = SimpleNamespace(
            outbox=copy.deepcopy(store.outbox), events=copy.deepcopy(store.events),
            fail_stage=getattr(store, "fail_stage", None),
        )
        self.outbox = OutboxMemoryRepository(self)
        self.trusted_tenant_id = None

    def bind_trusted_context(self, context):
        if not getattr(context, "authenticated", False) or not getattr(context, "tenant_id", None):
            raise ValueError("trusted worker tenant is required")
        self.trusted_tenant_id = context.tenant_id

    def failpoint(self, name):
        if self.working.fail_stage == name:
            raise RuntimeError("injected outbox failpoint")

    def commit(self):
        self.failpoint("COMMIT")
        self.store.outbox = copy.deepcopy(self.working.outbox)
        self._release()

    def rollback(self):
        self._release()

    def close(self):
        self._release()

    def _release(self):
        if not self._closed:
            self._closed = True
            self._lock.release()


class OutboxWorker:
    def __init__(self, store, uow_factory, sink, trusted_context, settings: WorkerSettings, *, clock=None):
        self.store = store
        self.uow_factory = uow_factory
        self.sink = sink
        self.context = trusted_context
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._validate_context()

    def _validate_context(self):
        context = self.context
        if not context.authenticated or not context.principal_id or context.caller_type != "INTERNAL_SERVICE":
            raise ValueError("trusted service worker identity is required")
        if context.tenant_id != self.settings.tenant_id or context.environment not in {"LOCAL", "TEST"}:
            raise ValueError("local tenant-bound worker identity is required")
        if context.audience != "avuhz-command-api" or PUBLISH_CAPABILITY not in context.capabilities:
            raise ValueError("bounded internal publication capability is required")
        if context.human_authority_role is not None or context.authority_roles:
            raise ValueError("worker identity cannot carry human authority")
        now = self.clock()
        if now.tzinfo is None or not context.authenticated_at:
            raise ValueError("trusted worker authentication time is required")
        if context.expires_at and datetime.fromisoformat(context.expires_at.replace("Z", "+00:00")) <= now:
            raise ValueError("trusted worker identity is expired")

    @staticmethod
    def _timestamp(moment: datetime) -> str:
        if moment.tzinfo is None:
            raise ValueError("trusted worker clock must be timezone-aware")
        return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _uow(self):
        uow = self.uow_factory(self.store)
        if hasattr(uow, "bind_trusted_context"):
            uow.bind_trusted_context(self.context)
        return uow

    @staticmethod
    def _finish(uow, operation):
        try:
            result = operation(uow)
            uow.commit()
            return result
        except Exception:
            if hasattr(uow, "rollback"):
                uow.rollback()
            raise
        finally:
            if hasattr(uow, "close"):
                uow.close()

    def _claim(self, now: datetime):
        current = self._timestamp(now)
        expires = self._timestamp(now + timedelta(seconds=self.settings.lease_seconds))
        uow = self._uow()
        return self._finish(uow, lambda active: active.outbox.claim_next(
            self.settings.tenant_id, self.settings.worker_reference,
            self.settings.destination_reference, current, expires, self.settings.max_attempts,
        ))

    def _published(self, delivery, now: datetime):
        uow = self._uow()
        return self._finish(uow, lambda active: active.outbox.mark_published(
            self.settings.tenant_id, delivery["outbox_delivery_id"], delivery["lease_token"],
            self._timestamp(now),
        ))

    def _failed(self, delivery, now: datetime, safe_error_code: str, terminal: bool):
        next_attempt = None
        if not terminal and delivery["attempt_count"] < self.settings.max_attempts:
            delay = min(
                self.settings.base_backoff_seconds * (2 ** (delivery["attempt_count"] - 1)),
                self.settings.max_backoff_seconds,
            )
            next_attempt = self._timestamp(now + timedelta(seconds=delay))
        uow = self._uow()
        return self._finish(uow, lambda active: active.outbox.mark_failed(
            self.settings.tenant_id, delivery["outbox_delivery_id"], delivery["lease_token"],
            self._timestamp(now), safe_error_code, next_attempt,
        ))

    def run_once(self):
        self._validate_context()
        summary = {"claimed": 0, "published": 0, "retry_scheduled": 0, "dead_lettered": 0}
        for _ in range(self.settings.batch_size):
            claim = self._claim(self.clock())
            if not claim:
                break
            if claim["disposition"] == "DEAD_LETTERED":
                summary["dead_lettered"] += 1
                continue
            summary["claimed"] += 1
            delivery, event = claim["delivery"], claim["event"]
            completed_at = self.clock()
            if event is None:
                self._failed(delivery, completed_at, "EVENT_UNAVAILABLE", True)
                summary["dead_lettered"] += 1
                continue
            try:
                self.sink.deliver(delivery["delivery_idempotency_key"], event, self._timestamp(completed_at))
            except DeliveryRejected:
                self._failed(delivery, completed_at, "DELIVERY_REJECTED", True)
                summary["dead_lettered"] += 1
            except Exception:
                updated = self._failed(delivery, completed_at, "DELIVERY_UNAVAILABLE", False)
                summary["retry_scheduled" if updated["status"] == "FAILED_RETRYABLE" else "dead_lettered"] += 1
            else:
                self._published(delivery, completed_at)
                summary["published"] += 1
        return summary
