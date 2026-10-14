"""System #001: dormant, tenant-isolated shared work intake and handoffs.

LOCAL/TEST only. A caller MUST inject a real trusted identity resolver before
hosted use; a browser-supplied tenant, owner or role is never authority. This
module creates no API route, n8n workflow, database, event bus, outbox or billing
path. The transition intent is data for a future SHARED Avuhz transactional
event/outbox writer, not evidence of an authoritative persisted event.

No customer-facing free-text fields: only bounded operational classifications,
safe channel codes and opaque caller references. Synthetic in-memory state and
idempotency receipts are not durable runtime or a competing core ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext

OPEN = "OPEN"
BLOCKED = "BLOCKED"
RESOLVED = "RESOLVED"

_OPEN = "OPEN"
_OFFER = "OFFER_HANDOFF"
_ACCEPT = "ACCEPT_HANDOFF"
_CANCEL = "CANCEL_HANDOFF"
_BLOCK = "BLOCK"
_RESUME = "RESUME"
_RESOLVE = "RESOLVE"
_KINDS = frozenset({_OPEN, _OFFER, _ACCEPT, _CANCEL, _BLOCK, _RESUME, _RESOLVE})
_SOURCE = frozenset({"phone", "email", "web", "internal", "api", "other"})
_CLASSIFICATION = frozenset({
    "service_request", "work_order", "support_request", "incident",
    "approval_request", "internal_task", "customer_question", "other",
})
_CAPABILITY = {
    _OPEN: "work_intake:create",
    _OFFER: "work_intake:manage",
    _ACCEPT: "work_intake:accept",
    _CANCEL: "work_intake:manage",
    _BLOCK: "work_intake:manage",
    _RESUME: "work_intake:manage",
    _RESOLVE: "work_intake:manage",
}
_EVENT_TYPE = {
    _OPEN: "work_intake.opened",
    _OFFER: "work_intake.handoff_offered",
    _ACCEPT: "work_intake.handoff_accepted",
    _CANCEL: "work_intake.handoff_cancelled",
    _BLOCK: "work_intake.blocked",
    _RESUME: "work_intake.resumed",
    _RESOLVE: "work_intake.resolved",
}
_REF = re.compile(r"^[a-z][a-z0-9._:-]{1,95}$", re.ASCII)
_KEY = re.compile(r"^[A-Za-z0-9_-]{8,96}$", re.ASCII)


class WorkIntakeDenied(PermissionError):
    """Safe, non-revealing denied operation."""


class WorkIntakeConflict(ValueError):
    """Safe version, state or idempotency collision."""


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _opaque(value: object) -> bool:
    return type(value) is str and _REF.fullmatch(value) is not None


def _fresh(context: TrustedExecutionContext) -> bool:
    if (
        type(context.authenticated_at) is not str
        or type(context.expires_at) is not str
        or not context.authenticated_at.endswith("Z")
        or not context.expires_at.endswith("Z")
        or context.authentication_strength != "STRONG"
        or type(context.step_up_satisfied) is not bool
    ):
        return False
    try:
        issued = datetime.fromisoformat(context.authenticated_at[:-1] + "+00:00")
        expiry = datetime.fromisoformat(context.expires_at[:-1] + "+00:00")
        now = datetime.now(timezone.utc)
        return (
            issued.utcoffset() == timezone.utc.utcoffset(issued)
            and expiry.utcoffset() == timezone.utc.utcoffset(expiry)
            and issued <= now < expiry
        )
    except (TypeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True)
class WorkIntakeCommand:
    kind: str
    work_item_id: str
    idempotency_key: str
    expected_record_version: int | None = None
    source: str | None = None
    classification: str | None = None
    recipient: str | None = None


@dataclass(frozen=True)
class WorkItem:
    tenant_id: str
    work_item_id: str
    owner_reference: str
    state: str
    record_version: int
    source: str
    classification: str
    pending_recipient: str | None = None


@dataclass(frozen=True)
class WorkTransitionIntent:
    """Sanitized non-authoritative intent; shared outbox is a future boundary."""

    event_type: str
    tenant_id: str
    work_item_id: str
    record_version: int
    state: str


@dataclass(frozen=True)
class WorkIntakeResult:
    item: WorkItem
    intent: WorkTransitionIntent | None
    replayed: bool = False



def evolve_work_item(current: WorkItem | None, command: WorkIntakeCommand,
                     context: TrustedExecutionContext,
                     resolve_member: Callable[[str, str], str | None]) -> WorkItem:
    """One shared, side-effect-free domain transition reducer.

    Caller must validate the command and trusted context first and serialize
    authoritative work-item access. This is NOT an authorization endpoint.
    """
    if command.kind == _OPEN:
        if current is not None:
            raise WorkIntakeConflict("work intake item already exists")
        updated = WorkItem(
            tenant_id=context.tenant_id,
            work_item_id=command.work_item_id,
            owner_reference=context.principal_id,
            state=OPEN,
            record_version=1,
            source=command.source,
            classification=command.classification,
        )
    else:
        if current is None:
            raise WorkIntakeDenied("work intake item unavailable")
        actor = context.principal_id
        kind = command.kind
        # Check per-item ownership BEFORE version or state. Otherwise
        # unrelated same-tenant principals can probe record versions.
        if ((kind == _ACCEPT and current.pending_recipient != actor)
            or (kind != _ACCEPT and current.owner_reference != actor)):
            raise WorkIntakeDenied("work intake item unavailable")
        if current.record_version != command.expected_record_version:
            raise WorkIntakeConflict("work intake record version stale")
        if kind == _ACCEPT:
            if current.state != OPEN:
                raise WorkIntakeConflict("work intake handoff unavailable")
            updated = replace(
                current, owner_reference=actor, pending_recipient=None,
                record_version=current.record_version + 1,
            )
        else:
            if kind == _OFFER:
                if (
                    current.state != OPEN
                    or current.pending_recipient is not None
                    or command.recipient == actor
                ):
                    raise WorkIntakeConflict("work intake handoff unavailable")
                try:
                    approved = resolve_member(context.tenant_id, command.recipient)
                    if approved != command.recipient or not _opaque(approved):
                        raise PermissionError
                except Exception:
                    raise WorkIntakeDenied("work intake recipient unavailable") from None
                updated = replace(
                    current, pending_recipient=approved,
                    record_version=current.record_version + 1,
                )
            elif kind == _CANCEL:
                if current.state != OPEN or current.pending_recipient is None:
                    raise WorkIntakeConflict("work intake handoff unavailable")
                updated = replace(
                    current, pending_recipient=None,
                    record_version=current.record_version + 1,
                )
            elif kind == _BLOCK:
                if current.state != OPEN or current.pending_recipient is not None:
                    raise WorkIntakeConflict("work intake block unavailable")
                updated = replace(current, state=BLOCKED, record_version=current.record_version + 1)
            elif kind == _RESUME:
                if current.state != BLOCKED or current.pending_recipient is not None:
                    raise WorkIntakeConflict("work intake resume unavailable")
                updated = replace(current, state=OPEN, record_version=current.record_version + 1)
            elif kind == _RESOLVE:
                if current.state != OPEN or current.pending_recipient is not None:
                    raise WorkIntakeConflict("work intake resolve unavailable")
                updated = replace(current, state=RESOLVED, record_version=current.record_version + 1)
            else:
                raise WorkIntakeDenied("work intake request invalid")

    return updated

class SharedWorkIntakeCandidate:
    """In-memory local prototype; never mount directly as a hosted write API.

    The injected resolver must independently authenticate the identity and
    return an Avuhz TrustedExecutionContext. A caller-crafted context, a true
    boolean callback, a request body or a browser claim is NOT a valid resolver.
    No hosted identity currently grants these new capability strings.
    """

    def __init__(
        self,
        resolve_identity: Callable[[object], TrustedExecutionContext],
        *,
        resolve_tenant_member: Callable[[str, str], str | None],
    ):
        if not callable(resolve_identity) or not callable(resolve_tenant_member):
            raise ValueError("trusted identity and tenant-member resolvers required")
        self._resolve = resolve_identity
        # A trusted tenant-scoped member directory MUST establish eligibility
        # independently of a client-supplied recipient reference. Missing or
        # unavailable membership evidence fails closed before any mutation.
        self._resolve_member = resolve_tenant_member
        self._lock = threading.RLock()
        self._items: dict[tuple[str, str], WorkItem] = {}
        self._receipts: dict[tuple[str, str, str], tuple[str, WorkIntakeResult]] = {}

    def _trusted(self, bearer: object, capability: str) -> TrustedExecutionContext:
        try:
            context = self._resolve(bearer)
            if (
                type(context) is not TrustedExecutionContext
                or context.authenticated is not True
                or context.environment != "DEVELOPMENT"
                or context.audience != "avuhz-command-api"
                or context.caller_type != "HUMAN"
                or not _opaque(context.principal_id)
                or not _canonical_uuid(context.tenant_id)
                or type(context.capabilities) is not frozenset
                or capability not in context.capabilities
                or type(context.authority_roles) is not frozenset
                or context.authority_roles
                or not _fresh(context)
            ):
                raise PermissionError
            return context
        except Exception:
            raise WorkIntakeDenied("work intake authority denied") from None

    @staticmethod
    def _validate(command: object) -> WorkIntakeCommand:
        if type(command) is not WorkIntakeCommand:
            raise WorkIntakeDenied("work intake request invalid")
        if (
            type(command.kind) is not str
            or command.kind not in _KINDS
            or not _canonical_uuid(command.work_item_id)
            or type(command.idempotency_key) is not str
            or _KEY.fullmatch(command.idempotency_key) is None
        ):
            raise WorkIntakeDenied("work intake request invalid")

        if command.kind == _OPEN:
            valid = (
                command.expected_record_version is None
                and type(command.source) is str
                and command.source in _SOURCE
                and type(command.classification) is str
                and command.classification in _CLASSIFICATION
                and command.recipient is None
            )
        else:
            valid = (
                type(command.expected_record_version) is int
                and 1 <= command.expected_record_version <= 2**31 - 1
                and command.source is None
                and command.classification is None
                and (
                    _opaque(command.recipient)
                    if command.kind == _OFFER
                    else command.recipient is None
                )
            )
        if not valid:
            raise WorkIntakeDenied("work intake request invalid")
        return command

    def apply(self, authenticated_identity: object, raw_command: object) -> WorkIntakeResult:
        command = self._validate(raw_command)
        context = self._trusted(authenticated_identity, _CAPABILITY[command.kind])
        # Fingerprint is based solely on validated operational classifications
        # and the already-authenticated caller, never untrusted authority claims.
        payload = {
            "kind": command.kind,
            "work_item_id": command.work_item_id,
            "expected_record_version": command.expected_record_version,
            "source": command.source,
            "classification": command.classification,
            "recipient": command.recipient,
            "principal": context.principal_id,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()

        item_key = (context.tenant_id, command.work_item_id)
        # Caller-specific receipt space prevents another authorized tenant
        # member from reserving the same idempotency key.
        receipt_key = (context.tenant_id, context.principal_id, command.idempotency_key)
        with self._lock:
            current = self._items.get(item_key)
            prior = self._receipts.get(receipt_key)
            if prior is not None:
                if prior[0] != digest:
                    raise WorkIntakeConflict("work intake idempotency conflict")
                # A former owner may not replay an old receipt to recover
                # information after their current item access is revoked.
                if current is None or context.principal_id not in {
                    current.owner_reference, current.pending_recipient,
                }:
                    raise WorkIntakeDenied("work intake item unavailable")
                # No second lifecycle event is generated on retry.
                return replace(prior[1], intent=None, replayed=True)

            updated = evolve_work_item(current, command, context, self._resolve_member)

            result = WorkIntakeResult(
                item=updated,
                intent=WorkTransitionIntent(
                    event_type=_EVENT_TYPE[command.kind],
                    tenant_id=context.tenant_id,
                    work_item_id=command.work_item_id,
                    record_version=updated.record_version,
                    state=updated.state,
                ),
            )
            self._items[item_key] = updated
            self._receipts[receipt_key] = (digest, result)
            return result

    def get(self, authenticated_identity: object, work_item_id: object) -> WorkItem:
        context = self._trusted(authenticated_identity, "work_intake:read")
        if not _canonical_uuid(work_item_id):
            raise WorkIntakeDenied("work intake item unavailable")
        with self._lock:
            item = self._items.get((context.tenant_id, work_item_id))
            if item is None or (
                context.principal_id not in {item.owner_reference, item.pending_recipient}
                and "work_intake:supervise" not in context.capabilities
            ):
                raise WorkIntakeDenied("work intake item unavailable")
            return item
