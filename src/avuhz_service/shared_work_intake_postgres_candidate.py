"""Dormant System #001 PostgreSQL writer using Avuhz's existing transaction.

LOCAL/TEST source candidate; no hosted route, credential, workflow activation or
new queue. A server-owned identity resolver and tenant membership directory are
mandatory. Nothing in this module proves a real user/business has been enrolled.
The existing shared PostgresUnitOfWork atomically commits the authoritative
WORK_ITEM, shared idempotency ledger, lifecycle event and outbox delivery.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.models import PreparedCommand
from avuhz_runtime.postgres import PostgresUnitOfWork

from .shared_work_intake_candidate import (
    SharedWorkIntakeCandidate, WorkItem, WorkIntakeCommand, WorkIntakeConflict,
    WorkIntakeDenied, _CAPABILITY, _opaque, evolve_work_item,
)

_COMMAND_TYPE = "TransitionWorkItem"
_SUBJECT_TYPE = "WORK_ITEM"
_SAFE_UNAVAILABLE = "work_intake_persistence_unavailable"
_SAFE_DENIED = "work intake item unavailable"


class WorkIntakePersistenceUnavailable(RuntimeError):
    """Sanitized failure: never return SQL diagnostics or customer details."""


@dataclass(frozen=True)
class DurableWorkReceipt:
    work_item_id: str
    accepted_version: int
    replayed: bool
    event_id: str | None


def _loaded_work_item(row, tenant_id: str) -> WorkItem | None:
    if row is None:
        return None
    return WorkItem(
        tenant_id=tenant_id,
        work_item_id=str(row["work_item_id"]),
        owner_reference=row["owner_reference"],
        state=row["state"],
        record_version=row["record_version"],
        source=row["source"],
        classification=row["classification"],
        pending_recipient=row["pending_recipient_reference"],
    )


def _fingerprint(context: TrustedExecutionContext, command: WorkIntakeCommand) -> str:
    # Canonical validated classification only, no contact information or JWT.
    payload = {
        "tenant": context.tenant_id, "principal": context.principal_id,
        "kind": command.kind, "item": command.work_item_id,
        "expected": command.expected_record_version,
        "source": command.source, "classification": command.classification,
        "recipient": command.recipient,
    }
    if command.next_action_due_at is not None:
        payload["next_action_due_at"] = command.next_action_due_at
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).hexdigest()
    return "fpv1:" + digest


def _trusted_now(clock) -> datetime:
    value = clock()
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("work intake clock unavailable")
    return value


class SharedWorkIntakePostgresCandidate:
    """Reusable shared DATA command candidate, not a public/registered handler.

    resolve_identity is a server-controlled authenticated identity provider:
    never accept a caller-constructed TrustedExecutionContext as proof.
    resolve_tenant_member(connection,tenant,opaque_principal) must query a
    separately verified authoritative membership source with the SAME UoW.
    Reject missing/revoked actors and handoff recipients. Its synthetic test
    implementation grants NO right to deploy a real customer workflow.

    Connection factory MUST already hold the bounded avuhz_command_service
    role. No service_role fallback, automatic grants, owner/tenant enrollment.
    """

    def __init__(
        self,
        store,
        *,
        resolve_identity: Callable[[object], TrustedExecutionContext],
        resolve_tenant_member: Callable[[object, str, str], str | None],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if (
            store is None or not hasattr(store, "connection_factory")
            or not callable(resolve_identity)
            or not callable(resolve_tenant_member)
            or not callable(clock)
        ):
            raise ValueError("trusted shared work item writer dependencies required")
        self._store = store
        self._member = resolve_tenant_member
        self._clock = clock
        # Share the existing command validation and trusted identity guard;
        # this in-memory guard is never used to accept a state change.
        self._guard = SharedWorkIntakeCandidate(
            resolve_identity,
            resolve_tenant_member=lambda _tenant, _member: None,
        )

    def execute(self, identity_evidence: object, raw_command: object) -> DurableWorkReceipt:
        command = self._guard._validate(raw_command)
        context = self._guard._trusted(identity_evidence, _CAPABILITY[command.kind])
        fingerprint = _fingerprint(context, command)
        key = (
            context.tenant_id, context.principal_id, _COMMAND_TYPE, _SUBJECT_TYPE,
            "SUBJECT:" + command.work_item_id, command.idempotency_key,
        )
        uow = None
        committed = False
        try:
            uow = PostgresUnitOfWork(self._store, trusted_context=context)
            con = uow.connection
            # No elevated-role or owner bypass, even in local tests.
            role = con.execute(
                "select current_user='avuhz_command_service' "
                "and current_setting('row_security')='on' "
                "and exists (select 1 from pg_roles r "
                "where r.rolname=current_user and not r.rolcanlogin "
                "and not r.rolsuper and not r.rolbypassrls "
                "and not r.rolcreaterole and not r.rolcreatedb "
                "and not r.rolreplication and not r.rolinherit) "
                "and not exists (select 1 from pg_auth_members m "
                "join pg_roles r on r.oid=m.member "
                "where r.rolname=current_user) "
                "and (select count(*) from pg_class c "
                "join pg_namespace n on n.oid=c.relnamespace "
                "where n.nspname='public' "
                "and c.relname in ('avuhz_work_items',"
                "'avuhz_idempotency_records','avuhz_lifecycle_events',"
                "'avuhz_outbox_deliveries') "
                "and c.relkind='r' and c.relrowsecurity "
                "and c.relowner<>(select oid from pg_roles where rolname=current_user))=4 "
                "and (select count(*) from pg_class c where "
                "c.oid='public.avuhz_work_items'::regclass "
                "and c.relforcerowsecurity)=1 "
                "and (select count(*) from pg_attribute a "
                "where a.attrelid='public.avuhz_work_items'::regclass "
                "and a.attname='next_action_due_at' and not a.attisdropped "
                "and a.atttypid='pg_catalog.timestamptz'::regtype "
                "and not a.attnotnull and not a.atthasdef)=1 "
                "and has_column_privilege(current_user,"
                "'public.avuhz_work_items','next_action_due_at','INSERT') "
                "and (select count(*) from pg_policies p "
                "where p.schemaname='public' and p.tablename in "
                "('avuhz_work_items','avuhz_idempotency_records',"
                "'avuhz_lifecycle_events','avuhz_outbox_deliveries'))=4 "
                "and (select count(*) from pg_policies p "
                "where p.schemaname='public' and p.tablename in "
                "('avuhz_work_items','avuhz_idempotency_records',"
                "'avuhz_lifecycle_events','avuhz_outbox_deliveries') "
                "and p.policyname='avuhz_command_service_tenant_isolation' "
                "and p.roles=ARRAY['avuhz_command_service']::name[] "
                "and p.cmd='ALL' "
                "and strpos(p.qual,'avuhz.tenant_id')>0 "
                "and strpos(p.with_check,'avuhz.tenant_id')>0)=4 "
                "and not has_table_privilege(current_user,"
                "'public.avuhz_work_items','DELETE') "
                "and not has_column_privilege(current_user,"
                "'public.avuhz_work_items','tenant_id','UPDATE') "
                "as bounded"
            ).fetchone()
            if role is None or role["bounded"] is not True:
                raise WorkIntakeDenied("work intake authority denied")
            # Server-maintained membership check applies to the ACTOR on
            # every write, not only new handoff recipients.
            try:
                member = self._member(con, context.tenant_id, context.principal_id)
            except Exception:
                member = None
            if member != context.principal_id or not _opaque(member):
                raise WorkIntakeDenied("work intake authority denied")

            # Serialize even first-time OPENs (an absent row cannot be
            # locked FOR UPDATE). Hash collisions only cause conservative
            # extra serialization, never cross-tenant authority.
            con.execute(
                "select pg_advisory_xact_lock(hashtextextended(%s,0))",
                (context.tenant_id + ":" + command.work_item_id,),
            )
            row = con.execute(
                "select tenant_id,work_item_id,owner_reference,"
                "pending_recipient_reference,source,classification,state,record_version "
                "from public.avuhz_work_items "
                "where tenant_id=%s and work_item_id=%s for update",
                (context.tenant_id, command.work_item_id),
            ).fetchone()
            current = _loaded_work_item(row, context.tenant_id)

            # Never disclose existence/version to an unauthorized same-tenant
            # colleague. A previous owner cannot retrieve historical receipts
            # once a handoff has been accepted.
            if current is not None and context.principal_id not in {
                current.owner_reference, current.pending_recipient,
            }:
                raise WorkIntakeDenied(_SAFE_DENIED)

            prior = uow.idempotency.get(key)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise WorkIntakeConflict("work intake idempotency conflict")
                reference = prior["command_id"]
                if (
                    current is None or type(reference) is not str
                    or not reference.startswith(command.work_item_id + ":")
                ):
                    raise WorkIntakeDenied(_SAFE_DENIED)
                try:
                    accepted_version = int(reference.rsplit(":", 1)[-1])
                except ValueError:
                    raise WorkIntakeDenied(_SAFE_DENIED) from None
                if not 1 <= accepted_version <= current.record_version:
                    raise WorkIntakeDenied(_SAFE_DENIED)
                uow.rollback()  # no event/outbox change on replay
                return DurableWorkReceipt(command.work_item_id, accepted_version, True, None)

            # The initial next-action deadline is part of the first OPEN
            # transaction, NEVER a browser-triggered scheduling side effect.
            # Enforce server-clock bounds only for a *new* command; a replay
            # must not fail just because real time passed after the commit.
            now = _trusted_now(self._clock)
            timestamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
            if command.kind == "OPEN" and command.next_action_due_at is not None:
                due = datetime.strptime(
                    command.next_action_due_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
                if not timedelta(minutes=1) <= due - now <= timedelta(days=30):
                    raise WorkIntakeDenied("work intake deadline unavailable")

            # Shared reducer enforces optimistic versions, owner authority,
            # handoff target validity, state machine and no reopened resolution.
            updated = evolve_work_item(
                current, command, context,
                lambda tenant, member: self._member(con, tenant, member),
            )
            prepared = PreparedCommand(
                command_type=_COMMAND_TYPE, command_id=str(uuid.uuid4()),
                tenant_id=context.tenant_id, subject_type=_SUBJECT_TYPE,
                subject_id=command.work_item_id, caller_identity_claim={},
                correlation_id=str(uuid.uuid4()),
                idempotency_key=command.idempotency_key,
                environment=context.environment,
                payload={}, payload_schema="urn:avuhz:work-intake:local-only",
                payload_version=1, expected_record_version=command.expected_record_version,
            )
            race = uow.idempotency.reserve(key, fingerprint, prepared=prepared)
            if race is not None:
                if race["fingerprint"] != fingerprint:
                    raise WorkIntakeConflict("work intake idempotency conflict")
                # A concurrent OPEN may have observed an absent item before
                # the winning transaction completed. Re-read AFTER the unique
                # receipt reservation waits for that commit, and verify present
                # ownership before revealing the accepted receipt.
                if current is None:
                    refreshed = con.execute(
                        "select tenant_id,work_item_id,owner_reference,"
                        "pending_recipient_reference,source,classification,state,record_version "
                        "from public.avuhz_work_items "
                        "where tenant_id=%s and work_item_id=%s for update",
                        (context.tenant_id, command.work_item_id),
                    ).fetchone()
                    current = _loaded_work_item(refreshed, context.tenant_id)
                if current is None or context.principal_id not in {
                    current.owner_reference, current.pending_recipient,
                }:
                    raise WorkIntakeDenied(_SAFE_DENIED)
                reference = race["command_id"]
                if type(reference) is not str or not reference.startswith(command.work_item_id + ":"):
                    raise WorkIntakeConflict("work intake idempotency conflict")
                try:
                    accepted_version = int(reference.rsplit(":", 1)[-1])
                except ValueError:
                    raise WorkIntakeConflict("work intake idempotency conflict") from None
                if not 1 <= accepted_version <= current.record_version:
                    raise WorkIntakeConflict("work intake idempotency conflict")
                uow.rollback()
                return DurableWorkReceipt(command.work_item_id, accepted_version, True, None)

            if command.kind == "OPEN":
                con.execute(
                    "insert into public.avuhz_work_items "
                    "(tenant_id,work_item_id,owner_reference,pending_recipient_reference,"
                    "source,classification,state,record_version,next_action_due_at) "
                    "values (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        context.tenant_id, updated.work_item_id, updated.owner_reference,
                        updated.pending_recipient, updated.source, updated.classification,
                        updated.state, updated.record_version,
                        updated.next_action_due_at,
                    ),
                )
            else:
                cur = con.execute(
                    "update public.avuhz_work_items set "
                    "owner_reference=%s,pending_recipient_reference=%s,"
                    "state=%s,record_version=%s,updated_at=now() "
                    "where tenant_id=%s and work_item_id=%s and record_version=%s",
                    (
                        updated.owner_reference, updated.pending_recipient,
                        updated.state, updated.record_version,
                        context.tenant_id, command.work_item_id,
                        command.expected_record_version,
                    ),
                )
                if cur.rowcount != 1:
                    raise WorkIntakeConflict("work intake record version stale")

            event_id = str(uuid.uuid4())
            uow.lifecycle_events.append({
                "event_id": event_id,
                "event_type": {
                    "OPEN": "work_intake.opened",
                    "OFFER_HANDOFF": "work_intake.handoff_offered",
                    "ACCEPT_HANDOFF": "work_intake.handoff_accepted",
                    "CANCEL_HANDOFF": "work_intake.handoff_cancelled",
                    "BLOCK": "work_intake.blocked",
                    "RESUME": "work_intake.resumed",
                    "RESOLVE": "work_intake.resolved",
                }[command.kind],
                "event_schema_version": 1,
                "tenant_id": context.tenant_id,
                "authoritative_subject_reference": {
                    "reference_type": "WORK_ITEM",
                    "reference_id": command.work_item_id,
                },
                "authoritative_subject_version": updated.record_version,
                "occurred_at": timestamp,
                "producer_reference": "command.service-01",
                "correlation_id": prepared.correlation_id,
                "idempotency_key": "work-item:" + event_id,
                "visibility": "TENANT_OPERATIONAL",
                "sanitized_metadata": {
                    "work_item_id": command.work_item_id,
                    "state": updated.state,
                },
            })
            uow.outbox.append({"event_id": event_id, "status": "PENDING"})
            uow.idempotency.save_result(
                key, {"command_id": command.work_item_id + ":" + str(updated.record_version)}
            )
            uow.commit()
            committed = True
            return DurableWorkReceipt(command.work_item_id, updated.record_version, False, event_id)
        except (WorkIntakeDenied, WorkIntakeConflict):
            raise
        except Exception:
            raise WorkIntakePersistenceUnavailable(_SAFE_UNAVAILABLE) from None
        finally:
            if uow is not None:
                if not committed:
                    try:
                        uow.rollback()
                    except Exception:
                        pass
                try:
                    uow.close()
                except Exception:
                    pass
