"""Shared System #001 due Work Item reader: LOCAL/TEST, not an HTTP route.

Uses the existing trusted HUMAN resolver, PostgresUnitOfWork tenant RLS, and
shared due-review predicate. Only current-owner rows are eligible. No network
send, notification, scheduler, tenant creation, customer text or writes.
Deployment requires separate hosted identity/membership and DATA migration proof.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork

from .shared_work_intake_candidate import (
    SharedWorkIntakeCandidate, WorkIntakeDenied, WorkItem, _opaque,
)
from .shared_revenue_followup_review import (
    FollowupObservation, FollowupReviewCandidate,
    FollowupReviewPolicy, review_followup_due,
)

_MAX = 100
_FAIL = "shared follow-up read unavailable"


class SharedFollowupReadUnavailable(RuntimeError):
    """No SQL, role, account, contact or provider failure details."""


class SharedDueWorkReadCandidate:
    """Read-only candidate: no alternate auth, tenancy or due scheduler.

    The resolver MUST independently authenticate identity; the membership
    callback MUST be backed by real server-controlled tenant membership using
    the same RLS-bounded connection. Passing a caller-created context is not
    authentication. No hosted capability is provisioned by this class.
    """

    def __init__(
        self, store, *,
        resolve_identity: Callable[[object], TrustedExecutionContext],
        resolve_tenant_member: Callable[[object, str, str], str | None],
    ):
        if (
            store is None or not callable(getattr(store, "connection_factory", None))
            or not callable(resolve_identity) or not callable(resolve_tenant_member)
        ):
            raise ValueError("shared follow-up read dependencies required")
        self._store = store
        self._member = resolve_tenant_member
        self._guard = SharedWorkIntakeCandidate(
            resolve_identity, resolve_tenant_member=lambda _tenant, _member: None,
        )

    def review_owned_due(
        self, identity_evidence: object, *,
        policy: FollowupReviewPolicy, now: datetime, limit: int = _MAX,
    ) -> tuple[FollowupReviewCandidate, ...]:
        if (
            type(policy) is not FollowupReviewPolicy
            or type(now) is not datetime or now.tzinfo is not timezone.utc
            or type(limit) is not int or not 1 <= limit <= _MAX
        ):
            raise SharedFollowupReadUnavailable(_FAIL)

        # Reuses existing approved application-level capability names; does
        # not accept tenant, role or owner from browser/n8n input.
        context = self._guard._trusted(identity_evidence, "work_intake:read")
        uow = None
        try:
            uow = PostgresUnitOfWork(self._store, trusted_context=context)
            con = uow.connection
            role = con.execute(
                "select current_user='avuhz_command_service' "
                "and current_setting('row_security')='on' "
                "and exists (select 1 from pg_roles r where r.rolname=current_user "
                "and not r.rolcanlogin and not r.rolsuper and not r.rolbypassrls "
                "and not r.rolcreaterole and not r.rolcreatedb and not r.rolreplication "
                "and not r.rolinherit) "
                "and not exists (select 1 from pg_auth_members m "
                "join pg_roles r on r.oid=m.member where r.rolname=current_user) "
                "and exists (select 1 from pg_class c where "
                "c.oid=to_regclass('public.avuhz_work_items') "
                "and c.relkind='r' and c.relrowsecurity and c.relforcerowsecurity "
                "and c.relowner<>(select oid from pg_roles where rolname=current_user)) "
                "and (select count(*) from pg_policies p where p.schemaname='public' "
                "and p.tablename='avuhz_work_items')=1 "
                "and exists (select 1 from pg_policies p where p.schemaname='public' "
                "and p.tablename='avuhz_work_items' "
                "and p.policyname='avuhz_command_service_tenant_isolation' "
                "and p.roles=ARRAY['avuhz_command_service']::name[] "
                "and p.cmd='ALL' and p.permissive='PERMISSIVE' "
                "and encode(sha256(convert_to("
                "coalesce(p.qual,'<NULL>')||'|'||coalesce(p.with_check,'<NULL>'),"
                "'UTF8')),'hex')="
                "'1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88') "
                "and exists (select 1 from pg_attribute a where "
                "a.attrelid=to_regclass('public.avuhz_work_items') "
                "and a.attname='next_action_due_at' and not a.attisdropped "
                "and a.atttypid='pg_catalog.timestamptz'::regtype) "
                "and has_table_privilege(current_user,'public.avuhz_work_items','SELECT') "
                "and not has_table_privilege(current_user,'public.avuhz_work_items','DELETE') "
                "as bounded"
            ).fetchone()
            if role is None or role["bounded"] is not True:
                raise SharedFollowupReadUnavailable(_FAIL)

            try:
                member = self._member(con, context.tenant_id, context.principal_id)
            except Exception:
                member = None
            if member != context.principal_id or not _opaque(member):
                raise WorkIntakeDenied("work intake authority denied")

            rows = con.execute(
                "select tenant_id,work_item_id,owner_reference,state,record_version,"
                "source,classification,pending_recipient_reference,next_action_due_at "
                "from public.avuhz_work_items "
                "where tenant_id=%s and owner_reference=%s "
                "and state in ('OPEN','BLOCKED') "
                "and next_action_due_at is not null and next_action_due_at <= %s "
                "order by next_action_due_at,work_item_id limit %s",
                (context.tenant_id, context.principal_id, now, limit),
            ).fetchall()
            if len(rows) > limit:
                raise SharedFollowupReadUnavailable(_FAIL)
            observations = []
            for row in rows:
                due = row["next_action_due_at"]
                if (
                    type(due) is not datetime or due.tzinfo is None
                    or due.utcoffset() != timedelta(0) or due.microsecond != 0
                    or str(row["tenant_id"]) != context.tenant_id
                    or row["owner_reference"] != context.principal_id
                ):
                    raise SharedFollowupReadUnavailable(_FAIL)
                due_text = due.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                item = WorkItem(
                    tenant_id=context.tenant_id,
                    work_item_id=str(row["work_item_id"]),
                    owner_reference=row["owner_reference"],
                    state=row["state"],
                    record_version=row["record_version"],
                    source=row["source"],
                    classification=row["classification"],
                    pending_recipient=row["pending_recipient_reference"],
                    next_action_due_at=due_text,
                )
                observations.append(FollowupObservation(item, due_text))
            result = review_followup_due(
                tuple(observations), trusted_tenant_id=context.tenant_id,
                policy=policy, now=now,
            ) if observations else ()
            return result
        except (SharedFollowupReadUnavailable, WorkIntakeDenied):
            raise
        except Exception:
            raise SharedFollowupReadUnavailable(_FAIL) from None
        finally:
            if uow is not None:
                cleanup_failed = False
                try:
                    uow.rollback()
                except Exception:
                    cleanup_failed = True
                try:
                    uow.close()
                except Exception:
                    cleanup_failed = True
                if cleanup_failed:
                    raise SharedFollowupReadUnavailable(_FAIL) from None
