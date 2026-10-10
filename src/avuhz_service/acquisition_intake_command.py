"""Dormant shared acquisition-intake PostgreSQL writer candidate.

This is NOT a public command, route, entitlement or registered handler.
No current DEVELOPMENT identity carries acquisition_intake:receive. The
three registries currently have no command-role SELECT/INSERT grants.
Before activation, a separately verified server-owned website binding,
durable rate limiter, scoped grants and real owner registration are required.

Never pass browser-created TrustedExecutionContext objects to this service.
The server's independently authenticated identity resolver must establish
the caller and tenant/organization; client payload labels are not authority.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork

from .acquisition_intake import ValidatedAcquisitionIntake, validate_acquisition_intake


_RECEIVE_CAPABILITY = "acquisition_intake:receive"
_DENIED = "acquisition_intake_not_authorized"
_UNAVAILABLE = "acquisition_intake_unavailable"
_CONFLICT = "acquisition_intake_conflict"


class AcquisitionIntakeUnavailable(RuntimeError):
    """Sanitized failure; never propagate PostgreSQL exceptions or input PII."""


@dataclass(frozen=True, slots=True)
class AcquisitionIntakeReceipt:
    intake_id: str
    duplicate: bool


def _canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError):
        return False


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        timestamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return timestamp if timestamp.utcoffset() == timedelta(0) else None


def _require_service_context(context: object, now: datetime) -> TrustedExecutionContext:
    """Server-only guard. It does not mint identity, grants or owner proof."""
    if (
        type(context) is not TrustedExecutionContext
        or now.tzinfo is None or now.utcoffset() != timedelta(0)
        or context.authenticated is not True
        or context.caller_type != "INTERNAL_SERVICE"
        or context.environment != "DEVELOPMENT"
        or context.audience != "avuhz-command-api"
        or not isinstance(context.principal_id, str)
        or not context.principal_id
        or not _canonical_uuid(context.tenant_id)
        or not _canonical_uuid(context.organization_id)
        or type(context.capabilities) is not frozenset
        or _RECEIVE_CAPABILITY not in context.capabilities
    ):
        raise PermissionError(_DENIED)
    issued = _utc_timestamp(context.authenticated_at)
    expires = _utc_timestamp(context.expires_at)
    if (
        issued is None or expires is None
        or issued > now or now - issued > timedelta(minutes=15)
        or expires <= now or expires <= issued
    ):
        raise PermissionError(_DENIED)
    return context


def _content_matches(row: dict, request: ValidatedAcquisitionIntake) -> bool:
    """Never serialize compared PII into a log, event or exception."""
    return all(
        row.get(name) == getattr(request, name)
        for name in (
            "source_system", "route_reference", "business_name", "contact_name",
            "contact_email", "contact_phone", "preferred_contact_method",
            "contact_requested", "diagnostic_summary",
        )
    )


class ReceiveAcquisitionIntakeCandidate:
    """Offline-testable shared writer; intentionally absent from command registry.

    The caller MUST supply an authenticated server context (not a website
    form field) and a durable, server-owned rate-limit admission function.
    An injected True-returning test function is NOT an activation-ready
    limiter. No hosted grants, connection or endpoint are enabled here.
    """

    def __init__(
        self,
        store,
        rate_limit_admit: Callable[[str, str, str], bool],
    ):
        if store is None or not callable(rate_limit_admit):
            raise ValueError("trusted writer dependencies required")
        self._store = store
        self._rate_limit_admit = rate_limit_admit

    def receive(
        self,
        payload: object,
        context: TrustedExecutionContext,
        *,
        evaluated_at: datetime,
    ) -> AcquisitionIntakeReceipt:
        authority = _require_service_context(context, evaluated_at)
        request = validate_acquisition_intake(payload)

        # Only opaque references leave this module to the limiter, not PII.
        try:
            admitted = self._rate_limit_admit(
                authority.tenant_id, authority.principal_id, request.external_request_id
            )
        except Exception:
            raise PermissionError(_DENIED) from None
        if admitted is not True:
            raise PermissionError(_DENIED)

        uow = None
        committed = False
        try:
            # Existing PostgresUnitOfWork binds the verified tenant as a
            # transaction-local RLS setting, never a browser-provided value.
            uow = PostgresUnitOfWork(self._store, trusted_context=authority)
            connection = uow.connection
            bound = connection.execute(
                "select 1 as authorized from public.avuhz_tenant_organizations as org "
                "where org.tenant_id=%s and org.organization_id=%s "
                "and org.lifecycle_state='ACTIVE' and exists ("
                "select 1 from public.avuhz_tenant_owner_memberships as owner "
                "where owner.tenant_id=org.tenant_id "
                "and owner.organization_id=org.organization_id "
                "and owner.member_role='OWNER' "
                "and owner.membership_state='ACTIVE' "
                "and owner.verified_at is not null)",
                (authority.tenant_id, authority.organization_id),
            ).fetchone()
            if not bound:
                raise PermissionError(_DENIED)

            intake_id = str(uuid.uuid4())
            inserted = connection.execute(
                "insert into public.avuhz_acquisition_intake_requests "
                "(intake_id,tenant_id,organization_id,external_request_id,"
                "source_system,route_reference,business_name,contact_name,"
                "contact_email,contact_phone,preferred_contact_method,"
                "contact_requested,diagnostic_summary) "
                "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "on conflict (tenant_id,external_request_id) do nothing "
                "returning intake_id",
                (
                    intake_id, authority.tenant_id, authority.organization_id,
                    request.external_request_id, request.source_system,
                    request.route_reference, request.business_name,
                    request.contact_name, request.contact_email,
                    request.contact_phone, request.preferred_contact_method,
                    request.contact_requested, request.diagnostic_summary,
                ),
            ).fetchone()
            if inserted:
                receipt = AcquisitionIntakeReceipt(str(inserted["intake_id"]), False)
            else:
                original = connection.execute(
                    "select intake_id,source_system,route_reference,business_name,"
                    "contact_name,contact_email,contact_phone,preferred_contact_method,"
                    "contact_requested,diagnostic_summary "
                    "from public.avuhz_acquisition_intake_requests "
                    "where tenant_id=%s and organization_id=%s "
                    "and external_request_id=%s for update",
                    (
                        authority.tenant_id, authority.organization_id,
                        request.external_request_id,
                    ),
                ).fetchone()
                if original is None or not _content_matches(original, request):
                    raise ValueError(_CONFLICT)
                receipt = AcquisitionIntakeReceipt(str(original["intake_id"]), True)

            uow.commit()
            committed = True
            return receipt
        except (PermissionError, ValueError):
            raise
        except Exception:
            raise AcquisitionIntakeUnavailable(_UNAVAILABLE) from None
        finally:
            if uow is not None:
                try:
                    if not committed:
                        uow.rollback()
                finally:
                    uow.close()
