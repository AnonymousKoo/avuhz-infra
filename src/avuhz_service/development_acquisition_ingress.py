"""Dormant shared DEVELOPMENT website-to-Avuhz authenticated acquisition ingress.

This is NOT an HTTP route, live ingress, credential issuer, hosted identity
registration, grant, or business activation. The current DEVELOPMENT AUTH
allowlist issues no acquisition_intake:receive capability; DATA grants are
also absent. It must remain unreachable until separately approved hosting,
identity enrollment, real active owner verification and DATA permissions.

A client request carries only untrusted acquisition content and an untrusted
authentication token. The existing pinned DEVELOPMENT identity resolver must
verify the token and return a server-owned tenant-scoped INTERNAL_SERVICE
identity with the exact shared intake capability. The organization is read
from authoritative RLS-bound DATA, never from browser headers or form JSON.

The existing shared writer independently rechecks the ACTIVE organization,
verified OWNER, rate limits, consent and tenant RLS within the write
transaction. No vertical-specific infrastructure is added.
"""
from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime
from typing import Callable, Mapping

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork

from .acquisition_intake import validate_acquisition_intake
from .acquisition_intake_command import (
    AcquisitionIntakeReceipt,
    AcquisitionIntakeUnavailable,
    ReceiveAcquisitionIntakeCandidate,
    _require_service_context,
)
from .development_identity import DevelopmentTrustedIdentityResolver

_DENIED = "acquisition_intake_not_authorized"
_UNAVAILABLE = "acquisition_intake_unavailable"
_RECEIVE_CAPABILITY = frozenset({"acquisition_intake:receive"})

# DISTINCT prevents several active verified owners of one company from
# looking like more than one company. LIMIT 2 deliberately denies ambiguous
# active company bindings. The query uses the verified tenant and session RLS,
# not request-supplied tenant, organization, business name or email.
_ACTIVE_ORGANIZATION_SQL = (
    "select distinct org.organization_id "
    "from public.avuhz_tenant_organizations as org "
    "join public.avuhz_tenant_owner_memberships as member "
    "on member.tenant_id=org.tenant_id "
    "and member.organization_id=org.organization_id "
    "where org.tenant_id=%s "
    "and org.lifecycle_state='ACTIVE' "
    "and member.member_role='OWNER' "
    "and member.membership_state='ACTIVE' "
    "and member.verified_at is not null "
    "limit 2"
)


class DevelopmentAuthenticatedAcquisitionIngress:
    """Reusable server-only bridge to the existing tenant-RLS-limited writer.

    Construct only with a real, server-configured DevelopmentTrustedIdentityResolver
    using an authenticated provider verifier and approved server-owned allowlist.
    A synthetic verifier in tests does not authorize hosting or a real customer.

    The rate_limit_admit callback MUST be a durable shared rate limiter in any
    approved live composition; a test lambda is not adequate for deployment.
    """

    def __init__(
        self,
        identity_resolver: DevelopmentTrustedIdentityResolver,
        store: object,
        *,
        rate_limit_admit: Callable[[str, str], bool],
    ) -> None:
        if type(identity_resolver) is not DevelopmentTrustedIdentityResolver:
            raise ValueError("approved DEVELOPMENT identity resolver is required")
        if store is None or not callable(getattr(store, "connection_factory", None)):
            raise ValueError("tenant-scoped DATA store is required")
        if not callable(rate_limit_admit):
            raise ValueError("durable server-owned admission is required")
        self._resolver = identity_resolver
        self._store = store
        self._writer = ReceiveAcquisitionIntakeCandidate(store, rate_limit_admit)

    def receive(
        self,
        *,
        untrusted_identity: object,
        untrusted_payload: object,
        evaluated_at: datetime,
    ) -> AcquisitionIntakeReceipt:
        # Only the existing DEVELOPMENT identity resolver may turn an
        # untrusted provider token into tenant/capability authority. No
        # caller-provided TrustedExecutionContext or organization is accepted.
        try:
            context = self._resolver.resolve(untrusted_identity)
            if type(context) is not TrustedExecutionContext:
                raise PermissionError
            _require_service_context(
                context, evaluated_at, require_organization=False
            )
            if (
                context.caller_type != "INTERNAL_SERVICE"
                or context.organization_id is not None
                or context.capabilities != _RECEIVE_CAPABILITY
                or context.authority_roles != frozenset()
            ):
                raise PermissionError
            # Validate before database contact; never serialize PII in errors.
            validate_acquisition_intake(untrusted_payload)
        except Exception:
            raise PermissionError(_DENIED) from None

        # An authenticated service knows its tenant, NOT an organization id.
        # Lookup uses transaction-local tenant RLS and verified owner records.
        # A second transaction in the existing writer repeats this check
        # under row locks before inserting; no stale read grants authority.
        uow = None
        try:
            uow = PostgresUnitOfWork(self._store, trusted_context=context)
            rows = uow.connection.execute(
                _ACTIVE_ORGANIZATION_SQL, (context.tenant_id,)
            ).fetchall()
            if not isinstance(rows, (list, tuple)) or len(rows) != 1:
                raise PermissionError
            row = rows[0]
            if not isinstance(row, Mapping):
                raise PermissionError
            raw_org = row.get("organization_id")
            organization_id = str(uuid.UUID(str(raw_org)))
            if not isinstance(raw_org, (str, uuid.UUID)) or str(raw_org) != organization_id:
                raise PermissionError
        except PermissionError:
            raise PermissionError(_DENIED) from None
        except (KeyError, TypeError, ValueError, AttributeError):
            raise PermissionError(_DENIED) from None
        except Exception:
            raise AcquisitionIntakeUnavailable(_UNAVAILABLE) from None
        finally:
            if uow is not None:
                try:
                    uow.rollback()
                except Exception:
                    pass
                try:
                    uow.close()
                except Exception:
                    pass

        # No direct INSERT path here: the shared writer performs the final
        # active OWNER + company check, rate admission, RLS INSERT and replay
        # handling with a tenant/organization identifier sourced only from DATA.
        return self._writer.receive(
            untrusted_payload,
            replace(context, organization_id=organization_id),
            evaluated_at=evaluated_at,
        )
