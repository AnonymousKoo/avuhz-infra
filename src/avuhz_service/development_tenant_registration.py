"""Dormant shared DEVELOPMENT tenant + owner registration transaction candidate.

Neither a Supabase JWT nor a caller-supplied business name proves ownership.
No live enrollment is possible until *independent server-owned* AUTH MFA
freshness and business ownership adapters exist, and a separately reviewed,
tenant-RLS-limited DATA writer role receives exact table grants.

No HTTP route, closed-command-registry entry, hosted role grant, owner record,
tenant activation, billing, or automation is authorized by this module.
It creates only PENDING_VERIFICATION records in a single transaction.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork

from .development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)

_BUSINESS = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", re.ASCII)
_DENIED = "tenant_registration_not_authorized"
_UNAVAILABLE = "tenant_registration_unavailable"
_CONFLICT = "tenant_registration_conflict"


class TenantRegistrationConflict(ValueError):
    """An existing registration is never overwritten or reactivated."""


class TenantRegistrationUnavailable(RuntimeError):
    """Sanitized data-access failure without source diagnostics."""


@dataclass(frozen=True, slots=True)
class PendingTenantRegistration:
    tenant_id: str
    organization_id: str
    state: str = "PENDING_VERIFICATION"
    # Never return or display the AUTH subject digest in this receipt.


class DevelopmentTenantRegistrationCandidate:
    """Single-transaction PENDING-only registration. Not connected to a route.

    check_fresh_auth_mfa(bearer, subject_digest) and
    check_business_owner(subject_digest, business_reference, environment)
    must be independently authenticated, authoritative server-bound adapters,
    not browser claims, local mocks, or an assumed JWT aal2 freshness claim.

    Injecting always-true test callbacks does NOT certify hosted integration.
    """

    def __init__(
        self,
        store: object,
        auth_checkpoint: DevelopmentOwnerAuthenticationCheckpoint,
        *,
        check_fresh_auth_mfa: Callable[[str, str], bool],
        check_business_owner: Callable[[str, str, str], bool],
    ):
        if (
            store is None
            or type(auth_checkpoint) is not DevelopmentOwnerAuthenticationCheckpoint
            or not callable(check_fresh_auth_mfa)
            or not callable(check_business_owner)
        ):
            raise ValueError("authoritative owner-registration dependencies required")
        self._store = store
        self._auth = auth_checkpoint
        self._check_fresh_auth_mfa = check_fresh_auth_mfa
        self._check_business_owner = check_business_owner

    def propose(
        self, *, untrusted_bearer: object, business_reference: object,
    ) -> PendingTenantRegistration:
        if (
            not isinstance(business_reference, str)
            or not 3 <= len(business_reference) <= 128
            or not _BUSINESS.fullmatch(business_reference)
        ):
            raise PermissionError(_DENIED)

        # Verify the actual signed DEVELOPMENT AUTH JWT via the existing
        # project-pinned checkpoint; never trust a digest from caller JSON.
        try:
            provisional = self._auth.inspect(untrusted_bearer)
            if (
                provisional.environment != "DEVELOPMENT"
                or provisional.auth_project_verified is not True
                or provisional.aal2_token_verified is not True
                or provisional.registration_authorized is not False
                or not isinstance(provisional.subject_digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", provisional.subject_digest)
            ):
                raise PermissionError
            if self._check_fresh_auth_mfa(
                untrusted_bearer, provisional.subject_digest
            ) is not True:
                raise PermissionError
            if self._check_business_owner(
                provisional.subject_digest, business_reference, "DEVELOPMENT"
            ) is not True:
                raise PermissionError
        except Exception:
            # Never return a bearer, raw token claims, subject, or provider error.
            raise PermissionError(_DENIED) from None

        tenant_id = str(uuid.uuid4())
        organization_id = str(uuid.uuid4())
        # Context is created by this server-owned candidate, never by a
        # browser. An actual invocation still requires approved composition.
        trusted = TrustedExecutionContext(
            authenticated=True,
            principal_id="service.shared-tenant-registration",
            caller_type="INTERNAL_SERVICE",
            tenant_id=tenant_id,
            organization_id=organization_id,
            capabilities=frozenset(),
            authority_roles=frozenset(),
            environment="DEVELOPMENT",
            audience="avuhz-command-api",
            authentication_strength="STRONG",
            step_up_satisfied=False,
            authenticated_at=None,
        )
        uow = None
        committed = False
        try:
            uow = PostgresUnitOfWork(self._store, trusted_context=trusted)
            db = uow.connection
            # The trusted tenant RLS setting is transaction-local. RLS and
            # FK checks remain mandatory even for an approved writer role.
            org = db.execute(
                "insert into public.avuhz_tenant_organizations "
                "(tenant_id,organization_id,business_reference) "
                "values (%s,%s,%s) "
                "on conflict do nothing returning tenant_id",
                (tenant_id, organization_id, business_reference),
            ).fetchone()
            if org is None:
                raise TenantRegistrationConflict(_CONFLICT)
            member = db.execute(
                "insert into public.avuhz_tenant_owner_memberships "
                "(tenant_id,organization_id,principal_subject_digest) "
                "values (%s,%s,%s) "
                "on conflict do nothing returning tenant_id",
                (tenant_id, organization_id, provisional.subject_digest),
            ).fetchone()
            if member is None:
                raise TenantRegistrationConflict(_CONFLICT)
            uow.commit()
            committed = True
            return PendingTenantRegistration(tenant_id, organization_id)
        except TenantRegistrationConflict:
            raise
        except Exception:
            raise TenantRegistrationUnavailable(_UNAVAILABLE) from None
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
