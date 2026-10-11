"""Dormant shared company/owner activation transaction for Avuhz DEVELOPMENT.

This is one generic transition from PENDING_VERIFICATION to ACTIVE. It is
NOT an API endpoint, a runtime identity grant, a business ownership verifier,
or permission to operate any third-party systems. It is not wired to hosted
composition; no DATA role currently has the SELECT/UPDATE grants it needs.

First-owner bearer -> exact DEVELOPMENT AUTH JWKS/checkpoint -> fresh provider
MFA/session check -> independent owner-directory verification -> RLS-bound DATA
lookup matching the verified AUTH subject digest -> atomic two-row transition.

All selectors (business, tenant and organization) are UNTRUSTED. They convey
no authority. In particular, merely setting a tenant GUC does not prove
ownership. The SQL must find the exact independently verified owner digest
and business binding before a single state change can occur. No generic
service-role, broad tenant enumeration or cross-tenant discovery is allowed.

The activation of a company is separate from grants to execute workflows,
deploy changes, access customer systems, communicate, or bill customers.
A later hosted binding needs a separately authorized, narrowly scoped writer
with transaction-local RLS and independent owner-directory evidence.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork

from .development_owner_authentication import DevelopmentOwnerAuthenticationCheckpoint

_BUSINESS = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_DENIED = "company_activation_not_authorized"
_CONFLICT = "company_activation_state_conflict"
_UNAVAILABLE = "company_activation_unavailable"


class CompanyActivationConflict(ValueError):
    """State mismatch: no membership is ever activated partially."""


class CompanyActivationUnavailable(RuntimeError):
    """Sanitized DATA error: no connection detail or user data may escape."""


@dataclass(frozen=True, slots=True)
class CompanyActivationReceipt:
    tenant_id: str
    organization_id: str
    state: str = "ACTIVE"
    duplicate: bool = False


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


class DevelopmentCompanyActivationCandidate:
    """Server-side candidate; must never receive browser-derived authority.

    check_fresh_auth_mfa(token, digest) must check a fresh signed factor AND
    current DEVELOPMENT AUTH session. check_business_owner(digest, business,
    environment) must call an independent, server-owned authoritative directory.
    Local lambda mocks in tests are NOT provider proofs or deployable adapters.

    The caller-supplied IDs are only exact-match selectors; the authenticated
    owner's independently derived digest is required by the locked SQL lookup.
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
            raise ValueError("company activation dependencies required")
        self._store = store
        self._auth = auth_checkpoint
        self._check_fresh_auth_mfa = check_fresh_auth_mfa
        self._check_business_owner = check_business_owner

    def activate(
        self,
        *,
        untrusted_bearer: object,
        tenant_id: object,
        organization_id: object,
        business_reference: object,
    ) -> CompanyActivationReceipt:
        if (
            not _uuid(tenant_id)
            or not _uuid(organization_id)
            or type(business_reference) is not str
            or not 3 <= len(business_reference) <= 128
            or not _BUSINESS.fullmatch(business_reference)
        ):
            raise PermissionError(_DENIED)

        try:
            provisional = self._auth.inspect(untrusted_bearer)
            if (
                provisional.environment != "DEVELOPMENT"
                or provisional.auth_project_verified is not True
                or provisional.aal2_token_verified is not True
                or provisional.registration_authorized is not False
                or type(provisional.subject_digest) is not str
                or not _DIGEST.fullmatch(provisional.subject_digest)
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
            raise PermissionError(_DENIED) from None

        # This scoped context is an INTERNAL SQL RLS selector only, not proof
        # of ownership. The independently checked AUTH subject digest and the
        # locked business/owner rows MUST also agree before any UPDATE.
        scoped = TrustedExecutionContext(
            authenticated=True,
            principal_id="service.shared-company-activation",
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
            uow = PostgresUnitOfWork(self._store, trusted_context=scoped)
            db = uow.connection
            row = db.execute(
                "select org.lifecycle_state, "
                "org.record_version as org_version, "
                "member.membership_state, "
                "member.record_version as membership_version, "
                "member.verified_at "
                "from public.avuhz_tenant_organizations as org "
                "join public.avuhz_tenant_owner_memberships as member "
                "on member.tenant_id=org.tenant_id "
                "and member.organization_id=org.organization_id "
                "where org.tenant_id=%s and org.organization_id=%s "
                "and org.business_reference=%s "
                "and member.principal_subject_digest=%s "
                "and member.member_role='OWNER' "
                "for update of org, member",
                (tenant_id, organization_id, business_reference,
                 provisional.subject_digest),
            ).fetchone()
            if row is None:
                raise PermissionError(_DENIED)
            if (
                type(row["org_version"]) is not int
                or type(row["membership_version"]) is not int
                or not 1 <= row["org_version"] < 2147483647
                or not 1 <= row["membership_version"] < 2147483647
            ):
                raise CompanyActivationConflict(_CONFLICT)

            if (
                row["lifecycle_state"] == "ACTIVE"
                and row["membership_state"] == "ACTIVE"
                and row["verified_at"] is not None
            ):
                # Exact authenticated same-owner replay is read-only.
                return CompanyActivationReceipt(
                    tenant_id, organization_id, duplicate=True,
                )

            if (
                row["lifecycle_state"] != "PENDING_VERIFICATION"
                or row["membership_state"] != "PENDING_VERIFICATION"
                or row["verified_at"] is not None
            ):
                raise CompanyActivationConflict(_CONFLICT)

            owner_updated = db.execute(
                "update public.avuhz_tenant_owner_memberships "
                "set membership_state='ACTIVE', verified_at=now(), "
                "record_version=record_version+1, updated_at=now() "
                "where tenant_id=%s and organization_id=%s "
                "and principal_subject_digest=%s and member_role='OWNER' "
                "and membership_state='PENDING_VERIFICATION' "
                "and verified_at is null and record_version=%s "
                "returning tenant_id",
                (tenant_id, organization_id, provisional.subject_digest,
                 row["membership_version"]),
            ).fetchone()
            if owner_updated is None:
                raise CompanyActivationConflict(_CONFLICT)

            company_updated = db.execute(
                "update public.avuhz_tenant_organizations "
                "set lifecycle_state='ACTIVE', record_version=record_version+1, "
                "updated_at=now() "
                "where tenant_id=%s and organization_id=%s "
                "and business_reference=%s "
                "and lifecycle_state='PENDING_VERIFICATION' "
                "and record_version=%s returning tenant_id",
                (tenant_id, organization_id, business_reference,
                 row["org_version"]),
            ).fetchone()
            if company_updated is None:
                raise CompanyActivationConflict(_CONFLICT)

            uow.commit()
            committed = True
            return CompanyActivationReceipt(tenant_id, organization_id)
        except (PermissionError, CompanyActivationConflict):
            raise
        except Exception:
            raise CompanyActivationUnavailable(_UNAVAILABLE) from None
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
