"""Bounded LOCAL/TEST composition proof for shared client onboarding.

This harness joins the existing dormant DEVELOPMENT candidates without adding
an endpoint, provider adapter, identity issuer, DATA writer, or authority path.
It deliberately returns no ``TrustedExecutionContext``: synthetic keys,
sessions, directory decisions, or database rows can prove local mechanics but
must never become a LIVE identity.

Registration, activation, active-membership lookup, and principal binding are
separate authority boundaries.  They are not atomic together.  A hosted
composition therefore still requires independently approved provider-backed
adapters, grants, recovery semantics, and exact resource authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext

from .development_company_activation import (
    CompanyActivationReceipt,
    DevelopmentCompanyActivationCandidate,
)
from .development_signed_work_owner_identity import (
    DevelopmentSignedWorkOwnerIdentityResolver,
)
from .development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
    PendingTenantRegistration,
)

_DENIED = "local_client_onboarding_proof_denied"


@dataclass(frozen=True, slots=True)
class LocalClientOnboardingProof:
    """Sanitized source evidence; never an identity, grant, or live receipt."""

    tenant_id: str
    organization_id: str
    principal_reference: str
    activation_duplicate: bool
    state: str = "ACTIVE"
    evidence_class: str = "LOCAL_TEST_ONLY"
    live_identity_authorized: bool = False
    provider_change_authorized: bool = False


class SharedClientOnboardingLocalProofHarness:
    """Sequence exact shared candidates while withholding runtime authority.

    The composition root, never an HTTP caller or workflow event, supplies the
    candidates and resolver.  The pending receipt must have been issued by
    this harness instance; tenant and organization selectors cannot be
    substituted at activation time.
    """

    def __init__(
        self,
        registration: DevelopmentTenantRegistrationCandidate,
        activation: DevelopmentCompanyActivationCandidate,
        *,
        identity_resolver_factory: Callable[
            [str, str], DevelopmentSignedWorkOwnerIdentityResolver
        ],
    ) -> None:
        if (
            type(registration) is not DevelopmentTenantRegistrationCandidate
            or type(activation) is not DevelopmentCompanyActivationCandidate
            or not callable(identity_resolver_factory)
        ):
            raise ValueError("exact shared onboarding candidates required")
        self._registration = registration
        self._activation = activation
        self._identity_resolver_factory = identity_resolver_factory
        self._pending: dict[
            tuple[str, str], tuple[PendingTenantRegistration, str]
        ] = {}

    def register_pending(
        self, *, untrusted_bearer: object, business_reference: object,
    ) -> PendingTenantRegistration:
        receipt = self._registration.propose(**{
            "untrusted_bearer": untrusted_bearer,
            "business_reference": business_reference,
        })
        if (
            type(receipt) is not PendingTenantRegistration
            or receipt.state != "PENDING_VERIFICATION"
            or type(business_reference) is not str
        ):
            raise PermissionError(_DENIED)
        self._pending[(receipt.tenant_id, receipt.organization_id)] = (
            receipt, business_reference,
        )
        return receipt

    def activate_and_bind(
        self,
        *,
        pending: object,
        untrusted_bearer: object,
        business_reference: object,
    ) -> LocalClientOnboardingProof:
        # Validate the configured local composition before attempting the
        # ACTIVE write. A caller-created context, receipt copy, or resolver
        # substitute cannot be used as onboarding authority.
        tracked = self._pending.get(
            (getattr(pending, "tenant_id", None),
             getattr(pending, "organization_id", None))
        )
        if (
            type(pending) is not PendingTenantRegistration
            or tracked is None
            or tracked[0] is not pending
            or tracked[1] != business_reference
        ):
            raise PermissionError(_DENIED)
        try:
            identity_resolver = self._identity_resolver_factory(
                pending.tenant_id, pending.organization_id,
            )
        except Exception:
            raise PermissionError(_DENIED) from None
        if type(identity_resolver) is not DevelopmentSignedWorkOwnerIdentityResolver:
            raise PermissionError(_DENIED)

        activated = self._activation.activate(**{
            "untrusted_bearer": untrusted_bearer,
            "tenant_id": pending.tenant_id,
            "organization_id": pending.organization_id,
            "business_reference": business_reference,
        })
        if (
            type(activated) is not CompanyActivationReceipt
            or activated.state != "ACTIVE"
            or activated.tenant_id != pending.tenant_id
            or activated.organization_id != pending.organization_id
        ):
            raise PermissionError(_DENIED)

        context = identity_resolver.resolve(untrusted_bearer)
        if (
            type(context) is not TrustedExecutionContext
            or context.authenticated is not True
            or context.caller_type != "HUMAN"
            or context.tenant_id != pending.tenant_id
            or context.organization_id != pending.organization_id
            or context.environment != "DEVELOPMENT"
            or context.audience != "avuhz-command-api"
            or context.authentication_strength != "STRONG"
            or context.capabilities != frozenset({"work_intake:create"})
            or context.authority_roles
            or type(context.principal_id) is not str
        ):
            raise PermissionError(_DENIED)

        return LocalClientOnboardingProof(
            tenant_id=pending.tenant_id,
            organization_id=pending.organization_id,
            principal_reference=context.principal_id,
            activation_duplicate=activated.duplicate,
        )
