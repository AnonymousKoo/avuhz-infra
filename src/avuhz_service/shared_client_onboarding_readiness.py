"""Reusable shared-client onboarding + System #001 operational gate projection.

Non-authoritative LOCAL/TEST-only planner. NO owner verification, provider read,
grant, workflow activation, payment, outbound message, tenant mutation or
conversion from this projection into a trusted execution context.

Separate BUSINESS and PLATFORM lanes let Avuhz finish reusable operations
without prematurely choosing its first paying client. One client-specific
status must never block shared platform testing. Every reported completion is
an *observation*, not authorization to mutate an external resource.

Before hosting, an independently reviewed server-owned adapter must gather
fresh evidence from exact approved AUTH/DATA providers and enforce the separate
execution approvals. Do not construct this object from a public HTTP request,
n8n payload, event or user-provided status flags for entitlement decisions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

_LOCAL = "LOCAL_TESTED"
_HOSTED = "DEVELOPMENT_VERIFIED"
_ABSENT = "NOT_READY"
_UNKNOWN = "UNKNOWN"
_LEVELS = frozenset({_ABSENT, _LOCAL, _HOSTED, _UNKNOWN})
_LIFECYCLE = frozenset({"NONE", "PENDING_VERIFICATION", "ACTIVE", "UNKNOWN"})
_OPAQUE_BUSINESS = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", re.ASCII)

# These are existing/shared service boundaries, not vertical-specific pipelines.
# Communications/booking are explicitly separate from due review; work
# readiness does not claim any customer has been notified.
_REQUIRED_PLATFORM = (
    ("ACQUISITION_RUNTIME", "CERTIFY_SHARED_ACQUISITION_RUNTIME"),
    ("TRUSTED_INGRESS", "CERTIFY_SHARED_HTTPS_INGRESS"),
    ("N8N_RECEIPT", "CERTIFY_SHARED_N8N_RECEIPT"),
    ("WORK_ITEM_WRITER", "CERTIFY_SHARED_WORK_ITEM_WRITER"),
    ("DUE_REVIEW", "CERTIFY_SHARED_DUE_REVIEW"),
    ("BOOKING_CONFIRMATION", "CERTIFY_BOOKING_CONFIRMATIONS"),
    ("CUSTOMER_COMMUNICATION", "CERTIFY_SHARED_CUSTOMER_COMMUNICATION"),
)
_OPTIONAL_PLATFORM = (
    ("SHARED_BILLING", "CERTIFY_SHARED_BILLING"),
)
_KEYS = frozenset(x[0] for x in _REQUIRED_PLATFORM + _OPTIONAL_PLATFORM)


class SharedClientOnboardingReadinessUnavailable(ValueError):
    """Invalid observations cannot even generate a positive plan."""


@dataclass(frozen=True, slots=True)
class ClientOnboardingObservation:
    """Source-only status, not permission or an authenticated owner receipt.

    The business is optional. This lets the platform lane make progress with
    fictional test clients before a real customer has signed an agreement.
    """
    business_reference: str | None = None
    owner_auth_mfa: str = _UNKNOWN
    independent_business_authority: str = _UNKNOWN
    organization_state: str = "NONE"
    owner_membership_state: str = "NONE"
    signed_principal_binding: str = _UNKNOWN
    pilot_approval: str = _UNKNOWN

    def __post_init__(self):
        # Deliberately no PII, email address, owner name, token or subject.
        business = self.business_reference
        if (business is not None and (
            type(business) is not str or not 3 <= len(business) <= 128
            or not _OPAQUE_BUSINESS.fullmatch(business)
        )):
            raise SharedClientOnboardingReadinessUnavailable("invalid onboarding observation")
        levels = (
            self.owner_auth_mfa,
            self.independent_business_authority,
            self.signed_principal_binding,
            self.pilot_approval,
        )
        if any(type(v) is not str or v not in _LEVELS for v in levels):
            raise SharedClientOnboardingReadinessUnavailable("invalid onboarding observation")
        if (type(self.organization_state) is not str
                or self.organization_state not in _LIFECYCLE
                or type(self.owner_membership_state) is not str
                or self.owner_membership_state not in _LIFECYCLE):
            raise SharedClientOnboardingReadinessUnavailable("invalid onboarding observation")
        # Reject a claim of client lifecycle state when no customer is selected.
        if business is None and (
            any(value != _UNKNOWN for value in levels)
            or self.organization_state != "NONE"
            or self.owner_membership_state != "NONE"
        ):
            raise SharedClientOnboardingReadinessUnavailable("invalid onboarding observation")


@dataclass(frozen=True, slots=True)
class OnboardingGate:
    code: str
    observed_status: str
    sufficient_hosted_evidence_reported: bool


@dataclass(frozen=True, slots=True)
class SharedClientOnboardingReadiness:
    """Non-authoritative output. Never use it to change provider resources."""
    business_stage: str
    next_business_action: str
    next_platform_action: str
    platform_gates: tuple[OnboardingGate, ...]
    # None of these flags may be inferred from a read-model or lifecycle event.
    authorized_to_register: bool = False
    authorized_to_activate: bool = False
    authorized_to_send: bool = False
    authorized_to_bill: bool = False
    authorized_to_open_hosted_intake: bool = False


def _business_stage(observation: ClientOnboardingObservation) -> tuple[str, str]:
    if observation.business_reference is None:
        return "NO_CLIENT_SELECTED", "CONTINUE_PROSPECT_DISCOVERY"
    # Even an attested owner still needs a fresh independent server-bound
    # verification and exact resource-scoped authorization at execution time.
    if observation.independent_business_authority != _HOSTED:
        return "OWNER_VERIFICATION_PENDING", "VERIFY_INDEPENDENT_BUSINESS_AUTHORITY"
    if observation.owner_auth_mfa != _HOSTED:
        return "OWNER_VERIFICATION_PENDING", "VERIFY_FRESH_AUTH_AND_MFA"
    state = observation.organization_state
    member = observation.owner_membership_state
    # Any split, unknown or regressively inconsistent state fails closed.
    if ((state == "NONE") != (member == "NONE")
            or (state == "PENDING_VERIFICATION") != (member == "PENDING_VERIFICATION")
            or (state == "ACTIVE") != (member == "ACTIVE")
            or "UNKNOWN" in (state, member)):
        return "RECONCILIATION_REQUIRED", "RECONCILE_TENANT_AND_OWNER_STATES"
    if state == "NONE":
        return "ENROLLMENT_PENDING", "REVIEW_PENDING_TENANT_REGISTRATION"
    if state == "PENDING_VERIFICATION":
        return "ACTIVATION_PENDING", "REVIEW_SEPARATE_ACTIVE_TRANSITION"
    if observation.signed_principal_binding != _HOSTED:
        return "PRINCIPAL_BINDING_PENDING", "VERIFY_INDEPENDENT_SIGNED_PRINCIPAL_BINDING"
    if observation.pilot_approval != _HOSTED:
        return "PILOT_REVIEW_PENDING", "REVIEW_CONTROLLED_PILOT_CUTOVER"
    # Deliberately "review" rather than "ready": an operator must still
    # verify all platform gates, fresh owner proof and explicit approvals.
    return "PILOT_REVIEW_PENDING", "REVERIFY_OWNER_AND_PILOT_SCOPE"


def review_shared_client_onboarding(
    client: ClientOnboardingObservation, *,
    platform_status: Mapping[str, str],
    paid_pilot: bool = False,
) -> SharedClientOnboardingReadiness:
    """Returns next missing shared-platform and business steps independently.

    LOCAL_TESTED is *never* reported as sufficient hosted evidence. All output
    is non-authoritative even if every status claims DEVELOPMENT_VERIFIED;
    claims cannot authorize an OWNER, n8n, service role, Stripe or a message.
    """
    if (type(client) is not ClientOnboardingObservation
            or type(platform_status) is not dict
            or type(paid_pilot) is not bool
            or set(platform_status) != _KEYS
            or any(type(v) is not str or v not in _LEVELS
                   for v in platform_status.values())):
        raise SharedClientOnboardingReadinessUnavailable("invalid onboarding observation")
    # Revalidate even an object whose attributes were forcibly modified.
    client.__post_init__()
    stages = _REQUIRED_PLATFORM + (_OPTIONAL_PLATFORM if paid_pilot else ())
    gates = tuple(
        OnboardingGate(
            code,
            platform_status[code],
            platform_status[code] == _HOSTED,
        ) for code, _ in stages
    )
    platform_action = next(
        (action for code, action in stages if platform_status[code] != _HOSTED),
        "REVIEW_SEPARATE_HOSTED_PILOT_AUTHORIZATION",
    )
    business_stage, business_action = _business_stage(client)
    return SharedClientOnboardingReadiness(
        business_stage, business_action, platform_action, gates,
    )


def source_only_platform_observation() -> dict[str, str]:
    """Conservative LOCAL/TEST example, NOT a provider inventory snapshot.

    Any real status must come from a separately authorized fresh live read.
    Maintains an explicit distinction between existing local proof and hosted
    operational readiness. Unknown items are not invented as completed.
    """
    return {
        "ACQUISITION_RUNTIME": _LOCAL,
        "TRUSTED_INGRESS": _ABSENT,
        "N8N_RECEIPT": _LOCAL,
        "WORK_ITEM_WRITER": _LOCAL,
        "DUE_REVIEW": _LOCAL,
        "BOOKING_CONFIRMATION": _ABSENT,
        "CUSTOMER_COMMUNICATION": _ABSENT,
        "SHARED_BILLING": _ABSENT,
    }
