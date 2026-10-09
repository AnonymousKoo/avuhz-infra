"""Shared, read-only tenant-owner preflight for future Avuhz onboarding.

INACTIVE: no API, command, identity resolver, tenant registry, membership
writer, DATA migration, billing integration or n8n dispatch uses this module.
It must never be treated as registration authority. The context and verifier
MUST originate in independent server-owned trust boundaries, never a client
payload or workflow-supplied claim. No such ownership verifier is live today.

One eligible result means only that human review may be requested; it does
not create a tenant, grant owner rights, or establish service entitlements.

>>> from avuhz_runtime.guards import TrustedExecutionContext
>>> from datetime import datetime, timezone
>>> from dataclasses import replace
>>> now = datetime(2026, 10, 9, 18, 0, tzinfo=timezone.utc)
>>> context = TrustedExecutionContext(authenticated=True, principal_id="principal.reviewed",
...     caller_type="HUMAN", tenant_id=None, organization_id=None,
...     capabilities=frozenset({"tenant:onboarding:request"}), authority_roles=frozenset(),
...     environment="DEVELOPMENT", audience="avuhz-command-api",
...     authentication_strength="STEP_UP", step_up_satisfied=True,
...     authenticated_at="2026-10-09T17:55:00Z", expires_at="2026-10-09T18:30:00Z")
>>> intent = {"intent_version": 1, "business_reference": "business.pilot",
...     "onboarding_purpose": "OWNER_OPERATED_PILOT",
...     "requested_shared_services": ["ENGAGEMENT_MANAGEMENT"],
...     "idempotency_key": "tenant-owner-intent-0001"}
>>> def verified_owner(principal, business, environment):
...     return VerifiedOwnerEvidence(principal, business, environment,
...         "AUTHORITATIVE_OWNER_DIRECTORY", "2026-10-09T17:55:00Z", "2026-10-09T18:05:00Z")
>>> preflight_owner_onboarding(intent, context, trusted_owner_verifier=verified_owner,
...     enabled_shared_services=frozenset({"ENGAGEMENT_MANAGEMENT"}), checked_at=now).reason_code
'ELIGIBLE_FOR_SEPARATE_REVIEW'
>>> preflight_owner_onboarding(intent, context, trusted_owner_verifier=verified_owner,
...     checked_at=now).reason_code
'SHARED_SERVICES_NOT_READY'
>>> preflight_owner_onboarding({**intent, "tenant_id": "untrusted"}, context,
...     trusted_owner_verifier=verified_owner, checked_at=now).reason_code
'INTENT_INVALID'
>>> preflight_owner_onboarding(intent, context, trusted_owner_verifier=None,
...     checked_at=now).reason_code
'OWNER_PROOF_UNAVAILABLE'
>>> preflight_owner_onboarding(intent, replace(context, capabilities=frozenset({"engagement:read"})),
...     trusted_owner_verifier=verified_owner, checked_at=now).reason_code
'ONBOARDING_CAPABILITY_UNAVAILABLE'
>>> preflight_owner_onboarding(intent, replace(context, environment="PRODUCTION"),
...     trusted_owner_verifier=verified_owner, checked_at=now).reason_code
'DEVELOPMENT_BOUNDARY_REQUIRED'
>>> def wrong_owner(principal, business, environment):
...     return VerifiedOwnerEvidence("principal.other", business, environment,
...         "AUTHORITATIVE_OWNER_DIRECTORY", "2026-10-09T17:55:00Z", "2026-10-09T18:05:00Z")
>>> preflight_owner_onboarding(intent, context, trusted_owner_verifier=wrong_owner,
...     checked_at=now).reason_code
'OWNER_PROOF_UNVERIFIED'
>>> preflight_owner_onboarding(intent, replace(context, step_up_satisfied=False),
...     trusted_owner_verifier=verified_owner, checked_at=now).reason_code
'OWNER_IDENTITY_UNVERIFIED'
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from .guards import TrustedExecutionContext


_ALLOWED_SERVICES = frozenset({
    "ACQUISITION", "ENGAGEMENT_MANAGEMENT", "WORKFLOW_ORCHESTRATION",
    "COMMUNICATIONS", "BILLING", "OPERATIONS_REPORTING",
})
_ALLOWED_PURPOSES = frozenset({"OWNER_OPERATED_PILOT", "STANDARD_BUSINESS_ONBOARDING"})
_INTENT_KEYS = frozenset({
    "intent_version", "business_reference", "onboarding_purpose",
    "requested_shared_services", "idempotency_key",
})
_OPAQUE_REF = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
_FORBIDDEN_KEY_PARTS = ("password", "secret", "token", "bearer", "api_key", "apikey")
_REQUIRED_CAPABILITY = "tenant:onboarding:request"
_TRUSTED_AUDIENCE = "avuhz-command-api"
_OWNER_PROOF_ORIGIN = "AUTHORITATIVE_OWNER_DIRECTORY"


@dataclass(frozen=True)
class VerifiedOwnerEvidence:
    """Server-owned ownership-directory verifier output only.

    A manually constructed or browser-provided instance is NOT valid owner
    proof. The real directory/verifier is not yet implemented or authorized.
    """

    principal_reference: str
    business_reference: str
    environment: str
    verified_source: str
    verified_at: str
    expires_at: str


@dataclass(frozen=True)
class OwnerOnboardingPreflight:
    """Sanitized non-authoritative finding; never an authorization or token."""

    reason_code: str
    eligible_for_separate_review: bool
    tenant_registered: bool = False
    owner_membership_created: bool = False
    automation_authorized: bool = False


def _result(reason: str) -> OwnerOnboardingPreflight:
    return OwnerOnboardingPreflight(reason, reason == "ELIGIBLE_FOR_SEPARATE_REVIEW")


def _utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        timestamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo == timezone.utc else None


def _validated_intent(intent: object) -> bool:
    if not isinstance(intent, dict) or set(intent) != _INTENT_KEYS:
        return False
    if type(intent["intent_version"]) is not int or intent["intent_version"] != 1:
        return False
    business = intent["business_reference"]
    if (not isinstance(business, str) or not 3 <= len(business) <= 128
            or not _OPAQUE_REF.fullmatch(business)):
        return False
    if not isinstance(intent["onboarding_purpose"], str) or intent["onboarding_purpose"] not in _ALLOWED_PURPOSES:
        return False
    services = intent["requested_shared_services"]
    if (type(services) is not list or not 1 <= len(services) <= 6
            or any(not isinstance(service, str) or service not in _ALLOWED_SERVICES
                   for service in services)
            or len(set(services)) != len(services)):
        return False
    key = intent["idempotency_key"]
    if not isinstance(key, str) or not _IDEMPOTENCY_KEY.fullmatch(key):
        return False
    return not any(word in key.lower() for word in _FORBIDDEN_KEY_PARTS)


def preflight_owner_onboarding(
    intent: Mapping[str, object],
    trusted_context: TrustedExecutionContext,
    *,
    trusted_owner_verifier: Callable[[str, str, str], VerifiedOwnerEvidence] | None,
    enabled_shared_services: frozenset[str] = frozenset(),
    checked_at: datetime,
) -> OwnerOnboardingPreflight:
    """Fail-closed screening prior to SEPARATELY authorized tenant registration.

    Identity and owner-verifier dependencies must be bound by trusted
    application composition. The existing DEVELOPMENT resolver grants no
    onboarding capability, so a real success is impossible today. No result
    authorizes membership, data RLS binding, billing, automation or deployment.
    """
    if not _validated_intent(intent):
        return _result("INTENT_INVALID")
    if (type(trusted_context) is not TrustedExecutionContext
            or not isinstance(checked_at, datetime) or checked_at.tzinfo is None):
        return _result("OWNER_IDENTITY_UNVERIFIED")
    now = checked_at.astimezone(timezone.utc)
    if trusted_context.environment != "DEVELOPMENT":
        return _result("DEVELOPMENT_BOUNDARY_REQUIRED")
    authenticated_at = _utc(trusted_context.authenticated_at)
    expires_at = _utc(trusted_context.expires_at)
    if (trusted_context.authenticated is not True
            or trusted_context.caller_type != "HUMAN"
            or not isinstance(trusted_context.principal_id, str)
            or not 3 <= len(trusted_context.principal_id) <= 128
            or not _OPAQUE_REF.fullmatch(trusted_context.principal_id)
            or trusted_context.audience != _TRUSTED_AUDIENCE
            or trusted_context.authentication_strength != "STEP_UP"
            or trusted_context.step_up_satisfied is not True
            or type(trusted_context.capabilities) is not frozenset
            or authenticated_at is None or expires_at is None
            or authenticated_at > now or expires_at <= now):
        return _result("OWNER_IDENTITY_UNVERIFIED")
    if _REQUIRED_CAPABILITY not in trusted_context.capabilities:
        return _result("ONBOARDING_CAPABILITY_UNAVAILABLE")
    if trusted_owner_verifier is None or not callable(trusted_owner_verifier):
        return _result("OWNER_PROOF_UNAVAILABLE")
    try:
        evidence = trusted_owner_verifier(
            trusted_context.principal_id, intent["business_reference"], "DEVELOPMENT"
        )
    except Exception:
        return _result("OWNER_PROOF_UNVERIFIED")
    if type(evidence) is not VerifiedOwnerEvidence:
        return _result("OWNER_PROOF_UNVERIFIED")
    verified_at = _utc(evidence.verified_at)
    proof_expiry = _utc(evidence.expires_at)
    if (evidence.principal_reference != trusted_context.principal_id
            or evidence.business_reference != intent["business_reference"]
            or evidence.environment != "DEVELOPMENT"
            or evidence.verified_source != _OWNER_PROOF_ORIGIN
            or verified_at is None or proof_expiry is None
            or verified_at > now or proof_expiry <= now
            or proof_expiry <= verified_at
            or now - verified_at > timedelta(minutes=15)
            or proof_expiry - verified_at > timedelta(hours=1)):
        return _result("OWNER_PROOF_UNVERIFIED")
    if (type(enabled_shared_services) is not frozenset
            or not enabled_shared_services <= _ALLOWED_SERVICES
            or not set(intent["requested_shared_services"]) <= enabled_shared_services):
        return _result("SHARED_SERVICES_NOT_READY")
    return _result("ELIGIBLE_FOR_SEPARATE_REVIEW")
