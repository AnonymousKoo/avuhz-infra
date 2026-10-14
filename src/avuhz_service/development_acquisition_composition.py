"""Unmounted shared DEVELOPMENT acquisition adapter composition candidate.

This assembles *existing* Avuhz JWT, identity, DATA, rate-counter and HTTP
components. It does not register a WSGI route, call any provider, issue a
credential, change a permission, enroll a company, or connect the public site.

A supplied policy is NOT evidence of an independently verified business owner
or of a registered acquisition workload. The signed JWT must still match that
policy, the restricted DATA connection must pass its fail-closed preflight, and
the shared writer must find one ACTIVE company with a verified ACTIVE OWNER.
Hosted use remains prohibited until G0-G7 separate approvals and certification.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from .development_acquisition_data import create_hosted_development_acquisition_store
from .development_acquisition_http import DevelopmentAcquisitionHttpAdapter
from .development_acquisition_ingress import DevelopmentAuthenticatedAcquisitionIngress
from .development_acquisition_rate_limit import DevelopmentPostgresAcquisitionRateLimiter
from .development_acquisition_service_identity_candidate import (
    DevelopmentAcquisitionServiceIdentityCandidate,
    DevelopmentAcquisitionServicePolicy,
)
from .development_identity import DevelopmentTrustedIdentityResolver
from .development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier


def create_unmounted_development_acquisition_http_candidate(
    *,
    service_policy: DevelopmentAcquisitionServicePolicy,
    acquisition_connection_factory: Callable[[], object],
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> DevelopmentAcquisitionHttpAdapter:
    """Prepare the shared adapter; caller must NOT mount or serve it yet.

    No JWT-verifier override or permissive admission callback is accepted.
    In particular, the future caller must provide the exact restricted DATA
    connection factory explicitly, rather than falling back to the existing
    command-service login or silently resolving a credential here.
    """
    if type(service_policy) is not DevelopmentAcquisitionServicePolicy:
        raise ValueError("approved acquisition identity policy required")
    if not callable(acquisition_connection_factory) or not callable(clock):
        raise ValueError("explicit acquisition DATA factory and clock required")

    verifier = DevelopmentAcquisitionServiceIdentityCandidate(
        DevelopmentSupabaseEs256JwtVerifier(),
        service_policy,
    )
    resolver = DevelopmentTrustedIdentityResolver(verifier, clock=clock)
    store = create_hosted_development_acquisition_store(
        acquisition_connection_factory,
    )
    admission = DevelopmentPostgresAcquisitionRateLimiter(store)
    ingress = DevelopmentAuthenticatedAcquisitionIngress(
        resolver,
        store,
        rate_limit_admit=admission,
    )
    return DevelopmentAcquisitionHttpAdapter(ingress, clock=clock)
