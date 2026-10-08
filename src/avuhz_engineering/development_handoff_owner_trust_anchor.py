"""PROPOSED DEVELOPMENT-only public-key trust-anchor material.

This offline checker matches a reviewed, source-pinned Ed25519 *public* key
against separately supplied GitHub environment-variable candidates. It is
not GitHub environment attestation, out-of-band owner attribution, an actual
environment setting, a signed-stage approval, or authorization to execute.

Do not call this directly with caller-provided values and infer that an
environment variable was installed or independently confirmed. Never
provide or store private PEM data, and never activate a workflow here.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping

from avuhz_engineering.development_handoff_approval_gate import EXPECTED_OWNER
from avuhz_engineering.development_source_bound_handoff_lifecycle import REPOSITORY
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)

# These are *public* values explicitly supplied by the owner for DEVELOPMENT
# trust-anchor PREPARATION, not secret material or proof of authorization.
OWNER_ED25519_PUBLIC_KEY_BASE64 = "ZFWF5ABLxtDjgvCbGEKyD2P5Dy4wBNGvRlNADkwMPXc="
OWNER_ED25519_FINGERPRINT = (
    "sha256:e750361f337cac029969240023eac3f17864580acd32cfd8dedcd7fef0612a87"
)
ENV_PUBLIC_KEY = "AVUHZ_HANDOFF_OWNER_ED25519_PUBLIC_KEY_BASE64"
ENV_FINGERPRINT = "AVUHZ_HANDOFF_OWNER_ED25519_FINGERPRINT"
EXPECTED_ENVIRONMENT = "development"


class DevelopmentTrustAnchorStop(ValueError):
    """A fixed rejection code only; no variable contents in errors."""


@dataclass(frozen=True)
class DevelopmentOwnerTrustAnchorCandidate:
    public_key: bytes
    public_key_fingerprint: str
    classification: str = "DEVELOPMENT_PUBLIC_KEY_MATERIAL_MATCH_OFFLINE_ONLY"
    source_pinned_public_key_matched: bool = True
    supplied_environment_values_matched: bool = True
    actual_github_environment_setting_verified: bool = False
    independent_owner_identity_verified: bool = False
    owner_key_enrolled_in_trusted_runner: bool = False
    signed_stage_approvals_verified: bool = False
    credential_resolution_authorized: bool = False
    live_command_authorized: bool = False


def _stop(code: str) -> None:
    raise DevelopmentTrustAnchorStop(code)


def prepare_development_owner_trust_anchor_candidate(
    *, environment_values: Mapping[str, str],
    observed_repository: str,
    observed_environment: str,
    observed_owner_identity: str,
    observed_auth_project_ref: str,
    observed_data_project_ref: str,
) -> DevelopmentOwnerTrustAnchorCandidate:
    """Match candidate values to reviewed public key; grant NO authority.

    The values must eventually be read from the *actual* protected GitHub
    Actions `development` environment by a separately reviewed workflow.
    A local dict with the right values is not environment provenance.
    """
    if (
        type(environment_values) is not dict
        or set(environment_values) != {ENV_PUBLIC_KEY, ENV_FINGERPRINT}
        or any(type(value) is not str for value in environment_values.values())
    ):
        _stop("HANDOFF_OWNER_ANCHOR_VALUES_INVALID")
    if (
        observed_repository != REPOSITORY
        or observed_environment != EXPECTED_ENVIRONMENT
        or observed_owner_identity != EXPECTED_OWNER
        or observed_auth_project_ref != DEVELOPMENT_AUTH_PROJECT_REF
        or observed_data_project_ref != DEVELOPMENT_DATA_PROJECT_REF
        or observed_auth_project_ref == observed_data_project_ref
    ):
        _stop("HANDOFF_OWNER_ANCHOR_SCOPE_INVALID")

    encoded = environment_values[ENV_PUBLIC_KEY]
    digest = environment_values[ENV_FINGERPRINT]
    if (
        not hmac.compare_digest(encoded, OWNER_ED25519_PUBLIC_KEY_BASE64)
        or not hmac.compare_digest(digest, OWNER_ED25519_FINGERPRINT)
    ):
        _stop("HANDOFF_OWNER_ANCHOR_VALUE_MISMATCH")

    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        _stop("HANDOFF_OWNER_ANCHOR_INVALID_ED25519_KEY")

    if (
        len(raw) != 32
        or base64.b64encode(raw).decode("ascii") != encoded
        or "sha256:" + hashlib.sha256(raw).hexdigest() != digest
    ):
        _stop("HANDOFF_OWNER_ANCHOR_INVALID_ED25519_KEY")

    return DevelopmentOwnerTrustAnchorCandidate(
        public_key=raw, public_key_fingerprint=digest,
    )
