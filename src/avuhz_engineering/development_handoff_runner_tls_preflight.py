"""Offline-only DEVELOPMENT DATA runner CA inspection and TLS policy builder.

Inspect a local public CA certificate against a digest supplied through a
*separate, previously authenticated* trust channel. Do not treat a matching
caller-supplied digest, a self-signed name or a file from a chat as proof of
provenance. Never connect to Postgres, resolve credentials, dispatch a workflow
or confer owner/tenant/claim authority here.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from avuhz_engineering.development_handoff_runner_connection_candidate import (
    DevelopmentRunnerConnectionPolicy,
    DevelopmentRunnerTransportStop,
)
from avuhz_service.development import DEVELOPMENT_DATA_PROJECT_REF
from avuhz_service.development_data import (
    DEVELOPMENT_DATA_ENDPOINT_HOST,
    DEVELOPMENT_DATA_SESSION_POOLER_HOST,
    DEVELOPMENT_DATA_ENDPOINT_PORT,
)

_SHA256_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----\r?\n?"
)
_MAX_CA_BYTES = 65536
_EXPECTED_CN = "Supabase Root 2021 CA"
_EXPECTED_ORGANIZATION = "Supabase Inc"
_RUNNER = "avuhz_handoff_claim_runner_dev"


def _deny(code: str) -> None:
    raise DevelopmentRunnerTransportStop(code)


@dataclass(frozen=True)
class OfflineRunnerTlsPreparation:
    """Preflight receipt. In particular, this is NOT a trusted issuer receipt."""

    policy: DevelopmentRunnerConnectionPolicy
    certificate_parsed: bool = True
    certificate_is_current_ca: bool = True
    certificate_signature_consistent: bool = True
    supplied_digest_matches_file: bool = True
    independent_ca_origin_verified: bool = False
    client_to_provider_tls_handshake_verified: bool = False
    connection_or_credential_authorized: bool = False


def prepare_development_runner_tls_policy_v1(
    *,
    environment: str,
    data_project_ref: str,
    mode: str,
    ca_path: str,
    independently_enrolled_ca_sha256: str,
    as_of_utc: datetime,
) -> OfflineRunnerTlsPreparation:
    """Prepare an immutable, credential-free connection profile.

    `independently_enrolled_ca_sha256` MUST come from a separately verified
    trusted control-plane source, never be calculated from the same untrusted
    upload as `ca_path`. This method can verify bytes, not the pin's origin.
    No fallback from direct to session pooler is permitted.
    """
    if (
        environment != "DEVELOPMENT"
        or data_project_ref != DEVELOPMENT_DATA_PROJECT_REF
        or mode not in ("direct", "session_pooler")
        or type(ca_path) is not str
        or not ca_path
        or type(independently_enrolled_ca_sha256) is not str
        or _SHA256_PIN.fullmatch(independently_enrolled_ca_sha256) is None
        or not isinstance(as_of_utc, datetime)
        or as_of_utc.tzinfo is None
        or as_of_utc.utcoffset() is None
    ):
        _deny("HANDOFF_RUNNER_TLS_PREFLIGHT_SCOPE_INVALID")

    file_path = Path(ca_path)
    if not file_path.is_absolute() or file_path.is_symlink():
        _deny("HANDOFF_RUNNER_CA_UNVERIFIED")
    try:
        if not file_path.is_file() or not (0 < file_path.stat().st_size <= _MAX_CA_BYTES):
            _deny("HANDOFF_RUNNER_CA_UNVERIFIED")
        data = file_path.read_bytes()
    except DevelopmentRunnerTransportStop:
        raise
    except (OSError, ValueError, TypeError):
        _deny("HANDOFF_RUNNER_CA_UNVERIFIED")

    if (
        not (0 < len(data) <= _MAX_CA_BYTES)
        or _PEM_CERTIFICATE.fullmatch(data) is None
        or not hmac.compare_digest(
            "sha256:" + hashlib.sha256(data).hexdigest(),
            independently_enrolled_ca_sha256,
        )
    ):
        _deny("HANDOFF_RUNNER_CA_UNVERIFIED")

    try:
        ca = x509.load_pem_x509_certificate(data)
        cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        organization = ca.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        basic = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        key = ca.public_key()
        at = as_of_utc.astimezone(timezone.utc)
        if (
            len(cn) != 1
            or cn[0].value != _EXPECTED_CN
            or len(organization) != 1
            or organization[0].value != _EXPECTED_ORGANIZATION
            or ca.issuer != ca.subject
            or not basic.critical
            or not basic.value.ca
            or not usage.key_cert_sign
            or not isinstance(key, rsa.RSAPublicKey)
            or not ca.not_valid_before_utc <= at < ca.not_valid_after_utc
        ):
            _deny("HANDOFF_RUNNER_CA_UNVERIFIED")
        key.verify(
            ca.signature,
            ca.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca.signature_hash_algorithm,
        )
    except DevelopmentRunnerTransportStop:
        raise
    except (ValueError, TypeError, x509.ExtensionNotFound, Exception):
        # Do not leak certificate parse/signature/provider error strings.
        _deny("HANDOFF_RUNNER_CA_UNVERIFIED")

    host, user = (
        (DEVELOPMENT_DATA_ENDPOINT_HOST, _RUNNER)
        if mode == "direct"
        else (
            DEVELOPMENT_DATA_SESSION_POOLER_HOST,
            _RUNNER + "." + DEVELOPMENT_DATA_PROJECT_REF,
        )
    )
    policy = DevelopmentRunnerConnectionPolicy(
        project_ref=DEVELOPMENT_DATA_PROJECT_REF,
        host=host,
        port=DEVELOPMENT_DATA_ENDPOINT_PORT,
        dbname="postgres",
        user=user,
        sslmode="verify-full",
        sslrootcert=str(file_path),
        expected_ca_sha256=independently_enrolled_ca_sha256,
    )
    return OfflineRunnerTlsPreparation(policy=policy)
