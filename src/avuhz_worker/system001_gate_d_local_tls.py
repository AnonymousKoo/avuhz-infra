"""Fail-closed LOCAL System #001 Gate D TLS 1.3 sink composition.

This source-only factory does not connect, dispatch, start a service, install
trust, or read the nginx leaf certificate/private-key boundary.  It loads one
root-owned public CA certificate into one application-scoped SSLContext.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import ssl
import stat
from pathlib import Path

from .local_n8n_https_transport import LocalN8nHttpsTransport
from .n8n_event_sink import N8nOutboxSink


SYSTEM001_GATE_D_LOCAL_PROFILE = "SYSTEM001_GATE_D_LOCAL_TLS13_V1"
SYSTEM001_GATE_D_LOCAL_HOST = "avuhz-gate-d.test"
SYSTEM001_GATE_D_LOCAL_ENDPOINT = (
    "https://avuhz-gate-d.test/webhook/avuhz-events"
)
SYSTEM001_GATE_D_LOCAL_CA_PATH = Path(
    "/etc/avuhz/trust/avuhz-gate-d-local-ca.crt"
)
SYSTEM001_GATE_D_LOCAL_CA_SHA256 = (
    "9D:31:E5:0D:71:AC:0D:C0:04:96:B1:46:32:E3:B4:C0:"
    "15:AA:11:12:9C:F3:14:86:5A:EA:CF:CD:2C:77:CF:90"
)

_AVUHZ_DIRECTORY = Path("/etc/avuhz")
_TRUST_DIRECTORY = Path("/etc/avuhz/trust")
_MAX_PUBLIC_CA_BYTES = 64 * 1024
_SINGLE_PEM_CERTIFICATE = re.compile(
    rb"\A-----BEGIN CERTIFICATE-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]+\r?\n)+"
    rb"-----END CERTIFICATE-----\r?\n?\Z"
)


class GateDLocalTlsConfigurationError(ValueError):
    """Safe, non-sensitive failure for a rejected Gate D TLS profile."""


def _stop() -> None:
    raise GateDLocalTlsConfigurationError(
        "SYSTEM001_GATE_D_LOCAL_TLS_CONFIGURATION_INVALID"
    )


def _validate_root_directory(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        _stop()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o500 != 0o500
    ):
        _stop()


def _read_deployed_public_ca() -> bytes:
    """Read only the exact public CA after owner/mode and symlink checks."""

    _validate_root_directory(_AVUHZ_DIRECTORY)
    _validate_root_directory(_TRUST_DIRECTORY)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(SYSTEM001_GATE_D_LOCAL_CA_PATH, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_PUBLIC_CA_BYTES
        ):
            _stop()
        chunks: list[bytes] = []
        remaining = _MAX_PUBLIC_CA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        public_ca_pem = b"".join(chunks)
        if len(public_ca_pem) != metadata.st_size or len(public_ca_pem) > _MAX_PUBLIC_CA_BYTES:
            _stop()
        return public_ca_pem
    except GateDLocalTlsConfigurationError:
        raise
    except (OSError, TypeError, ValueError):
        _stop()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    raise AssertionError("unreachable")


def _certificate_der_and_fingerprint(public_ca_pem: bytes) -> tuple[bytes, str]:
    if (
        type(public_ca_pem) is not bytes
        or not _SINGLE_PEM_CERTIFICATE.fullmatch(public_ca_pem)
        or public_ca_pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or public_ca_pem.count(b"-----END CERTIFICATE-----") != 1
    ):
        _stop()
    try:
        pem_text = public_ca_pem.decode("ascii")
        certificate_der = ssl.PEM_cert_to_DER_cert(pem_text)
    except (UnicodeDecodeError, ValueError):
        _stop()
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    fingerprint = ":".join(digest[index:index + 2] for index in range(0, 64, 2))
    return certificate_der, fingerprint


def _build_tls13_context(public_ca_pem: bytes, expected_sha256: str) -> ssl.SSLContext:
    certificate_der, fingerprint = _certificate_der_and_fingerprint(public_ca_pem)
    if (
        type(expected_sha256) is not str
        or not hmac.compare_digest(fingerprint, expected_sha256)
    ):
        _stop()
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=public_ca_pem.decode("ascii"))
        loaded = context.get_ca_certs(binary_form=True)
    except (OSError, ssl.SSLError, UnicodeDecodeError, ValueError):
        _stop()
    if loaded != [certificate_der]:
        _stop()
    return context


def build_system001_gate_d_tls13_context_for_offline_test(
    *, public_ca_pem: bytes, expected_sha256: str,
) -> ssl.SSLContext:
    """Build a context from an injected PUBLIC fixture for offline tests only.

    This deliberately cannot create a sink and is not called by the deployed
    factory.  Runtime trust always comes from the exact root-owned path and pin.
    """

    return _build_tls13_context(public_ca_pem, expected_sha256)


def build_system001_gate_d_local_tls13_context() -> ssl.SSLContext:
    """Build the deployed context from the sole approved public CA path."""

    return _build_tls13_context(
        _read_deployed_public_ca(), SYSTEM001_GATE_D_LOCAL_CA_SHA256,
    )


def _require_tls13_context(
    context: ssl.SSLContext, expected_ca_der: bytes | None = None,
) -> None:
    try:
        loaded_ca_certificates = context.get_ca_certs(binary_form=True)
    except (AttributeError, ssl.SSLError, ValueError):
        _stop()
    if (
        not isinstance(context, ssl.SSLContext)
        or context.verify_mode != ssl.CERT_REQUIRED
        or not context.check_hostname
        or context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
        or len(loaded_ca_certificates) != 1
        or (
            expected_ca_der is not None
            and loaded_ca_certificates[0] != expected_ca_der
        )
    ):
        _stop()


class _GateDTls13OnlyTransport:
    """Revalidate the exclusive TLS 1.3 policy before every delegated send."""

    def __init__(
        self, context: ssl.SSLContext, timeout_seconds: int, environment: str,
    ) -> None:
        _require_tls13_context(context)
        self._context = context
        self._expected_ca_der = context.get_ca_certs(binary_form=True)[0]
        self._delegate = LocalN8nHttpsTransport(
            environment=environment,
            expected_host=SYSTEM001_GATE_D_LOCAL_HOST,
            tls_context=context,
            timeout_seconds=timeout_seconds,
        )

    def __call__(self, url: str, headers: dict, body: bytes) -> int:
        _require_tls13_context(self._context, self._expected_ca_der)
        if url != SYSTEM001_GATE_D_LOCAL_ENDPOINT:
            _stop()
        return self._delegate(url, headers, body)


def build_system001_gate_d_local_sink(
    *, environment: str, profile: str, tenant_id: str,
    credential_provider, timeout_seconds: int = 5,
) -> N8nOutboxSink:
    """Compose the exact LOCAL sink without performing network activity."""

    if environment not in ("LOCAL", "TEST") or profile != SYSTEM001_GATE_D_LOCAL_PROFILE:
        _stop()
    context = build_system001_gate_d_local_tls13_context()
    transport = _GateDTls13OnlyTransport(context, timeout_seconds, environment)
    return N8nOutboxSink(
        environment=environment,
        tenant_id=tenant_id,
        endpoint=SYSTEM001_GATE_D_LOCAL_ENDPOINT,
        expected_host=SYSTEM001_GATE_D_LOCAL_HOST,
        credential_provider=credential_provider,
        post=transport,
    )
