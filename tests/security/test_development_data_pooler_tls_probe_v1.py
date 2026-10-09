"""DEVELOPMENT DATA shared-pooler TLS probe: NO LOGIN, NO SECRET, NO SQL.

This offline-tested program can be invoked from a *separately reviewed* manual
GitHub DEVELOPMENT workflow. Its presence does not create or authorize such a
workflow. It sends a PostgreSQL SSLRequest (only) and verifies CA + hostname.

The shared pooler's certificate is NOT proof of routing to one Supabase project,
Postgres login, GitHub environment administrator restrictions, or owner authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

REPOSITORY = "AnonymousKoo/avuhz-infra"
REPOSITORY_ID = "1231399336"
OWNER = "AnonymousKoo"
OWNER_ID = "168945054"
AUTH_PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
HOST = "aws-1-us-west-2.pooler.supabase.com"
PORT = 5432
SSL_REQUEST = struct.pack("!II", 8, 80877103)
WORKFLOW_REF = (
    REPOSITORY + "/.github/workflows/"
    "development-data-session-tls-probe-v1.yml@refs/heads/main"
)
RESOURCE_RELATIVE_PATH = (
    "contracts/plans/v1/"
    "development-render-data-supavisor-session-dsn-v2.resource.json"
)
SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class TlsProbeStop(ValueError):
    """Deliberately opaque error code, not an exception or connection payload."""


def _stop(code: str) -> None:
    raise TlsProbeStop(code)


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], text=True, timeout=20, stderr=subprocess.DEVNULL
    ).strip()


def verify_development_github_context(env, *, git_command=_git) -> None:
    """Source restrictions only, NOT independent owner/environment approval."""
    allowed = (
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == REPOSITORY_ID
        and env.get("GITHUB_ACTOR") == OWNER
        and env.get("GITHUB_ACTOR_ID") == OWNER_ID
        and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW_REF
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and env.get("AVUHZ_ENVIRONMENT") == "development"
        and isinstance(env.get("GITHUB_SHA"), str)
        and SHA_PATTERN.fullmatch(env["GITHUB_SHA"]) is not None
        and env.get("GITHUB_WORKFLOW_SHA") == env.get("GITHUB_SHA")
    )
    if not allowed:
        _stop("DATA_TLS_GITHUB_CONTEXT_UNVERIFIED")
    try:
        sha = env["GITHUB_SHA"]
        if not (
            git_command("rev-parse", "HEAD") == sha
            and git_command("remote", "get-url", "origin") in (
                "https://github.com/AnonymousKoo/avuhz-infra",
                "https://github.com/AnonymousKoo/avuhz-infra.git",
            )
            and git_command("ls-remote", "--exit-code", "origin", "refs/heads/main")
            == sha + "\trefs/heads/main"
        ):
            _stop("DATA_TLS_SOURCE_DRIFT")
    except TlsProbeStop:
        raise
    except Exception:
        _stop("DATA_TLS_SOURCE_UNVERIFIED")


def verify_pinned_target(resource: dict) -> None:
    if not (
        type(resource) is dict
        and resource.get("data_project_ref") == DATA_PROJECT
        and DATA_PROJECT != AUTH_PROJECT
        and resource.get("pooler_host") == HOST
        and type(resource.get("pooler_port")) is int
        and resource.get("pooler_port") == PORT
        and resource.get("pooler_mode") == "SESSION"
        and resource.get("pooler_database") == "postgres"
        and resource.get("pooler_username") ==
        "avuhz_data_runtime_service_dev." + DATA_PROJECT
        and resource.get("sslmode") == "require"
        and resource.get("secret_value_must_remain_unobserved") is True
    ):
        _stop("DATA_TLS_PINNED_ENDPOINT_UNVERIFIED")


def verify_ca_file(ca_path: Path, expected_digest: str) -> None:
    """Require operator-reviewed SHA-256 for a Supabase-downloaded PUBLIC CA."""
    if type(expected_digest) is not str or not DIGEST_PATTERN.fullmatch(expected_digest):
        _stop("DATA_TLS_CA_DIGEST_UNVERIFIED")
    try:
        if not ca_path.is_absolute() or not ca_path.is_file():
            _stop("DATA_TLS_CA_FILE_UNVERIFIED")
        data = ca_path.read_bytes()
        if not data or len(data) > 65536:
            _stop("DATA_TLS_CA_FILE_UNVERIFIED")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            _stop("DATA_TLS_CA_DIGEST_UNVERIFIED")
    except TlsProbeStop:
        raise
    except Exception:
        _stop("DATA_TLS_CA_FILE_UNVERIFIED")


def probe_tls(ca_path: Path, expected_digest: str, *, dial=None,
              context_factory=None) -> None:
    """One SSLRequest and CA/hostname-verified TLS; NEVER StartupMessage."""
    verify_ca_file(ca_path, expected_digest)
    if dial is None:
        dial = socket.create_connection
    if context_factory is None:
        context_factory = ssl.create_default_context
    try:
        ctx = context_factory(purpose=ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with dial((HOST, PORT), timeout=10) as sock:
            sock.settimeout(10)
            sock.sendall(SSL_REQUEST)
            if sock.recv(1) != b"S":
                _stop("DATA_TLS_SSLREQUEST_REJECTED")
            with ctx.wrap_socket(sock, server_hostname=HOST) as tls:
                if tls.version() not in ("TLSv1.2", "TLSv1.3") or not tls.getpeercert():
                    _stop("DATA_TLS_CERTIFICATE_UNVERIFIED")
                # Deliberately send zero bytes after SSLRequest. No login or SQL.
    except TlsProbeStop:
        raise
    except Exception:
        _stop("DATA_TLS_HANDSHAKE_UNVERIFIED")


def run_probe(*, ca_path: Path, expected_digest: str, env=None,
              resource_path: Path | None = None) -> None:
    verify_development_github_context(os.environ if env is None else env)
    resource_path = resource_path or Path(__file__).resolve().parents[2] / RESOURCE_RELATIVE_PATH
    try:
        verify_pinned_target(json.loads(resource_path.read_text(encoding="utf-8")))
    except TlsProbeStop:
        raise
    except Exception:
        _stop("DATA_TLS_PINNED_ENDPOINT_UNVERIFIED")
    probe_tls(ca_path, expected_digest)


class DataPoolerTLSProbeOfflineTests(unittest.TestCase):
    """All CI-discovered cases are offline with zero network connections."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-data-tls-ca-")
        self.addCleanup(self.temp.cleanup)
        self.ca = Path(self.temp.name) / "fictional-test-ca.pem"
        self.ca.write_bytes(b"fictional offline test CA only")
        self.digest = hashlib.sha256(self.ca.read_bytes()).hexdigest()

    @staticmethod
    def fake_context():
        sha = "a" * 40
        env = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
            "GITHUB_ACTOR": OWNER, "GITHUB_ACTOR_ID": OWNER_ID,
            "GITHUB_TRIGGERING_ACTOR": OWNER, "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": WORKFLOW_REF, "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": sha,
            "AVUHZ_ENVIRONMENT": "development",
        }
        def git(*args):
            return {
                ("rev-parse", "HEAD"): sha,
                ("remote", "get-url", "origin"):
                    "https://github.com/AnonymousKoo/avuhz-infra",
                ("ls-remote", "--exit-code", "origin", "refs/heads/main"):
                    sha + "\trefs/heads/main",
            }[args]
        return env, git

    def test_owner_and_exact_protected_main_claim_needed(self):
        env, git = self.fake_context()
        verify_development_github_context(env, git_command=git)
        for field, value in (
            ("GITHUB_ACTOR", "other"), ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_WORKFLOW_REF", "other"), ("GITHUB_RUN_ATTEMPT", "2"),
            ("AVUHZ_ENVIRONMENT", "production"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(TlsProbeStop, "DATA_TLS_GITHUB_CONTEXT_UNVERIFIED"):
                    verify_development_github_context({**env, field: value}, git_command=git)
        with self.assertRaisesRegex(TlsProbeStop, "DATA_TLS_SOURCE_DRIFT"):
            verify_development_github_context(env, git_command=lambda *args: "f" * 40)

    def test_pinned_data_project_cannot_be_auth_or_other_pooler(self):
        resource = {
            "data_project_ref": DATA_PROJECT,
            "pooler_host": HOST, "pooler_port": PORT,
            "pooler_mode": "SESSION", "pooler_database": "postgres",
            "pooler_username": "avuhz_data_runtime_service_dev." + DATA_PROJECT,
            "sslmode": "require", "secret_value_must_remain_unobserved": True,
        }
        verify_pinned_target(resource)
        for changed in (
            {"data_project_ref": AUTH_PROJECT},
            {"pooler_host": "example.invalid"},
            {"pooler_port": 6543},
            {"pooler_mode": "TRANSACTION"},
            {"secret_value_must_remain_unobserved": False},
        ):
            with self.subTest(changed=changed), self.assertRaises(TlsProbeStop):
                verify_pinned_target({**resource, **changed})

    def test_ca_missing_or_wrong_digest_never_reaches_network(self):
        dial = Mock(side_effect=AssertionError("network must stay offline"))
        with self.assertRaisesRegex(TlsProbeStop, "DATA_TLS_CA_DIGEST_UNVERIFIED"):
            probe_tls(self.ca, "0" * 64, dial=dial)
        with self.assertRaisesRegex(TlsProbeStop, "DATA_TLS_CA_FILE_UNVERIFIED"):
            probe_tls(Path(self.temp.name) / "absent.pem", self.digest, dial=dial)
        dial.assert_not_called()

    def test_only_ssl_request_is_sent_and_tls_hostname_is_verified(self):
        fake_socket = Mock()
        fake_socket.__enter__ = Mock(return_value=fake_socket)
        fake_socket.__exit__ = Mock(return_value=None)
        fake_socket.recv.return_value = b"S"
        fake_tls = Mock()
        fake_tls.__enter__ = Mock(return_value=fake_tls)
        fake_tls.__exit__ = Mock(return_value=None)
        fake_tls.version.return_value = "TLSv1.3"
        fake_tls.getpeercert.return_value = {"subject": "fixture"}
        ctx = Mock()
        ctx.wrap_socket.return_value = fake_tls
        factory = Mock(return_value=ctx)
        dial = Mock(return_value=fake_socket)
        probe_tls(self.ca, self.digest, dial=dial, context_factory=factory)
        dial.assert_called_once_with((HOST, PORT), timeout=10)
        fake_socket.sendall.assert_called_once_with(SSL_REQUEST)
        ctx.wrap_socket.assert_called_once_with(fake_socket, server_hostname=HOST)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_ssl_rejected_or_invalid_cert_fails_closed_without_raw_errors(self):
        for reply in (b"N", b""):
            sock = Mock()
            sock.__enter__ = Mock(return_value=sock)
            sock.__exit__ = Mock(return_value=None)
            sock.recv.return_value = reply
            with self.subTest(reply=reply), self.assertRaisesRegex(
                TlsProbeStop, "DATA_TLS_SSLREQUEST_REJECTED"
            ):
                probe_tls(self.ca, self.digest, dial=lambda *a, **kw: sock,
                          context_factory=lambda **kw: Mock())
            sock.sendall.assert_called_once_with(SSL_REQUEST)
        leaked = "fictional_sensitive_certificate_error"
        def fail_context(**kwargs):
            raise ssl.SSLError(leaked)
        with self.assertRaises(TlsProbeStop) as caught:
            probe_tls(self.ca, self.digest,
                      dial=lambda *a, **kw: Mock(), context_factory=fail_context)
        self.assertEqual(str(caught.exception), "DATA_TLS_HANDSHAKE_UNVERIFIED")
        self.assertNotIn(leaked, str(caught.exception))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        unittest.main()
    else:
        parser = argparse.ArgumentParser(description="Strict password-free DATA pooler TLS probe")
        parser.add_argument("--probe", action="store_true")
        parser.add_argument("--ca-file", type=Path)
        parser.add_argument("--ca-sha256")
        flags = parser.parse_args()
        if not flags.probe or flags.ca_file is None or flags.ca_sha256 is None:
            raise SystemExit("DATA_TLS_EXPLICIT_PROBE_ARGUMENTS_REQUIRED")
        try:
            run_probe(ca_path=flags.ca_file, expected_digest=flags.ca_sha256)
        except TlsProbeStop as error:
            raise SystemExit(str(error)) from None
        print("development_data_shared_pooler_tls_ca_hostname=PASS")
        print("database_login_attempted=false")
        print("data_project_routing_verified=false")
        print("github_environment_protection_verified=false")
        print("credential_resolution_authorized=false")
        print("live_command_authorized=false")
