"""Opt-in LOCAL/TEST credential provider for the EXISTING shared n8n sink.

A separately approved and signed-in 1Password CLI is REQUIRED before use.
This source does not authenticate to 1Password, discover accounts/items,
create or rotate secrets, install n8n credentials, open network listeners,
activate workflows or touch AUTH/DATA. It reads only an independently approved
single secret reference, once per requested delivery, through a child stdout
PIPE held inside the trusted caller process. No shell, file or env secret copy.
"""
from __future__ import annotations

import os
import re
import subprocess

_REF = re.compile(
    r"op://[A-Za-z0-9][A-Za-z0-9_-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z",
    re.ASCII,
)
MAX_SECRET_BYTES = 512


class LocalN8nSecretUnavailable(RuntimeError):
    """Sanitized error; never retain subprocess response, reference or value."""


class LocalN8nOnePasswordCredential:
    """Callable compatible with N8nOutboxSink credential_provider.

    The op:// reference is a separately approved 3-part stable-ID reference,
    *not* the value of a secret. No default issuer, item, token or fallback.
    The same field must be independently installed in n8n encrypted Header
    Auth credentials by another separately authorized one-resource operation.
    """

    def __init__(self, *, environment: str, approved_secret_reference: str,
                 timeout_seconds: int = 5) -> None:
        if (
            environment not in ("LOCAL", "TEST")
            or type(approved_secret_reference) is not str
            or _REF.fullmatch(approved_secret_reference) is None
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 10
        ):
            raise ValueError("approved LOCAL secret reference required")
        self._ref = approved_secret_reference
        self._timeout = timeout_seconds

    def __call__(self) -> str:
        # Never query a personal/password manager in CI or hosted execution.
        # A successful source-only test uses a stubbed subprocess and env.
        if (
            os.environ.get("CI")
            or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("AVUHZ_ENVIRONMENT", "LOCAL") not in ("LOCAL", "TEST")
        ):
            raise LocalN8nSecretUnavailable("approved LOCAL secret issuer unavailable")
        try:
            # op's 2.39 CLI read --no-newline returns a single field to
            # stdout. Capture it in memory; never print, stream into a shell,
            # log stderr or use --out-file. No retry or session bootstrap.
            result = subprocess.run(
                ["op", "read", "--no-newline", self._ref],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self._timeout,
                check=False,
            )
            if result.returncode != 0 or type(result.stdout) is not bytes:
                raise ValueError
            raw = result.stdout
            if (
                not 32 <= len(raw) <= MAX_SECRET_BYTES
                or any(byte < 33 or byte > 126 for byte in raw)
            ):
                raise ValueError
            return raw.decode("ascii")
        except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
            raise LocalN8nSecretUnavailable(
                "approved LOCAL secret issuer unavailable"
            ) from None
