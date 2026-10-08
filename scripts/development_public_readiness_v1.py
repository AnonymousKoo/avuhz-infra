#!/usr/bin/env python3
"""One-attempt, unauthenticated DEVELOPMENT runtime readiness verification.

This is a read-only public-health probe, NOT an authentication test. No Supabase
credential, GitHub environment secret, provider mutation, or session is used.
Results are safe fixed codes; HTTP response data and errors are never logged.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

SERVICE_ORIGIN = "https://avuhz-command-dev.onrender.com"
CONFIRMATION = "VERIFY_AVUHZ_DEVELOPMENT_PUBLIC_READINESS_V1"
MAX_BYTES = 4096
TIMEOUT_SECONDS = 15
EXPECTED_HEALTH = {
    "startup": {"status": "started", "checks": {"runtime": "started"}},
    "live": {"status": "alive", "checks": {"runtime": "alive"}},
    "ready": {
        "status": "ready",
        "checks": {"configuration": "ready", "data": "ready", "identity": "ready"},
    },
}


class PublicReadinessStop(Exception):
    """Only fixed, sanitized failure codes may be used in this exception."""

    ALLOWED = frozenset({
        "INVOCATION_INVALID",
        "HTTP_STATUS_UNEXPECTED",
        "HTTP_BODY_OVERSIZED",
        "HTTP_BODY_INVALID",
        "NETWORK_TIMEOUT",
        "NETWORK_FAILED",
    })

    def __init__(self, code: str):
        super().__init__(code if code in self.ALLOWED else "NETWORK_FAILED")
        self.code = str(self)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def verify_invocation(environ: Mapping[str, str]) -> None:
    if (
        environ.get("GITHUB_REPOSITORY") != "AnonymousKoo/avuhz-infra"
        or environ.get("GITHUB_REF") != "refs/heads/main"
        or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or environ.get("AVUHZ_CONFIRMATION") != CONFIRMATION
    ):
        raise PublicReadinessStop("INVOCATION_INVALID")


def check_health(
    opener: Callable[..., Any],
    *,
    name: str,
) -> None:
    """Make exactly one HTTPS GET to the exact allowlisted service and path."""
    if name not in EXPECTED_HEALTH:
        raise PublicReadinessStop("INVOCATION_INVALID")
    request = urllib.request.Request(
        f"{SERVICE_ORIGIN}/health/{name}",
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.getcode()
            if type(status) is not int or status != 200:
                raise PublicReadinessStop("HTTP_STATUS_UNEXPECTED")
            raw = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError:
        raise PublicReadinessStop("HTTP_STATUS_UNEXPECTED") from None
    except (socket.timeout, TimeoutError):
        raise PublicReadinessStop("NETWORK_TIMEOUT") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise PublicReadinessStop("NETWORK_TIMEOUT") from None
        raise PublicReadinessStop("NETWORK_FAILED") from None
    except PublicReadinessStop:
        raise
    except Exception:
        raise PublicReadinessStop("NETWORK_FAILED") from None

    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise PublicReadinessStop("HTTP_BODY_OVERSIZED")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise PublicReadinessStop("HTTP_BODY_INVALID") from None
    if type(payload) is not dict or payload != EXPECTED_HEALTH[name]:
        raise PublicReadinessStop("HTTP_BODY_INVALID")


def run_probe(
    *,
    opener: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """One pass; no retries, no credential resolution, no provider mutations."""
    if opener is None:
        opener = urllib.request.build_opener(
            _RejectRedirects,
            urllib.request.ProxyHandler({}),
        ).open
    completed = []
    for name in ("startup", "live", "ready"):
        try:
            check_health(opener, name=name)
        except PublicReadinessStop as exc:
            return {
                "classification": "DEVELOPMENT_PUBLIC_READINESS_FAILED",
                "failure_code": exc.code,
                "failed_check": name,
                "passed_checks": completed,
                "credential_used": False,
                "provider_mutation_attempted": False,
            }
        completed.append(name)
    return {
        "classification": "DEVELOPMENT_PUBLIC_READINESS_PASS",
        "passed_checks": completed,
        "credential_used": False,
        "provider_mutation_attempted": False,
    }


def main(environ: Mapping[str, str] | None = None) -> int:
    try:
        verify_invocation(os.environ if environ is None else environ)
    except PublicReadinessStop as exc:
        print(json.dumps({
            "classification": "DEVELOPMENT_PUBLIC_READINESS_FAILED",
            "failure_code": exc.code,
            "credential_used": False,
            "provider_mutation_attempted": False,
        }, sort_keys=True))
        return 1

    result = run_probe()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["classification"] == "DEVELOPMENT_PUBLIC_READINESS_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
