"""Bounded authenticated HTTP probe for a *future* DEVELOPMENT provider-adapter test.

This module performs no session creation, JWT issuance, logout, or provider
administration. It makes one authorized caller-supplied bearer-token request to
the existing Avuhz DEVELOPMENT query endpoint. Only the exact HTTP 400
{"error":"invalid_query"} response establishes live identity acceptance.

The failed/consumed v14 executors are immutable; incorporating this probe into a
new lifecycle requires fresh exact authorization and source-digest bindings.
Never print, persist, hash, or include bearer tokens or provider response text
in error messages.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from avuhz_engineering.development_auth_token_lifecycle import SafeLifecycleStop
from scripts.development_live_probe_classifier_v1 import (
    MAX_RESPONSE_BYTES,
    PROBE_ACCEPTED,
    classify_http_response,
    classify_transport_error,
)

DEVELOPMENT_QUERY_URL = "https://avuhz-command-dev.onrender.com/v1/queries"
PROBE_TIMEOUT_SECONDS = 15


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _fixed_failure(code: str) -> None:
    """Propagate an allowlisted status category, never raw exception text."""
    raise SafeLifecycleStop(code)


def authenticated_live_identity_probe(
    access_token: str,
    *,
    opener: Callable[..., Any] | None = None,
) -> None:
    """One HTTPS request, no retry or redirects; no data-changing API call."""
    if (
        type(access_token) is not str
        or not 32 <= len(access_token) <= 16384
        or any(character.isspace() for character in access_token)
    ):
        _fixed_failure("LIVE_PROBE_CREDENTIAL_UNAVAILABLE")

    if opener is None:
        opener = urllib.request.build_opener(
            _RejectRedirects(),
            urllib.request.ProxyHandler({}),
        ).open

    request = urllib.request.Request(
        DEVELOPMENT_QUERY_URL,
        data=b"{}",
        method="POST",
        headers={
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with opener(request, timeout=PROBE_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            raw = response.read(MAX_RESPONSE_BYTES + 1) if status == 400 else None
            outcome = classify_http_response(status, raw)
    except urllib.error.HTTPError as error:
        outcome = classify_transport_error(error)
    except Exception as error:
        outcome = classify_transport_error(error)

    if outcome != PROBE_ACCEPTED:
        _fixed_failure(outcome)
