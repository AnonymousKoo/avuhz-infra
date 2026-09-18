"""Body-free, bounded HTTP handling for provider-read operations."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, NoReturn


MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024


def _management_headers(
    read_token: str,
    *,
    stop: Callable[[str], NoReturn],
    credential_code: str,
) -> dict[str, str]:
    if not isinstance(read_token, str) or not read_token:
        stop(credential_code)
    return {
        "Authorization": f"Bearer {read_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def http_failure_code(failure_code_prefix: str, status: Any) -> str:
    """Map only a bounded HTTP status class; never inspect response content."""

    if status == 401:
        suffix = "AUTHENTICATION_REJECTED"
    elif status == 403:
        suffix = "FORBIDDEN"
    elif status == 404:
        suffix = "NOT_FOUND"
    elif status == 429:
        suffix = "RATE_LIMITED"
    elif isinstance(status, int) and 500 <= status <= 599:
        suffix = "PROVIDER_FAILURE"
    else:
        suffix = "UNEXPECTED_STATUS"
    return f"{failure_code_prefix}_{suffix}"


def request_json(
    url: str,
    *,
    read_token: str,
    accepted_statuses: tuple[int, ...],
    failure_code_prefix: str,
    credential_unavailable_code: str,
    stop: Callable[[str], NoReturn],
    urlopen: Callable[..., Any],
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
) -> Any:
    """Perform exactly one request and retain no raw response or failure body."""

    encoded = (
        None
        if body is None
        else json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
    )
    request = urllib.request.Request(
        url,
        data=encoded,
        method=method,
        headers=_management_headers(
            read_token,
            stop=stop,
            credential_code=credential_unavailable_code,
        ),
    )
    raw = bytearray()
    response_failure_code: str | None = None
    try:
        try:
            with urlopen(request, timeout=30) as response:
                if response.status not in accepted_statuses:
                    # Non-accepted bodies can carry provider or credential-
                    # adjacent details. Classify by bounded status only.
                    response_failure_code = http_failure_code(
                        failure_code_prefix,
                        response.status,
                    )
                else:
                    raw.extend(response.read(MAX_PROVIDER_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as exc:
            # HTTPError is response-like. Inspect only its integer code; never
            # read/stringify its body, headers, reason, or arbitrary text.
            stop(http_failure_code(failure_code_prefix, exc.code))
        except Exception:
            # Transport exception text can expose hosts or request details.
            stop(f"{failure_code_prefix}_REQUEST_FAILED")
        if response_failure_code is not None:
            stop(response_failure_code)
        if not raw or len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            stop(f"{failure_code_prefix}_RESPONSE_INVALID")
        try:
            return json.loads(raw)
        except Exception:
            stop(f"{failure_code_prefix}_RESPONSE_INVALID")
    finally:
        for index in range(len(raw)):
            raw[index] = 0
        raw.clear()
