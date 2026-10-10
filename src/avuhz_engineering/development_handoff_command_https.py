"""One-shot HTTPS command transport for a future approved DEVELOPMENT handoff.

This is a dormant *transport only*, not a runnable handoff, credential source,
approval, workflow step, or owner/client registration mechanism.

The existing source-bound executor independently verifies GitHub provenance,
owner signatures, stage authorization, protected DATA claims, and the exact
synthetic command *before* injecting this callable as `send_once`. This module
must never be invoked with real customer content or outside that approved
execution boundary. There is no default workflow binding.

At most one HTTPS POST per transport instance; neither transport errors nor
ambiguous responses may trigger a retry. This local guard is NOT a substitute
for cross-run durable claim consumption.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from avuhz_engineering.development_source_bound_handoff_lifecycle import COMMAND_URL
from avuhz_engineering.development_synthetic_handoff_preflight import (
    MAX_COMMAND_RESPONSE_BYTES,
)

_MAX_COMMAND_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 10
_TRANSPORT_INVALID = "HANDOFF_TRANSPORT_INPUT_INVALID"
_TRANSPORT_FAILED = "HANDOFF_TRANSPORT_OUTCOME_UNVERIFIED"
_TRANSPORT_USED = "HANDOFF_TRANSPORT_ATTEMPT_ALREADY_CONSUMED"


class HandoffCommandTransportStop(RuntimeError):
    """Fixed non-sensitive code; never include JWT, payload, URL or provider text."""


class _NeverRedirectBearer(urllib.request.HTTPRedirectHandler):
    """The Authorization header must not be copied to any redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DevelopmentOneShotCommandHttps:
    """Accepts the existing `send_once(command, token)` call signature.

    Does not own credentials, sign an approval, authorize a command, resolve
    providers or grant permission to contact Render. An authorized, disposable
    runner must construct this only *after* all independent gates pass.
    """

    def __init__(self):
        self._attempt_lock = threading.Lock()
        self._attempted = False

    def __call__(self, command: dict, access_token: str) -> tuple[int, bytes]:
        # Validate all local inputs before consuming the one-attempt guard.
        if type(command) is not dict or type(access_token) is not str:
            raise HandoffCommandTransportStop(_TRANSPORT_INVALID)
        if (
            not 32 <= len(access_token) <= 16384
            or any(ord(c) < 33 or ord(c) > 126 for c in access_token)
        ):
            raise HandoffCommandTransportStop(_TRANSPORT_INVALID)
        try:
            body = json.dumps(
                command, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, OverflowError):
            raise HandoffCommandTransportStop(_TRANSPORT_INVALID) from None
        if not body or len(body) > _MAX_COMMAND_BYTES:
            raise HandoffCommandTransportStop(_TRANSPORT_INVALID)

        with self._attempt_lock:
            if self._attempted:
                raise HandoffCommandTransportStop(_TRANSPORT_USED)
            # Any exception or 5xx after this point is ambiguous. No retry.
            self._attempted = True

        req = urllib.request.Request(
            COMMAND_URL, method="POST", data=body,
            headers={
                "Authorization": "Bearer " + access_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Cache-Control": "no-store",
            },
        )
        # Only a fixed HTTPS origin; no environment proxies or redirects.
        # Uses Python's standard system-CA TLS verification.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NeverRedirectBearer(),
        )
        try:
            with opener.open(req, timeout=_TIMEOUT_SECONDS) as response:
                status = response.status
                if type(status) is not int or not 100 <= status <= 599:
                    raise HandoffCommandTransportStop(_TRANSPORT_FAILED)
                if response.geturl() != COMMAND_URL:
                    raise HandoffCommandTransportStop(_TRANSPORT_FAILED)
                # Never read error bodies; even benign status responses may
                # contain provider or customer information.
                if status != 202:
                    return status, b""
                result = response.read(MAX_COMMAND_RESPONSE_BYTES + 1)
                if type(result) is not bytes or len(result) > MAX_COMMAND_RESPONSE_BYTES:
                    raise HandoffCommandTransportStop(_TRANSPORT_FAILED)
                return status, result
        except urllib.error.HTTPError as error:
            # HTTPError contains response headers/body and the outbound
            # Authorization request. Never format/log/raise it.
            status = error.code
            try:
                error.close()
            except Exception:
                pass
            if type(status) is int and 100 <= status <= 599:
                return status, b""
            raise HandoffCommandTransportStop(_TRANSPORT_FAILED) from None
        except Exception:
            raise HandoffCommandTransportStop(_TRANSPORT_FAILED) from None
