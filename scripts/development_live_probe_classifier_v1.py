"""Safe, offline classification for a *future* DEVELOPMENT live-auth probe.

The consumed v14 / continuation executors remain immutable. This module performs
no HTTP requests and accepts no credentials. An independently authorized future
executor may use these pure classifiers to record a bounded outcome code rather
than flattening an HTTP failure, timeout, or cold start into one generic error.

Never log response bodies, exception text, URLs, or bearer-token material.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error

MAX_RESPONSE_BYTES = 4096

PROBE_ACCEPTED = "LIVE_PROBE_AUTH_ACCEPTED"


def classify_http_response(status: object, body: object = None) -> str:
    """Return a safe status code, never a raw response or response-derived text.

    The existing Avuhz side-effect-free probe expects HTTP 400 and exactly
    {"error": "invalid_query"} after successful trusted identity resolution.
    """
    if type(status) is not int or not 100 <= status <= 599:
        return "LIVE_PROBE_HTTP_STATUS_INVALID"
    if status == 400:
        if type(body) is not bytes or len(body) > MAX_RESPONSE_BYTES:
            return "LIVE_PROBE_RESPONSE_SHAPE_INVALID"
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "LIVE_PROBE_RESPONSE_SHAPE_INVALID"
        return (
            PROBE_ACCEPTED
            if type(decoded) is dict and decoded == {"error": "invalid_query"}
            else "LIVE_PROBE_RESPONSE_SHAPE_INVALID"
        )
    if status == 401:
        return "LIVE_PROBE_IDENTITY_REJECTED"
    if status == 403:
        return "LIVE_PROBE_AUTHORIZATION_DENIED"
    if 300 <= status <= 399:
        return "LIVE_PROBE_REDIRECT_REJECTED"
    if status in (408, 504):
        return "LIVE_PROBE_HTTP_TIMEOUT"
    if status == 429:
        return "LIVE_PROBE_RATE_LIMITED"
    if 500 <= status <= 599:
        return "LIVE_PROBE_SERVICE_UNAVAILABLE"
    return "LIVE_PROBE_UNEXPECTED_HTTP_STATUS"


def classify_transport_error(error: BaseException) -> str:
    """Classify by exception *type only*, never by potentially sensitive text.

    HTTPError carries an optional bounded body; reading that body is permitted
    solely to compare against the fixed expected response. Nothing is retained.
    """
    if isinstance(error, urllib.error.HTTPError):
        try:
            body = error.read(MAX_RESPONSE_BYTES + 1)
        except Exception:
            return "LIVE_PROBE_RESPONSE_READ_FAILED"
        return classify_http_response(error.code, body)
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "LIVE_PROBE_NETWORK_TIMEOUT"
    if isinstance(reason, ssl.SSLError):
        return "LIVE_PROBE_TLS_FAILURE"
    if isinstance(reason, socket.gaierror):
        return "LIVE_PROBE_DNS_FAILURE"
    if isinstance(reason, (ConnectionRefusedError, ConnectionResetError, BrokenPipeError)):
        return "LIVE_PROBE_CONNECTION_FAILURE"
    return "LIVE_PROBE_NETWORK_FAILURE"
