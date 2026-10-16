"""Strict TLS-only transport for the EXISTING shared N8nOutboxSink.

LOCAL/TEST source-only adapter, not a newly activated n8n listener, credential
provider, URL discovery service, owner authority, database writer, scheduler,
or hosted client. The caller supplies an independently reviewed SSLContext
with the exact approved destination's trust material and a hostname.
Credentials are passed only ephemerally by N8nOutboxSink.deliver().

No network happens on import or construction. Do not use this with the
existing plain-HTTP LOCAL n8n :5678 endpoint; an explicitly approved TLS
termination + authenticated durable receiver must exist first.
"""
from __future__ import annotations

import http.client
import json
import ssl
from urllib.parse import urlsplit

from .n8n_event_sink import _verified_https_endpoint

_ENVELOPE = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})
_HEADERS = frozenset({
    "Content-Type", "X-Avuhz-Webhook-Token", "X-Avuhz-Delivery-Key",
})


class LocalN8nHttpsTransport:
    """One bounded non-redirecting POST; supports no other HTTP methods.

    Use as post= in N8nOutboxSink only after a separate operator-controlled
    localhost or domain-verified HTTPS edge is explicitly authorized. The
    HTTPSConnection standard library verifies the hostname and chain through
    the supplied client SSLContext. Credentials and response bodies are never
    recorded or returned.
    """

    def __init__(
        self, *, environment: str, expected_host: str,
        tls_context: ssl.SSLContext, timeout_seconds: int = 5,
    ) -> None:
        if environment not in ("LOCAL", "TEST") or type(timeout_seconds) is not int \
                or not 1 <= timeout_seconds <= 30:
            raise ValueError("approved local n8n transport configuration required")
        # Reuse the same hostname/path policy as the shared N8nOutboxSink.
        _verified_https_endpoint(
            f"https://{expected_host}/webhook/avuhz-events", expected_host,
        )
        if (
            not isinstance(tls_context, ssl.SSLContext)
            or not tls_context.check_hostname
            or tls_context.verify_mode != ssl.CERT_REQUIRED
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("verified TLS context required")
        self._host = expected_host
        self._tls = tls_context
        self._timeout = timeout_seconds

    def __call__(self, url: str, headers: dict, body: bytes) -> int:
        # SSLContext is mutable and owned by the caller. Revalidate it at
        # *each send*, not only construction, to deny later TLS downgrades.
        if (not self._tls.check_hostname
                or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError("verified TLS context required")
        endpoint = _verified_https_endpoint(url, self._host)
        if (
            type(headers) is not dict or set(headers) != _HEADERS
            or headers.get("Content-Type") != "application/json"
            or type(headers.get("X-Avuhz-Webhook-Token")) is not str
            or not 16 <= len(headers["X-Avuhz-Webhook-Token"]) <= 512
            or any(ord(c) < 33 or ord(c) > 126
                   for c in headers["X-Avuhz-Webhook-Token"])
            or type(headers.get("X-Avuhz-Delivery-Key")) is not str
            or type(body) is not bytes or len(body) > 4096
        ):
            raise ValueError("bounded n8n transport request required")
        try:
            event = json.loads(body)
        except (UnicodeDecodeError, ValueError, TypeError):
            raise ValueError("bounded n8n transport request required") from None
        if (
            type(event) is not dict or set(event) != _ENVELOPE
            or event["delivery_idempotency_key"] != headers["X-Avuhz-Delivery-Key"]
        ):
            raise ValueError("bounded n8n transport request required")

        parsed = urlsplit(endpoint)
        # http.client has no redirect following, cookie jar, retries, proxy
        # discovery or response-body rendering. Never print transport errors.
        conn = http.client.HTTPSConnection(
            self._host, port=443, timeout=self._timeout, context=self._tls,
        )
        try:
            conn.request("POST", parsed.path, body=body, headers=headers.copy())
            response = conn.getresponse()
            status = response.status
            # No body/header read, no Location following, no logs, no token echo.
            # Existing sink handles 4xx vs retryable 429/5xx independently.
            if type(status) is not int or not 100 <= status <= 599:
                raise OSError("n8n response unavailable")
            if 300 <= status < 400:
                raise OSError("n8n redirect denied")
            return status
        finally:
            conn.close()
