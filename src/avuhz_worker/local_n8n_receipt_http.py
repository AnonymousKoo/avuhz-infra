"""LOCAL/TEST-only loopback HTTP facade for the shared n8n receipt store.

No network-facing n8n workflow, external service, HTTP client, DATA access,
credential provisioning, or production feature is provided. The caller must
inject a protected, process-memory-only LOCAL/TEST shared secret. This proof
runs on 127.0.0.1 only; a Docker-connected deployment requires its own
separately approved network and credential boundary.
"""
from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .local_n8n_receipt_store import (
    ConflictingReceipt,
    InvalidReceipt,
    LocalN8nReceiptStore,
    ReceiptStoreUnavailable,
    UnauthorizedReceipt,
)

PATH = "/v1/avuhz/local-n8n-receipts"
AUTH_HEADER = "X-Avuhz-Receipt-Bridge-Token"
DELIVERY_HEADER = "X-Avuhz-Delivery-Key"
MAX_BODY = 4096


class LocalN8nReceiptHTTPServer(ThreadingHTTPServer):
    """Only a loopback, independently authenticated test receiver."""

    daemon_threads = True

    def __init__(
        self, *, receipt_store: LocalN8nReceiptStore,
        token_provider: Callable[[], str],
    ):
        if not isinstance(receipt_store, LocalN8nReceiptStore) or not callable(token_provider):
            raise ValueError("approved LOCAL receipt storage and secret source required")
        self.receipt_store = receipt_store
        self.token_provider = token_provider
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: LocalN8nReceiptHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        # Standard access logging can expose request paths and operational IDs.
        # Nothing from inbound requests may be printed here.
        pass

    def _respond(self, code: int, message: dict) -> None:
        raw = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path != PATH:
            self._respond(404, {"error": "not_found"})
            return
        try:
            expected = self.server.token_provider()
        except Exception:
            self._respond(503, {"error": "credential_unavailable"})
            return
        if (
            type(expected) is not str or not 32 <= len(expected) <= 512
            or any(ord(c) < 33 or ord(c) > 126 for c in expected)
        ):
            self._respond(503, {"error": "credential_unavailable"})
            return
        supplied_values = self.headers.get_all(AUTH_HEADER, [])
        supplied = supplied_values[0] if len(supplied_values) == 1 else None
        if (
            type(supplied) is not str
            or len(supplied) > 512
            or not hmac.compare_digest(supplied, expected)
        ):
            self._respond(401, {"error": "unauthorized"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._respond(415, {"error": "unsupported_media_type"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
            self._respond(400, {"error": "invalid_request"})
            return
        size_header = lengths[0]
        try:
            if not size_header or not size_header.isascii() or not size_header.isdecimal():
                raise ValueError
            size = int(size_header)
        except ValueError:
            self._respond(400, {"error": "invalid_request"})
            return
        if not 1 <= size <= MAX_BODY:
            self._respond(413, {"error": "payload_too_large"})
            return
        try:
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError
            def unique_pairs(pairs):
                output = {}
                for key, value in pairs:
                    if key in output:
                        raise ValueError("duplicate JSON field")
                    output[key] = value
                return output
            obj = json.loads(body, object_pairs_hook=unique_pairs)
        except (ValueError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_event_envelope"})
            return
        try:
            receipt = self.server.receipt_store.receive(
                obj, delivery_header=self.headers.get(DELIVERY_HEADER)
            )
        except InvalidReceipt:
            self._respond(400, {"error": "invalid_event_envelope"})
        except UnauthorizedReceipt:
            self._respond(403, {"error": "not_authorized"})
        except ConflictingReceipt:
            self._respond(409, {"error": "delivery_key_conflict"})
        except ReceiptStoreUnavailable:
            self._respond(503, {"error": "receipt_store_unavailable"})
        else:
            self._respond(receipt.status, {"accepted": True, "duplicate": receipt.duplicate})

    def do_GET(self):
        self._respond(405, {"error": "method_not_allowed"})

    def do_PUT(self):
        self._respond(405, {"error": "method_not_allowed"})
