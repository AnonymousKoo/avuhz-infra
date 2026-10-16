"""LOCAL/TEST-only contract adapter from the Avuhz outbox to an n8n webhook.

Repository preparation, NOT a live integration. The caller must inject a trusted,
non-redirecting HTTPS transport and an environment-scoped encrypted credential.
No network client, deployment binding, workflow, or provider permission is created.
The Avuhz outbox owns delivery/retry; n8n cannot change authoritative state here.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.schema_registry import SchemaRegistry
from .outbox import DeliveryRejected, DeliveryUnavailable


_WEBHOOK_PATH = re.compile(r"/webhook/[a-z0-9][a-z0-9-]{0,63}\Z")
_DELIVERY_KEY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")
_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"
_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "contracts/schemas/v1"
# Receiver v2 emits 202 only after an independently committed durable receipt.
# Generic 2xx responses do NOT prove durable acceptance of a work event.
_DURABLE_ACK_STATUS = 202


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError):
        return False


def _verified_https_endpoint(endpoint: object, expected_host: object) -> str:
    if type(endpoint) is not str or type(expected_host) is not str:
        raise ValueError("approved n8n destination required")
    if not expected_host or expected_host.lower() != expected_host or "." not in expected_host:
        raise ValueError("approved n8n destination required")
    try:
        ipaddress.ip_address(expected_host)
    except ValueError:
        pass
    else:
        raise ValueError("approved n8n destination required")
    if expected_host.endswith(".local") or expected_host.endswith(".internal"):
        raise ValueError("approved n8n destination required")
    try:
        parsed = urlsplit(endpoint)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == expected_host
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and _WEBHOOK_PATH.fullmatch(parsed.path) is not None
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("approved n8n destination required")
    return endpoint


class N8nOutboxSink:
    """A bounded event-notification sink compatible with OutboxWorker.deliver.

    `post` is a trusted injected function (url, headers, body_bytes) -> HTTP
    status integer. It MUST use verified TLS, disable redirects, and never log
    the credential/header/body. No default network transport is provided.
    An n8n consumer must authenticate headers, deduplicate the delivery key,
    and acknowledge only after durable receipt. Provider setup is separate.
    """

    def __init__(
        self, *, environment: str, tenant_id: str, endpoint: str,
        expected_host: str, credential_provider, post,
    ) -> None:
        if environment not in ("LOCAL", "TEST"):
            raise ValueError("n8n adapter is not authorized for hosted execution")
        if not _canonical_uuid(tenant_id):
            raise ValueError("canonical trusted tenant required")
        if not callable(credential_provider) or not callable(post):
            raise ValueError("approved n8n transport and credential injection required")
        self._tenant_id = tenant_id
        self._endpoint = _verified_https_endpoint(endpoint, expected_host)
        self._credential_provider = credential_provider
        self._post = post
        registry = SchemaRegistry(_SCHEMA_ROOT)
        self._validator = Draft202012Validator(
            registry.expanded(_SCHEMA_ID), format_checker=FormatChecker()
        )

    def deliver(self, idempotency_key: str, event: dict, delivered_at: str):
        if (
            type(event) is not dict
            or type(idempotency_key) is not str
            or _DELIVERY_KEY.fullmatch(idempotency_key) is None
            or event.get("tenant_id") != self._tenant_id
            or not _canonical_uuid(event.get("event_id"))
            or not _canonical_uuid(event.get("correlation_id"))
            or not self._validator.is_valid(event)
        ):
            raise DeliveryRejected("invalid or cross-tenant lifecycle event")

        # Projection deliberately excludes sanitized_metadata, payloads,
        # names, emails, phone numbers, raw provider data, and command inputs.
        envelope = {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "tenant_id": self._tenant_id,
            "correlation_id": event["correlation_id"],
            "occurred_at": event["occurred_at"],
            "authoritative_subject_reference": event["authoritative_subject_reference"],
            "authoritative_subject_version": event["authoritative_subject_version"],
            "delivery_idempotency_key": idempotency_key,
        }
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > 4096:
            raise DeliveryRejected("bounded n8n event envelope required")
        try:
            credential = self._credential_provider()
        except Exception:
            raise DeliveryUnavailable("n8n credential temporarily unavailable") from None
        if (
            type(credential) is not str
            or not 16 <= len(credential) <= 512
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in credential)
        ):
            raise DeliveryRejected("n8n credential is not configured")
        headers = {
            "Content-Type": "application/json",
            "X-Avuhz-Webhook-Token": credential,
            "X-Avuhz-Delivery-Key": idempotency_key,
        }
        try:
            status = self._post(self._endpoint, headers, body)
        except Exception:
            raise DeliveryUnavailable("n8n transport unavailable") from None
        if type(status) is not int:
            raise DeliveryUnavailable("n8n response unavailable")
        if status == _DURABLE_ACK_STATUS:
            return {"result": "PUBLISHED", "event_id": event["event_id"]}
        if 200 <= status < 300:
            # An upstream 200/201/204 can be a default webhook response,
            # proxy acknowledgment or an error page with 2xx status. It
            # cannot promote the shared outbox to PUBLISHED without v2's
            # exact durable-commit gate; keep the existing retry ledger.
            raise DeliveryUnavailable("n8n durable acknowledgment not confirmed")
        if status == 429 or status >= 500:
            raise DeliveryUnavailable("n8n temporarily unavailable")
        raise DeliveryRejected("n8n delivery was rejected")
