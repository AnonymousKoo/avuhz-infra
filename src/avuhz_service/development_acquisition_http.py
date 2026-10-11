"""Dormant, shared DEVELOPMENT-only HTTP boundary for acquisition intake.

This WSGI application is NOT mounted by the hosted Avuhz service and does not
register a route, a credential, an access policy, or an environment secret.
The public Sekinfra form is NOT connected. All live AUTH/DATA access requires
separate exact approvals, active owner/tenant verification, a persistent rate
limiter, and least-privileged RLS grants.

The server-only caller authenticates with a bearer token verified by the
existing DevelopmentAuthenticatedAcquisitionIngress. Client data may never
provide tenant/organization authority. No PII, token, or raw body is logged,
returned on failure, or included in exception messages.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Callable

from .acquisition_intake_command import (
    AcquisitionIntakeConflict,
    AcquisitionIntakeUnavailable,
)
from .application import AvuhzApplication, RequestError
from .development_acquisition_ingress import DevelopmentAuthenticatedAcquisitionIngress

_PATH = "/v1/acquisition/intakes"
_MAX_BYTES = 8192
_BEARER = re.compile(r"Bearer ([A-Za-z0-9_.~-]{32,16384})", re.ASCII)


class DevelopmentAcquisitionHttpAdapter:
    """Unmounted, authenticated WSGI adapter to the shared Avuhz intake core.

    HTTPS scheme is an additional fail-closed check. Real deployment must use
    a TLS-terminating trusted ingress and protect internal hops; never trust
    request-supplied X-Forwarded-* headers as transport or identity evidence.
    """

    def __init__(
        self,
        ingress: DevelopmentAuthenticatedAcquisitionIngress,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if type(ingress) is not DevelopmentAuthenticatedAcquisitionIngress:
            raise ValueError("shared DEVELOPMENT acquisition ingress required")
        if not callable(clock):
            raise ValueError("server clock required")
        self._ingress = ingress
        self._clock = clock

    def __call__(self, environ, start_response):
        try:
            status, result = self._route(environ)
        except RequestError as error:
            status, result = error.status, {"error": error.code}
        except PermissionError:
            status, result = 403, {"error": "acquisition_intake_not_authorized"}
        except AcquisitionIntakeConflict:
            status, result = 409, {"error": "acquisition_intake_conflict"}
        except AcquisitionIntakeUnavailable:
            status, result = 503, {"error": "acquisition_intake_unavailable"}
        except Exception:
            status, result = 503, {"error": "acquisition_intake_unavailable"}
        return AvuhzApplication._respond(start_response, status, result)

    def _route(self, environ):
        if not isinstance(environ, dict):
            raise RequestError(400, "invalid_acquisition_request")
        if environ.get("PATH_INFO") != _PATH:
            raise RequestError(404, "not_found")
        if environ.get("REQUEST_METHOD") != "POST":
            raise RequestError(405, "method_not_allowed")
        # Never infer HTTPS from headers supplied by an arbitrary client.
        if environ.get("wsgi.url_scheme") != "https":
            raise RequestError(403, "secure_transport_required")
        authorization = environ.get("HTTP_AUTHORIZATION")
        if type(authorization) is not str:
            raise RequestError(401, "bearer_authentication_required")
        match = _BEARER.fullmatch(authorization)
        if match is None:
            raise RequestError(401, "bearer_authentication_required")
        untrusted_token = match.group(1)

        # Parse only after bearer structure validation. The downstream
        # cryptographic verifier always authenticates before any DATA query.
        request = self._read_bounded_json(environ)
        receipt = self._ingress.receive(
            untrusted_identity=untrusted_token,
            untrusted_payload=request,
            evaluated_at=self._clock(),
        )
        return (
            200 if receipt.duplicate else 202,
            {"intake_id": receipt.intake_id, "duplicate": receipt.duplicate},
        )

    @staticmethod
    def _read_bounded_json(environ):
        if environ.get("CONTENT_TYPE") != "application/json":
            raise RequestError(415, "json_content_type_required")
        length_text = environ.get("CONTENT_LENGTH")
        if (
            type(length_text) is not str
            or not length_text
            or len(length_text) > 8
            or not length_text.isascii()
            or not length_text.isdecimal()
        ):
            raise RequestError(411, "content_length_required")
        length = int(length_text)
        if length < 1:
            raise RequestError(400, "invalid_json")
        if length > _MAX_BYTES:
            raise RequestError(413, "request_too_large")
        try:
            raw = environ["wsgi.input"].read(length)
            if type(raw) is not bytes or len(raw) != length:
                raise ValueError

            def reject_duplicate_keys(pairs):
                obj = {}
                for key, value in pairs:
                    if key in obj:
                        raise ValueError
                    obj[key] = value
                return obj

            def reject_nonstandard_constants(value):
                raise ValueError

            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonstandard_constants,
            )
            if type(value) is not dict:
                raise ValueError
            return value
        except Exception:
            raise RequestError(400, "invalid_json") from None
