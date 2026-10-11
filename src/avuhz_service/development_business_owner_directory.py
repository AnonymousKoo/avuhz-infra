"""Dormant shared DEVELOPMENT business-owner directory signature verifier.

This is NOT a directory, ownership investigation, trusted-key enrollment,
hosted binding or authorization. Signed platform-operator/GitHub approval,
JWT login, MFA, self-attested business details and tenant metadata DO NOT
constitute independent proof of ownership.

A trusted, separately approved server-side directory integration must fetch a
fresh Ed25519-signed decision for the exact verified AUTH subject digest and
opaque business reference. The directory signing key MUST be independently
attributed and fingerprint-pinned in a protected DEVELOPMENT configuration;
a browser-supplied key/statement or a test-generated key provides no authority.

The source must independently verify business ownership and authorization of
the named person, maintain current revocation state, and issue decisions only
on a live server-side lookup. Signed data can prove who attested, not whether
the directory's real-world checks were performed correctly.

No API, registry entry, DATA grant, credential, AUTH mutation, vertical-specific
path, or production/provider contact is added by this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .development import DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF

PURPOSE = "AVUHZ_DEVELOPMENT_BUSINESS_OWNER_ASSERTION_V1"
ISSUER = "AUTHORITATIVE_OWNER_DIRECTORY"
ENVIRONMENT = "DEVELOPMENT"
_FIELDS = frozenset({
    "purpose", "issuer", "environment", "auth_project_ref", "data_project_ref",
    "business_reference", "subject_digest", "ownership_status",
    "issued_at", "expires_at",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_BUSINESS = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", re.ASCII)
_MAX_AGE = timedelta(seconds=60)
_MAX_VALIDITY = timedelta(seconds=90)


@dataclass(frozen=True, slots=True)
class SignedBusinessOwnerDecision:
    """Transport envelope from a trusted internal directory, never a form."""

    statement: Mapping[str, object]
    signature: bytes


def _parse_utc(value: object) -> datetime | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (ValueError, OverflowError):
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


class DevelopmentBusinessOwnerDirectoryCheck:
    """Callable check_business_owner(digest,business,environment) adapter.

    fetch_signed_decision must perform an independent, authenticated,
    server-owned lookup and return a fresh signed decision (or raise).
    Its return value is NEVER directly trusted without signature validation.

    directory_public_key and pinned_fingerprint must be loaded by the trusted
    server from independently approved, environment-specific trust material.
    This constructor only checks their consistency: it CANNOT attest their
    provenance. Do not compose with caller-provided configuration.
    """

    def __init__(
        self,
        *,
        directory_public_key: Ed25519PublicKey,
        pinned_fingerprint: str,
        fetch_signed_decision: Callable[[str, str], SignedBusinessOwnerDecision],
    ):
        if (
            type(directory_public_key) is not Ed25519PublicKey
            or type(pinned_fingerprint) is not str
            or not _DIGEST.fullmatch(pinned_fingerprint)
            or not callable(fetch_signed_decision)
        ):
            raise ValueError("approved owner directory trust boundary required")
        fingerprint = "sha256:" + hashlib.sha256(
            directory_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        if not hmac.compare_digest(fingerprint, pinned_fingerprint):
            raise ValueError("owner directory signing key fingerprint mismatch")
        self._public_key = directory_public_key
        self._fetch_signed_decision = fetch_signed_decision

    def __call__(
        self, subject_digest: object, business_reference: object, environment: object
    ) -> bool:
        # Nothing about a caller's identity is derived from the business name.
        # The subject digest must originate in the signed AUTH checkpoint.
        if (
            type(subject_digest) is not str
            or not _DIGEST.fullmatch(subject_digest)
            or type(business_reference) is not str
            or not 3 <= len(business_reference) <= 128
            or not _BUSINESS.fullmatch(business_reference)
            or environment != ENVIRONMENT
        ):
            return False
        try:
            result = self._fetch_signed_decision(subject_digest, business_reference)
            if type(result) is not SignedBusinessOwnerDecision:
                return False
            statement = result.statement
            if type(statement) is not dict or set(statement) != _FIELDS:
                return False
            if (
                statement["purpose"] != PURPOSE
                or statement["issuer"] != ISSUER
                or statement["environment"] != ENVIRONMENT
                or statement["auth_project_ref"] != DEVELOPMENT_AUTH_PROJECT_REF
                or statement["data_project_ref"] != DEVELOPMENT_DATA_PROJECT_REF
                or statement["auth_project_ref"] == statement["data_project_ref"]
                or statement["business_reference"] != business_reference
                or statement["subject_digest"] != subject_digest
                or statement["ownership_status"] != "VERIFIED"
                or type(result.signature) is not bytes
                or len(result.signature) != 64
            ):
                return False
            issued = _parse_utc(statement["issued_at"])
            expires = _parse_utc(statement["expires_at"])
            now = datetime.now(timezone.utc)
            if (
                issued is None or expires is None
                or issued > now or expires <= now
                or now - issued > _MAX_AGE
                or expires <= issued or expires - issued > _MAX_VALIDITY
            ):
                return False
            canonical = json.dumps(
                statement, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
            self._public_key.verify(result.signature, canonical)
            return True
        except (InvalidSignature, Exception):
            # No PII, attestation, signature, underlying provider details or
            # ownership directory errors should leave this trust boundary.
            return False
