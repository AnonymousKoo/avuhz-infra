"""Read-only DEVELOPMENT AUTH session-state inspection primitives.

This module prepares one narrowly bounded Management API read. It has no
provider-mutation or session-cleanup function. The existing DEVELOPMENT
provider-read credential is supplied only at execution time and never logged,
returned, persisted, or represented here.

The query uses Supabase's Management API read-only SQL endpoint and verifies
``current_user = 'supabase_read_only_user'``. Public contract evidence checked
2026-09-18: the Management API introduction requires an access token in the
``Authorization: Bearer <access_token>`` header; the Get project reference
documents ``GET /v1/projects/{ref}``; and the read-only query reference
documents ``POST /v1/projects/{ref}/database/query/read-only``. Supabase
Platform Access Control documents that Read-Only SQL Query Snippet activity
runs as ``supabase_read_only_user``.

Authoritative sources:
https://supabase.com/docs/reference/api/v1-read-only-query
https://supabase.com/docs/reference/api/v1-get-project
https://supabase.com/docs/reference/api/introduction
https://supabase.com/docs/guides/platform/access-control

The provider may return raw Auth subject UUIDs to this process only. They are
hashed immediately for constant-time comparison to the canonical expected
subject digest and are never copied into results, errors, evidence, or logs.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn

from avuhz_engineering.provider_read_http import request_json


DEVELOPMENT_AUTH_PROJECT_REF = "pwlhruwutoitnieactol"
PROVIDER_READ_CREDENTIAL_CLASS = "SUPABASE_PROVIDER_READ"
PROVIDER_READ_ENV_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"
MANAGEMENT_API_ORIGIN = "https://api.supabase.com"
READ_ONLY_SQL_PATH = (
    f"/v1/projects/{DEVELOPMENT_AUTH_PROJECT_REF}/database/query/read-only"
)
EXPECTED_READ_ONLY_IDENTITY = "supabase_read_only_user"
MAX_STATE_ROWS = 4096

_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


# SELECT/UNION ALL only: no callable in this module accepts caller-supplied SQL.
SESSION_STATE_QUERY = """
select
  'BOUNDARY'::text as row_kind,
  (current_user = 'supabase_read_only_user') as read_only_identity_ok,
  null::text as state_kind,
  null::text as provider_subject
union all
select
  'STATE'::text,
  true,
  'SESSION'::text,
  user_id::text
from auth.sessions
union all
select
  'STATE'::text,
  true,
  'REFRESH_TOKEN'::text,
  user_id::text
from auth.refresh_tokens
order by row_kind, state_kind, provider_subject
""".strip()


class InspectionClassification(str, Enum):
    CLEAN_0_0 = "CLEAN_0_0"
    SESSION_PRESENT = "SESSION_PRESENT"
    REFRESH_TOKEN_PRESENT = "REFRESH_TOKEN_PRESENT"
    SESSION_AND_REFRESH_PRESENT = "SESSION_AND_REFRESH_PRESENT"
    IDENTITY_BINDING_MISMATCH = "IDENTITY_BINDING_MISMATCH"
    SESSION_STATE_UNVERIFIED = "SESSION_STATE_UNVERIFIED"


class SafeInspectionStop(RuntimeError):
    """Fail closed with only a fixed code and sanitized classification."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.classification = InspectionClassification.SESSION_STATE_UNVERIFIED

    def __repr__(self) -> str:
        return (
            "SafeInspectionStop("
            f"code={self.code!r}, classification={self.classification.value!r})"
        )


def _stop(code: str) -> NoReturn:
    raise SafeInspectionStop(code)


@dataclass(frozen=True)
class SessionInspectionResult:
    classification: InspectionClassification
    session_count: int
    refresh_token_count: int
    expected_subject_binding_verified: bool | None


def _extract_state_rows(payload: Any) -> list[dict[str, Any]]:
    expected_fields = {
        "row_kind",
        "read_only_identity_ok",
        "state_kind",
        "provider_subject",
    }
    rows: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == expected_fields:
                rows.append(value)
            else:
                for child in value.values():
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    if not rows or len(rows) > MAX_STATE_ROWS + 1:
        _stop("SESSION_INSPECTION_RESPONSE_INVALID")
    return rows


def classify_session_state(
    payload: Any,
    *,
    expected_subject_digest: str,
) -> SessionInspectionResult:
    """Classify raw readback while retaining no provider subject identifiers."""

    if not isinstance(expected_subject_digest, str) or not _SHA256.fullmatch(
        expected_subject_digest
    ):
        _stop("SESSION_INSPECTION_EXPECTED_SUBJECT_INVALID")
    rows = _extract_state_rows(payload)
    boundary = [row for row in rows if row.get("row_kind") == "BOUNDARY"]
    state_rows = [row for row in rows if row.get("row_kind") == "STATE"]
    if (
        len(boundary) != 1
        or boundary[0] != {
            "row_kind": "BOUNDARY",
            "read_only_identity_ok": True,
            "state_kind": None,
            "provider_subject": None,
        }
        or len(boundary) + len(state_rows) != len(rows)
    ):
        _stop("SESSION_INSPECTION_RESPONSE_INVALID")

    sessions = 0
    refresh_tokens = 0
    identity_mismatch = False
    for row in state_rows:
        state_kind = row.get("state_kind")
        provider_subject = row.get("provider_subject")
        if (
            row.get("read_only_identity_ok") is not True
            or state_kind not in {"SESSION", "REFRESH_TOKEN"}
            or not isinstance(provider_subject, str)
            or not _CANONICAL_UUID.fullmatch(provider_subject)
        ):
            _stop("SESSION_INSPECTION_RESPONSE_INVALID")
        observed_digest = "sha256:" + hashlib.sha256(
            provider_subject.encode("utf-8")
        ).hexdigest()
        identity_mismatch = identity_mismatch or not hmac.compare_digest(
            observed_digest,
            expected_subject_digest,
        )
        if state_kind == "SESSION":
            sessions += 1
        else:
            refresh_tokens += 1

    if identity_mismatch:
        classification = InspectionClassification.IDENTITY_BINDING_MISMATCH
        binding_verified: bool | None = False
    elif not state_rows:
        classification = InspectionClassification.CLEAN_0_0
        binding_verified = None
    elif sessions and refresh_tokens:
        classification = InspectionClassification.SESSION_AND_REFRESH_PRESENT
        binding_verified = True
    elif sessions:
        classification = InspectionClassification.SESSION_PRESENT
        binding_verified = True
    else:
        classification = InspectionClassification.REFRESH_TOKEN_PRESENT
        binding_verified = True

    return SessionInspectionResult(
        classification=classification,
        session_count=sessions,
        refresh_token_count=refresh_tokens,
        expected_subject_binding_verified=binding_verified,
    )


def inspect_development_auth_session_state(
    *,
    read_token: str,
    expected_subject_digest: str,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> SessionInspectionResult:
    """Perform target preflight and one read-only SQL inspection; never mutate."""

    project = request_json(
        f"{MANAGEMENT_API_ORIGIN}/v1/projects/{DEVELOPMENT_AUTH_PROJECT_REF}",
        read_token=read_token,
        accepted_statuses=(200,),
        failure_code_prefix="SESSION_INSPECTION_PROJECT_READ",
        credential_unavailable_code="SESSION_INSPECTION_CREDENTIAL_UNAVAILABLE",
        stop=_stop,
        urlopen=urlopen,
    )
    if (
        not isinstance(project, dict)
        or project.get("id") != DEVELOPMENT_AUTH_PROJECT_REF
        or project.get("ref") != DEVELOPMENT_AUTH_PROJECT_REF
        or project.get("name") != "DEVELOPMENT AUTH"
    ):
        _stop("SESSION_INSPECTION_PROJECT_MISMATCH")

    payload = request_json(
        f"{MANAGEMENT_API_ORIGIN}{READ_ONLY_SQL_PATH}",
        read_token=read_token,
        method="POST",
        body={"query": SESSION_STATE_QUERY},
        accepted_statuses=(201,),
        failure_code_prefix="SESSION_INSPECTION_READ",
        credential_unavailable_code="SESSION_INSPECTION_CREDENTIAL_UNAVAILABLE",
        stop=_stop,
        urlopen=urlopen,
    )
    return classify_session_state(
        payload,
        expected_subject_digest=expected_subject_digest,
    )


def sanitized_inspection_evidence(
    result: SessionInspectionResult,
    *,
    plan_id: str,
    plan_digest: str,
) -> dict[str, Any]:
    """Build the only future evidence surface; raw rows are unrepresentable."""

    evidence: dict[str, Any] = {
        "environment": "DEVELOPMENT",
        "project_reference": DEVELOPMENT_AUTH_PROJECT_REF,
        "responsibility": "AUTH",
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "inspection_classification": result.classification.value,
        "session_count": result.session_count,
        "refresh_token_count": result.refresh_token_count,
        "provider_read_attempted": True,
        "provider_mutation_attempted": False,
        "credential_material_retained": False,
        "pii_retained": False,
        "data_touched": False,
        "render_touched": False,
        "n8n_touched": False,
        "staging_touched": False,
        "production_touched": False,
    }
    if result.expected_subject_binding_verified is not None:
        evidence["expected_subject_binding_verified"] = (
            result.expected_subject_binding_verified
        )
    return evidence
