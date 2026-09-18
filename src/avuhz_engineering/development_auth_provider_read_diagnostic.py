"""One-request DEVELOPMENT AUTH project-metadata diagnostic.

This helper can issue only the project metadata GET. It has no SQL, Auth
Admin, session, token, cleanup, or mutation path. Raw provider JSON and the
runtime provider-read credential are never returned or represented in evidence.
"""
from __future__ import annotations

import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, NoReturn

from avuhz_engineering.provider_read_http import (
    MAX_PROVIDER_RESPONSE_BYTES,
    request_json,
)


DEVELOPMENT_AUTH_PROJECT_REF = "pwlhruwutoitnieactol"
DEVELOPMENT_AUTH_PROJECT_NAME = "DEVELOPMENT AUTH"
PROVIDER_READ_CREDENTIAL_CLASS = "SUPABASE_PROVIDER_READ"
PROVIDER_READ_ENV_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"
PROJECT_READ_URL = (
    f"https://api.supabase.com/v1/projects/{DEVELOPMENT_AUTH_PROJECT_REF}"
)
PROJECT_READ_CONTRACT = {
    "method": "GET",
    "url": PROJECT_READ_URL,
    "accepted_statuses": [200],
    "maximum_response_bytes": MAX_PROVIDER_RESPONSE_BYTES,
    "expected_project": {
        "id": DEVELOPMENT_AUTH_PROJECT_REF,
        "ref": DEVELOPMENT_AUTH_PROJECT_REF,
        "name": DEVELOPMENT_AUTH_PROJECT_NAME,
    },
}


class ProjectReadClassification(str, Enum):
    PROJECT_READ_OK = "PROJECT_READ_OK"


class SafeProviderReadDiagnosticStop(RuntimeError):
    """Fail closed with one fixed code and no provider-derived text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"SafeProviderReadDiagnosticStop(code={self.code!r})"


def _stop(code: str) -> NoReturn:
    raise SafeProviderReadDiagnosticStop(code)


@dataclass(frozen=True)
class ProjectReadDiagnosticResult:
    classification: ProjectReadClassification


def inspect_development_auth_project_metadata(
    *,
    read_token: str,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> ProjectReadDiagnosticResult:
    """Issue exactly one project GET and retain only the target-match result."""

    project = request_json(
        PROJECT_READ_URL,
        read_token=read_token,
        accepted_statuses=(200,),
        failure_code_prefix="PROJECT_READ",
        credential_unavailable_code="PROJECT_READ_CREDENTIAL_UNAVAILABLE",
        stop=_stop,
        urlopen=urlopen,
    )
    if not isinstance(project, dict) or any(
        not isinstance(project.get(field), str)
        for field in ("id", "ref", "name")
    ):
        _stop("PROJECT_READ_RESPONSE_INVALID")
    if any(
        project[field] != expected
        for field, expected in PROJECT_READ_CONTRACT["expected_project"].items()
    ):
        _stop("PROJECT_READ_MISMATCH")
    return ProjectReadDiagnosticResult(
        classification=ProjectReadClassification.PROJECT_READ_OK,
    )


def sanitized_project_read_evidence(
    result: ProjectReadDiagnosticResult,
    *,
    plan_id: str,
    plan_digest: str,
) -> dict[str, Any]:
    """Return the only permitted future success output surface."""

    return {
        "environment": "DEVELOPMENT",
        "project_reference": DEVELOPMENT_AUTH_PROJECT_REF,
        "responsibility": "AUTH",
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "diagnostic_classification": result.classification.value,
        "provider_read_attempted": True,
        "provider_request_count": 1,
        "sql_session_inspection_attempted": False,
        "provider_mutation_attempted": False,
        "credential_material_retained": False,
        "raw_provider_response_retained": False,
        "pii_retained": False,
        "data_touched": False,
        "render_touched": False,
        "n8n_touched": False,
        "staging_touched": False,
        "production_touched": False,
    }
