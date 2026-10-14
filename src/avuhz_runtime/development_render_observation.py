"""Bound one untrusted Render readback to an approved DEVELOPMENT scope.

This is LOCAL/TEST normalization of read-only provider claims. It does not
authenticate a Render response, fetch resources, attest provenance, deploy,
authorize an action, or establish Phase-5D verification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

_ID = re.compile(r"(?:tea|evm|srv|dep)-[a-z0-9]{10,40}\Z", re.ASCII)
_COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_REPO = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z", re.ASCII)
_NAME = re.compile(r"[a-z][a-z0-9-]{2,78}\Z", re.ASCII)
_MAX_DEPLOYS = 20


class RenderReadbackDenied(ValueError):
    """Fail closed without propagating provider payloads."""


@dataclass(frozen=True, slots=True)
class RenderDevelopmentScope:
    workspace_id: str
    environment_id: str
    service_id: str
    service_name: str
    repository_url: str
    branch: str


@dataclass(frozen=True, slots=True)
class RenderObservationCandidate:
    """An untrusted, non-authoritative provider claim for independent review."""

    status: str
    service_reference: str
    deployment_reference: str | None
    commit_sha: str | None
    observed_at: datetime


def _valid_id(value: object, prefix: str) -> bool:
    return type(value) is str and value.startswith(prefix + "-") and bool(_ID.fullmatch(value))


def _valid_scope(scope: object) -> bool:
    return (
        type(scope) is RenderDevelopmentScope
        and _valid_id(scope.workspace_id, "tea")
        and _valid_id(scope.environment_id, "evm")
        and _valid_id(scope.service_id, "srv")
        and type(scope.service_name) is str and bool(_NAME.fullmatch(scope.service_name))
        and type(scope.repository_url) is str and bool(_REPO.fullmatch(scope.repository_url))
        and type(scope.branch) is str and scope.branch == "main"
    )


def normalize_render_development_readback(
    scope: RenderDevelopmentScope,
    service: dict,
    deployments: tuple[dict, ...],
    *,
    observed_at: datetime,
) -> RenderObservationCandidate:
    """Allowlisted projection of *claimed* Render service/deployment readback.

    Callers must independently bind the Render connector workspace and exact
    service request, authenticate provenance, and establish tenant/Phase-5D
    authority. No fields from unknown provider payload keys are retained.
    """
    if (
        not _valid_scope(scope)
        or type(service) is not dict
        or type(deployments) is not tuple
        or len(deployments) > _MAX_DEPLOYS
        or type(observed_at) is not datetime
        or observed_at.tzinfo is not timezone.utc
    ):
        raise RenderReadbackDenied("trusted development scope and UTC clock required")

    if (
        type(service.get("id")) is not str or service["id"] != scope.service_id
        or type(service.get("name")) is not str or service["name"] != scope.service_name
        or type(service.get("ownerId")) is not str or service["ownerId"] != scope.workspace_id
        or type(service.get("environmentId")) is not str or service["environmentId"] != scope.environment_id
        or type(service.get("repo")) is not str or service["repo"] != scope.repository_url
        or type(service.get("branch")) is not str or service["branch"] != scope.branch
        or type(service.get("type")) is not str or service["type"] != "web_service"
    ):
        raise RenderReadbackDenied("Render resource boundary mismatch")

    live: list[dict] = []
    for deployment in deployments:
        if type(deployment) is not dict or type(deployment.get("status")) is not str:
            raise RenderReadbackDenied("invalid Render deployment readback")
        if deployment["status"] == "live":
            live.append(deployment)

    if not live:
        return RenderObservationCandidate("BLOCKED_UNVERIFIED", scope.service_id, None, None, observed_at)
    if len(live) != 1:
        raise RenderReadbackDenied("ambiguous Render live deployment readback")

    deployment = live[0]
    commit = deployment.get("commit")
    if (
        not _valid_id(deployment.get("id"), "dep")
        or type(commit) is not dict
        or type(commit.get("id")) is not str
        or not _COMMIT.fullmatch(commit["id"])
    ):
        raise RenderReadbackDenied("invalid Render live deployment identity")
    return RenderObservationCandidate(
        "UNATTESTED_LIVE_CLAIM", scope.service_id,
        deployment["id"], commit["id"], observed_at,
    )
