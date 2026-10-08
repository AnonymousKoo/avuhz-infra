"""Trusted GitHub Actions *invocation* verification for the first DEVELOPMENT handoff.

This is a source-bound, one-shot, provider-free dispatch boundary; it is not
authorization to issue credentials, consume any approved plan, or submit a
live business command. The caller MUST obtain the environment/event values
from GitHub Actions, and the source observations from trusted Git.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

REPOSITORY = "AnonymousKoo/avuhz-infra"
REPOSITORY_ID = "1231399336"
OWNER_LOGIN = "AnonymousKoo"
OWNER_ACCOUNT_ID = "168945054"
WORKFLOW_PATH = ".github/workflows/development-first-handoff-trusted-dispatch-v1.yml"
WORKFLOW_REF = REPOSITORY + "/" + WORKFLOW_PATH + "@refs/heads/main"
CONFIRMATION = "VERIFY_TRUSTED_DEVELOPMENT_HANDOFF_DISPATCH_V1"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")

REQUIRED_ENVIRONMENT = frozenset({
    "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID",
    "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
    "GITHUB_RUN_NUMBER", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID",
    "AVUHZ_ENVIRONMENT", "AVUHZ_CONFIRMATION", "AVUHZ_EXPECTED_SOURCE_SHA",
    "AVUHZ_AUTHORIZATION_SET_DIGEST",
})


class TrustedInvocationStop(ValueError):
    """Safe code only. No event body, credential, path or PII in failures."""


@dataclass(frozen=True)
class TrustedInvocationEvidence:
    canonical_main_sha: str
    authorization_set_claimed_digest: str
    github_run_id: str
    classification: str = "TRUSTED_GITHUB_ONE_SHOT_DISPATCH_VERIFIED_OFFLINE_ONLY"
    invocation_source_verified: bool = True
    github_first_attempt_verified: bool = True
    owner_approval_verified: bool = False
    authorization_set_verified: bool = False
    distributed_authorization_consumed: bool = False
    credential_resolution_authorized: bool = False
    live_command_authorized: bool = False
    provider_contact_attempted: bool = False


def _deny(code: str) -> None:
    raise TrustedInvocationStop(code)


def verify_trusted_github_invocation(
    environment: Mapping[str, str],
    event: Mapping[str, object],
    *,
    observed_checkout_sha: str,
    observed_remote_main_sha: str,
    observed_git_origin: str,
) -> TrustedInvocationEvidence:
    """Verify GH-supplied dispatch identity, source, and one-shot workflow counter.

    Neither the workflow inputs nor the event sender identity alone constitute
    a separately validated signed owner approval. Never pass this receipt as
    authorize_stage=True or use it to unlock secrets.
    """
    if (
        not isinstance(environment, Mapping)
        or not REQUIRED_ENVIRONMENT <= set(environment)
        or not isinstance(event, dict)
        or not event
    ):
        _deny("HANDOFF_GITHUB_INVOCATION_MISSING")
    try:
        valid = (
            environment["GITHUB_ACTIONS"] == "true"
            and environment["GITHUB_REPOSITORY"] == REPOSITORY
            and environment["GITHUB_REPOSITORY_ID"] == REPOSITORY_ID
            and environment["GITHUB_ACTOR"] == OWNER_LOGIN
            and environment["GITHUB_ACTOR_ID"] == OWNER_ACCOUNT_ID
            and environment["GITHUB_TRIGGERING_ACTOR"] == OWNER_LOGIN
            and environment["GITHUB_EVENT_NAME"] == "workflow_dispatch"
            and environment["GITHUB_REF"] == "refs/heads/main"
            and environment["GITHUB_WORKFLOW_REF"] == WORKFLOW_REF
            and environment["GITHUB_RUN_NUMBER"] == "1"
            and environment["GITHUB_RUN_ATTEMPT"] == "1"
            and environment["AVUHZ_ENVIRONMENT"] == "development"
            and environment["AVUHZ_CONFIRMATION"] == CONFIRMATION
            and type(environment["GITHUB_RUN_ID"]) is str
            and _RUN_ID.fullmatch(environment["GITHUB_RUN_ID"]) is not None
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        _deny("HANDOFF_GITHUB_TRUSTED_CONTEXT_INVALID")
    try:
        actor = event["sender"]
        repository = event["repository"]
        inputs = event["inputs"]
        same_event = (
            isinstance(actor, dict)
            and actor.get("login") == OWNER_LOGIN
            and type(actor.get("id")) is int
            and actor.get("id") == int(OWNER_ACCOUNT_ID)
            and isinstance(repository, dict)
            and repository.get("full_name") == REPOSITORY
            and type(repository.get("id")) is int
            and repository.get("id") == int(REPOSITORY_ID)
            and event.get("ref") == "refs/heads/main"
            and isinstance(inputs, dict)
            and set(inputs) == {"confirmation", "source_sha", "authorization_set_digest"}
            and inputs["confirmation"] == CONFIRMATION
            and inputs["source_sha"] == environment["AVUHZ_EXPECTED_SOURCE_SHA"]
            and inputs["authorization_set_digest"]
            == environment["AVUHZ_AUTHORIZATION_SET_DIGEST"]
        )
    except (KeyError, TypeError, ValueError):
        same_event = False
    if not same_event:
        _deny("HANDOFF_GITHUB_EVENT_MISMATCH")
    sha = environment["GITHUB_SHA"]
    if not (
        type(sha) is str and _SHA.fullmatch(sha) is not None
        and sha == environment["AVUHZ_EXPECTED_SOURCE_SHA"]
        and sha == environment["GITHUB_WORKFLOW_SHA"]
        and sha == observed_checkout_sha == observed_remote_main_sha
        and observed_git_origin in (
            "https://github.com/AnonymousKoo/avuhz-infra",
            "https://github.com/AnonymousKoo/avuhz-infra.git",
        )
    ):
        _deny("HANDOFF_GITHUB_SOURCE_DRIFT")
    digest = environment["AVUHZ_AUTHORIZATION_SET_DIGEST"]
    if (
        type(digest) is not str
        or _DIGEST.fullmatch(digest) is None
        or digest == "sha256:" + "0" * 64
    ):
        _deny("HANDOFF_GITHUB_DIGEST_INVALID")
    return TrustedInvocationEvidence(
        canonical_main_sha=sha,
        authorization_set_claimed_digest=digest,
        github_run_id=environment["GITHUB_RUN_ID"],
    )
