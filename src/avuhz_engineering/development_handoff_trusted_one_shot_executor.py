"""Injection-only one-shot DEVELOPMENT handoff execution composition.

This module makes the previously separate GitHub invocation, cryptographic
owner proof, bounded plan preflight and four-stage claim atomic at the
single-runner boundary *before* the existing one-shot lifecycle may call any
injected provider callback.

NO workflow step imports/runs this module by default. NO credential source,
HTTP client, signing key or live approval is bundled. The existing one-run
GitHub workflow is OFFLINE ONLY. A future approved executor must separately
verify the signing-key enrollment, runner/ledger durability, provider
credentials, stage scopes, DATA postconditions and secret retirement.

The pre-provisioned SQLite ledger is shared only among processes using that
exact host file. GitHub's run_number==1/attempt==1 guard makes one exact
workflow dispatch non-repeatable but is NOT a general distributed claim store.
"""
from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from avuhz_engineering.development_handoff_approval_gate import (
    EXPECTED_OWNER, EXPECTED_STAGES, GatePreflightResult,
    HandoffApprovalGateStop, StageAuthorizationDocuments,
    authorization_set_digest, prepare_handoff_stage_approval_state,
)
from avuhz_engineering.development_handoff_single_use_claim import (
    SingleUseClaimStop, _PURPOSE, _NONCE, _CLAIM_FIELDS, _checked_ledger,
    _utc, _verify_owner_signature,
)
from avuhz_engineering.development_handoff_trusted_github_invocation import (
    TrustedInvocationStop, verify_trusted_github_invocation,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    DevelopmentHandoffLifecycleResult, DevelopmentHandoffSource,
    execute_source_bound_handoff,
)
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)


class TrustedOneShotStop(ValueError):
    """Fixed failure code; never serialize untrusted arguments or exceptions."""


@dataclass(frozen=True)
class SignedStageProof:
    claims: dict
    signature: bytes


@dataclass(frozen=True)
class TrustedOneShotOutcome:
    run_id: str
    command_digest: str
    claimed_stage_count: int
    lifecycle: DevelopmentHandoffLifecycleResult
    classification: str = "ONE_SHOT_EXECUTION_REQUIRES_INDEPENDENT_POSTCONDITION_READBACK"
    owner_key_enrollment_verified_by_runner: bool = False
    distributed_across_runners_verified: bool = False
    data_readback_verified: bool = False
    temporary_credential_retirement_verified: bool = False
    retry_authorized: bool = False


def _stop(code: str) -> None:
    raise TrustedOneShotStop(code)


def _time(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_proof(
    stage: str,
    *,
    proof: SignedStageProof,
    document: StageAuthorizationDocuments,
    source: DevelopmentHandoffSource,
    observed_main_sha: str,
    now: datetime,
    key: bytes,
    key_digest: str,
) -> None:
    if (
        type(proof) is not SignedStageProof
        or type(proof.claims) is not dict
        or set(proof.claims) != _CLAIM_FIELDS
    ):
        _stop("HANDOFF_STAGE_PROOF_INVALID")
    try:
        plan, approval = document.plan, document.approval
        project = (
            DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
            else DEVELOPMENT_AUTH_PROJECT_REF
        )
        expected = {
            "purpose": _PURPOSE,
            "owner_identity": EXPECTED_OWNER,
            "repository": source.repository,
            "source_sha": observed_main_sha,
            "command_digest": source.command_digest,
            "authorization_set_digest": source.authorization_plan_digest,
            "stage": stage,
            "plan_digest": plan["plan_digest"],
            "approval_digest": approval["approval_digest"],
            "tenant_id": source.tenant_id,
            "project_reference": project,
            "not_before": approval["effective_at"],
            "expires_at": approval["expires_at"],
        }
        correct = (
            all(proof.claims.get(field) == value for field, value in expected.items())
            and type(proof.claims.get("nonce")) is str
            and _NONCE.fullmatch(proof.claims["nonce"]) is not None
            and _utc(proof.claims["not_before"]) <= now
            and now < _utc(proof.claims["expires_at"])
        )
    except (KeyError, TypeError, ValueError, AttributeError, SingleUseClaimStop):
        correct = False
    if not correct:
        _stop("HANDOFF_STAGE_PROOF_BINDING_INVALID")
    try:
        _verify_owner_signature(proof.claims, proof.signature, key, key_digest)
    except SingleUseClaimStop:
        _stop("HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED")


def _claim_four_stages_once(
    ledger_path: Path,
    proposals: list[tuple[str, StageAuthorizationDocuments, GatePreflightResult]],
    *,
    canonical_main_sha: str,
    now: str,
) -> None:
    """Commit all four claims in ONE atomic local transaction; never retry."""
    try:
        uri = _checked_ledger(ledger_path)
    except SingleUseClaimStop:
        _stop("HANDOFF_SHARED_LEDGER_UNAVAILABLE")
    connection = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=3, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        # Same canonical table/constraints as the merged single-stage claim.
        connection.execute(
            "CREATE TABLE IF NOT EXISTS avuhz_offline_handoff_stage_claim ("
            "plan_id TEXT NOT NULL, step_id TEXT NOT NULL, stage TEXT NOT NULL, "
            "plan_digest TEXT NOT NULL, approval_digest TEXT NOT NULL UNIQUE, "
            "command_digest TEXT NOT NULL, source_sha TEXT NOT NULL, "
            "claimed_at TEXT NOT NULL, PRIMARY KEY (plan_id, step_id))"
        )
        for stage, documents, proposal in proposals:
            step = documents.plan["steps"][0]
            connection.execute(
                "INSERT INTO avuhz_offline_handoff_stage_claim "
                "(plan_id, step_id, stage, plan_digest, approval_digest, command_digest, "
                "source_sha, claimed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    documents.plan["plan_id"], step["step_id"], stage,
                    documents.plan["plan_digest"], documents.approval["approval_digest"],
                    proposal.command_digest, canonical_main_sha, now,
                ),
            )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError:
        if connection is not None:
            connection.rollback()
        _stop("HANDOFF_LIFECYCLE_ALREADY_CLAIMED")
    except (sqlite3.Error, KeyError, TypeError):
        if connection is not None:
            connection.rollback()
        _stop("HANDOFF_LIFECYCLE_CLAIM_UNVERIFIED")
    finally:
        if connection is not None:
            connection.close()


def execute_trusted_development_handoff_once(
    request: dict,
    *,
    source: DevelopmentHandoffSource,
    github_environment: Mapping[str, str],
    github_event: dict,
    observed_checkout_sha: str,
    observed_remote_main_sha: str,
    observed_git_origin: str,
    at_utc: datetime,
    stages: dict[str, StageAuthorizationDocuments],
    signed_proofs: dict[str, SignedStageProof],
    owner_public_key: bytes,
    independently_pinned_key_digest: str,
    shared_runner_ledger: Path,
    admin_secret_supplier: Callable[[], str],
    publishable_key_supplier: Callable[[], str],
    existing_user_email_supplier: Callable[[], str],
    generate: Callable[..., Any],
    verify: Callable[..., Any],
    validate_jwt: Callable[[str], Any],
    logout_global: Callable[..., None],
    send_once: Callable[[dict, str], tuple[int, bytes]],
) -> TrustedOneShotOutcome:
    """Authorize, atomically claim, then permit one bounded injected lifecycle.

    This must only be called by a trusted owner-enrolled, first-dispatch
    DEVELOPMENT runner with separately reviewed credential and provider
    transport dependencies. It does not issue or sign approvals itself.
    """
    try:
        invocation = verify_trusted_github_invocation(
            github_environment, github_event,
            observed_checkout_sha=observed_checkout_sha,
            observed_remote_main_sha=observed_remote_main_sha,
            observed_git_origin=observed_git_origin,
        )
    except TrustedInvocationStop:
        _stop("HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED")
    if (
        not isinstance(source, DevelopmentHandoffSource)
        or source.canonical_main_sha != invocation.canonical_main_sha
        or source.authorization_plan_digest != invocation.authorization_set_claimed_digest
        or type(stages) is not dict or set(stages) != set(EXPECTED_STAGES)
        or type(signed_proofs) is not dict or set(signed_proofs) != set(EXPECTED_STAGES)
        or not isinstance(at_utc, datetime) or at_utc.tzinfo is None
    ):
        _stop("HANDOFF_TRUSTED_SOURCE_OR_STAGE_SET_INVALID")
    try:
        digest = authorization_set_digest(stages)
    except HandoffApprovalGateStop:
        _stop("HANDOFF_AUTHORIZATION_SET_INVALID")
    if digest != source.authorization_plan_digest:
        _stop("HANDOFF_AUTHORIZATION_SET_INVALID")

    # Validate every signed approval and plan before *any* claim/credential.
    proposals = []
    now = at_utc.astimezone(timezone.utc)
    for stage in EXPECTED_STAGES:
        document = stages[stage]
        if type(document) is not StageAuthorizationDocuments:
            _stop("HANDOFF_STAGE_DOCUMENT_INVALID")
        _validate_proof(
            stage, proof=signed_proofs[stage], document=document, source=source,
            observed_main_sha=invocation.canonical_main_sha, now=now,
            key=owner_public_key, key_digest=independently_pinned_key_digest,
        )
        try:
            proposal = prepare_handoff_stage_approval_state(
                copy.deepcopy(request), source=source,
                observed_main_sha=invocation.canonical_main_sha,
                at_utc=now, stage=stage, stages=stages,
                owner_source_verified=True, observed_owner_identity=EXPECTED_OWNER,
                authorization_set_attested_digest=digest,
            )
        except HandoffApprovalGateStop:
            _stop("HANDOFF_STAGE_APPROVAL_DENIED")
        if (
            proposal.remote_execution_authorized
            or proposal.stage.stage != stage
            or proposal.stage.authorized_progress["step_states"][0]["authorization_consumed"]
        ):
            _stop("HANDOFF_STAGE_APPROVAL_UNVERIFIED")
        proposals.append((stage, document, proposal))

    # Four claims are one sqlite transaction shared by this runner. A
    # duplicate, expired proof, or error before COMMIT executes NO provider call.
    _claim_four_stages_once(
        shared_runner_ledger, proposals,
        canonical_main_sha=invocation.canonical_main_sha, now=_time(now),
    )
    expected_project = {
        stage: DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
        else DEVELOPMENT_AUTH_PROJECT_REF
        for stage in EXPECTED_STAGES
    }

    def authorized_claimed_stage(stage, project, observed_source):
        return (
            stage in expected_project and project == expected_project[stage]
            and observed_source == source
        )

    # Provider/HTTP callbacks are exclusively caller-injected; there is no
    # default credential or network implementation in this module.
    try:
        lifecycle = execute_source_bound_handoff(
            request, source=source,
            observed_main_sha=invocation.canonical_main_sha, at_utc=now,
            authorize_stage=authorized_claimed_stage,
            admin_secret_supplier=admin_secret_supplier,
            publishable_key_supplier=publishable_key_supplier,
            existing_user_email_supplier=existing_user_email_supplier,
            generate=generate, verify=verify, validate_jwt=validate_jwt,
            logout_global=logout_global, send_once=send_once,
        )
    except Exception:
        # Claim has been consumed. Never allow retries on ambiguous failure.
        _stop("HANDOFF_CONSUMED_EXECUTION_UNVERIFIED")

    return TrustedOneShotOutcome(
        run_id=invocation.github_run_id, command_digest=source.command_digest,
        claimed_stage_count=len(proposals), lifecycle=lifecycle,
    )
