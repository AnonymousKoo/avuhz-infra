"""Repository-only PostgreSQL durable claim candidate; NEVER a live authority.

This adapter tests exactly one four-stage atomic insert into a separately
provisioned shared PostgreSQL security store. It does NOT install that store,
verify signatures, enroll the human owner, issue credentials, or invoke
the DEVELOPMENT handoff. No workflow imports this module.

Callers must separately establish the trusted source, exact signed plans,
owner attribution, runner and DB provenance before this function could
ever participate in an authorized execution. Its receipt grants no authority.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Callable

import psycopg

from avuhz_engineering.development_handoff_approval_gate import EXPECTED_STAGES
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_ROLE = "avuhz_handoff_claim_writer"
_RUNNER = "avuhz_handoff_claim_runner_dev"
_TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"


class DurableHandoffClaimStop(ValueError):
    """Fixed safe stop codes; never include DB or user-supplied values."""


@dataclass(frozen=True)
class DurableStageClaim:
    stage: str
    plan_id: str
    step_id: str
    plan_digest: str
    approval_digest: str
    project_reference: str


@dataclass(frozen=True)
class DurableClaimCandidateReceipt:
    claimed_stage_count: int
    classification: str = "SHARED_POSTGRES_ATOMIC_CLAIM_NO_LIVE_AUTHORITY"
    provider_environment_installed: bool = False
    human_owner_binding_verified: bool = False
    signed_approval_authority_verified: bool = False
    live_execution_authorized: bool = False
    retry_authorized: bool = False


def _stop(code: str) -> None:
    raise DurableHandoffClaimStop(code)


def _validate(
    *, tenant_id: str, source_sha: str, authorization_set_digest: str,
    command_digest: str, auth_project_ref: str, data_project_ref: str,
    claims: tuple[DurableStageClaim, ...],
) -> None:
    try:
        tenant_is_canonical = (
            type(tenant_id) is str
            and str(uuid.UUID(tenant_id)) == tenant_id
        )
    except (ValueError, AttributeError, TypeError):
        tenant_is_canonical = False
    if not (
        tenant_is_canonical
        and type(source_sha) is str and _SHA.fullmatch(source_sha)
        and type(authorization_set_digest) is str
        and _DIGEST.fullmatch(authorization_set_digest)
        and type(command_digest) is str and _DIGEST.fullmatch(command_digest)
        and auth_project_ref == DEVELOPMENT_AUTH_PROJECT_REF
        and data_project_ref == DEVELOPMENT_DATA_PROJECT_REF
        and auth_project_ref != data_project_ref
        and type(claims) is tuple and len(claims) == len(EXPECTED_STAGES)
        and all(type(c) is DurableStageClaim for c in claims)
        and tuple(c.stage for c in claims) == EXPECTED_STAGES
        and all(
            type(c.plan_id) is str and _IDENTIFIER.fullmatch(c.plan_id)
            and type(c.step_id) is str and _IDENTIFIER.fullmatch(c.step_id)
            and type(c.plan_digest) is str and _DIGEST.fullmatch(c.plan_digest)
            and type(c.approval_digest) is str
            and _DIGEST.fullmatch(c.approval_digest)
            and c.project_reference == (
                data_project_ref if c.stage == "DATA_COMMAND"
                else auth_project_ref
            )
            for c in claims
        )
        and len({c.plan_id for c in claims}) == len(EXPECTED_STAGES)
        and len({c.step_id for c in claims}) == len(EXPECTED_STAGES)
        and len({c.approval_digest for c in claims}) == len(EXPECTED_STAGES)
    ):
        _stop("HANDOFF_DURABLE_CLAIM_SCOPE_INVALID")


def claim_four_stages_candidate(
    *, connection_factory: Callable[[], psycopg.Connection],
    tenant_id: str, source_sha: str, authorization_set_digest: str,
    command_digest: str, auth_project_ref: str, data_project_ref: str,
    claims: tuple[DurableStageClaim, ...],
) -> DurableClaimCandidateReceipt:
    """Atomically consume exact four stages on one SHARED PostgreSQL database.

    Requires a separately provisioned DB with a forced-RLS table and a
    minimally privileged dedicated writer. No DDL, retries, credential lookup,
    provider calls, or handoff callbacks. A failed/ambiguous COMMIT is terminal:
    do not retry or infer that the claim was not committed.
    """
    _validate(
        tenant_id=tenant_id, source_sha=source_sha,
        authorization_set_digest=authorization_set_digest,
        command_digest=command_digest,
        auth_project_ref=auth_project_ref, data_project_ref=data_project_ref,
        claims=claims,
    )
    if not callable(connection_factory):
        _stop("HANDOFF_DURABLE_CLAIM_CONNECTION_UNAVAILABLE")
    try:
        with connection_factory() as connection:
            with connection.transaction():
                # The caller is responsible for a TRUSTED writer connection,
                # not a customer session, AUTH DB connection or service_role.
                # Guard against a privileged/general-purpose session
                # impersonating the writer with SET ROLE. This proves only
                # PostgreSQL session/role provenance, NOT independent GitHub
                # runner attribution, signed human-owner authority, or tenant.
                observed = connection.execute(
                    "select session_user,current_user"
                ).fetchone()
                if observed != (_RUNNER, _ROLE):
                    _stop("HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED")
                attributes = connection.execute(
                    "select rolcanlogin,rolinherit,rolsuper,rolbypassrls,"
                    "rolcreatedb,rolcreaterole,rolreplication "
                    "from pg_roles where rolname=%s",
                    (_RUNNER,),
                ).fetchone()
                if attributes != (True, False, False, False, False, False, False):
                    _stop("HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED")
                edges = connection.execute(
                    "select m.admin_option,m.inherit_option,m.set_option "
                    "from pg_auth_members m "
                    "join pg_roles member on member.oid=m.member "
                    "join pg_roles granted on granted.oid=m.roleid "
                    "where member.rolname=%s and granted.rolname=%s",
                    (_RUNNER, _ROLE),
                ).fetchall()
                if edges != [(False, False, True)]:
                    _stop("HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED")
                if (
                    connection.execute(
                        "select pg_has_role(%s,%s,'USAGE')",
                        (_RUNNER, _ROLE),
                    ).fetchone() != (False,)
                    or connection.execute(
                        "select has_table_privilege(%s,%s,'INSERT')",
                        (_RUNNER, _TABLE),
                    ).fetchone() != (False,)
                ):
                    _stop("HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED")
                contract = connection.execute(
                    "select c.relrowsecurity, c.relforcerowsecurity "
                    "from pg_class c where c.oid="
                    "to_regclass('avuhz_handoff_control.avuhz_handoff_approval_claims')"
                ).fetchone()
                if contract != (True, True):
                    _stop("HANDOFF_DURABLE_CLAIM_RLS_UNVERIFIED")
                connection.execute(
                    "select set_config('avuhz.handoff_claim_tenant', %s, true)",
                    (tenant_id,),
                )
                for claim in claims:
                    connection.execute(
                        "insert into avuhz_handoff_control."
                        "avuhz_handoff_approval_claims "
                        "(tenant_id, stage, plan_id, step_id, plan_digest, "
                        "approval_digest, project_reference, "
                        "authorization_set_digest, command_digest, source_sha) "
                        "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            tenant_id, claim.stage, claim.plan_id,
                            claim.step_id, claim.plan_digest,
                            claim.approval_digest, claim.project_reference,
                            authorization_set_digest, command_digest, source_sha,
                        ),
                    )
    except DurableHandoffClaimStop:
        raise
    except psycopg.errors.UniqueViolation:
        _stop("HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED")
    except Exception:
        # Includes an ambiguous connection failure around COMMIT.
        _stop("HANDOFF_DURABLE_CLAIM_OUTCOME_UNVERIFIED")

    return DurableClaimCandidateReceipt(claimed_stage_count=len(claims))
