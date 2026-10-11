"""Injection-only DEVELOPMENT handoff PostgreSQL runner connection candidate.

Offline tests use a fake connector; no caller, live workflow or runtime imports
this candidate. It does not issue or discover a password, enroll an owner, prove
trusted GitHub provenance, install a role grant, or authorize a DATA operation.

An injected connector could contact a provider: invoking it against hosted DATA
requires its own exact authority. A verified connection is NOT owner authority.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from avuhz_service.development import DEVELOPMENT_DATA_PROJECT_REF
from avuhz_service.development_data import (
    DEVELOPMENT_DATA_ENDPOINT_HOST,
    DEVELOPMENT_DATA_SESSION_POOLER_HOST,
    DEVELOPMENT_DATA_ENDPOINT_PORT,
)

_HOST = DEVELOPMENT_DATA_ENDPOINT_HOST
_POOLER_HOST = DEVELOPMENT_DATA_SESSION_POOLER_HOST
_RUNNER = "avuhz_handoff_claim_runner_dev"
_POOLER_USER = _RUNNER + "." + DEVELOPMENT_DATA_PROJECT_REF
_WRITER = "avuhz_handoff_claim_writer"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CA_MAX_BYTES = 65536


class DevelopmentRunnerTransportStop(ValueError):
    """One fixed safe failure code, never raw connection or provider text."""


def _stop(code: str) -> None:
    raise DevelopmentRunnerTransportStop(code)


@dataclass(frozen=True)
class DevelopmentRunnerConnectionPolicy:
    """Exact DEVELOPMENT direct or Supavisor *session* profile.

    On IPv4-only GitHub Actions, the direct Postgres endpoint may be unreachable
    without a separately confirmed IPv4 add-on. Session-mode Supavisor uses
    the existing project-scoped pooler host, port 5432 and a role.project_ref
    login name, but the effective database session_user must remain _RUNNER.
    The trusted CA digest must come from separately pinned configuration.
    Constructing a profile does not establish owner, runner or tenant trust.
    No password, DSN, hostaddr, role or GUC may be caller-supplied here.
    """

    project_ref: str
    host: str
    port: int
    dbname: str
    user: str
    sslmode: str
    sslrootcert: str
    expected_ca_sha256: str

    def __post_init__(self) -> None:
        if not (
            self.project_ref == DEVELOPMENT_DATA_PROJECT_REF
            and (self.host, self.user) in {
                (_HOST, _RUNNER),
                (_POOLER_HOST, _POOLER_USER),
            }
            and type(self.port) is int and self.port == DEVELOPMENT_DATA_ENDPOINT_PORT
            and self.dbname == "postgres"
            and self.sslmode == "verify-full"
            and type(self.sslrootcert) is str
            and bool(self.sslrootcert)
            and Path(self.sslrootcert).is_absolute()
            and type(self.expected_ca_sha256) is str
            and _SHA256.fullmatch(self.expected_ca_sha256) is not None
        ):
            _stop("HANDOFF_RUNNER_CONNECTION_POLICY_INVALID")


def _verify_ca_file(policy: DevelopmentRunnerConnectionPolicy) -> None:
    """Verify CA bytes against an external trusted digest, without storing them."""
    try:
        path = Path(policy.sslrootcert)
        if path.is_symlink() or not path.is_file():
            _stop("HANDOFF_RUNNER_CA_UNVERIFIED")
        contents = path.read_bytes()
        if not 0 < len(contents) <= _CA_MAX_BYTES:
            _stop("HANDOFF_RUNNER_CA_UNVERIFIED")
        digest = "sha256:" + hashlib.sha256(contents).hexdigest()
        if not hmac.compare_digest(digest, policy.expected_ca_sha256):
            _stop("HANDOFF_RUNNER_CA_UNVERIFIED")
    except DevelopmentRunnerTransportStop:
        raise
    except (OSError, ValueError, TypeError):
        _stop("HANDOFF_RUNNER_CA_UNVERIFIED")


class DevelopmentRunnerConnectionFactoryCandidate:
    """Single-attempt connection factory for a separately verified stage gate.

    The existing claim_signed_handoff_stages_postgres_candidate must verify
    source, owner pin, four signatures and stage documents before calling this
    injected factory. This candidate does not make those statements true.
    """

    def __init__(
        self,
        *,
        policy: DevelopmentRunnerConnectionPolicy,
        secret_supplier: Callable[[], str],
        connector: Callable[..., Any],
    ) -> None:
        if (
            type(policy) is not DevelopmentRunnerConnectionPolicy
            or not callable(secret_supplier)
            or not callable(connector)
        ):
            _stop("HANDOFF_RUNNER_CONNECTION_DEPENDENCY_INVALID")
        self._policy = policy
        self._secret_supplier = secret_supplier
        self._connector = connector
        self._lock = Lock()
        self._used = False

    def __call__(self) -> Any:
        with self._lock:
            if self._used:
                _stop("HANDOFF_RUNNER_CONNECTION_ATTEMPT_CONSUMED")
            # Consume even when preflight or connection fails; never retry.
            self._used = True

        policy = self._policy
        # The trusted CA digest must come from a separate protected source,
        # NOT be copied from untrusted request data alongside the CA file.
        _verify_ca_file(policy)

        connection = None
        pw = None
        try:
            pw = self._secret_supplier()
            if type(pw) is not str or len(pw) < 16:
                _stop("HANDOFF_RUNNER_CREDENTIAL_UNAVAILABLE")

            # Keyword-only transport: exact direct or session-mode pooler,
            # never the transaction pooler, privileged role, URL, hostaddr,
            # caller-supplied session options or tenant GUC.
            # verify-full checks both CA trust and the server hostname.
            connection = self._connector(
                host=policy.host, port=policy.port,
                dbname=policy.dbname, user=policy.user,
                password=pw,
                sslmode=policy.sslmode, sslrootcert=policy.sslrootcert,
                gssencmode="disable", connect_timeout=5, options="",
            )
            info = connection.info
            parameters = info.get_parameters()
            if (
                info.host != policy.host
                or str(info.port) != str(policy.port)
                or info.dbname != policy.dbname
                or info.user != policy.user
                or type(parameters) is not dict
                or parameters.get("sslmode") != "verify-full"
                or parameters.get("sslrootcert") != policy.sslrootcert
                or parameters.get("gssencmode") != "disable"
            ):
                _stop("HANDOFF_RUNNER_TLS_OR_ENDPOINT_UNVERIFIED")
            # For direct Postgres, pg_stat_ssl describes this client session.
            # For Supavisor it describes the pooler-to-Postgres upstream hop,
            # not the runner-to-pooler TLS link, so it must NOT substitute for
            # or contradict the client libpq verify-full certificate check.
            # libpq verifies the provided CA and hostname during connect().
            if policy.host == _HOST:
                tls = connection.execute(
                    "select ssl, version from pg_stat_ssl where pid=pg_backend_pid()"
                ).fetchone()
                if (
                    not isinstance(tls, tuple)
                    or len(tls) != 2
                    or tls[0] is not True
                    or type(tls[1]) is not str
                    or not tls[1].startswith("TLSv")
                ):
                    _stop("HANDOFF_RUNNER_TLS_OR_ENDPOINT_UNVERIFIED")
            before = connection.execute(
                "select session_user, current_user, current_database()"
            ).fetchone()
            if before != (_RUNNER, _RUNNER, policy.dbname):
                _stop("HANDOFF_RUNNER_IDENTITY_UNVERIFIED")
            connection.execute("set role avuhz_handoff_claim_writer")
            after = connection.execute(
                "select session_user, current_user"
            ).fetchone()
            if after != (_RUNNER, _WRITER):
                _stop("HANDOFF_RUNNER_ROLE_UNVERIFIED")
            # Existing durable claim adapter separately verifies forced RLS,
            # exact SET-only membership, and lack of direct table grants.
            return connection
        except DevelopmentRunnerTransportStop:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            raise
        except Exception:
            # A driver exception may include connection strings or credentials.
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            _stop("HANDOFF_RUNNER_CONNECTION_UNVERIFIED")
        finally:
            pw = None
