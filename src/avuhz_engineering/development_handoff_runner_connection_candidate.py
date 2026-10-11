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

_HOST = "db.gnuqaefotwgkwurjpyik.supabase.co"
_RUNNER = "avuhz_handoff_claim_runner_dev"
_WRITER = "avuhz_handoff_claim_writer"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CA_MAX_BYTES = 65536


class DevelopmentRunnerTransportStop(ValueError):
    """One fixed safe failure code, never raw connection or provider text."""


def _stop(code: str) -> None:
    raise DevelopmentRunnerTransportStop(code)


@dataclass(frozen=True)
class DevelopmentRunnerConnectionPolicy:
    """Exact direct-connection profile; the CA digest must be pinned separately.

    Constructing this profile does not establish runner, owner, or tenant trust.
    The profile intentionally has no password, DSN, hostaddr, role or GUC field.
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
            and self.host == _HOST
            and type(self.port) is int and self.port == 5432
            and self.dbname == "postgres"
            and self.user == _RUNNER
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
        password = None
        try:
            password = self._secret_supplier()
            if type(password) is not str or len(password) < 16:
                _stop("HANDOFF_RUNNER_CREDENTIAL_UNAVAILABLE")

            # Keyword-only libpq transport. No implicit URL, session-pooler,
            # transaction pooler, service role, caller-supplied options or GUC.
            # verify-full checks both CA trust and the server hostname.
            connection = self._connector(
                host=policy.host, port=policy.port,
                dbname=policy.dbname, user=policy.user,
                password=password,
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
            password = None
