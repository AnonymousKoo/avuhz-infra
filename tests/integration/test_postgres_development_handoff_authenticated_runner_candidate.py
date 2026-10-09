"""DISPOSABLE-ONLY actual SCRAM login proof for the Avuhz handoff claim runner.

Starts one separate digest-pinned local PostgreSQL 17 container with SCRAM
host authentication. No hosted Supabase, real account, GitHub secret,
provider key, workflow dispatch, or shared CI database mutation occurs.
All passwords are generated in memory and never recorded in source/output.
This does not attest an actual GitHub runner, owner, or hosted credential.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
import unittest
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "src"),
    str(ROOT / "tests/integration"),
    str(ROOT / "tests/security"),
    str(ROOT / "tests/service"),
]

from test_postgres_development_handoff_durable_claim_candidate import (
    LOCAL_FIXTURE_DDL,
)
from test_development_handoff_trusted_one_shot_executor import (
    TrustedOneShotExecutorTests,
)
from test_development_handoff_approval_gate import AT
from avuhz_engineering.development_handoff_trusted_one_shot_executor import (
    SignedStageProof, TrustedOneShotStop,
    claim_signed_handoff_stages_postgres_candidate,
)

IMAGE_DIGEST = "sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675"
IMAGE = "postgres@" + IMAGE_DIGEST
RUNNER = "avuhz_handoff_claim_runner_dev"
WRITER = "avuhz_handoff_claim_writer"
TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"
OTHER_TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f1"


def _disposable_ci_scope() -> None:
    """Never start a container outside the preexisting pinned local CI boundary."""
    parameters = conninfo_to_dict(os.environ.get("AVUHZ_POSTGRES_DSN", ""))
    if not (
        parameters.get("host") == "127.0.0.1"
        and parameters.get("port") == "5432"
        and parameters.get("dbname") == "avuhz_main_pr_gate"
        and parameters.get("user") == "postgres"
        and not parameters.get("password")
        and os.environ.get("AVUHZ_INTEGRATION_DATABASE") == "avuhz_main_pr_gate"
        and os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
        == "avuhz-main-pr-gate-postgres"
        and os.environ.get("AVUHZ_POSTGRES_IMAGE") == IMAGE
        and os.environ.get("AVUHZ_POSTGRES_DIGEST") == IMAGE_DIGEST
    ):
        raise RuntimeError("DISPOSABLE_AUTH_RUNNER_SCOPE_INVALID")


def _docker(*args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["docker", *args], text=True, capture_output=True,
        check=False, timeout=45, env=env,
    )
    if result.returncode != 0:
        # Never echo Docker stderr: it can contain environment material.
        raise RuntimeError("DISPOSABLE_AUTH_RUNNER_DOCKER_OPERATION_FAILED")
    return result.stdout.strip()


class AuthenticatedRunnerDisposableTests(unittest.TestCase):
    """Separately authenticated runner, never privileged session impersonation."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        _disposable_ci_scope()
        cls._password = secrets.token_urlsafe(40)
        cls._container = "avuhz-auth-runner-" + secrets.token_hex(6)
        cls._port = None

        # The image is pre-pulled and pinned by the existing Main PR Gate.
        image_info = _docker("image", "inspect", IMAGE, "--format",
                             "{{json .RepoDigests}}")
        import json
        digests = json.loads(image_info)
        if not any(value.endswith("@" + IMAGE_DIGEST) for value in digests):
            raise RuntimeError("DISPOSABLE_AUTH_RUNNER_IMAGE_MISMATCH")

        # Password exists only in this disposable Docker child environment.
        # --env NAME does not expose its value on the command line.
        docker_env = dict(os.environ)
        docker_env["POSTGRES_PASSWORD"] = cls._password
        try:
            _docker(
                "run", "--detach", "--rm", "--pull=never",
                "--name", cls._container,
                "--publish", "127.0.0.1::5432",
                "--env", "POSTGRES_PASSWORD",
                "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
                "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
                IMAGE, env=docker_env,
            )
        finally:
            docker_env.pop("POSTGRES_PASSWORD", None)
        cls.addClassCleanup(cls._stop_container)
        port_binding = _docker("port", cls._container, "5432/tcp")
        if not port_binding.startswith("127.0.0.1:"):
            raise RuntimeError("DISPOSABLE_AUTH_RUNNER_HOST_BIND_INVALID")
        cls._port = int(port_binding.rsplit(":", 1)[1])
        if cls._port == 5432 or not 1 <= cls._port <= 65535:
            raise RuntimeError("DISPOSABLE_AUTH_RUNNER_PORT_INVALID")

        # Prove the new server is the separate SCRAM-configured Postgres 17.
        ready = False
        for _ in range(90):
            try:
                with cls._connect("postgres") as db:
                    version = db.execute("show server_version_num").fetchone()[0]
                    rules = db.execute(
                        "select type,auth_method,error from pg_hba_file_rules"
                    ).fetchall()
                    ready = (
                        version.startswith("17")
                        and any(kind == "host" and auth == "scram-sha-256"
                                and error is None for kind, auth, error in rules)
                        and not any(kind == "host" and auth == "trust"
                                    for kind, auth, _ in rules)
                    )
                if ready:
                    break
            except psycopg.OperationalError:
                time.sleep(0.4)
        if not ready:
            raise RuntimeError("DISPOSABLE_AUTH_RUNNER_SCRAM_UNVERIFIED")

        with cls._connect("postgres") as db:
            db.execute(LOCAL_FIXTURE_DDL)
            # The shared fixture creates a password-NULL login. Set a random
            # test-only password, sent through the DB protocol, never Git.
            db.execute(
                sql.SQL("alter role {} password {}").format(
                    sql.Identifier(RUNNER), sql.Literal(cls._password)
                )
            )
            method = db.execute(
                "select rolpassword like %s "
                "from pg_authid where rolname=%s", ("SCRAM-SHA-256$%", RUNNER)
            ).fetchone()
            if method != (True,):
                raise RuntimeError("DISPOSABLE_AUTH_RUNNER_PASSWORD_NOT_SCRAM")

        # Reject a bad password through a *new network connection*. If this
        # succeeds, host authentication was actually trust/bypass: hard stop.
        try:
            with cls._connect(RUNNER, secrets.token_urlsafe(40)) as db:
                db.execute("select 1")
        except psycopg.OperationalError:
            pass
        else:
            raise RuntimeError("DISPOSABLE_AUTH_RUNNER_PASSWORD_BYPASS")

        # Real login starts as runner, not as a privileged session user.
        with cls._connect(RUNNER) as db:
            observed = db.execute(
                "select session_user,current_user,inet_client_addr() is not null"
            ).fetchone()
            if observed != (RUNNER, RUNNER, True):
                raise RuntimeError("DISPOSABLE_AUTH_RUNNER_SESSION_UNVERIFIED")

    @classmethod
    def _stop_container(cls) -> None:
        try:
            _docker("rm", "--force", cls._container)
        finally:
            cls._password = None

    @classmethod
    def _connect(cls, user: str, password: str | None = None):
        return psycopg.connect(
            host="127.0.0.1", port=cls._port, dbname="postgres",
            user=user, password=(cls._password if password is None else password),
            sslmode="disable", connect_timeout=2,
        )

    @classmethod
    def writer(cls):
        db = cls._connect(RUNNER)
        try:
            if db.execute("select session_user,current_user").fetchone() != (
                RUNNER, RUNNER
            ):
                raise RuntimeError("DISPOSABLE_AUTH_RUNNER_SESSION_UNVERIFIED")
            db.execute(sql.SQL("set role {}").format(sql.Identifier(WRITER)))
            db.commit()
            if db.execute("select session_user,current_user").fetchone() != (
                RUNNER, WRITER
            ):
                raise RuntimeError("DISPOSABLE_AUTH_RUNNER_SET_ROLE_UNVERIFIED")
            db.commit()
            return db
        except Exception:
            db.close()
            raise

    def setUp(self) -> None:
        self.signed = TrustedOneShotExecutorTests(
            methodName="test_four_exact_signed_stage_claims_precede_single_send_and_logout"
        )
        self.signed.setUp()
        self.addCleanup(self.signed.doCleanups)
        with self._connect("postgres") as db:
            db.execute(sql.SQL("truncate {}").format(sql.SQL(TABLE)))

    def args(self):
        f = self.signed
        return dict(
            request=f.f.fixture.command,
            source=f.source,
            github_environment=f.env,
            github_event=f.event,
            observed_checkout_sha=f.source.canonical_main_sha,
            observed_remote_main_sha=f.source.canonical_main_sha,
            observed_git_origin="https://github.com/AnonymousKoo/avuhz-infra",
            at_utc=AT,
            stages=f.f.fixture.stages,
            signed_proofs=f.signed_proofs,
            owner_public_key=f.f.public,
            independently_pinned_key_digest=f.f.anchor,
            connection_factory=self.writer,
        )

    def claim(self, **updates):
        args = self.args()
        args.update(updates)
        return claim_signed_handoff_stages_postgres_candidate(**args)

    def count(self) -> int:
        with self._connect("postgres") as db:
            return db.execute(
                sql.SQL("select count(*) from {}").format(sql.SQL(TABLE))
            ).fetchone()[0]

    def test_authenticated_four_stage_claim_and_replay_stop(self):
        receipt = self.claim()
        self.assertEqual(receipt.claimed_stage_count, 4)
        self.assertFalse(receipt.human_owner_binding_verified)
        self.assertFalse(receipt.signed_approval_authority_verified)
        self.assertFalse(receipt.live_execution_authorized)
        self.assertEqual(self.count(), 4)
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.claim()
        self.assertEqual(self.count(), 4)

    def test_real_runner_without_set_role_cannot_claim(self):
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED"
        ):
            self.claim(connection_factory=lambda: self._connect(RUNNER))
        self.assertEqual(self.count(), 0)

    def test_wrong_login_identity_cannot_claim(self):
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED"
        ):
            self.claim(connection_factory=lambda: self._connect("postgres"))
        self.assertEqual(self.count(), 0)

    def test_direct_insert_grant_is_detected_and_denied(self):
        with self._connect("postgres") as db:
            db.execute(sql.SQL("grant insert on {} to {}").format(
                sql.SQL(TABLE), sql.Identifier(RUNNER)
            ))
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED"
        ):
            self.claim()
        self.assertEqual(self.count(), 0)
        with self._connect("postgres") as db:
            db.execute(sql.SQL("revoke insert on {} from {}").format(
                sql.SQL(TABLE), sql.Identifier(RUNNER)
            ))

    def test_bypassrls_role_flag_is_detected_and_denied(self):
        with self._connect("postgres") as db:
            db.execute(sql.SQL("alter role {} bypassrls").format(
                sql.Identifier(RUNNER)
            ))
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_RUNNER_UNTRUSTED"
        ):
            self.claim()
        self.assertEqual(self.count(), 0)
        with self._connect("postgres") as db:
            db.execute(sql.SQL("alter role {} nobypassrls").format(
                sql.Identifier(RUNNER)
            ))

    def test_forged_stage_proof_stops_before_authenticated_connection(self):
        invalid = dict(self.signed.signed_proofs)
        proof = invalid["DATA_COMMAND"]
        invalid["DATA_COMMAND"] = SignedStageProof(
            claims=proof.claims, signature=b"0" * 64
        )

        def forbidden_connection():
            raise AssertionError("untrusted proof attempted DB connection")

        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED"
        ):
            self.claim(
                signed_proofs=invalid, connection_factory=forbidden_connection
            )
        self.assertEqual(self.count(), 0)

    def test_source_drift_stops_before_authenticated_connection(self):
        def forbidden_connection():
            raise AssertionError("untrusted source attempted DB connection")

        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"
        ):
            self.claim(
                observed_remote_main_sha="f" * 40,
                connection_factory=forbidden_connection,
            )
        self.assertEqual(self.count(), 0)

    def test_forced_rls_denies_cross_tenant_row(self):
        with self.writer() as db:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    db.execute(
                        "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                        (OTHER_TENANT,),
                    )
                    source = self.signed.source
                    claim = self.signed.f.fixture.stages["DATA_COMMAND"]
                    db.execute(
                        sql.SQL(
                            "insert into {} (tenant_id,stage,plan_id,step_id,"
                            "plan_digest,approval_digest,project_reference,"
                            "authorization_set_digest,command_digest,source_sha)"
                            " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                        ).format(sql.SQL(TABLE)),
                        (
                            source.tenant_id, "DATA_COMMAND",
                            claim.plan["plan_id"],
                            claim.plan["steps"][0]["step_id"],
                            claim.plan["plan_digest"],
                            claim.approval["approval_digest"],
                            source.data_project_ref,
                            source.authorization_plan_digest,
                            source.command_digest,
                            source.canonical_main_sha,
                        ),
                    )
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main()
