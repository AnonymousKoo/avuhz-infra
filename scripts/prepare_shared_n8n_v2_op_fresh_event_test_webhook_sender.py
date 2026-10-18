#!/usr/bin/env python3
"""LOCAL fresh-event preparation and dormant one-attempt core; DEFAULT READ ONLY.

--send-one is unconditionally BLOCKED. No issuer, token FD or HTTP sender is
called. CLI flags cannot establish independent owner authorization. Runtime
inspection is intended for a later authorized read-only invocation; source-only
preparation runs this module only with mocked runtime boundaries.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from scripts import prepare_shared_n8n_v2_local_first_event_qa as qa
from scripts import prepare_shared_n8n_v2_local_test_webhook_sender as first
from avuhz_worker.local_n8n_onepassword_credential import LocalN8nOnePasswordCredential

TARGET = "LOCAL_DEVELOPMENT_N8N_5678"
BASE_COMMIT = "24e941207974931d14f940945b39d4bbdf2b2d9d"
PROJECT_ID = "axT3GLERZRiPXxnj"
RECEIVER_ID = "0068feb4c96bdb5f"
INBOUND_ID = "6ece28c3-f72d-4021-942d-8d0eb072b711"
RECEIPT_ID = "154a1ca8-60d2-449e-bb5a-6f7c1bbf04d2"
SOURCE_SHA256 = "fe2b5abf9fb5e8a3fb4fba248fb092ea4395e14f90a1c47fe04a5dc7722fad7f"
EVENT_ID = "822db2e6-fd66-4b17-a85f-f3d4c5221921"
CORRELATION_ID = "8ada11c9-bebe-4935-b4ec-a46deba50a0d"
DELIVERY_KEY = "avuhz.qa.system001.fresh-receipt-002"
EVENT_SHA256 = "0dd4988ba6f3c365d63c4ca933d02ed21190a1a3c008d3fc06008ebeeee39b70"
HISTORICAL_SHA256 = "5d6483c5d7d971a30f2416f03174c4e6ee480eeb00ead3667699b26ec22f4974"
STORE = Path("/home/network-p/.local/share/avuhz-qa-receipts.sqlite")
TEST_URL = "http://127.0.0.1:5678/webhook-test/avuhz-events"
FIELDS = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})
# Relevant unchanged helpers from the archive, not a claim of a clean Git HEAD.
SOURCE_FILES = {
    'src/avuhz_worker/local_n8n_onepassword_credential.py':
        'b1156768f25efa398b7916b0e9cd0e5d5b95e77d061a49741577452c38f49e26',
    'scripts/prepare_shared_n8n_v2_local_test_webhook_sender.py':
        'f7ea2e38e9c335a5d13fb2d5787e36bebe68c4e44a257bde387977492c942e46',
    "scripts/prepare_shared_n8n_v2_local_first_event_qa.py":
        "56898a6af424107db8933290e9c539abd3d071b9cf09f207f016768cd9a04a7e",
    "scripts/prepare_shared_n8n_receiver_v2_local.py":
        "fe65f14e64036fe0bb7ecc2fa39653ae0a562f43973258707eb249ddf2c3b5de",
    "scripts/prepare_shared_n8n_v2_local_receipt_node_binding.py":
        "2e2c3bd1b73f35030fea429bbbb78636e3d08c65060059fd6b941b9b5d98506e",
    "scripts/prepare_local_n8n_receipt_op_service_launcher.py":
        "414c3f4cc4ce0725a99ebf55eb4435088ed0555ac328a3b805f8d642178ab679",
    "src/avuhz_worker/local_n8n_receipt_dev_runner.py":
        "97f2f4bbda81bc6f382484ec8c2d351ea016d0e615fad2cf2d1343cf046ce421",
}


class FreshEventDenied(RuntimeError):
    """Fixed category only; never include database, process or secret content."""


@dataclass(frozen=True)
class Evidence:
    endpoint: str
    listener_pid: int
    event_digest: str
    historical_receipts: int = 1
    fresh_collisions: int = 0
    # Native registration is ephemeral, not proven by webhook_entity counts.
    test_listener_verified: bool = False
    ready_for_send: bool = False
    gateway: str = ""


def fictional_event() -> dict:
    event = qa.fictional_event()
    if qa._digest(event) != HISTORICAL_SHA256 or set(event) != FIELDS:
        raise FreshEventDenied("historical_source_drift")
    event = copy.deepcopy(event)
    event.update(event_id=EVENT_ID, correlation_id=CORRELATION_ID,
                 delivery_idempotency_key=DELIVERY_KEY)
    if qa._digest(event) != EVENT_SHA256 or event["tenant_id"] != qa.TENANT_ID:
        raise FreshEventDenied("fresh_source_drift")
    return event


def _source() -> dict:
    for name, digest in SOURCE_FILES.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise FreshEventDenied("helper_source_drift")
    if qa.receiver.SOURCE_SHA256 != SOURCE_SHA256:
        raise FreshEventDenied("receiver_source_drift")
    return qa.receiver._source()


def _protected_file(path: Path, *, receipt: bool) -> None:
    if not path.is_absolute() or path.resolve() != path:
        raise FreshEventDenied("storage_path_denied")
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) & 0o022
            or (receipt and stat.S_IMODE(st.st_mode) != 0o600)):
        raise FreshEventDenied("storage_owner_or_mode_denied")


@contextmanager
def _readonly(path: Path, *, receipt: bool = False):
    _protected_file(path, receipt=receipt)
    # No immutable=1: it could ignore current WAL receipts and miss collisions.
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=4)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")  # consistent aggregate/metadata read transaction
        yield db
    finally:
        db.close()


def _receipt_readback(path: Path, *, after: bool = False) -> None:
    old, new = qa.fictional_event(), fictional_event()
    with _readonly(path, receipt=True) as db:
        counts = db.execute(
            "SELECT count(*), "
            "coalesce(sum(trusted_tenant_id=? AND event_id=? AND delivery_key=? "
            "AND envelope_digest=?),0), "
            "coalesce(sum(event_id=? OR delivery_key=?),0), "
            "coalesce(sum(trusted_tenant_id=? AND event_id=? AND delivery_key=? "
            "AND envelope_digest=?),0) "
            "FROM local_n8n_receipts",
            (qa.TENANT_ID, old["event_id"], old["delivery_idempotency_key"],
             HISTORICAL_SHA256, new["event_id"], new["delivery_idempotency_key"],
             qa.TENANT_ID, EVENT_ID, DELIVERY_KEY, EVENT_SHA256),
        ).fetchone()
        if counts != ((2, 1, 1, 1) if after else (1, 1, 0, 0)):
            raise FreshEventDenied("receipt_baseline_or_collision_denied")


def _receiver_metadata(path: Path, source: dict, endpoint: str) -> None:
    with _readonly(path) as db:
        if db.execute("SELECT id FROM project WHERE type='personal'").fetchall() != [(PROJECT_ID,)]:
            raise FreshEventDenied("project_denied")
        counts = db.execute(
            "SELECT count(*), coalesce(sum(isArchived=0),0), "
            "coalesce(sum(isArchived=1),0), coalesce(sum(active!=0),0), "
            "coalesce(sum(active IS NULL),0) FROM workflow_entity"
        ).fetchone()
        if counts != (7, 6, 1, 0, 0):
            raise FreshEventDenied("workflow_inventory_denied")
        if db.execute("SELECT count(*) FROM webhook_entity").fetchone() != (0,):
            raise FreshEventDenied("persistent_webhook_denied")
        # Execution metadata/content is not necessary to prove this boundary.
        expected = ((INBOUND_ID, qa.inbound.CREDENTIAL_NAME),
                    (RECEIPT_ID, qa.receipt.CREDENTIAL_NAME))
        for ident, name in expected:
            rows = db.execute(
                "SELECT id,name,type FROM credentials_entity WHERE id=? OR name=?",
                (ident, name),
            ).fetchall()
            if rows != [(ident, name, "httpHeaderAuth")]:
                raise FreshEventDenied("credential_metadata_denied")
            if db.execute(
                "SELECT projectId,role FROM shared_credentials WHERE credentialsId=?",
                (ident,),
            ).fetchall() != [(PROJECT_ID, "credential:owner")]:
                raise FreshEventDenied("credential_share_denied")
        if db.execute(
            "SELECT projectId,role FROM shared_workflow WHERE workflowId=?",
            (RECEIVER_ID,),
        ).fetchall() != [(PROJECT_ID, "workflow:owner")]:
            raise FreshEventDenied("workflow_share_denied")
        rows = db.execute(
            "SELECT id,name,active,isArchived,nodes,connections,settings,"
            "staticData IS NULL,pinData IS NULL FROM workflow_entity WHERE id=? OR name=?",
            (RECEIVER_ID, source["name"]),
        ).fetchall()
        wanted = copy.deepcopy(source["nodes"])
        wanted[0]["credentials"] = {
            "httpHeaderAuth": {"id": INBOUND_ID, "name": qa.inbound.CREDENTIAL_NAME}}
        wanted[2]["parameters"]["url"] = endpoint
        wanted[2]["credentials"] = {
            "httpHeaderAuth": {"id": RECEIPT_ID, "name": qa.receipt.CREDENTIAL_NAME}}
        if (len(wanted) != 5 or len(rows) != 1
                or rows[0][:4] != (RECEIVER_ID, source["name"], 0, 0)
                or rows[0][7:] != (1, 1)
                or json.loads(rows[0][4]) != wanted
                or json.loads(rows[0][5]) != source["connections"]
                or json.loads(rows[0][6]) != source["settings"]):
            raise FreshEventDenied("installed_receiver_drift")


def _process_sources(pid: int) -> None:
    """Check owned process source paths, never environment or private token FDs."""
    _, parent = qa.binding._proc_uid_parent(pid)
    qa.binding._proc_uid_parent(parent)
    runner = "src/avuhz_worker/local_n8n_receipt_dev_runner.py"
    launcher = "scripts/prepare_local_n8n_receipt_op_service_launcher.py"
    child_cwd = (Path("/proc") / str(pid) / "cwd").resolve(strict=True)
    parent_cwd = (Path("/proc") / str(parent) / "cwd").resolve(strict=True)
    args = qa.binding._proc_args(parent)
    paths = [Path(arg) for arg in args if arg.endswith(launcher)]
    if len(paths) != 1:
        raise FreshEventDenied("launcher_path_denied")
    launch_path = paths[0] if paths[0].is_absolute() else parent_cwd / paths[0]
    for path, name in ((child_cwd / runner, runner), (launch_path, launcher)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != SOURCE_FILES[name]:
            raise FreshEventDenied("process_source_drift")


def preflight(*, after: bool = False) -> Evidence:
    """Compose safe helpers, replacing only incompatible first-receipt gates."""
    try:
        event = fictional_event()
        source = _source()
        boundary = qa.service.inspect_private_local_n8n()
        qa.service.validate_storage_path(STORE)
        _protected_file(STORE, receipt=True)
        endpoint, pid = qa.binding._service_listener(boundary.gateway, qa.TENANT_ID, STORE)
        if not endpoint.startswith("http://" + boundary.gateway + ":"):
            raise FreshEventDenied("endpoint_denied")
        _process_sources(pid)
        _receiver_metadata(qa.receiver._db_path(), source, endpoint)
        _receipt_readback(STORE, after=after)
        # Detect process/endpoint drift across the read-only inspection.
        if qa.binding._service_listener(boundary.gateway, qa.TENANT_ID, STORE) != (endpoint, pid):
            raise FreshEventDenied("bridge_drift")
        return Evidence(endpoint, pid, qa._digest(event), gateway=boundary.gateway)
    except Exception:
        raise FreshEventDenied("fresh_event_readback_denied") from None


@dataclass(frozen=True, repr=False)
class _OwnerAuthorization:
    """Internal verifier result, NEVER an approval parser or caller capability.

    Only _verified_owner_authorization may supply this record. A digest or a
    locally constructed instance does not authenticate an owner. No artifact
    input, trust root, configurable verifier, or enable switch is exposed.
    """

    artifact_sha256: str
    authorization_id: str
    owner_identity: str
    valid_from: int
    valid_until: int
    binding: dict


def _verified_owner_authorization() -> _OwnerAuthorization:
    """Unavailable: independently authenticate the exact owner-issued artifact.

    Existing authorization_plan.validate_approval/authorize_step validate
    bindings, not artifact provenance, native listener state or issuer sessions.
    Their progress objects are not an atomic durable claim. Do not reinterpret
    a caller-supplied JSON file, CLI flag, checksum, login or this task as proof.
    A separately reviewed integration with that framework is still required.
    """
    raise FreshEventDenied("independent_owner_authorization_unavailable")


def _listener_and_issuer_observation() -> dict:
    """Unavailable trusted, fresh metadata-only observation (no secret read).

    Must independently verify the approved ephemeral native registration and
    owner-signed-in 1Password account/user/session, existing inbound reference
    binding and metadata. Service-account sessions cannot satisfy this gate.
    Never infer registration from webhook_entity or merely a listening port.
    """
    raise FreshEventDenied("listener_and_issuer_verifier_unavailable")


def _consume_owner_authorization(grant: _OwnerAuthorization) -> bool:
    """Unavailable atomic, durable, single-winner claim before secret access.

    Must revalidate artifact status/window/bindings, reject revoked/superseded/
    consumed authority across processes and restarts, persist consumption before
    returning True, and never refund on failure. No local replacement ledger.
    """
    raise FreshEventDenied("durable_authorization_consumption_unavailable")


def _checked_binding(grant: _OwnerAuthorization, state: Evidence) -> dict:
    """Exact binding checks AFTER independent verification, never authentication."""
    observed = _listener_and_issuer_observation()
    commit = first._pinned_source_commit()
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    # Evaluate freshness after potentially slow observation/source reads.
    now = time.time()
    required = {
        "owner_identity", "issuer_account", "issuer_user", "issuer_session",
        "issuer_kind", "inbound_reference", "issuer_metadata_sha256",
        "native_listener_id", "listener_registered_at", "listener_expires_at",
        "observed_at", "test_url", "project_id", "workflow_id", "inbound_id",
    }
    if type(observed) is not dict or set(observed) != required:
        raise FreshEventDenied("observation_shape_denied")
    for name in ("owner_identity", "issuer_account", "issuer_user", "issuer_session",
                 "native_listener_id"):
        if (type(observed[name]) is not str
                or re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", observed[name]) is None):
            raise FreshEventDenied("observed_identity_denied")
    for name in ("listener_registered_at", "listener_expires_at", "observed_at"):
        if type(observed[name]) is not int:
            raise FreshEventDenied("observation_time_denied")
    if (
        type(grant) is not _OwnerAuthorization
        or type(grant.valid_from) is not int or type(grant.valid_until) is not int
        or not grant.valid_from <= now < grant.valid_until
        or not 0 < grant.valid_until - grant.valid_from <= 120
        or re.fullmatch(r"[0-9a-f]{64}", grant.artifact_sha256) is None
        or re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", grant.authorization_id) is None
        or observed["owner_identity"] != grant.owner_identity
        or observed["issuer_kind"] != "SIGNED_IN_OWNER"
        or observed["test_url"] != TEST_URL
        or observed["project_id"] != PROJECT_ID
        or observed["workflow_id"] != RECEIVER_ID
        or observed["inbound_id"] != INBOUND_ID
        or re.fullmatch(r"[0-9a-f]{64}", observed["issuer_metadata_sha256"]) is None
        or not 0 <= now - observed["observed_at"] <= 5
        or not observed["listener_registered_at"] <= observed["observed_at"]
        or not 0 < observed["listener_expires_at"] - observed["listener_registered_at"] <= 120
        or not now < observed["listener_expires_at"]
        or grant.valid_until > observed["listener_expires_at"]
        or state.event_digest != EVENT_SHA256
        or not state.endpoint.startswith("http://" + state.gateway + ":")
        or not state.gateway or type(state.listener_pid) is not int or state.listener_pid <= 0
    ):
        raise FreshEventDenied("authorization_identity_or_window_denied")
    # Validation-only constructor: verifies reference syntax without op access.
    LocalN8nOnePasswordCredential(environment="LOCAL",
                                  approved_secret_reference=observed["inbound_reference"])
    binding = {key: value for key, value in observed.items() if key != "observed_at"}
    binding.update(
        environment="LOCAL", machine="DefNet", target=TARGET,
        source_commit=commit, sender_sha256=source_hash,
        receiver_sha256=SOURCE_SHA256, event_id=EVENT_ID,
        correlation_id=CORRELATION_ID, delivery_key=DELIVERY_KEY,
        event_sha256=EVENT_SHA256, tenant_id=qa.TENANT_ID,
        historical_sha256=HISTORICAL_SHA256, receipt_store=str(STORE),
        gateway=state.gateway, receipt_endpoint=state.endpoint,
        bridge_pid=state.listener_pid, max_attempts=1,
        receipt_before=[1, 1, 0, 0], receipt_after=[2, 1, 1, 1],
    )
    # JSON equality would equate True with 1; compare canonical encodings too.
    if (type(grant.binding) is not dict or grant.binding != binding
            or qa._digest(grant.binding) != qa._digest(binding)):
        raise FreshEventDenied("exact_authorization_binding_denied")
    return binding


def _post_fresh_once(token: str) -> None:
    """One fixed native test request. Exact boolean acknowledgment; no retries."""
    body = json.dumps(fictional_event(), separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    conn = http.client.HTTPConnection("127.0.0.1", 5678, timeout=8)
    try:
        conn.request("POST", "/webhook-test/avuhz-events", body=body, headers={
            first.inbound.HEADER_NAME: token, "Content-Type": "application/json",
            "X-Avuhz-Delivery-Key": DELIVERY_KEY, "Cache-Control": "no-store",
            "Connection": "close",
        })
        response = conn.getresponse()
        if response.status != 202:
            raise FreshEventDenied("http_not_accepted_no_retry")
        declared = response.getheader("Content-Length")
        if declared is not None and (not declared.isdecimal() or int(declared) > 512):
            raise FreshEventDenied("invalid_acknowledgment_no_retry")
        raw = response.read(513)
        if len(raw) > 512:
            raise FreshEventDenied("invalid_acknowledgment_no_retry")
        pairs = json.loads(raw, object_pairs_hook=list)
        if pairs != [("accepted", True)] or pairs[0][1] is not True:
            raise FreshEventDenied("invalid_acknowledgment_no_retry")
    except (OSError, http.client.HTTPException):
        raise FreshEventDenied("transport_ambiguous_no_retry") from None
    except (ValueError, UnicodeError):
        raise FreshEventDenied("invalid_acknowledgment_no_retry") from None
    finally:
        conn.close()


def _governed_attempt() -> None:
    """Dormant core: only offline mocks can currently satisfy its trust gates.

    No caller-supplied grant or verifier argument. CLI never calls this core.
    Consume before op read; failures (including timeout) retain consumption.
    """
    reader = writer = None
    token = raw = None
    try:
        if (platform.node() != "DefNet" or os.environ.get("AVUHZ_ENVIRONMENT") != "LOCAL"
                or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")):
            raise FreshEventDenied("execution_boundary_denied")
        grant = _verified_owner_authorization()
        before = preflight()
        binding = _checked_binding(grant, before)
        if preflight() != before or _checked_binding(grant, before) != binding:
            raise FreshEventDenied("pre_attempt_drift_denied")
        # A True return is a durable single-winner claim, not a CLI assertion.
        if _consume_owner_authorization(grant) is not True:
            raise FreshEventDenied("authorization_not_consumed")
        provider = LocalN8nOnePasswordCredential(
            environment="LOCAL", approved_secret_reference=binding["inbound_reference"])
        token = provider()
        if (type(token) is not str or not 32 <= len(token) <= 512
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise FreshEventDenied("private_field_denied")
        reader, writer = os.pipe()
        raw = token.encode("ascii")
        if os.write(writer, raw) != len(raw):
            raise FreshEventDenied("private_fd_denied")
        os.close(writer)
        writer = None
        token = raw = None
        private_fd, reader = reader, None  # canonical reader always closes FD
        token = first._read_inbound_from_fd(private_fd)
        # Revalidate fresh registration, session, commit and receipt baseline
        # after issuer access and immediately before the only HTTP request.
        if preflight() != before or _checked_binding(grant, before) != binding:
            raise FreshEventDenied("pre_send_drift_denied")
        _post_fresh_once(token)
        token = None
        if preflight(after=True) != before:
            raise FreshEventDenied("post_send_drift_no_retry")
    except FreshEventDenied:
        raise
    except Exception:
        raise FreshEventDenied("attempt_unverified_no_retry") from None
    finally:
        token = raw = None
        for fd in (reader, writer):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--send-one", action="store_true",
                        help="Always BLOCKED; independent trust adapters are unavailable")
    args = parser.parse_args(argv)
    if args.send_one:
        print("BLOCKED future-send: independent approvals, issuer metadata and native listener proof missing")
        return 2
    if (args.target != TARGET or platform.node() != "DefNet"
            or os.environ.get("AVUHZ_ENVIRONMENT") != "LOCAL"
            or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")):
        print("BLOCKED wrong LOCAL preparation boundary")
        return 2
    try:
        preflight()
    except Exception:
        print("BLOCKED LOCAL read-only preparation; source or runtime evidence unavailable")
        return 2
    print("PASS read-only source, receiver metadata, private bridge and aggregate receipt checks")
    print("PASS exactly one historical QA receipt; zero fresh event-ID/key collisions")
    print("PASS fictional fresh event sha256:" + EVENT_SHA256)
    print("NOT READY FOR SEND: native test listener unverified; future-send BLOCKED")
    print("NO credential access, listener registration, HTTP request or receipt write")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
