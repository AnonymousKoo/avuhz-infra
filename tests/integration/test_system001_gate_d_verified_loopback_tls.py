"""Gate D SOURCE-ONLY real TLS loopback integration; never installed n8n.

One disposable localhost TLS listener simulates the *contract* of the shared
authenticated, receipt-gated n8n receiver. The real Avuhz acquisition HTTP
writer, outbox, unattended dispatcher, n8n sink, and HTTPS transport run
together. No installed n8n port, production endpoint, external DNS request,
provider credential, real owner, Supabase project, or persistent service is used.

The patched HTTPSConnection connects ONLY to this test's random loopback port,
but uses the original approved hostname for actual TLS SNI/certificate
verification. A temporary CA and leaf private key are generated on each test
and securely discarded. Passing here does NOT certify actual n8n HTTPS ingress
or the authoritative PostgreSQL Work Item writer.
"""
from __future__ import annotations

import copy
import datetime
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT / "src", ROOT / "tests/service", ROOT / "tests/worker"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from avuhz_runtime.in_memory import MemoryStore
from avuhz_worker import MemoryOutboxUnitOfWork, OutboxWorker, WorkerSettings
from avuhz_worker.local_n8n_https_transport import LocalN8nHttpsTransport
from avuhz_worker.local_unattended_n8n_dispatch import (
    LocalN8nDispatchConfig, LocalN8nOutboxDispatcher,
)
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
    FIELDS, event_and_outbox_from_committed_intake,
)
from test_development_acquisition_http import application, request
from test_development_acquisition_ingress import TENANT_A, sample
from test_outbox_worker import MutableClock, context

HOST = "n8n.example.invalid"
ENDPOINT = f"https://{HOST}/webhook/avuhz-events"
# Keep a reference to the genuine client before patching just this module.
REAL_HTTPS_CONNECTION = http.client.HTTPSConnection


def _create_ephemeral_tls(directory: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Private ephemeral certs, no committed fixture, logs or outbound CA call."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "Avuhz ephemeral QA CA",
    )])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
        .issuer_name(ca_name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]),
                       critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "qa-ca.crt"
    cert_path = directory / "qa-leaf.crt"
    key_path = directory / "qa-leaf.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    # Never print, commit or retain the private key; temp dir has 0700.
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(str(cert_path), str(key_path))
    client_context = ssl.create_default_context(cafile=str(ca_path))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    assert client_context.check_hostname and client_context.verify_mode == ssl.CERT_REQUIRED
    return server_context, client_context


class ReceiptContractHandler(BaseHTTPRequestHandler):
    """Local-only fake: no forwarding to n8n, no body/headers logged."""

    def log_message(self, format, *args):
        return

    def _result(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        self._result(404)

    def do_POST(self):
        if self.path != "/webhook/avuhz-events":
            self._result(404)
            return
        if self.headers.get("X-Avuhz-Webhook-Token") != self.server.qa_token:
            self._result(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                self._result(400)
                return
            body = self.rfile.read(length)
            event = json.loads(body)
        except (ValueError, UnicodeError):
            self._result(400)
            return
        if (
            type(event) is not dict or frozenset(event) != FIELDS
            or event.get("tenant_id") != TENANT_A
            or event.get("event_type") != "acquisition.intake.received"
            or self.headers.get("Content-Type") != "application/json"
            or event.get("delivery_idempotency_key")
               != self.headers.get("X-Avuhz-Delivery-Key")
        ):
            self._result(403)
            return
        key = event["delivery_idempotency_key"]
        prior = self.server.receipts.get(key)
        if prior is not None and prior != body:
            self._result(409)
            return
        self.server.receipts.setdefault(key, body)
        self.server.attempt_count += 1
        if self.server.drop_next_ack:
            self.server.drop_next_ack = False
            # Durable logical receipt was committed, but the ACK was lost.
            # No fake 202 is given to the real transport.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        self._result(202)


class RealVerifiedTlsGateDTests(unittest.TestCase):
    def setUp(self):
        # This test creates only a random-port loopback server. It does not
        # inspect or alter any installed n8n, Tailscale, firewall or DNS state.
        self.tmp = tempfile.TemporaryDirectory(prefix="avuhz-qa-tls-")
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        tls_server, self.trusted_client = _create_ephemeral_tls(Path(self.tmp.name))
        self.qa_token = secrets.token_urlsafe(32)
        srv = HTTPServer(("127.0.0.1", 0), ReceiptContractHandler)
        srv.qa_token = self.qa_token
        srv.receipts = {}
        srv.attempt_count = 0
        srv.drop_next_ack = False
        srv.socket = tls_server.wrap_socket(srv.socket, server_side=True)
        self.server = srv
        self.addCleanup(srv.server_close)
        thread = Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02},
                        daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(timeout=3)))
        local_port = srv.server_address[1]

        def local_only_connect(conn):
            # Patch *only* the real client's socket destination; patching
            # HTTPSConnection the class breaks its Python super() lookup.
            # All TLS verification and SNI still run in the original client.
            if conn.host != HOST or conn.port != 443:
                raise OSError("unapproved test destination")
            plain = socket.create_connection(("127.0.0.1", local_port),
                                             timeout=conn.timeout)
            try:
                conn.sock = conn._context.wrap_socket(
                    plain, server_hostname=conn.host,
                )
            except BaseException:
                plain.close()
                raise

        self.local_connect = local_only_connect

    def _runner(self, store, *, context_tls=None, token=None, max_cycles=3):
        tls = context_tls if context_tls is not None else self.trusted_client
        sender = LocalN8nHttpsTransport(
            environment="TEST", expected_host=HOST, tls_context=tls,
            timeout_seconds=3,
        )
        sink = N8nOutboxSink(
            environment="TEST", tenant_id=TENANT_A,
            endpoint=ENDPOINT, expected_host=HOST,
            credential_provider=lambda: token if token is not None else self.qa_token,
            post=sender,
        )
        clock = MutableClock()
        worker = OutboxWorker(
            store, MemoryOutboxUnitOfWork, sink, context(tenant=TENANT_A),
            WorkerSettings(tenant_id=TENANT_A, base_backoff_seconds=5,
                           max_attempts=3),
            clock=clock,
        )
        return (LocalN8nOutboxDispatcher(
            worker, LocalN8nDispatchConfig(
                TENANT_A, poll_interval_seconds=5, max_cycles=max_cycles,
            ),
        ), clock)

    def _fictional_intake(self):
        app, connection = application()
        status, result, _ = request(app)
        self.assertEqual(status, 202)
        self.assertFalse(result["duplicate"])
        return event_and_outbox_from_committed_intake(connection), result

    def _run(self, runner, clock, *, on_first_wait=None):
        stop = Event()
        cycles = 0

        def wait(seconds):
            nonlocal cycles
            cycles += 1
            clock.advance(seconds)
            if cycles == 1 and on_first_wait is not None:
                on_first_wait()
            return False

        with patch.object(
            REAL_HTTPS_CONNECTION, "connect", self.local_connect,
        ), patch.object(stop, "wait", side_effect=wait):
            return runner.run_until_stopped(stop)

    def test_unattended_late_intake_over_real_verified_tls_exactly_once(self):
        # The dispatcher has already started; intake appears after tick 1.
        incoming, response = self._fictional_intake()
        store = MemoryStore(events=[], outbox=[])
        runner, clock = self._runner(store)
        def arrive():
            store.events.extend(copy.deepcopy(incoming.events))
            store.outbox.extend(copy.deepcopy(incoming.outbox))
        summary = self._run(runner, clock, on_first_wait=arrive)
        self.assertEqual((summary.cycles, summary.claimed, summary.published),
                         (3, 1, 1))
        self.assertEqual(store.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(len(self.server.receipts), 1)
        self.assertEqual(self.server.attempt_count, 1)
        envelope = json.loads(next(iter(self.server.receipts.values())))
        self.assertEqual(frozenset(envelope), FIELDS)
        self.assertEqual(envelope["tenant_id"], TENANT_A)
        self.assertEqual(envelope["authoritative_subject_reference"]["reference_id"],
                         response["intake_id"])
        for forbidden in (
            sample()["contact_email"], sample()["contact_name"],
            sample()["business_name"], sample()["diagnostic_summary"],
            self.qa_token, "sanitized_metadata",
        ):
            self.assertNotIn(forbidden, json.dumps(envelope))
        self.assertNotIn(self.qa_token, repr(summary))

    def test_real_tls_untrusted_ca_fails_closed_before_receipt(self):
        incoming, _ = self._fictional_intake()
        untrusted = ssl.create_default_context()
        untrusted.minimum_version = ssl.TLSVersion.TLSv1_2
        runner, clock = self._runner(incoming, context_tls=untrusted, max_cycles=1)
        summary = self._run(runner, clock)
        self.assertEqual((summary.claimed, summary.published,
                          summary.retry_scheduled), (1, 0, 1))
        self.assertEqual(incoming.outbox[0]["status"], "FAILED_RETRYABLE")
        self.assertEqual(self.server.receipts, {})

    def test_real_tls_bad_native_header_denied_without_receipt(self):
        incoming, _ = self._fictional_intake()
        runner, clock = self._runner(incoming,
                                     token=secrets.token_urlsafe(32), max_cycles=2)
        summary = self._run(runner, clock)
        self.assertEqual((summary.dead_lettered, summary.published), (1, 0))
        self.assertEqual(incoming.outbox[0]["status"], "FAILED_TERMINAL")
        self.assertEqual(self.server.receipts, {})
        self.assertEqual(self.server.attempt_count, 0)

    def test_real_tls_lost_ack_retries_but_keeps_one_receipt(self):
        incoming, _ = self._fictional_intake()
        self.server.drop_next_ack = True
        runner, clock = self._runner(incoming, max_cycles=3)
        summary = self._run(runner, clock)
        self.assertEqual((summary.claimed, summary.published,
                          summary.retry_scheduled), (2, 1, 1))
        self.assertEqual(incoming.outbox[0]["status"], "PUBLISHED")
        self.assertEqual(len(self.server.receipts), 1)
        self.assertEqual(self.server.attempt_count, 2)


if __name__ == "__main__":
    unittest.main()
