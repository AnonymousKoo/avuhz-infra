"""Fail-closed LOCAL/TEST n8n service preflight; no real services started."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from avuhz_worker import local_n8n_receipt_dev_runner as dev

TENANT = "a4770000-0000-4000-8000-000000000001"


def metadata(*, host="127.0.0.1", port="5678", mode="bridge", ip="172.17.0.3"):
    values = [
        "/n8n", True, mode,
        {"5678/tcp": [{"HostIp": host, "HostPort": port}]},
        {"bridge": {"Gateway": "172.17.0.1", "IPAddress": ip}},
    ]
    return "|".join(json.dumps(x) for x in values) + "\n"


class LocalN8nDevRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avuhz-runner-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.db = self.parent / "local_receipts.sqlite"
        self.params = [
            "--target", "LOCAL_DEVELOPMENT_N8N_5678",
            "--trusted-tenant-id", TENANT,
            "--receipt-db", str(self.db),
        ]

    @contextlib.contextmanager
    def mock_docker(self, first=None, second=None):
        if first is None:
            first = metadata()
        if second is None:
            second = json.dumps([{"Subnet": "172.17.0.0/16"}])
        with mock.patch.object(dev, "_docker_output", side_effect=[first, second]):
            yield

    def test_exact_local_n8n_network_only(self):
        with self.mock_docker():
            result = dev.inspect_private_local_n8n()
        self.assertEqual(result, dev.PrivateDockerBoundary(
            gateway="172.17.0.1", client="172.17.0.3", cidr="172.17.0.0/16",
        ))

    def test_rejects_public_ports_drifted_network_or_untrusted_source(self):
        for case in (
            metadata(host="0.0.0.0"),
            metadata(host="172.17.0.1"),
            metadata(port="5679"),
            metadata(mode="host"),
            metadata(ip="172.18.1.10"),
            metadata(ip="172.17.0.1"),
            '{"wrong":"format"}\n',
        ):
            with self.subTest(case=case), self.mock_docker(first=case):
                with self.assertRaisesRegex(ValueError, "local_n8n_network_boundary_untrusted"):
                    dev.inspect_private_local_n8n()

    def test_preflight_does_not_create_store_or_read_a_credential(self):
        output = io.StringIO()
        with self.mock_docker(), contextlib.redirect_stdout(output):
            self.assertEqual(dev.run(self.params), 0)
        self.assertIn("LOCAL_DEVELOPMENT_PREFLIGHT_PASS", output.getvalue())
        self.assertNotIn(TENANT, output.getvalue())
        self.assertFalse(self.db.exists())

    def test_rejects_wrong_target_and_untrusted_tenant_before_docker(self):
        with mock.patch.object(dev, "_docker_output") as forbidden:
            with self.assertRaisesRegex(ValueError, "local_development_target_required"):
                dev.run(["--target", "PRODUCTION", *self.params[2:]])
            with self.assertRaisesRegex(ValueError, "independently_verified_tenant_required"):
                dev.run(["--target", "LOCAL_DEVELOPMENT_N8N_5678",
                         "--trusted-tenant-id", "untrusted", "--receipt-db", str(self.db)])
            forbidden.assert_not_called()

    def test_private_storage_and_symlinks_required(self):
        dev.validate_storage_path(self.db)
        self.parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private_receipt_directory_required"):
            dev.validate_storage_path(self.db)
        self.parent.chmod(0o700)
        link = self.parent / "symlinked.sqlite"
        link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "private_receipt_path_required"):
            dev.validate_storage_path(link)
        link.unlink()

    def test_missing_secret_fd_never_creates_store_or_listener(self):
        with self.mock_docker(), mock.patch.object(dev, "LocalN8nReceiptStore") as store:
            with mock.patch.object(dev, "LocalN8nReceiptHTTPServer") as http:
                with self.assertRaisesRegex(ValueError, "approved_secret_fd_required"):
                    dev.run([*self.params, "--serve"])
                store.assert_not_called()
                http.assert_not_called()
        self.assertFalse(self.db.exists())

    def test_secret_fd_must_be_printable_and_never_logged(self):
        for secret in (b"short", b"a" * 513, b"a" * 39 + b"\n", b"a" * 31):
            read, write = os.pipe()
            self.addCleanup(lambda fd=read: self._close_if_open(fd))
            os.write(write, secret)
            os.close(write)
            with self.assertRaisesRegex(ValueError, "approved_secret_unavailable"):
                dev.load_token_from_fd(read)
        for bad_fd in (0, 1, 2, -1):
            with self.assertRaisesRegex(ValueError, "approved_secret_fd_required"):
                dev.load_token_from_fd(bad_fd)

    @staticmethod
    def _close_if_open(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def test_serve_requires_injected_secret_and_uses_existing_shared_classes(self):
        read, write = os.pipe()
        self.addCleanup(lambda: self._close_if_open(read))
        fake_secret = b"SYNTHETIC-only-private-test-credential-0123456789"
        os.write(write, fake_secret)
        os.close(write)
        out = io.StringIO()
        with self.mock_docker(), mock.patch.object(dev, "LocalN8nReceiptStore") as store:
            with mock.patch.object(dev, "LocalN8nReceiptHTTPServer") as server:
                server.return_value.server_port = 32901
                with contextlib.redirect_stdout(out):
                    self.assertEqual(dev.run([*self.params, "--serve", "--token-fd", str(read)]), 0)
                store.assert_called_once_with(
                    self.db, trusted_tenant_id=TENANT,
                    allowed_event_types=frozenset({"acquisition.intake.received"}),
                )
                self.assertEqual(server.call_args.kwargs["bind_host"], "172.17.0.1")
                self.assertEqual(server.call_args.kwargs["trusted_client_ip"], "172.17.0.3")
                self.assertEqual(server.call_args.kwargs["bridge_cidr"], "172.17.0.0/16")
                self.assertEqual(server.call_args.kwargs["token_provider"](), fake_secret.decode())
                server.return_value.serve_forever.assert_called_once()
                server.return_value.server_close.assert_called_once()
        self.assertNotIn(fake_secret.decode(), out.getvalue())
        self.assertNotIn(TENANT, out.getvalue())
        self.assertIn("http://172.17.0.1:32901", out.getvalue())
        self.assertFalse(self.db.exists())


if __name__ == "__main__":
    unittest.main()
