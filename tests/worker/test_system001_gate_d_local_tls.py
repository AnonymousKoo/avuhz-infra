"""Offline tests for the source-only Gate D TLS 1.3 composition."""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import logging
import os
import ssl
import stat
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import call, patch

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import avuhz_worker.system001_gate_d_local_tls as gate_d
from tests.worker.test_n8n_event_sink import KEY, TENANT, fixture_event


PUBLIC_CA_FIXTURE = b"""-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIIXsO3pkN/pOAwDQYJKoZIhvcNAQEFBQAwQjESMBAGA1UE
AwwJQUNDVlJBSVoxMRAwDgYDVQQLDAdQS0lBQ0NWMQ0wCwYDVQQKDARBQ0NWMQsw
CQYDVQQGEwJFUzAeFw0xMTA1MDUwOTM3MzdaFw0zMDEyMzEwOTM3MzdaMEIxEjAQ
BgNVBAMMCUFDQ1ZSQUlaMTEQMA4GA1UECwwHUEtJQUNDVjENMAsGA1UECgwEQUND
VjELMAkGA1UEBhMCRVMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCb
qau/YUqXry+XZpp0X9DZlv3P4uRm7x8fRzPCRKPfmt4ftVTdFXxpNRFvu8gMjmoY
HtiP2Ra8EEg2XPBjs5BaXCQ316PWywlxufEBcoSwfdtNgM3802/J+Nq2DoLSRYWo
G2ioPej0RGy9ocLLA76MPhMAhN9KSMDjIgro6TenGEyxCQ0jVn8ETdkXhBilyNpA
lHPrzg5XPAOBOp0KoVdDaaxXbXmQeOW1tDvYvEyNKKGno6e6Ak4l0Squ7a4DIrhr
IA8wKFSVf+DuzgpmndFALW4ir50awQUZ0m/A8p/4e7MCQvtQqR0tkw8jq8bBD5L/
0KIV9VMJcRz/RROE5iZe+OCIHAr8Fraocwa48GOEAqDGWuzndN9wrqODJerWx5eH
k6fGioozl2A3ED6XPm4pFdahD9GILBKfb6qkxkLrQaLjlUPTAYVtjrs78yM2x/47
4KElB0iryYl0/wiPgL/AlmXz7uxLaL2diMMxs0Dx6M/2OLuc5NF/1OVYm3z61PMO
m3WR5LpSLhl+0fXNWhn8ugb2+1KoS5kE3fj5tItQo05iifCHJPqDQsGH+tUtKSpa
cXpkatcnYGMN285J9Y0fkIkyF/hzQ7jSWpOGYdbhdQrqeWZ2iE9x6wQl1gpaepPl
uUsXQA+xtrn13k/c4LOsOxFwYIRKQ26ZIMApcQrAZQIDAQABo4ICyzCCAscwfQYI
KwYBBQUHAQEEcTBvMEwGCCsGAQUFBzAChkBodHRwOi8vd3d3LmFjY3YuZXMvZmls
ZWFkbWluL0FyY2hpdm9zL2NlcnRpZmljYWRvcy9yYWl6YWNjdjEuY3J0MB8GCCsG
AQUFBzABhhNodHRwOi8vb2NzcC5hY2N2LmVzMB0GA1UdDgQWBBTSh7Tj3zcnk1X2
VuqB5TbMjB4/vTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNKHtOPfNyeT
VfZW6oHlNsyMHj+9MIIBcwYDVR0gBIIBajCCAWYwggFiBgRVHSAAMIIBWDCCASIG
CCsGAQUFBwICMIIBFB6CARAAQQB1AHQAbwByAGkAZABhAGQAIABkAGUAIABDAGUA
cgB0AGkAZgBpAGMAYQBjAGkA8wBuACAAUgBhAO0AegAgAGQAZQAgAGwAYQAgAEEA
QwBDAFYAIAAoAEEAZwBlAG4AYwBpAGEAIABkAGUAIABUAGUAYwBuAG8AbABvAGcA
7QBhACAAeQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQDzAG4AIABFAGwAZQBjAHQA
cgDzAG4AaQBjAGEALAAgAEMASQBGACAAUQA0ADYAMAAxADEANQA2AEUAKQAuACAA
QwBQAFMAIABlAG4AIABoAHQAdABwADoALwAvAHcAdwB3AC4AYQBjAGMAdgAuAGUA
czAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5hY2N2LmVzL2xlZ2lzbGFjaW9uX2Mu
aHRtMFUGA1UdHwROMEwwSqBIoEaGRGh0dHA6Ly93d3cuYWNjdi5lcy9maWxlYWRt
aW4vQXJjaGl2b3MvY2VydGlmaWNhZG9zL3JhaXphY2N2MV9kZXIuY3JsMA4GA1Ud
DwEB/wQEAwIBBjAXBgNVHREEEDAOgQxhY2N2QGFjY3YuZXMwDQYJKoZIhvcNAQEF
BQADggIBAJcxAp/n/UNnSEQU5CmH7UwoZtCPNdpNYbdKl02125DgBS4OxnnQ8pdp
D70ER9m+27Up2pvZrqmZ1dM8MJP1jaGo/AaNRPTKFpV8M9xii6g3+CfYCS0b78gU
JyCpZET/LtZ1qmxNYEAZSUNUY9rizLpm5U9EelvZaoErQNV/+QEnWCzI7UiRfD+m
AM/EKXMRNt6GGT6d7hmKG9Ww7Y49nCrADdg9ZuM8Db3VlFzi4qc1GwQA9j9ajepD
vV+JHanBsMyZ4k0ACtrJJ1vnE5Bc5PUzolVt3OAJTS+xJlsndQAJxGJ3KQhfnlms
tn6tn1QwIgPBHnFk/vk4CpYY3QIUrCPLBhwepH2NDd4nQeit2hW3sCPdK6jT2iWH
7ehVRE2I9DZ+hJp4rPcOVkkO1jMl1oRQQmwgEh0q1b688nCBpHBgvgW1m54ERL5h
I6zppSSMEYCUWqKiuUnSwdzRp+0xESyeGabu4VXhwOrPDYTkF7eifKXeVSUG7szA
h1xA2syVP1XgNce4hL60Xc16gwFy7ofmXx2utYXGJt/mwZrpHgJHnyqobalbz+xF
d3+YJ5oyXSrjhO7FmGYvliAd3djDJ9ew+f7Zfc3Qn48LFFhRny+Lwzgt3uiP1o2H
pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7
-----END CERTIFICATE-----
"""


def fixture_fingerprint() -> str:
    der = ssl.PEM_cert_to_DER_cert(PUBLIC_CA_FIXTURE.decode("ascii"))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, 64, 2))


def context_fixture() -> ssl.SSLContext:
    return gate_d.build_system001_gate_d_tls13_context_for_offline_test(
        public_ca_pem=PUBLIC_CA_FIXTURE,
        expected_sha256=fixture_fingerprint(),
    )


class MockConnection:
    calls = []

    def __init__(self, host, *, port, timeout, context):
        self.calls.append(("init", host, port, timeout, context))

    def request(self, method, path, *, body, headers):
        self.calls.append(("request", method, path, body, headers.copy()))

    def getresponse(self):
        self.calls.append(("getresponse",))
        return SimpleNamespace(status=202)

    def close(self):
        self.calls.append(("close",))


class GateDLocalTlsTests(unittest.TestCase):
    def setUp(self):
        MockConnection.calls = []

    def test_context_uses_one_injected_public_ca_and_never_os_trust(self):
        with patch.object(ssl, "create_default_context", side_effect=AssertionError), \
                patch.object(ssl.SSLContext, "load_default_certs", side_effect=AssertionError):
            context = context_fixture()
        expected = ssl.PEM_cert_to_DER_cert(PUBLIC_CA_FIXTURE.decode("ascii"))
        self.assertEqual(context.get_ca_certs(binary_form=True), [expected])
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_3)

    def test_bad_fingerprint_and_extra_or_invalid_cert_bundle_fail_closed(self):
        invalid_inputs = (
            (PUBLIC_CA_FIXTURE, "00:" * 31 + "00"),
            (PUBLIC_CA_FIXTURE + PUBLIC_CA_FIXTURE, fixture_fingerprint()),
            (PUBLIC_CA_FIXTURE + b"extra\n", fixture_fingerprint()),
            (b"not a certificate\n", fixture_fingerprint()),
        )
        for public_ca, fingerprint in invalid_inputs:
            with self.subTest(length=len(public_ca)), self.assertRaises(
                gate_d.GateDLocalTlsConfigurationError
            ):
                gate_d.build_system001_gate_d_tls13_context_for_offline_test(
                    public_ca_pem=public_ca, expected_sha256=fingerprint,
                )

    def test_deployed_loader_uses_exact_path_read_only_and_validates_metadata(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        public_file = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
            st_nlink=1, st_size=len(PUBLIC_CA_FIXTURE),
        )
        reads = [PUBLIC_CA_FIXTURE, b""]
        with patch.object(gate_d.os, "lstat", return_value=directory) as lstat_call, \
                patch.object(gate_d.os, "open", return_value=17) as open_call, \
                patch.object(gate_d.os, "fstat", return_value=public_file), \
                patch.object(gate_d.os, "read", side_effect=lambda *_: reads.pop(0)), \
                patch.object(gate_d.os, "close") as close_call:
            self.assertEqual(gate_d._read_deployed_public_ca(), PUBLIC_CA_FIXTURE)
        self.assertEqual(lstat_call.call_args_list, [
            call(gate_d._AVUHZ_DIRECTORY), call(gate_d._TRUST_DIRECTORY),
        ])
        open_call.assert_called_once_with(
            gate_d.SYSTEM001_GATE_D_LOCAL_CA_PATH,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        close_call.assert_called_once_with(17)

    def test_missing_wrong_owner_mode_type_link_count_or_size_fail_closed(self):
        good_directory = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
        )
        bad_directories = (
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o255, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=0),
        )
        for metadata in bad_directories:
            with self.subTest(mode=metadata.st_mode), patch.object(
                gate_d.os, "lstat", return_value=metadata,
            ), self.assertRaises(gate_d.GateDLocalTlsConfigurationError):
                gate_d._read_deployed_public_ca()
        valid_file = dict(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
            st_nlink=1, st_size=len(PUBLIC_CA_FIXTURE),
        )
        changes = (
            {"st_mode": stat.S_IFREG | 0o600}, {"st_uid": 1000}, {"st_gid": 1000},
            {"st_mode": stat.S_IFLNK | 0o644}, {"st_nlink": 2}, {"st_size": 0},
            {"st_size": gate_d._MAX_PUBLIC_CA_BYTES + 1},
        )
        for change in changes:
            metadata = SimpleNamespace(**{**valid_file, **change})
            with self.subTest(change=change), patch.object(
                gate_d.os, "lstat", return_value=good_directory,
            ), patch.object(gate_d.os, "open", return_value=19), patch.object(
                gate_d.os, "fstat", return_value=metadata,
            ), patch.object(gate_d.os, "close"), self.assertRaises(
                gate_d.GateDLocalTlsConfigurationError
            ):
                gate_d._read_deployed_public_ca()
        with patch.object(gate_d.os, "lstat", side_effect=FileNotFoundError), \
                self.assertRaises(gate_d.GateDLocalTlsConfigurationError):
            gate_d._read_deployed_public_ca()

    def test_factory_is_exact_local_profile_and_has_no_path_or_cert_override(self):
        for environment, profile in (
            ("DEVELOPMENT", gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE),
            ("PRODUCTION", gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE),
            ("LOCAL", "other"), ("local", gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE),
        ):
            with self.subTest(environment=environment, profile=profile), patch.object(
                gate_d, "build_system001_gate_d_local_tls13_context",
                side_effect=AssertionError("CA must not be read"),
            ), self.assertRaises(gate_d.GateDLocalTlsConfigurationError):
                gate_d.build_system001_gate_d_local_sink(
                    environment=environment, profile=profile, tenant_id=TENANT,
                    credential_provider=lambda: "x" * 24,
                )
        with self.assertRaises(TypeError):
            gate_d.build_system001_gate_d_local_sink(
                environment="LOCAL", profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                tenant_id=TENANT, credential_provider=lambda: "x" * 24,
                ca_path="/tmp/alternate-ca.crt",
            )
        for environment in ("LOCAL", "TEST"):
            with self.subTest(allowed_environment=environment), patch.object(
                gate_d, "build_system001_gate_d_local_tls13_context",
                return_value=context_fixture(),
            ):
                sink = gate_d.build_system001_gate_d_local_sink(
                    environment=environment,
                    profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                    tenant_id=TENANT, credential_provider=lambda: "x" * 24,
                )
            self.assertEqual(sink._endpoint, gate_d.SYSTEM001_GATE_D_LOCAL_ENDPOINT)

    def test_factory_and_import_do_not_open_network_and_pin_exact_url(self):
        context = context_fixture()
        credential_reads = []
        with patch.object(
            gate_d, "build_system001_gate_d_local_tls13_context", return_value=context,
        ), patch(
            "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden during factory"),
        ) as connection:
            sink = gate_d.build_system001_gate_d_local_sink(
                environment="LOCAL", profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                tenant_id=TENANT,
                credential_provider=lambda: credential_reads.append(True) or "x" * 24,
            )
        connection.assert_not_called()
        self.assertEqual(credential_reads, [])
        self.assertEqual(sink._endpoint, gate_d.SYSTEM001_GATE_D_LOCAL_ENDPOINT)
        self.assertEqual(sink._post._delegate._host, gate_d.SYSTEM001_GATE_D_LOCAL_HOST)
        with self.assertRaises(TypeError):
            gate_d.build_system001_gate_d_local_sink(
                environment="LOCAL", profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                tenant_id=TENANT, credential_provider=lambda: "x" * 24,
                endpoint="https://avuhz-gate-d.test/other",
            )

    def test_mocked_transport_preserves_hostname_validation_and_tls13_only(self):
        context = context_fixture()
        token = "fictional-test-token-value"
        with patch.object(
            gate_d, "build_system001_gate_d_local_tls13_context", return_value=context,
        ):
            sink = gate_d.build_system001_gate_d_local_sink(
                environment="LOCAL", profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                tenant_id=TENANT, credential_provider=lambda: token, timeout_seconds=4,
            )
        with patch(
            "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
            MockConnection,
        ):
            result = sink.deliver(KEY, fixture_event(), "2030-01-15T15:01:00Z")
        self.assertEqual(result["result"], "PUBLISHED")
        init = MockConnection.calls[0]
        self.assertEqual(init[:4], ("init", gate_d.SYSTEM001_GATE_D_LOCAL_HOST, 443, 4))
        self.assertIs(init[4], context)
        self.assertTrue(init[4].check_hostname)
        self.assertEqual(init[4].minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(init[4].maximum_version, ssl.TLSVersion.TLSv1_3)
        request = MockConnection.calls[1]
        self.assertEqual(request[:3], ("request", "POST", "/webhook/avuhz-events"))

    def test_module_import_performs_no_network(self):
        with patch("http.client.HTTPSConnection") as connection, patch(
            "socket.create_connection",
        ) as create_connection:
            importlib.reload(gate_d)
        connection.assert_not_called()
        create_connection.assert_not_called()

    def test_transport_rejects_every_nonexact_url_before_connection(self):
        context = context_fixture()
        transport = gate_d._GateDTls13OnlyTransport(context, 5, "TEST")
        for url in (
            "https://avuhz-gate-d.test:443/webhook/avuhz-events",
            "https://avuhz-gate-d.test/webhook/other",
            "https://avuhz-gate-d.test/webhook/avuhz-events?x=1",
            "https://other.test/webhook/avuhz-events",
            "http://avuhz-gate-d.test/webhook/avuhz-events",
        ):
            with self.subTest(url=url), patch(
                "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
            ) as connection, self.assertRaises(gate_d.GateDLocalTlsConfigurationError):
                transport(url, {}, b"")
            connection.assert_not_called()

    def test_tls12_or_policy_mutation_is_denied_before_connection(self):
        context = context_fixture()
        transport = gate_d._GateDTls13OnlyTransport(context, 5, "TEST")
        fields = {
            "event_id": "a4730000-0000-4000-8000-000000000041",
            "event_type": "acquisition.intake.received", "tenant_id": TENANT,
            "correlation_id": "a4730000-0000-4000-8000-000000000042",
            "occurred_at": "2030-01-15T15:00:00Z",
            "authoritative_subject_reference": {
                "reference_type": "ACQUISITION_INTAKE",
                "reference_id": "a4730000-0000-4000-8000-000000000021",
            },
            "authoritative_subject_version": 1, "delivery_idempotency_key": KEY,
        }
        headers = {
            "Content-Type": "application/json", "X-Avuhz-Webhook-Token": "x" * 24,
            "X-Avuhz-Delivery-Key": KEY,
        }
        for attribute, value in (
            ("minimum_version", ssl.TLSVersion.TLSv1_2),
            ("maximum_version", ssl.TLSVersion.MAXIMUM_SUPPORTED),
            ("check_hostname", False),
        ):
            test_context = context_fixture()
            test_transport = gate_d._GateDTls13OnlyTransport(test_context, 5, "TEST")
            setattr(test_context, attribute, value)
            with self.subTest(attribute=attribute), patch(
                "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
            ) as connection, self.assertRaises(gate_d.GateDLocalTlsConfigurationError):
                test_transport(
                    gate_d.SYSTEM001_GATE_D_LOCAL_ENDPOINT, headers,
                    json.dumps(fields).encode("utf-8"),
                )
            connection.assert_not_called()

    def test_secret_is_not_logged_or_printed(self):
        context = context_fixture()
        secret = "fictional-secret-never-log"
        output = io.StringIO()
        records = io.StringIO()
        handler = logging.StreamHandler(records)
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            with redirect_stdout(output), redirect_stderr(output), patch.object(
                gate_d, "build_system001_gate_d_local_tls13_context", return_value=context,
            ):
                sink = gate_d.build_system001_gate_d_local_sink(
                    environment="LOCAL", profile=gate_d.SYSTEM001_GATE_D_LOCAL_PROFILE,
                    tenant_id=TENANT, credential_provider=lambda: secret,
                )
                with patch(
                    "avuhz_worker.local_n8n_https_transport.http.client.HTTPSConnection",
                    MockConnection,
                ):
                    sink.deliver(KEY, fixture_event(), "2030-01-15T15:01:00Z")
        finally:
            root.removeHandler(handler)
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(secret, records.getvalue())


if __name__ == "__main__":
    unittest.main()
