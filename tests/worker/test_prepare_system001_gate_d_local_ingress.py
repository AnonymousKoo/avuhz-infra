"""Offline safety tests for the source-only Gate D ingress preflight."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_system001_gate_d_local_ingress as gate


def workflow(**changes) -> gate.WorkflowObservation:
    values = {
        "project_id": gate.PROJECT_ID,
        "receiver_id": gate.RECEIVER_ID,
        "receiver_active": False,
        "active_workflows": 0,
        "persisted_executions": 0,
        "webhook_method": "POST",
        "webhook_route": gate.WEBHOOK_ROUTE,
        "metadata_verified": True,
    }
    values.update(changes)
    return gate.WorkflowObservation(**values)


def ingress(**changes) -> gate.IngressObservation:
    values = {
        "hostname": gate.CANDIDATE_HOSTNAME,
        "resolved_addresses": (gate.INGRESS_ADDRESS,),
        "listener_bindings": (f"{gate.INGRESS_ADDRESS}:{gate.INGRESS_PORT}",),
        "tls_chain_verified": True,
        "tls_hostname_verified": True,
        "tls_minimum_version": "TLSv1.3",
        "upstream": (gate.N8N_ADDRESS, gate.N8N_PORT),
        "exposed_routes": gate.EXACT_EXPOSED_ROUTES,
        "admin_routes_denied": True,
        "proof_independently_established": True,
    }
    values.update(changes)
    return gate.IngressObservation(**values)


LOCAL = {"AVUHZ_ENVIRONMENT": "LOCAL", "CI": "", "GITHUB_ACTIONS": ""}


class GateDIngressPreflightTests(unittest.TestCase):
    def test_exact_independent_evidence_can_pass_pure_evaluator(self):
        result = gate.evaluate_preflight(workflow(), ingress(), environment=LOCAL)
        self.assertEqual(result, gate.PreflightResult("PASS", ()))

    def test_current_candidate_without_dns_cert_or_443_is_blocked(self):
        observed = gate.IngressObservation(
            hostname=gate.CANDIDATE_HOSTNAME,
            resolved_addresses=(), listener_bindings=(),
            tls_chain_verified=False, tls_hostname_verified=False,
            tls_minimum_version=None, upstream=None, exposed_routes=(),
            admin_routes_denied=False, proof_independently_established=False,
        )
        result = gate.evaluate_preflight(workflow(), observed, environment=LOCAL)
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("hostname_not_loopback_verified", result.blockers)
        self.assertIn("port_443_loopback_listener_absent_or_public", result.blockers)
        self.assertIn("verified_tls_absent", result.blockers)
        self.assertIn("exact_path_isolation_unverified", result.blockers)

    def test_port_listening_or_candidate_text_alone_never_passes(self):
        observed = ingress(
            resolved_addresses=(), tls_chain_verified=False,
            tls_hostname_verified=False, tls_minimum_version=None,
            upstream=None, exposed_routes=(), admin_routes_denied=False,
            proof_independently_established=False,
        )
        result = gate.evaluate_preflight(workflow(), observed, environment=LOCAL)
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("verified_tls_absent", result.blockers)

    def test_public_or_wildcard_binding_is_denied(self):
        for binding in ("0.0.0.0:443", ":::443", "192.0.2.10:443"):
            with self.subTest(binding=binding):
                result = gate.evaluate_preflight(
                    workflow(), ingress(listener_bindings=(binding,)), environment=LOCAL,
                )
                self.assertIn("port_443_loopback_listener_absent_or_public", result.blockers)

    def test_wrong_project_active_workflow_and_execution_each_deny(self):
        cases = (
            {"project_id": "wrong-project"},
            {"receiver_active": True},
            {"active_workflows": 1},
            {"persisted_executions": 1},
        )
        for change in cases:
            with self.subTest(change=change):
                result = gate.evaluate_preflight(
                    workflow(**change), ingress(), environment=LOCAL,
                )
                self.assertEqual(result.status, "BLOCKED")
                self.assertIn("workflow_metadata_unverified", result.blockers)

    def test_only_exact_post_route_and_no_admin_routes_can_pass(self):
        cases = (
            {"exposed_routes": (("GET", gate.WEBHOOK_ROUTE),)},
            {"exposed_routes": gate.EXACT_EXPOSED_ROUTES + (("GET", "/"),)},
            {"exposed_routes": (("POST", "/webhook-test/avuhz-events"),)},
            {"admin_routes_denied": False},
            {"proof_independently_established": False},
        )
        for change in cases:
            with self.subTest(change=change):
                result = gate.evaluate_preflight(
                    workflow(), ingress(**change), environment=LOCAL,
                )
                self.assertIn("exact_path_isolation_unverified", result.blockers)

    def test_tls_chain_hostname_and_minimum_version_are_independent_gates(self):
        cases = (
            {"tls_chain_verified": False},
            {"tls_hostname_verified": False},
            {"tls_minimum_version": "TLSv1.1"},
        )
        for change in cases:
            with self.subTest(change=change):
                result = gate.evaluate_preflight(
                    workflow(), ingress(**change), environment=LOCAL,
                )
                self.assertIn("verified_tls_absent", result.blockers)

    def test_unexpected_upstream_hostname_and_environment_are_denied(self):
        self.assertIn(
            "exact_loopback_n8n_upstream_unverified",
            gate.evaluate_preflight(
                workflow(), ingress(upstream=("127.0.0.1", 5679)), environment=LOCAL,
            ).blockers,
        )
        self.assertIn(
            "unexpected_hostname",
            gate.evaluate_preflight(
                workflow(), ingress(hostname="other.test"), environment=LOCAL,
            ).blockers,
        )
        for environment in (
            {"AVUHZ_ENVIRONMENT": "PRODUCTION"},
            {"AVUHZ_ENVIRONMENT": "LOCAL", "CI": "1"},
        ):
            with self.subTest(environment=environment):
                self.assertEqual(
                    gate.evaluate_preflight(
                        workflow(), ingress(), environment=environment,
                    ).status,
                    "BLOCKED",
                )

    def test_absent_environment_is_denied_before_observation(self):
        workflow_reader = Mock()
        host_reader = Mock()
        result = gate.preflight(
            workflow_reader=workflow_reader,
            host_reader=host_reader,
            environment={},
        )
        self.assertEqual(
            result, gate.PreflightResult("BLOCKED", ("unsafe_environment",)),
        )
        workflow_reader.assert_not_called()
        host_reader.assert_not_called()

    def test_host_collector_uses_files_only_and_never_asserts_tls_or_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tcp = root / "tcp"
            tcp6 = root / "tcp6"
            hosts = root / "hosts"
            tcp.write_text(
                "  sl  local_address rem_address st\n"
                "   0: 0100007F:01BB 00000000:0000 0A\n",
                encoding="ascii",
            )
            tcp6.write_text(
                "  sl  local_address rem_address st\n", encoding="ascii",
            )
            hosts.write_text(
                "127.0.0.1 avuhz-gate-d.test\n", encoding="utf-8",
            )
            with patch("socket.create_connection") as connect:
                observed = gate.collect_host_observation(
                    proc_tcp=tcp, proc_tcp6=tcp6, hosts=hosts,
                )
        connect.assert_not_called()
        self.assertEqual(observed.resolved_addresses, ("127.0.0.1",))
        self.assertEqual(observed.listener_bindings, ("127.0.0.1:443",))
        self.assertFalse(observed.tls_chain_verified)
        self.assertFalse(observed.proof_independently_established)

    def test_host_collector_denies_any_nonexact_443_listener_with_loopback(self):
        cases = (
            ("00000000", None),
            ("0A0200C0", None),
            (None, "00000000000000000000000000000000"),
            (None, "B80D0120000000000000000001000000"),
        )
        for ipv4, ipv6 in cases:
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    tcp = root / "tcp"
                    tcp6 = root / "tcp6"
                    hosts = root / "hosts"
                    tcp.write_text(
                        "  sl  local_address rem_address st\n"
                        "   0: 0100007F:01BB 00000000:0000 0A\n"
                        + (
                            f"   1: {ipv4}:01BB 00000000:0000 0A\n"
                            if ipv4 is not None else ""
                        ),
                        encoding="ascii",
                    )
                    tcp6.write_text(
                        "  sl  local_address rem_address st\n"
                        + (
                            f"   0: {ipv6}:01BB "
                            "00000000000000000000000000000000:0000 0A\n"
                            if ipv6 is not None else ""
                        ),
                        encoding="ascii",
                    )
                    hosts.write_text(
                        "127.0.0.1 avuhz-gate-d.test\n", encoding="utf-8",
                    )
                    observed = gate.collect_host_observation(
                        proc_tcp=tcp, proc_tcp6=tcp6, hosts=hosts,
                    )
                result = gate.evaluate_preflight(
                    workflow(), observed, environment=LOCAL,
                )
                self.assertIn(
                    "port_443_loopback_listener_absent_or_public",
                    result.blockers,
                )

    def test_host_collector_fails_closed_when_either_table_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tcp = root / "tcp"
            tcp6 = root / "tcp6"
            hosts = root / "hosts"
            tcp.write_text(
                "  sl  local_address rem_address st\n", encoding="ascii",
            )
            tcp6.write_text(
                "  sl  local_address rem_address st\n", encoding="ascii",
            )
            hosts.write_text(
                "127.0.0.1 avuhz-gate-d.test\n", encoding="utf-8",
            )
            cases = (
                (root / "missing-tcp", tcp6),
                (tcp, root / "missing-tcp6"),
                (root, tcp6),
                (tcp, root),
            )
            for proc_tcp, proc_tcp6 in cases:
                with self.subTest(proc_tcp=proc_tcp, proc_tcp6=proc_tcp6):
                    with self.assertRaisesRegex(
                        gate.GateDPreflightDenied,
                        "host_listener_state_unavailable",
                    ):
                        gate.collect_host_observation(
                            proc_tcp=proc_tcp,
                            proc_tcp6=proc_tcp6,
                            hosts=hosts,
                        )

    def test_preflight_observation_failure_is_sanitized_and_fail_closed(self):
        def unsafe_reader():
            raise RuntimeError("raw secret-shaped diagnostic must not escape")

        result = gate.preflight(
            workflow_reader=unsafe_reader,
            host_reader=Mock(),
            environment=LOCAL,
        )
        self.assertEqual(
            result,
            gate.PreflightResult("BLOCKED", ("preflight_observation_unavailable",)),
        )

    def test_cli_has_no_apply_mode_and_performs_no_side_effects(self):
        with (
            patch.dict(os.environ, LOCAL, clear=True),
            patch.object(gate, "collect_workflow_observation", return_value=workflow()) as meta,
            patch.object(gate, "collect_host_observation", return_value=ingress()) as host,
            patch("subprocess.run") as process,
            patch("socket.create_connection") as network,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            code = gate.run(["--target", gate.TARGET])
        self.assertEqual(code, 0)
        meta.assert_called_once_with()
        host.assert_called_once_with()
        process.assert_not_called()
        network.assert_not_called()
        self.assertIn("READ_ONLY", output.getvalue())

    def test_live_cli_style_current_observation_returns_blocked_not_pass(self):
        current = ingress(
            resolved_addresses=(), listener_bindings=(),
            tls_chain_verified=False, tls_hostname_verified=False,
            tls_minimum_version=None, upstream=None, exposed_routes=(),
            admin_routes_denied=False, proof_independently_established=False,
        )
        with (
            patch.dict(os.environ, LOCAL, clear=True),
            patch.object(gate, "collect_workflow_observation", return_value=workflow()),
            patch.object(gate, "collect_host_observation", return_value=current),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            code = gate.run(["--target", gate.TARGET])
        self.assertEqual(code, 2)
        self.assertTrue(output.getvalue().startswith("BLOCKED "))
        self.assertNotIn("PASS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
