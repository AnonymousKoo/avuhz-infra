"""Offline structural and negative tests for the inactive Gate D nginx template."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (
    ROOT
    / "contracts/templates/nginx/avuhz-system001-gate-d-loopback-inactive.conf"
)


class GateDNginxTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    @staticmethod
    def _ssl_protocols(text: str) -> list[tuple[str, ...]]:
        return [
            tuple(value.split())
            for value in re.findall(
                r"^\s*ssl_protocols\s+([^;]+);\s*$", text, re.MULTILINE
            )
        ]

    def test_is_explicitly_inactive_and_contains_no_key_material(self):
        self.assertIn("INACTIVE SOURCE TEMPLATE", self.text)
        self.assertNotIn("BEGIN CERTIFICATE", self.text)
        self.assertNotIn("BEGIN PRIVATE KEY", self.text)
        self.assertIn(
            "ssl_certificate /etc/avuhz/private/avuhz-gate-d.test.crt;",
            self.text,
        )
        self.assertIn(
            "ssl_certificate_key /etc/avuhz/private/avuhz-gate-d.test.key;",
            self.text,
        )

    def test_listener_and_tls_are_exact_and_loopback_only(self):
        listens = re.findall(r"^\s*listen\s+([^;]+);", self.text, re.MULTILINE)
        self.assertEqual(listens, ["127.0.0.1:443 ssl"])
        self.assertNotRegex(self.text, r"listen\s+(?:\[|\*|0\.0\.0\.0|::)")
        self.assertIn("server_name avuhz-gate-d.test;", self.text)
        self.assertEqual(self._ssl_protocols(self.text), [("TLSv1.3",)])

    def test_tls_policy_rejects_fallback_duplicate_and_conflict_patterns(self):
        invalid_policies = (
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_protocols TLSv1.3 TLSv1.2;",
            "ssl_protocols SSLv3 TLSv1.3;",
            "ssl_protocols TLSv1.3;\nssl_protocols TLSv1.3;",
            "ssl_protocols TLSv1.3;\nssl_protocols TLSv1.2;",
        )
        for policy in invalid_policies:
            with self.subTest(policy=policy):
                self.assertNotEqual(
                    self._ssl_protocols(policy), [("TLSv1.3",)]
                )

    def test_only_exact_post_webhook_can_reach_exact_upstream(self):
        self.assertEqual(
            self.text.count("location = /webhook/avuhz-events {"), 1
        )
        self.assertIn("limit_except POST {", self.text)
        self.assertRegex(
            self.text, r"limit_except POST \{\s+deny all;\s+\}"
        )
        self.assertEqual(
            self.text.count("proxy_pass http://127.0.0.1:5678;"), 1
        )
        self.assertEqual(self.text.count("proxy_pass "), 1)
        self.assertIn("location / {\n        deny all;\n    }", self.text)
        for forbidden in (
            "location /webhook-test",
            "location /rest",
            "location /api",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_redirects_are_not_followed_or_emitted(self):
        self.assertIn("proxy_redirect off;", self.text)
        self.assertIn("proxy_intercept_errors on;", self.text)
        self.assertRegex(
            self.text,
            r"error_page 300 301 302 303 304 305 306 307 308 "
            r"=502 @upstream_redirect_denied;",
        )
        self.assertNotRegex(self.text, r"(?m)^\s*(?:rewrite|return 30[1278])\b")

    def test_body_and_time_are_bounded_and_access_log_is_off(self):
        expected = (
            "client_max_body_size 4k;",
            "client_body_timeout 5s;",
            "keepalive_timeout 5s;",
            "send_timeout 5s;",
            "proxy_connect_timeout 2s;",
            "proxy_send_timeout 5s;",
            "proxy_read_timeout 10s;",
            "access_log off;",
        )
        for directive in expected:
            with self.subTest(directive=directive):
                self.assertEqual(
                    len(
                        re.findall(
                            rf"^\s*{re.escape(directive)}$",
                            self.text,
                            re.MULTILINE,
                        )
                    ),
                    1,
                )


if __name__ == "__main__":
    unittest.main()
