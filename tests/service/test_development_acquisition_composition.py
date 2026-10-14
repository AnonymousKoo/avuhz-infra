"""Offline-only shared acquisition composition: inert and denied by default.

A fake JWT verifier and fake DATA store are used only inside these tests.
They do not authorize owner enrollment, a public website route, provider
access, or a real-data transaction. Production composition has no verifier
or rate-admission override parameter.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "service")]

from avuhz_service.development_acquisition_composition import (
    create_unmounted_development_acquisition_http_candidate,
)
from avuhz_service.development_acquisition_http import DevelopmentAcquisitionHttpAdapter
from avuhz_service.development_acquisition_service_identity_candidate import (
    DevelopmentAcquisitionServicePolicy,
)
from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
from test_development_acquisition_http import TOKEN, request
from test_development_acquisition_ingress import NOW, TENANT_A, Store
from test_development_acquisition_service_identity_candidate import SUBJECT, claims

SUBJECT_DIGEST = "sha256:" + hashlib.sha256(SUBJECT.encode("ascii")).hexdigest()


def policy():
    return DevelopmentAcquisitionServicePolicy(
        subject_digest=SUBJECT_DIGEST,
        principal_reference="service.acquisition-development",
        tenant_id=TENANT_A,
    )


class SyntheticJwt:
    def __init__(self, **claim_overrides):
        self.claim_overrides = claim_overrides
        self.calls = []

    def verify(self, token):
        self.calls.append(token)
        if token != TOKEN:
            raise PermissionError("private synthetic verifier diagnostics")
        return claims(
            avuhz_tenant_id=TENANT_A,
            app_metadata={
                "avuhz_workload": "acquisition_intake",
                "avuhz_tenant_id": TENANT_A,
            },
            **self.claim_overrides,
        )


class SpyConnectionFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise RuntimeError("private DSN and owner contact details must never leak")


class UnmountedSharedAcquisitionCompositionTests(unittest.TestCase):
    def test_requires_explicit_policy_data_and_clock_without_alternate_security_paths(self):
        raw = SpyConnectionFactory()
        for overrides in (
            {"service_policy": None},
            {"service_policy": "synthetic-untrusted"},
            {"acquisition_connection_factory": None},
            {"clock": None},
        ):
            with self.subTest(overrides=list(overrides)):
                kwargs = {
                    "service_policy": policy(),
                    "acquisition_connection_factory": raw,
                    "clock": lambda: NOW,
                }
                kwargs.update(overrides)
                with self.assertRaises(ValueError):
                    create_unmounted_development_acquisition_http_candidate(**kwargs)
        self.assertEqual(raw.calls, 0)
        parameters = inspect.signature(
            create_unmounted_development_acquisition_http_candidate,
        ).parameters
        self.assertEqual(
            set(parameters),
            {"service_policy", "acquisition_connection_factory", "clock"},
        )
        self.assertTrue(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()))
        for forbidden in ("jwt_verifier", "admit", "rate_limit_admit", "route", "public"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(TypeError):
                    create_unmounted_development_acquisition_http_candidate(
                        service_policy=policy(),
                        acquisition_connection_factory=raw,
                        **{forbidden: object()},
                    )
        self.assertEqual(raw.calls, 0)

    def test_constructor_is_lazy_and_cryptographic_verifier_is_mandatory(self):
        raw = SpyConnectionFactory()
        with patch(
            "avuhz_service.development_acquisition_composition."
            "DevelopmentSupabaseEs256JwtVerifier",
        ) as jwt_constructor:
            app = create_unmounted_development_acquisition_http_candidate(
                service_policy=policy(),
                acquisition_connection_factory=raw,
                clock=lambda: NOW,
            )
        self.assertIsInstance(app, DevelopmentAcquisitionHttpAdapter)
        jwt_constructor.assert_called_once_with()
        self.assertEqual(raw.calls, 0)
        status, body, _ = request(app, headers={"HTTP_AUTHORIZATION": ""})
        self.assertEqual((status, body), (401, {"error": "bearer_authentication_required"}))
        self.assertEqual(raw.calls, 0)

    def test_bad_jwt_and_untrusted_browser_authority_fail_before_any_data_contact(self):
        raw = SpyConnectionFactory()
        fake = SyntheticJwt()
        with patch(
            "avuhz_service.development_acquisition_composition."
            "DevelopmentSupabaseEs256JwtVerifier",
            return_value=fake,
        ):
            app = create_unmounted_development_acquisition_http_candidate(
                service_policy=policy(),
                acquisition_connection_factory=raw,
                clock=lambda: NOW,
            )
        status, body, _ = request(
            app,
            headers={
                "HTTP_AUTHORIZATION": "Bearer " + "x" * 50,
                "HTTP_X_AVUHZ_TENANT_ID": TENANT_A,
                "HTTP_X_AVUHZ_ORGANIZATION_ID": "a4730000-0000-4000-8000-000000000011",
                "HTTP_X_FORWARDED_PROTO": "https",
            },
        )
        self.assertEqual((status, body), (403, {"error": "acquisition_intake_not_authorized"}))
        self.assertEqual(raw.calls, 0)
        self.assertEqual(fake.calls, ["x" * 50])

    def test_valid_synthetic_identity_cannot_bypass_missing_data_connection(self):
        raw = SpyConnectionFactory()
        with patch(
            "avuhz_service.development_acquisition_composition."
            "DevelopmentSupabaseEs256JwtVerifier",
            return_value=SyntheticJwt(),
        ):
            app = create_unmounted_development_acquisition_http_candidate(
                service_policy=policy(),
                acquisition_connection_factory=raw,
                clock=lambda: NOW,
            )
        status, body, headers = request(app)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "acquisition_intake_unavailable"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(raw.calls, 1)
        self.assertNotIn("private DSN", json.dumps(body))
        self.assertNotIn(TOKEN, json.dumps(body))

    def test_complete_synthetic_path_reuses_shared_writer_without_mounting(self):
        store = Store()
        fake = SyntheticJwt()
        created = []
        admission = []

        def make_limiter(actual_store):
            created.append(actual_store)
            return lambda tenant, principal: admission.append((tenant, principal)) or True

        with (
            patch(
                "avuhz_service.development_acquisition_composition."
                "DevelopmentSupabaseEs256JwtVerifier",
                return_value=fake,
            ),
            patch(
                "avuhz_service.development_acquisition_composition."
                "create_hosted_development_acquisition_store",
                return_value=store,
            ) as data_builder,
            patch(
                "avuhz_service.development_acquisition_composition."
                "DevelopmentPostgresAcquisitionRateLimiter",
                side_effect=make_limiter,
            ) as limiter_builder,
        ):
            app = create_unmounted_development_acquisition_http_candidate(
                service_policy=policy(),
                acquisition_connection_factory=lambda: None,
                clock=lambda: NOW,
            )
        self.assertEqual(store.connections, [])
        data_builder.assert_called_once()
        limiter_builder.assert_called_once_with(store)
        self.assertEqual(created, [store])
        status, result, _ = request(app)
        self.assertEqual(status, 202)
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["intake_id"], "a4730000-0000-4000-8000-000000000031")
        self.assertEqual(fake.calls, [TOKEN])
        self.assertEqual(admission, [(TENANT_A, "service.acquisition-development")])
        self.assertEqual(len(store.connections), 2)
        self.assertEqual(store.connections[1].commits, 1)
        self.assertNotIn("alpha@example.invalid", json.dumps(result))

    def test_no_global_route_or_auth_policy_is_activated(self):
        source_dir = ROOT / "src" / "avuhz_service"
        for filename in ("development.py", "application.py", "composition.py", "__init__.py"):
            with self.subTest(filename=filename):
                text = (source_dir / filename).read_text(encoding="utf-8")
                self.assertNotIn("create_unmounted_development_acquisition_http_candidate", text)
        self.assertEqual(len(DEVELOPMENT_IDENTITY_ALLOWLIST), 2)
        self.assertTrue(all(
            "acquisition_intake:receive" not in entry.capabilities
            for entry in DEVELOPMENT_IDENTITY_ALLOWLIST
        ))


if __name__ == "__main__":
    unittest.main()
