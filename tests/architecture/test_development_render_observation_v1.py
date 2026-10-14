"""Provider-free DEVELOPMENT Render readback normalization tests."""
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import unittest

from avuhz_runtime.development_render_observation import (
    RenderDevelopmentScope, RenderObservationCandidate,
    RenderReadbackDenied, normalize_render_development_readback,
)

NOW = datetime(2030, 1, 15, 12, tzinfo=timezone.utc)
COMMIT = "a" * 40


def scope(**changes):
    return replace(RenderDevelopmentScope(
        "tea-dab95hv40ujc73a7ccag", "evm-dab96l2jobas73bp95bg",
        "srv-dab9n4qd0e5s73dq37mg", "avuhz-command-dev",
        "https://github.com/AnonymousKoo/avuhz-infra", "main",
    ), **changes)


def service():
    s = scope()
    return dict(
        id=s.service_id, name=s.service_name, ownerId=s.workspace_id,
        environmentId=s.environment_id, repo=s.repository_url,
        branch=s.branch, type="web_service",
    )


def deployment(status="live"):
    return dict(id="dep-db5rjkg473hc73c5vtmg", status=status, commit={"id": COMMIT})


def review(boundary=None, state=None, deployments=None, observed_at=NOW):
    return normalize_render_development_readback(
        scope() if boundary is None else boundary,
        service() if state is None else state,
        (deployment(),) if deployments is None else deployments,
        observed_at=observed_at,
    )


class DevelopmentRenderObservationTests(unittest.TestCase):
    def test_live_claim_not_attestation(self):
        value = review()
        self.assertEqual(value, RenderObservationCandidate(
            "UNATTESTED_LIVE_CLAIM", scope().service_id,
            deployment()["id"], COMMIT, NOW,
        ))
        self.assertFalse(hasattr(value, "tenant_id"))
        self.assertFalse(hasattr(value, "verified"))
        self.assertFalse(hasattr(value, "authorized"))

    def test_historical_deployments_are_not_active(self):
        state = review(deployments=(deployment(), deployment("deactivated"),
                                    deployment("canceled")))
        self.assertEqual(state.status, "UNATTESTED_LIVE_CLAIM")

    def test_absent_live_is_blocked_not_failed(self):
        for items in ((), (deployment("deactivated"),), (deployment("build_failed"),)):
            with self.subTest(items=items):
                result = review(deployments=items)
                self.assertEqual(result.status, "BLOCKED_UNVERIFIED")
                self.assertIsNone(result.commit_sha)

    def test_scope_mismatches_denied(self):
        for key, value in (
            ("id", "srv-aaaaaaaaaaaaaaaaaaaa"),
            ("ownerId", "tea-aaaaaaaaaaaaaaaaaaaa"),
            ("environmentId", "evm-aaaaaaaaaaaaaaaaaaaa"),
            ("repo", "https://github.com/other/project"),
            ("branch", "feature"),
            ("type", "background_worker"),
            ("name", "unexpected-service"),
        ):
            data = service()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(RenderReadbackDenied):
                review(state=data)
        for bound in (
            scope(service_id="srv-aaaaaaaaaaaaaaaaaaaa"),
            scope(environment_id="evm-aaaaaaaaaaaaaaaaaaaa"),
            scope(workspace_id="tea-aaaaaaaaaaaaaaaaaaaa"),
            scope(branch="production"),
        ):
            with self.assertRaises(RenderReadbackDenied):
                review(boundary=bound)

    def test_malformed_or_ambiguous_deployments_denied(self):
        samples = (
            (deployment(), deployment()),
            ({"status": True},),
            ({"status": "live", "commit": {"id": COMMIT}},),
            ({**deployment(), "commit": {"id": "short"}},),
            ({**deployment(), "id": "dep-short"},),
            ({**deployment(), "commit": "unstructured"},),
            (object(),),
            tuple(deployment("deactivated") for _ in range(21)),
        )
        for items in samples:
            with self.subTest(length=len(items)), self.assertRaises(RenderReadbackDenied):
                review(deployments=items)

    def test_bad_types_and_timezone_denied(self):
        tests = (
            dict(boundary={"service_id": scope().service_id}),
            dict(state=[]),
            dict(deployments=[deployment()]),
            dict(observed_at=NOW.replace(tzinfo=None)),
            dict(observed_at=NOW.replace(tzinfo=timezone(timedelta(hours=-4)))),
            dict(observed_at=True),
        )
        for kwargs in tests:
            with self.subTest(keys=tuple(kwargs)), self.assertRaises(RenderReadbackDenied):
                review(**kwargs)

    def test_unknown_fields_are_never_in_output(self):
        data = service()
        data["extra_payload"] = {"contact": "sample-private-field"}
        d = deployment()
        d["raw_context"] = {"contact": "sample-private-field"}
        result = review(state=data, deployments=(d,))
        self.assertNotIn("sample-private-field", repr(result))
        self.assertFalse(hasattr(result, "extra_payload"))

    def test_hostile_type_denied_without_invoking_equality(self):
        class Hostile:
            def __eq__(self, other):
                raise RuntimeError("comparison was invoked")
        for key in ("id", "ownerId", "environmentId", "repo", "type"):
            data = service()
            data[key] = Hostile()
            with self.subTest(key=key), self.assertRaises(RenderReadbackDenied):
                review(state=data)


if __name__ == "__main__":
    unittest.main()
