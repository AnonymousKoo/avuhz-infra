"""V1 infrastructure authority intake review is scoped, pure and not a deploy gate."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
import unittest

from avuhz_runtime.infrastructure_state_review import (
    DesiredResource, ObservedResource, ResourceAssessment,
    InfrastructureStateReviewDenied, assess_development_resources,
)

TENANT = "ea000000-0000-4000-8000-000000000001"
OTHER = "ea000000-0000-4000-8000-000000000002"
NOW = datetime(2030, 1, 15, 16, 0, 0, tzinfo=timezone.utc)
DIGEST = "sha256:"+"a"*64
OTHER_DIGEST = "sha256:"+"b"*64


def desired(**changes):
    return replace(DesiredResource(
        TENANT, "render.srv123", "SERVICE", "DEVELOPMENT", DIGEST,
    ), **changes)


def observed(**changes):
    return replace(ObservedResource(
        TENANT, "render.srv123", "SERVICE", "DEVELOPMENT", DIGEST,
        "fpv1:"+"c"*40, "evidence.render123", "TARGET_STATE",
        "provider.readonly01", NOW-timedelta(minutes=4),
    ), **changes)


def review(*, want=None, saw=None, **other):
    return assess_development_resources(
        (desired(),) if want is None else want,
        (observed(),) if saw is None else saw,
        trusted_tenant_id=TENANT, now=NOW, max_observation_age_minutes=10,
        **other,
    )


class InfrastructureV1StateReviewTests(unittest.TestCase):
    def test_exact_match_is_only_a_review_candidate(self):
        result=review()
        self.assertEqual(result,(ResourceAssessment(
            "render.srv123", "SERVICE", "MATCHED", "evidence.render123",
        ),))
        self.assertFalse(hasattr(result[0],"tenant_id"))
        self.assertFalse(hasattr(result[0],"provider_url"))
        self.assertFalse(hasattr(result[0],"authorized"))
        self.assertFalse(hasattr(result[0],"execution_id"))

    def test_drift_returns_review_not_approval(self):
        result=review(saw=(observed(observed_artifact_digest=OTHER_DIGEST),))
        self.assertEqual(result[0].result, "MISMATCHED")

    def test_missing_stale_and_future_evidence_fail_closed(self):
        for inputs in (
            {"saw":()},
            {"saw":(observed(observed_at=NOW-timedelta(minutes=11)),)},
            {"saw":(observed(observed_at=NOW+timedelta(seconds=1)),)},
        ):
            with self.subTest(inputs=inputs):
                result=review(**inputs)
                self.assertEqual(result[0].result,"BLOCKED")
                self.assertIsNone(result[0].evidence_reference_id)

    def test_equality_spoof_and_raising_timezone_never_escapes_denial(self):
        class EqualEverything:
            def __eq__(self, other): return True
        class DangerousEqual:
            def __eq__(self, other): raise RuntimeError("untrusted equality invoked")
        class HostileTimezone(tzinfo):
            def utcoffset(self, dt): raise RuntimeError("untrusted UTC offset invoked")
            def tzname(self, dt): return "fake"
            def dst(self, dt): return timedelta(0)
        hostile_dt = datetime(2030,1,15,16,0,tzinfo=HostileTimezone())
        cases=(
            {"want":(desired(tenant_id=EqualEverything()),)},
            {"want":(desired(tenant_id=DangerousEqual()),)},
            {"saw":(observed(tenant_id=EqualEverything()),)},
            {"saw":(observed(tenant_id=DangerousEqual()),)},
            {"want":(desired(target_environment=EqualEverything()),)},
            {"want":(desired(target_environment=DangerousEqual()),)},
            {"saw":(observed(target_environment=EqualEverything()),)},
            {"saw":(observed(target_environment=DangerousEqual()),)},
            {"saw":(observed(observed_at=hostile_dt),)},
        )
        for inputs in cases:
            with self.subTest(keys=tuple(inputs)),self.assertRaises(InfrastructureStateReviewDenied):
                review(**inputs)
        with self.assertRaises(InfrastructureStateReviewDenied):
            assess_development_resources(
                (desired(),),(observed(),),trusted_tenant_id=TENANT,
                now=hostile_dt,max_observation_age_minutes=10,
            )

    def test_wrong_tenant_environment_or_target_denied(self):
        for value in (
            {"want":(desired(tenant_id=OTHER),)},
            {"want":(desired(target_environment="PRODUCTION"),)},
            {"saw":(observed(tenant_id=OTHER),)},
            {"saw":(observed(target_environment="PRODUCTION"),)},
            {"saw":(observed(target_reference_id="render.other"),)},
            {"saw":(observed(target_class="HOST_GROUP"),)},
        ):
            with self.subTest(value=value), self.assertRaises(InfrastructureStateReviewDenied):
                review(**value)

    def test_no_raw_payload_or_secrets_survive_validation(self):
        for extra in (
            {"observed_artifact_digest":"sha256:secret"},
            {"provenance_reference":"https://user:password@example.invalid"},
            {"evidence_reference_id":"Bearer secret"},
            {"observed_state_fingerprint":"fpv1:BearerSecret"},
            {"evidence_class":"MANUAL_INSPECTION"},
        ):
            with self.subTest(extra=extra), self.assertRaises(InfrastructureStateReviewDenied):
                review(saw=(observed(**extra),))

    def test_duplicate_and_unexpected_inventory_denied(self):
        for target, obs in (
            ((desired(),desired()),(observed(),)),
            ((desired(),),(observed(),observed())),
            ((desired(),),(observed(),observed(target_reference_id="render.other"))),
        ):
            with self.subTest(), self.assertRaises(InfrastructureStateReviewDenied):
                review(want=target,saw=obs)

    def test_fifty_resource_limit_and_deterministic_order(self):
        want=tuple(desired(target_reference_id=f"render.r{i:04d}") for i in range(50))
        got=tuple(observed(target_reference_id=f"render.r{i:04d}") for i in range(50))
        self.assertEqual(len(review(want=want,saw=got)),50)
        self.assertEqual(review(want=want,saw=got),review(want=want,saw=got))
        with self.assertRaises(InfrastructureStateReviewDenied):
            review(want=want+(desired(target_reference_id="render.extra"),),saw=got)

    def test_untrusted_types_and_invalid_clock_are_denied(self):
        for inp in (
            {"want":[desired()]}, {"saw":[observed()]},
            {"want":()}, {"want":({"target_reference_id":"render.r"},)},
            {"saw":({"evidence_reference_id":"evidence.r"},)},
            {"saw":(observed(observed_at=NOW.replace(tzinfo=None)),)},
            {"saw":(observed(target_class=[]),)},
        ):
            with self.subTest(keys=tuple(inp)), self.assertRaises(InfrastructureStateReviewDenied):
                review(**inp)
        for elapsed in (True,"10",0,1441):
            with self.subTest(minutes=elapsed),self.assertRaises(InfrastructureStateReviewDenied):
                assess_development_resources((desired(),),(observed(),),
                    trusted_tenant_id=TENANT,now=NOW,max_observation_age_minutes=elapsed)


if __name__=="__main__":
    unittest.main()
