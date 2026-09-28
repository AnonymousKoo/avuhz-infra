from __future__ import annotations

import json

from avuhz_engineering.development_auth_recovery_verification_diagnostic import (
    classify_recovery_verification_parser_predicates,
)

USER_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ID = "22222222-2222-4222-8222-222222222222"
ACCESS = "access-secret-material-" + "x" * 40
REFRESH = "refresh-secret-material-" + "y" * 40
EMAIL = "synthetic-fixture@example.invalid"


def _payload() -> dict[str, object]:
    return {
        "access_token": ACCESS,
        "refresh_token": REFRESH,
        "token_type": "bearer",
        "expires_in": 3600,
        "expires_at": 1799999999,
        "user": {"id": USER_ID, "email": EMAIL},
    }


def test_all_current_parser_predicates_pass_for_synthetic_valid_shape() -> None:
    result = classify_recovery_verification_parser_predicates(
        _payload(), expected_user_id=USER_ID
    )
    assert set(result.values()) == {"pass"}


def test_classifier_identifies_value_level_failures_without_returning_values() -> None:
    payload = _payload()
    payload["token_type"] = "unexpected-secret-type"
    payload["expires_in"] = 0
    payload["id"] = OTHER_ID
    result = classify_recovery_verification_parser_predicates(
        payload, expected_user_id=OTHER_ID
    )
    assert result["token_type_bearer"] == "fail"
    assert result["expires_in_positive_int"] == "fail"
    assert result["dual_identity_consistent"] == "fail"
    assert result["expected_user_id_match"] == "fail"


def test_classifier_output_cannot_expose_sensitive_or_identity_values() -> None:
    payload = _payload()
    payload["provider_extra"] = "raw-provider-secret-value"
    rendered = json.dumps(
        classify_recovery_verification_parser_predicates(
            payload, expected_user_id=USER_ID
        ),
        sort_keys=True,
    )
    for forbidden in (
        ACCESS,
        REFRESH,
        USER_ID,
        OTHER_ID,
        EMAIL,
        "raw-provider-secret-value",
        "provider_extra",
    ):
        assert forbidden not in rendered
    assert set(json.loads(rendered).values()) <= {"pass", "fail"}


def test_non_mapping_payload_returns_only_fixed_failure_label() -> None:
    result = classify_recovery_verification_parser_predicates(  # type: ignore[arg-type]
        [ACCESS], expected_user_id=USER_ID
    )
    assert result == {"payload_mapping": "fail"}
