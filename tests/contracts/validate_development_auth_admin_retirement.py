#!/usr/bin/env python3
"""Validate the completed DEVELOPMENT AUTH bootstrap-credential retirement audit."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "contracts/plans/v1/development-auth-admin-bootstrap-retirement.evidence.json"
EXPECTED_RAW_DIGEST = "sha256:9e310b6b114b4b4a2b71f35a6f9b6324231f3f071a2fdecc5d589d7b91e635ef"
EXPECTED_OBSERVED_AT = "2026-09-15T16:48:52Z"


def main() -> int:
    raw = EVIDENCE.read_bytes()
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == EXPECTED_RAW_DIGEST
    record = json.loads(raw)
    assert record == {
        "record_type": "DEVELOPMENT_AUTH_ADMIN_BOOTSTRAP_CREDENTIAL_RETIREMENT",
        "record_version": 1,
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "credential_reference": "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "outcome": "RETIRED",
        "observed_at": EXPECTED_OBSERVED_AT,
        "provider_secret_key_deletion": {
            "status": "OWNER_CONFIRMED_DELETED",
            "verification_basis": "OWNER_INTERACTIVE_CONFIRMATION",
            "independently_verified": False,
        },
        "github_environment_binding": {
            "environment_reference": "development",
            "status": "VERIFIED_ABSENT",
            "verification_basis": "GITHUB_ENVIRONMENT_SECRET_NAME_LIST",
            "independently_verified": True,
        },
        "local_temp_secret_material": {
            "scope": "supabase/.temp/**",
            "status": "VERIFIED_ABSENT",
            "verification_basis": "LOCAL_FILESYSTEM_RESCAN",
            "independently_verified": True,
        },
        "security_state": {
            "credential_material_observed_by_control_plane": False,
            "credential_material_persisted": False,
            "credential_material_logged": False,
            "provider_read_token_changed": False,
            "data_resource_touched": False,
            "render_touched": False,
            "hook_state_changed": False,
            "token_or_session_issued": False,
        },
        "continuation_rule": "DO_NOT_REUSE_RETIRED_BOOTSTRAP_CREDENTIAL; FRESH_EXACT_AUTHORIZATION_AND_FRESH_CREDENTIAL_REQUIRED_FOR_ANY_FUTURE_PROVIDER_MUTATION",
    }
    text = raw.decode("utf-8")
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", text) is None
    assert re.search(r"sbp_[A-Za-z0-9._-]{8,}", text) is None
    assert "service_role" not in text.lower()
    print(
        "DEVELOPMENT_AUTH_ADMIN_RETIREMENT=PASS "
        "(provider deletion owner-confirmed; GitHub binding absent; local temp material absent; no credential material retained)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
