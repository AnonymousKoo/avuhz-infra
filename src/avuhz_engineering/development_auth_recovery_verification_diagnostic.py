"""Local-only recovery verification parser-predicate diagnostic.

Returns fixed pass/fail labels only. This module performs no provider or network I/O.
"""
from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from typing import Any

_CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

def classify_recovery_verification_parser_predicates(
    payload: Mapping[str, Any], *, expected_user_id: str,
) -> dict[str, str]:
    """Return only fixed pass/fail labels for the parser predicates."""
    def status(value: bool) -> str:
        return "pass" if value else "fail"
    if not isinstance(payload, Mapping):
        return {"payload_mapping": "fail"}
    access_token = payload.get("access_token"); refresh_token = payload.get("refresh_token")
    expires_in = payload.get("expires_in"); expires_at = payload.get("expires_at")
    user = payload.get("user"); nested_user_id = user.get("id") if isinstance(user, Mapping) else None
    top_level_user_id = payload.get("id"); user_id = nested_user_id if "user" in payload else top_level_user_id
    return {
        "payload_mapping": "pass",
        "access_token_length": status(isinstance(access_token, str) and 32 <= len(access_token) <= 16384),
        "refresh_token_length": status(isinstance(refresh_token, str) and 1 <= len(refresh_token) <= 4096),
        "token_type_bearer": status(payload.get("token_type") == "bearer"),
        "expires_in_positive_int": status(not isinstance(expires_in, bool) and isinstance(expires_in, int) and expires_in > 0),
        "expires_at_valid": status(not isinstance(expires_at, bool) and (expires_at is None or (isinstance(expires_at, int) and expires_at > 0))),
        "user_mapping": status("user" not in payload or isinstance(user, Mapping)),
        "nested_user_id_string": status("user" not in payload or isinstance(nested_user_id, str)),
        "dual_identity_consistent": status(not ("user" in payload and "id" in payload) or (isinstance(top_level_user_id, str) and top_level_user_id == nested_user_id)),
        "user_id_canonical_uuid": status(isinstance(user_id, str) and bool(_CANONICAL_UUID.fullmatch(user_id))),
        "expected_user_id_canonical_uuid": status(isinstance(expected_user_id, str) and bool(_CANONICAL_UUID.fullmatch(expected_user_id))),
        "expected_user_id_match": status(isinstance(user_id, str) and isinstance(expected_user_id, str) and hmac.compare_digest(user_id, expected_user_id)),
    }
