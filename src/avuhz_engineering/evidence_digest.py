"""Forward-only helpers for canonical evidence digests.

Historical authorization-plan source files are hash-bound by sealed plans and
must remain byte-for-byte immutable. New continuations should use this module
for evidence envelopes that may carry their own `evidence_digest` field.
"""
from __future__ import annotations

import copy

from avuhz_engineering.authorization_plan import AuthorizationPlanError
from avuhz_runtime.implementation_handoff import canonical_digest


def evidence_digest(evidence: dict) -> str:
    """Return the canonical evidence-body digest and validate any embedded digest."""
    body = {
        key: copy.deepcopy(value)
        for key, value in evidence.items()
        if key != "evidence_digest"
    }
    computed = canonical_digest(body)
    embedded = evidence.get("evidence_digest")
    if embedded is not None and embedded != computed:
        raise AuthorizationPlanError("EVIDENCE_DIGEST_INVALID")
    return computed
