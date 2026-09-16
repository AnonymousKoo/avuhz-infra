#!/usr/bin/env python3
"""Execute DEVELOPMENT AUTH v32 by deriving the reviewed v30 executor in memory.

v32 is the forward-only correction after v31 stopped with an ambiguous Step 1 outcome.
It changes only the plan identity, labels, and authorization window while retaining
the reviewed direct-HTTP response parser and distinct safe error classifications.
The reviewed v30 executor source is digest-pinned before any transformation occurs.
No credential or token material is read, written, logged, or transformed here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_EXECUTOR = ROOT / "scripts/development_auth_v30_token_executor.py"
BASE_EXECUTOR_SHA256 = "6e3e8e79cdc8f726b3f0b3981fdf00045a3beac70dece3898d91c3c81bf5d9a5"

OLD_PLAN_ID = "d89b1ba0-6a85-4897-8d40-33af4de45e4a"
NEW_PLAN_ID = "e8cd574a-a532-4c95-ab5d-5c069c1bbb96"
OLD_PLAN_DIGEST = "sha256:8b1d92022e192c73b856d5d399843a3ee4c9dac4d08e9c7778293f765f8ebd6f"
NEW_PLAN_DIGEST = "sha256:c43b0b906bfb0c03e763d6cc5a13d47a900b40eb4db8fd904c799c524ec6c37c"
OLD_WINDOW_START = "2026-09-15T23:00:00Z"
NEW_WINDOW_START = "2026-09-17T15:00:00Z"
OLD_WINDOW_END = "2026-09-16T05:00:00Z"
NEW_WINDOW_END = "2026-09-17T21:00:00Z"
OLD_PLAN_VERSION_GUARD = 'plan["plan_version"] != 30'
NEW_PLAN_VERSION_GUARD = 'plan["plan_version"] != 32'


def derived_source() -> str:
    raw = BASE_EXECUTOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_EXECUTOR_SHA256:
        raise SystemExit("V32_BASE_EXECUTOR_DIGEST_MISMATCH")
    source = raw.decode("utf-8")
    required = (
        OLD_PLAN_ID,
        OLD_PLAN_DIGEST,
        OLD_WINDOW_START,
        OLD_WINDOW_END,
        '"plan_version": 30',
        OLD_PLAN_VERSION_GUARD,
    )
    if any(value not in source for value in required):
        raise SystemExit("V32_BASE_EXECUTOR_SHAPE_MISMATCH")
    source = source.replace("v30", "v32").replace("V30", "V32")
    source = source.replace(OLD_PLAN_ID, NEW_PLAN_ID)
    source = source.replace(OLD_PLAN_DIGEST, NEW_PLAN_DIGEST)
    source = source.replace(OLD_WINDOW_START, NEW_WINDOW_START)
    source = source.replace(OLD_WINDOW_END, NEW_WINDOW_END)
    source = source.replace('"plan_version": 30', '"plan_version": 32')
    source = source.replace(OLD_PLAN_VERSION_GUARD, NEW_PLAN_VERSION_GUARD)
    return source


def main() -> int:
    namespace = {
        "__name__": "__avuhz_v32_runtime__",
        "__file__": str(BASE_EXECUTOR),
    }
    exec(compile(derived_source(), str(BASE_EXECUTOR), "exec"), namespace)
    return int(namespace["main"]())


if __name__ == "__main__":
    raise SystemExit(main())
