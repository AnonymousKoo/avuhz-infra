#!/usr/bin/env python3
"""Execute DEVELOPMENT AUTH v31 by deriving the reviewed v30 executor in memory.

v31 changes only the forward-only plan identity, labels, and authorization window.
The reviewed v30 executor source is digest-pinned before any transformation occurs.
No credential or token material is read, written, logged, or transformed here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_EXECUTOR = ROOT / "scripts/development_auth_v30_token_executor.py"
BASE_EXECUTOR_SHA256 = "a32ae8d3598c615cc6e96f6673274c1bdd43c4ded569046b2547ceb24acc22c4"

OLD_PLAN_ID = "d89b1ba0-6a85-4897-8d40-33af4de45e4a"
NEW_PLAN_ID = "c2a83103-7177-4bf4-855f-c3428b2d5b73"
OLD_PLAN_DIGEST = "sha256:8b1d92022e192c73b856d5d399843a3ee4c9dac4d08e9c7778293f765f8ebd6f"
NEW_PLAN_DIGEST = "sha256:8ea09f44c3c5e65a6a8d86b0df6579b0f4476b63ae6c167a6194948c86aab043"
OLD_WINDOW_START = "2026-09-15T23:00:00Z"
NEW_WINDOW_START = "2026-09-16T00:15:00Z"
OLD_WINDOW_END = "2026-09-16T05:00:00Z"
NEW_WINDOW_END = "2026-09-16T06:15:00Z"


def derived_source() -> str:
    raw = BASE_EXECUTOR.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_EXECUTOR_SHA256:
        raise SystemExit("V31_BASE_EXECUTOR_DIGEST_MISMATCH")
    source = raw.decode("utf-8")
    required = (OLD_PLAN_ID, OLD_PLAN_DIGEST, OLD_WINDOW_START, OLD_WINDOW_END, '"plan_version": 30')
    if any(value not in source for value in required):
        raise SystemExit("V31_BASE_EXECUTOR_SHAPE_MISMATCH")
    source = source.replace("v30", "v31").replace("V30", "V31")
    source = source.replace(OLD_PLAN_ID, NEW_PLAN_ID)
    source = source.replace(OLD_PLAN_DIGEST, NEW_PLAN_DIGEST)
    source = source.replace(OLD_WINDOW_START, NEW_WINDOW_START)
    source = source.replace(OLD_WINDOW_END, NEW_WINDOW_END)
    source = source.replace('"plan_version": 30', '"plan_version": 31')
    return source


def main() -> int:
    namespace = {
        "__name__": "__avuhz_v31_runtime__",
        "__file__": str(BASE_EXECUTOR),
    }
    exec(compile(derived_source(), str(BASE_EXECUTOR), "exec"), namespace)
    return int(namespace["main"]())


if __name__ == "__main__":
    raise SystemExit(main())
