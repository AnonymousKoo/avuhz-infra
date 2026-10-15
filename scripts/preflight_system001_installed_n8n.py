#!/usr/bin/env python3
"""Run one read-only diagnostic of the existing LOCAL System #001 n8n child."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_worker.local_system001_n8n_readiness import (
    LocalN8nPreflightDenied, preflight,
)


def main() -> int:
    try:
        evidence = preflight(root=ROOT)
    except LocalN8nPreflightDenied:
        print("LOCAL_SYSTEM001_N8N_PREFLIGHT_DENIED")
        return 2
    print("LOCAL_SYSTEM001_N8N_PREFLIGHT_PASS")
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    print("NEXT: separately authorize LOCAL private receipt server, "
          "encrypted n8n header credential, source-bound child input, and ONE QA event.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
