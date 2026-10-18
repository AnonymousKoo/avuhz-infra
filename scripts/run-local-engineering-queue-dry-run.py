#!/usr/bin/env python3
"""Validate and advance one LOCAL engineering manifest without executing it."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_engineering_queue import (  # noqa: E402
    LocalEngineeringQueue,
    QueueError,
    load_manifest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the non-executing AAE/local manifest dry run")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--dry-run", required=True, action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        summary = LocalEngineeringQueue(ROOT, args.state_dir).run_resumable_dry_run(manifest)
    except QueueError as exc:
        print(json.dumps({"error_code": exc.code, "result": "BLOCKED"}, sort_keys=True))
        return 2
    print(json.dumps({"result": "DRY_RUN_VERIFIED", "summary": summary.as_dict()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
