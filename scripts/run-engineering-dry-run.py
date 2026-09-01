#!/usr/bin/env python3
"""Run or verify the bounded local engineering readiness simulation."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.evidence import load_bundle, verify_bundle
from avuhz_engineering.pipeline import DryRunPipeline


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    run = sub.add_parser("run")
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--simulated-approval", choices=("APPROVE", "DECLINE", "NOT_RECORDED"), default="NOT_RECORDED")
    run.add_argument("--reviewer-reference")
    verify = sub.add_parser("verify")
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--artifact", type=Path)
    args = parser.parse_args(argv)
    if args.operation == "run":
        result = DryRunPipeline(ROOT).run(args.output_dir, simulated_approval=args.simulated_approval, reviewer_reference=args.reviewer_reference)
        print(json.dumps({"bundle_digest": result.bundle_digest, "result": result.status}, sort_keys=True))
        return 0 if result.status == "SIMULATION_READY" else 2
    bundle = load_bundle(args.evidence)
    issues = verify_bundle(bundle, ROOT, args.artifact, datetime.now(timezone.utc))
    print(json.dumps({"result": "VALID" if not issues else "BLOCKED", "issue_codes": list(issues)}, sort_keys=True))
    return 0 if not issues else 2


if __name__ == "__main__":
    raise SystemExit(main())
