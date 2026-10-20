#!/usr/bin/env python3
"""Offline component evidence, never a Gates 1–10 release certificate."""
import argparse
import contextlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SUITES = tuple('tests.architecture.test_local_infrastructure_' + name + '_v1' for name in (
    'authority', 'trust', 'policy', 'execution', 'verification', 'audit', 'recovery'))
SUPPLEMENTAL = 'tests.architecture.test_local_infrastructure_recovery_safety_v1'


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True,
                                   stderr=subprocess.DEVNULL).strip()


def preflight(check, output):
    if not re.fullmatch(r'[0-9a-f]{40}', check) or git('rev-parse', 'HEAD') != check:
        raise ValueError('SOURCE_PIN_MISMATCH')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('SOURCE_NOT_CLEAN')
    # Reject provider/service configuration without inspecting or reporting values.
    for key in os.environ:
        if any(part in key.upper() for part in (
            'SUPABASE', 'DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD',
            'PGSERVICE', 'PGDATABASE', 'N8N', 'RENDER', 'STRIPE', 'TOKEN', 'SECRET',
            'CREDENTIAL', 'AVUHZ_', 'AWS_', 'AZURE_', 'GOOGLE_', 'OPENAI_',
            'KUBECONFIG', 'DOCKER_HOST', 'PGPASSFILE', '_KEY', '_PASSWORD')):
            raise ValueError('UNSAFE_ENVIRONMENT')
    target = Path(output)
    resolved = target.resolve()
    if (not target.is_absolute() or not resolved.is_relative_to('/tmp')
            or resolved == Path('/tmp') or resolved.is_relative_to(ROOT)
            or target.is_symlink() or target.exists()):
        raise ValueError('UNSAFE_EVIDENCE_PATH')
    return resolved


def run_suites():
    reports = []
    sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]
    for name in (*SUITES, SUPPLEMENTAL):
        loader = unittest.TestLoader()
        stream = io.StringIO()
        # Deterministic local fixtures must not create service transports.
        with patch.object(socket, 'socket', side_effect=OSError('OFFLINE_TRANSPORT_DENIED')):
            suite = loader.loadTestsFromName(name)
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                result = unittest.TextTestRunner(stream=stream).run(suite)
        reports.append(dict(suite=name, tests=result.testsRun, failures=len(result.failures),
                            errors=len(result.errors) + len(loader.errors), skips=len(result.skipped)))
    return reports


def assess(reports):
    required = {*SUITES, SUPPLEMENTAL}
    if {row['suite'] for row in reports} != required or len(reports) != len(required):
        return 'REQUIRED_SUITE_MISSING'
    if any(row['tests'] <= 0 or row['failures'] or row['errors'] or row['skips'] for row in reports):
        return 'REQUIRED_SUITE_UNPROVEN'
    return 'RECOVERY_MUTATION_GATE_UNMET'


def write_evidence(path, summary):
    # Exclusive creation denies overwrites; success is reported only after fsync.
    with path.open('x', encoding='utf-8') as output:
        json.dump(summary, output, sort_keys=True, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', required=True, help='exact clean HEAD SHA (40 hex digits)')
    parser.add_argument('--output', required=True, help='new evidence file explicitly selected under /tmp')
    args = parser.parse_args(argv)
    try:
        path = preflight(args.check, args.output)
        reports = run_suites()
        code = assess(reports)
        summary = dict(status='NOT CERTIFIED', code=code, source_sha=args.check,
                       command=['python3', 'scripts/certify-local-infrastructure-v1.py',
                                '--check', args.check, '--output', '<selected-/tmp-file>'],
                       python=sys.version.split()[0], suites=reports,
                       dependencies={name: importlib.metadata.version(name) for name in ('jsonschema',)},
                       missing_required_proof=['Gate9 bounded recovery mutation with new attempt and independent verification',
                                               'Gate10 independently reviewed offline baseline and pinned dependency/artifact proof'])
        write_evidence(path, summary)
    except (OSError, ValueError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as exc:
        safe_codes = {'SOURCE_PIN_MISMATCH', 'SOURCE_NOT_CLEAN', 'UNSAFE_ENVIRONMENT',
                      'UNSAFE_EVIDENCE_PATH'}
        code = str(exc) if isinstance(exc, ValueError) and str(exc) in safe_codes else 'EVIDENCE_OR_EXECUTION_ERROR'
    print(json.dumps(dict(status='NOT CERTIFIED', code=code)))
    return 1


if __name__ == '__main__':
    sys.exit(main())
