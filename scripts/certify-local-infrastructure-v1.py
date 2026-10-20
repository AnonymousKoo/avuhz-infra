#!/usr/bin/env python3
"""Offline component evidence, never a Gates 1–10 release certificate."""
import argparse
import contextlib
import importlib.metadata
import io
import hashlib
import stat
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
REQUIRED_SUITES = (*SUITES, SUPPLEMENTAL,
    'tests.architecture.test_local_infrastructure_recovery_action_v1',
    'tests.architecture.test_local_infrastructure_fencing_v1')
# These assertions are required in addition to nonempty, wholly passing suites.
GATE9_CASES = tuple('tests.architecture.test_local_infrastructure_recovery_action_v1.RecoveryActionTests.' + name for name in (
    'test_end_to_end_restart_original_failure_preserved',
    'test_forged_handles_policy_and_original_consent',
    'test_stale_future_revoked_grants_and_authority',
    'test_wrong_actual_poststate_unverified_immutable',
    'test_cross_process_delayed_original_recovery_replay'))
BASE = 'a6104c48511465c583f7f2de2fc7e38d9fa0991a'
DEPENDENCY_SOURCES = ('requirements.txt', 'package-lock.json', 'pyproject.toml',
                      '.github/workflows/main-pr-gate.yml')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tmp_path(value):
    # Literal direct /tmp children avoid traversal and symlinked parent races.
    path = Path(value)
    if (str(path) != value or path.parent != Path('/tmp')
            or path.name in ('', '.', '..') or path.is_symlink()
            or path.resolve().is_relative_to(ROOT)):
        raise ValueError('UNSAFE_EVIDENCE_PATH')
    return path


def read_local_file(value, limit=16 * 1024 * 1024):
    path = tmp_path(value)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('INVALID_RELEASE_INPUT')
        data = source.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError('INVALID_RELEASE_INPUT')
    return data


def release_inputs(value, expected_digest, check):
    if value is None and expected_digest is None:
        return {'classification': 'MISSING', 'missing': ['baseline', 'dependency', 'artifact', 'review', 'ci']}
    if value is None or not re.fullmatch(r'[0-9a-f]{64}', expected_digest or ''):
        raise ValueError('INVALID_RELEASE_INPUT')
    data = read_local_file(value)
    if digest(data) != expected_digest:
        raise ValueError('INVALID_RELEASE_INPUT')
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError('INVALID_RELEASE_INPUT')
            result[key] = item
        return result
    try:
        manifest = json.loads(data, object_pairs_hook=unique)
        if (type(manifest) is not dict or set(manifest) != {'schema', 'source_sha', 'reviewed_sha', 'records'}
                or manifest['schema'] != 'avuhz-local-release-input-v1'
                or manifest['source_sha'] != check or manifest['reviewed_sha'] != check
                or type(manifest['records']) is not dict
                or set(manifest['records']) != {'baseline', 'dependency', 'artifact', 'review', 'ci'}):
            raise ValueError('INVALID_RELEASE_INPUT')
        records = {}
        for kind, record in manifest['records'].items():
            if (type(record) is not dict or set(record) != {'source_sha', 'path', 'sha256', 'result'}
                    or record['source_sha'] != check or record['result'] != 'PASS'
                    or not re.fullmatch(r'[0-9a-f]{64}', record['sha256'])):
                raise ValueError('INVALID_RELEASE_INPUT')
            actual = digest(read_local_file(record['path'], 128 * 1024 * 1024))
            if actual != record['sha256']:
                raise ValueError('INVALID_RELEASE_INPUT')
            # Persist only the digest, never paths, arbitrary claims or payloads.
            records[kind] = actual
        baseline = (ROOT / 'scripts/check-baseline.sh').read_bytes()
        pinned = subprocess.check_output(['git', '-C', str(ROOT), 'show',
                                         BASE + ':scripts/check-baseline.sh'])
        if baseline != pinned:
            raise ValueError('BASELINE_CHANGED')
        return dict(classification='CANDIDATE_UNAUTHENTICATED', manifest_sha256=digest(data),
                    records=records, baseline_script_sha256=digest(baseline),
                    dependency_sources={name: digest((ROOT / name).read_bytes())
                                        for name in DEPENDENCY_SOURCES})
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError('INVALID_RELEASE_INPUT') from None



def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True,
                                   stderr=subprocess.DEVNULL).strip()


def preflight(check, output):
    # Reject provider/service configuration without inspecting or reporting values.
    for key in os.environ:
        if any(part in key.upper() for part in (
            'GIT_', 'PYTHONOPTIMIZE', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'SUPABASE', 'DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD',
            'PGSERVICE', 'PGDATABASE', 'N8N', 'RENDER', 'STRIPE', 'TOKEN', 'SECRET',
            'CREDENTIAL', 'AVUHZ_', 'AWS_', 'AZURE_', 'GOOGLE_', 'OPENAI_',
            'KUBECONFIG', 'DOCKER_HOST', 'PGPASSFILE', '_KEY', '_PASSWORD')):
            raise ValueError('UNSAFE_ENVIRONMENT')
    if not re.fullmatch(r'[0-9a-f]{40}', check) or git('rev-parse', 'HEAD') != check:
        raise ValueError('SOURCE_PIN_MISMATCH')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('SOURCE_NOT_CLEAN')
    target = tmp_path(output)
    if target.exists():
        raise ValueError('UNSAFE_EVIDENCE_PATH')
    return target


def run_suites(check):
    reports = []
    sys.path[:0] = [str(ROOT / 'src'), str(ROOT)]
    for name in REQUIRED_SUITES:
        class Assertions(unittest.TextTestResult):
            def addSuccess(self, test):
                super().addSuccess(test)
                passed.append(test.id())
        passed = []
        loader = unittest.TestLoader()
        stream = io.StringIO()
        # Deterministic local fixtures must not create service transports.
        with patch.object(socket, 'socket', side_effect=OSError('OFFLINE_TRANSPORT_DENIED')):
            suite = loader.loadTestsFromName(name)
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                result = unittest.TextTestRunner(stream=stream, resultclass=Assertions).run(suite)
        reports.append(dict(suite=name, tests=result.testsRun, failures=len(result.failures),
                            errors=len(result.errors) + len(loader.errors), skips=len(result.skipped),
                            source_sha=check, passed=sorted(passed)))
    return reports


def assess(reports, check):
    required = set(REQUIRED_SUITES)
    if {row['suite'] for row in reports} != required or len(reports) != len(required):
        return 'REQUIRED_SUITE_MISSING'
    if any(type(row[field]) is not int or row[field] < (1 if field == 'tests' else 0)
           for row in reports for field in ('tests', 'failures', 'errors', 'skips')):
        return 'REQUIRED_SUITE_UNPROVEN'
    if any(row['failures'] or row['errors'] or row['skips'] for row in reports):
        return 'REQUIRED_SUITE_UNPROVEN'
    if any(row.get('source_sha') != check or len(row.get('passed', [])) != row['tests']
           or len(set(row['passed'])) != row['tests'] for row in reports):
        return 'GATE9_EVIDENCE_UNPROVEN'
    passed = {case for row in reports for case in row['passed']}
    if not set(GATE9_CASES) <= passed:
        return 'GATE9_EVIDENCE_UNPROVEN'
    return 'GATE10_INDEPENDENT_PROOF_UNVERIFIED'


def write_evidence(path, summary):
    path = tmp_path(str(path))
    data = (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if read_local_file(str(path)) != data:
        raise ValueError('EVIDENCE_PERSISTENCE_ERROR')
    return digest(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', required=True, help='exact clean HEAD SHA (40 hex digits)')
    parser.add_argument('--output', required=True, help='new evidence file explicitly selected under /tmp')
    parser.add_argument('--release-input', help='candidate manifest, literal new /tmp child')
    parser.add_argument('--release-input-sha256', help='expected manifest byte digest')
    args = parser.parse_args(argv)
    evidence_digest = None
    try:
        path = preflight(args.check, args.output)
        identity = (git('rev-parse', '--show-toplevel'), git('rev-parse', '--git-common-dir'))
        if Path(identity[0]) != ROOT:
            raise ValueError('SOURCE_PIN_MISMATCH')
        inputs = release_inputs(args.release_input, args.release_input_sha256, args.check)
        reports = run_suites(args.check)
        preflight(args.check, args.output)
        if identity != (git('rev-parse', '--show-toplevel'), git('rev-parse', '--git-common-dir')):
            raise ValueError('SOURCE_PIN_MISMATCH')
        if inputs != release_inputs(args.release_input, args.release_input_sha256, args.check):
            raise ValueError('INVALID_RELEASE_INPUT')
        code = assess(reports, args.check)
        summary = dict(status='NOT CERTIFIED', code=code, source_sha=args.check,
                       command=['python3', 'scripts/certify-local-infrastructure-v1.py',
                                '--check', args.check, '--output', '<selected-/tmp-file>'],
                       classification='EVIDENCE_CANDIDATE', release_inputs=inputs,
                       python=sys.version.split()[0], suites=reports,
                       dependencies={name: importlib.metadata.version(name) for name in ('jsonschema',)},
                       missing_required_proof=['Independent security review and CI authenticity at exact HEAD',
                                               'Verified unchanged offline baseline, dependency lock/SBOM and built artifact provenance',
                                               'Applicable PG17/wheel gates not executed by this harness',
                                               'Human Gate10 approval; no offline trust root configured'])
        evidence_digest = write_evidence(path, summary)

    except (OSError, ValueError, SystemExit, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as exc:
        safe_codes = {'SOURCE_PIN_MISMATCH', 'SOURCE_NOT_CLEAN', 'UNSAFE_ENVIRONMENT',
                      'UNSAFE_EVIDENCE_PATH', 'INVALID_RELEASE_INPUT', 'BASELINE_CHANGED',
                      'EVIDENCE_PERSISTENCE_ERROR'}
        code = str(exc) if isinstance(exc, ValueError) and str(exc) in safe_codes else 'EVIDENCE_OR_EXECUTION_ERROR'
    print(json.dumps(dict(status='NOT CERTIFIED', code=code, evidence_sha256=evidence_digest)))
    return 1


if __name__ == '__main__':
    sys.exit(main())
