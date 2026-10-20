"""Fail-closed evidence contracts. Never recursively execute the release runner."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('local_certification', ROOT / 'scripts/certify-local-infrastructure-v1.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
SHA = 'a' * 40


class ReleaseTests(unittest.TestCase):
    def new_path(self):
        path = Path('/tmp') / ('avuhz-release-test-' + uuid.uuid4().hex)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def reports(self):
        reports = []
        for name in runner.REQUIRED_SUITES:
            passed = [case for case in runner.GATE9_CASES if case.startswith(name + '.')]
            passed = passed or [name + '.Case.test_assertion']
            reports.append(dict(suite=name, tests=len(passed), failures=0, errors=0,
                                skips=0, source_sha=SHA, passed=passed))
        return reports

    def test_exact_canonical_modules_without_self_recursion(self):
        self.assertEqual(runner.REQUIRED_SUITES, tuple('tests.architecture.test_local_infrastructure_' + name + '_v1' for name in (
            'authority', 'trust', 'policy', 'execution', 'verification', 'audit', 'recovery',
            'recovery_safety', 'recovery_action', 'fencing')))
        self.assertNotIn(__name__, runner.REQUIRED_SUITES)

    def test_green_components_are_candidate_never_certificate(self):
        self.assertEqual(runner.assess(self.reports(), SHA), 'GATE10_INDEPENDENT_PROOF_UNVERIFIED')
        self.assertEqual(runner.release_inputs(None, None, SHA)['classification'], 'MISSING')

    def test_missing_duplicate_empty_failed_errored_skipped_proof_denied(self):
        for reports in (self.reports()[:-1], self.reports() + self.reports()[:1]):
            self.assertEqual(runner.assess(reports, SHA), 'REQUIRED_SUITE_MISSING')
        for field, value in [('tests', 0), ('tests', True), ('failures', 1), ('errors', 1), ('skips', 1), ('errors', -1)]:
            reports = self.reports()
            reports[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(runner.assess(reports, SHA), 'REQUIRED_SUITE_UNPROVEN')

    def test_stale_or_unverified_gate9_assertions_denied(self):
        for changes in ({'source_sha': 'b'*40}, {'passed': []}):
            reports = self.reports()
            reports[-2].update(changes)
            self.assertEqual(runner.assess(reports, SHA), 'GATE9_EVIDENCE_UNPROVEN')
        reports = self.reports()
        reports[-2]['passed'][0] = reports[-2]['suite'] + '.Case.test_unrelated'
        self.assertEqual(runner.assess(reports, SHA), 'GATE9_EVIDENCE_UNPROVEN')

    def test_pin_dirty_environment_and_path_denied(self):
        for head, dirty, env, output, code in [
            ('b'*40, '', {}, '/tmp/new-proof', 'SOURCE_PIN_MISMATCH'),
            (SHA, ' M file', {}, '/tmp/new-proof', 'SOURCE_NOT_CLEAN'),
            (SHA, '', {'PGHOST': 'fictional'}, '/tmp/new-proof', 'UNSAFE_ENVIRONMENT'),
            (SHA, '', {}, str(ROOT / 'proof.json'), 'UNSAFE_EVIDENCE_PATH'),
            (SHA, '', {}, '/tmp/../tmp/proof', 'UNSAFE_EVIDENCE_PATH'),
            (SHA, '', {}, '/tmp/subdir/proof', 'UNSAFE_EVIDENCE_PATH'),
            (SHA, '', {}, 'relative.json', 'UNSAFE_EVIDENCE_PATH')]:
            with self.subTest(code=code), patch.object(runner, 'git', side_effect=[head, dirty]), patch.dict(runner.os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, code):
                    runner.preflight(SHA, output)

    def test_common_service_configuration_denied(self):
        for key in ('AWS_ACCESS_KEY_ID', 'OPENAI_API_KEY', 'AZURE_CLIENT_ID',
                    'KUBECONFIG', 'DOCKER_HOST', 'PGPASSFILE', 'AVUHZ_POSTGRES_DSN',
                    'GIT_DIR', 'GIT_CONFIG_COUNT', 'PYTHONOPTIMIZE'):
            with self.subTest(key=key), patch.object(runner, 'git', side_effect=[SHA, '']), patch.dict(runner.os.environ, {key: 'fictional'}, clear=True):
                with self.assertRaisesRegex(ValueError, 'UNSAFE_ENVIRONMENT'):
                    runner.preflight(SHA, '/tmp/new-proof')

    def test_unsafe_environment_denied_before_git(self):
        with patch.dict(runner.os.environ, {'GIT_CONFIG_COUNT': '1'}, clear=True), patch.object(runner, 'git') as git:
            with self.assertRaisesRegex(ValueError, 'UNSAFE_ENVIRONMENT'):
                runner.preflight(SHA, str(self.new_path()))
            git.assert_not_called()

    def manifest(self):
        records = {}
        for kind in ('baseline', 'dependency', 'artifact', 'review', 'ci'):
            path = self.new_path()
            path.write_bytes(('fictional-' + kind).encode())
            records[kind] = dict(source_sha=SHA, result='PASS', path=str(path),
                                 sha256=runner.digest(path.read_bytes()))
        return dict(schema='avuhz-local-release-input-v1', source_sha=SHA, reviewed_sha=SHA, records=records)

    def inputs(self, manifest):
        path = self.new_path()
        path.write_text(json.dumps(manifest))
        return runner.release_inputs(str(path), runner.digest(path.read_bytes()), SHA)

    def test_complete_hashed_self_attestation_is_only_candidate(self):
        manifest = self.manifest()
        result = self.inputs(manifest)
        self.assertEqual(result['classification'], 'CANDIDATE_UNAUTHENTICATED')
        self.assertEqual(result['records']['artifact'], runner.digest(Path(manifest['records']['artifact']['path']).read_bytes()))
        self.assertNotIn('/tmp', json.dumps(result))
        self.assertEqual(self.inputs(manifest), result)

    def test_malformed_mismatched_missing_or_tampered_evidence_denied(self):
        manifest = self.manifest()
        variants = []
        bad = copy.deepcopy(manifest); bad['records'] = list(manifest['records']); variants.append(bad)
        bad = copy.deepcopy(manifest); bad['records']['review'] = ['source_sha', 'path', 'sha256', 'result']; variants.append(bad)
        for field in ('source_sha', 'reviewed_sha', 'schema'):
            changed = copy.deepcopy(manifest); changed[field] = 'wrong'; variants.append(changed)
        for kind in manifest['records']:
            for field, value in [('source_sha', 'b'*40), ('result', 'FAIL'), ('sha256', '0'*64), ('path', '../unsafe')]:
                changed = copy.deepcopy(manifest)
                changed['records'][kind][field] = value
                variants.append(changed)
            changed = copy.deepcopy(manifest); del changed['records'][kind]; variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.inputs(changed)
        Path(manifest['records']['artifact']['path']).write_bytes(b'changed-built-bytes')
        with self.assertRaisesRegex(ValueError, 'INVALID_RELEASE_INPUT'):
            self.inputs(manifest)

    def test_bad_manifest_digest_json_and_duplicate_keys_denied(self):
        for data in (b'not-json', b'{"schema":1,"schema":2}', b'[]', b'null'):
            path = self.new_path(); path.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                runner.release_inputs(str(path), runner.digest(data), SHA)
        path = self.new_path(); path.write_bytes(b'{}')
        for location, pin in ((str(path), '0'*64), (str(path), None), (None, '0'*64)):
            with self.assertRaises(ValueError): runner.release_inputs(location, pin, SHA)

    def test_changed_baseline_denied(self):
        with patch.object(runner.subprocess, 'check_output', return_value=b'changed'):
            with self.assertRaisesRegex(ValueError, 'BASELINE_CHANGED'):
                self.inputs(self.manifest())

    def test_unsafe_paths_symlinks_and_overwrite_denied(self):
        target = self.new_path(); target.write_bytes(b'original')
        link = self.new_path(); link.symlink_to(target)
        for path in (target, link):
            with patch.object(runner, 'git', side_effect=[SHA, '']), patch.dict(runner.os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'UNSAFE_EVIDENCE_PATH'):
                    runner.preflight(SHA, str(path))
            with self.assertRaises((ValueError, FileExistsError)):
                runner.write_evidence(path, {})
        self.assertEqual(target.read_bytes(), b'original')
        with self.assertRaises(ValueError): runner.read_local_file(str(link))

    def test_persisted_evidence_digest_determinism_and_private_mode(self):
        summary = {'status': 'NOT CERTIFIED', 'suites': self.reports()}
        paths = (self.new_path(), self.new_path())
        hashes = [runner.write_evidence(path, summary) for path in paths]
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual(hashes[0], runner.digest(paths[0].read_bytes()))
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_persistence_failure_never_returns_digest(self):
        for failure_at in (1, 2):
            path = self.new_path()
            calls = [None] * (failure_at - 1) + [OSError('fictional')]
            with patch.object(runner.os, 'fsync', side_effect=calls):
                with self.assertRaises(OSError): runner.write_evidence(path, {})
            with self.assertRaises(FileExistsError): runner.write_evidence(path, {})

    def run_main(self, *, preflight_error=None, write_error=None, reports=None):
        path = self.new_path()
        stream = io.StringIO()
        with patch.object(runner, 'preflight', side_effect=preflight_error, return_value=path), patch.object(runner, 'git', return_value=str(ROOT)), patch.object(runner, 'run_suites', return_value=reports if reports is not None else self.reports()), patch.object(runner, 'write_evidence', side_effect=write_error, return_value='d'*64), contextlib.redirect_stdout(stream):
            result = runner.main(['--check', SHA, '--output', str(path)])
        return result, json.loads(stream.getvalue())

    def test_main_exit_and_missing_external_gates(self):
        result, output = self.run_main()
        self.assertEqual(result, 1)
        self.assertEqual(output['status'], 'NOT CERTIFIED')
        self.assertEqual(output['code'], 'GATE10_INDEPENDENT_PROOF_UNVERIFIED')
        for error in (OSError('fictional'), ValueError('SOURCE_PIN_MISMATCH')):
            result, output = self.run_main(preflight_error=error)
            self.assertEqual(result, 1); self.assertIsNone(output['evidence_sha256'])
        result, output = self.run_main(write_error=OSError('fictional'))
        self.assertEqual(result, 1)
        self.assertEqual(output['code'], 'EVIDENCE_OR_EXECUTION_ERROR')
        self.assertIsNone(output['evidence_sha256'])
        reports = self.reports(); reports[0]['errors'] = 1
        self.assertEqual(self.run_main(reports=reports)[1]['code'], 'REQUIRED_SUITE_UNPROVEN')

    def test_bad_suite_exit_is_sanitized_and_nonzero(self):
        for error in (SystemExit(0), runner.subprocess.CalledProcessError(2, 'fictional')):
            with patch.object(runner, 'preflight', return_value=self.new_path()), patch.object(runner, 'git', return_value=str(ROOT)), patch.object(runner, 'run_suites', side_effect=error), patch.object(runner, 'write_evidence') as writer, patch('builtins.print') as printed:
                self.assertEqual(runner.main(['--check', SHA, '--output', str(self.new_path())]), 1)
                writer.assert_not_called()
                self.assertIn('EVIDENCE_OR_EXECUTION_ERROR', printed.call_args.args[0])

    def test_after_suite_source_change_denied(self):
        for error in ('SOURCE_PIN_MISMATCH', 'SOURCE_NOT_CLEAN'):
            with patch.object(runner, 'preflight', side_effect=[self.new_path(), ValueError(error)]), patch.object(runner, 'git', return_value=str(ROOT)), patch.object(runner, 'run_suites', return_value=self.reports()), patch.object(runner, 'write_evidence') as writer, patch('builtins.print') as printed:
                self.assertEqual(runner.main(['--check', SHA, '--output', str(self.new_path())]), 1)
                writer.assert_not_called()
                self.assertIn(error, printed.call_args.args[0])
