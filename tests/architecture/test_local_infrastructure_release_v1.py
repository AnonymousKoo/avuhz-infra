"""Fail-closed release evidence contract, without rerunning component suites."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('local_certification', ROOT / 'scripts/certify-local-infrastructure-v1.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReleaseTests(unittest.TestCase):
    def reports(self):
        return [dict(suite=name, tests=1, failures=0, errors=0, skips=0)
                for name in (*runner.SUITES, runner.SUPPLEMENTAL)]

    def test_green_components_still_block_gate9(self):
        self.assertEqual(runner.assess(self.reports()), 'RECOVERY_MUTATION_GATE_UNMET')

    def test_missing_empty_failed_errored_skipped_proof_denied(self):
        self.assertEqual(runner.assess(self.reports()[:-1]), 'REQUIRED_SUITE_MISSING')
        for field, value in [('tests', 0), ('failures', 1), ('errors', 1), ('skips', 1)]:
            reports = self.reports()
            reports[0][field] = value
            with self.subTest(field=field):
                self.assertEqual(runner.assess(reports), 'REQUIRED_SUITE_UNPROVEN')

    def test_pin_dirty_environment_and_path_denied(self):
        sha = 'a' * 40
        for head, dirty, env, output, code in [
            ('b'*40, '', {}, '/tmp/new-proof', 'SOURCE_PIN_MISMATCH'),
            (sha, ' M file', {}, '/tmp/new-proof', 'SOURCE_NOT_CLEAN'),
            (sha, '', {'PGHOST': 'fictional'}, '/tmp/new-proof', 'UNSAFE_ENVIRONMENT'),
            (sha, '', {}, str(ROOT / 'proof.json'), 'UNSAFE_EVIDENCE_PATH'),
            (sha, '', {}, 'relative.json', 'UNSAFE_EVIDENCE_PATH')]:
            with self.subTest(code=code), patch.object(runner, 'git', side_effect=[head, dirty]), patch.dict(runner.os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, code):
                    runner.preflight(sha, output)

    def test_common_service_configuration_denied(self):
        for key in ('AWS_ACCESS_KEY_ID', 'OPENAI_API_KEY', 'AZURE_CLIENT_ID',
                    'KUBECONFIG', 'DOCKER_HOST', 'PGPASSFILE'):
            with self.subTest(key=key), patch.object(runner, 'git', side_effect=['a'*40, '']), patch.dict(runner.os.environ, {key: 'fictional'}, clear=True):
                with self.assertRaisesRegex(ValueError, 'UNSAFE_ENVIRONMENT'):
                    runner.preflight('a'*40, '/tmp/new-proof')

    def test_main_never_success_and_write_failure_is_explicit(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            path = Path(tmp) / 'proof.json'
            for failure in (False, True):
                with self.subTest(write_failure=failure), patch.object(runner, 'preflight', return_value=path), patch.object(runner, 'run_suites', return_value=self.reports()), patch.object(runner, 'write_evidence', side_effect=OSError('fictional') if failure else None) as writer, patch('builtins.print') as printed:
                    self.assertEqual(runner.main(['--check', 'a'*40, '--output', str(path)]), 1)
                    writer.assert_called_once()
                    self.assertIn('EVIDENCE_OR_EXECUTION_ERROR' if failure else 'RECOVERY_MUTATION_GATE_UNMET', printed.call_args.args[0])

    def test_real_evidence_exclusive_and_fsync_failure(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            path = Path(tmp) / 'proof.json'
            with patch.object(runner.os, 'fsync', side_effect=OSError('fictional')):
                with self.assertRaises(OSError):
                    runner.write_evidence(path, {'status': 'NOT CERTIFIED'})
            with self.assertRaises(FileExistsError):
                runner.write_evidence(path, {})
