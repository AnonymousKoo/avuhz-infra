"""Offline supply-chain candidate denial and observed-byte contracts."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('supply_candidate', ROOT / 'scripts/build-local-v1-supply-chain-candidate.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp', prefix='avuhz-supply-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Local Fixture')
        self.put('requirements.txt', 'Example[crypto]==1.2.3\n')
        self.put('pyproject.toml', '[project]\nname="fixture"\nversion="1.0.0"\ndependencies=["Example[crypto]==1.2.3"]\n')
        self.put('package-lock.json', json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/example': {'version': '1.2.3', 'integrity': 'sha512-' + base64.b64encode(bytes(64)).decode()}}}))
        self.put('src/fixture.py', 'VALUE = 1\n')
        self.put('contracts/schemas/v1/fixture.json', '{}\n')
        self.commit()

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(self.repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def put(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fictional fixture')
        self.sha = self.git('rev-parse', 'HEAD')

    def build(self):
        return json.loads(runner.build(self.repo, self.sha))

    def wheel(self, forged=False):
        prefix = 'fixture-1.0.0.dist-info/'
        files = {prefix + 'METADATA': b'Name: fixture\nVersion: 1.0.0\n', prefix + 'WHEEL': b'Wheel-Version: 1.0\n', 'fixture.py': b'VALUE=1\n'}
        rows = []
        for name, data in files.items():
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
            rows.append(f'{name},sha256={encoded},{len(data)}')
        if forged:
            files['fixture.py'] = b'VALUE=2\n'
        files[prefix + 'RECORD'] = ('\n'.join(rows) + '\n' + prefix + 'RECORD,,\n').encode()
        path = self.base / 'fixture-1.0.0-py3-none-any.whl'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return path

    def test_deterministic_observed_source_and_schema_hashes(self):
        first = runner.build(self.repo, self.sha)
        self.assertEqual(first, runner.build(self.repo, self.sha))
        result = json.loads(first)
        for name, item in result['files'].items():
            self.assertEqual(item['sha256'], hashlib.sha256((self.repo / name).read_bytes()).hexdigest())
        self.assertEqual(result['schemas'], 'OBSERVED')

    def test_missing_wheel_and_no_certification_transition(self):
        result = self.build()
        self.assertEqual(result['status'], 'NOT CERTIFIED')
        self.assertEqual(result['wheel'], {'classification': 'MISSING'})
        self.assertEqual(len(result['missing']), 7)
        self.assertIn('UNSIGNED', result['classification'])

    def test_exact_sha_required(self):
        for sha in ('HEAD', self.sha[:7], 'g'*40, self.sha.upper(), '0'*40):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                runner.build(self.repo, sha)

    def test_dirty_tracked_or_untracked_denied(self):
        self.put('src/fixture.py', 'changed')
        with self.assertRaisesRegex(ValueError, 'DIRTY'):
            self.build()
        self.commit()
        self.put('extra.txt', 'untracked')
        with self.assertRaisesRegex(ValueError, 'DIRTY'):
            self.build()

    def test_assume_unchanged_tamper_denied(self):
        self.git('update-index', '--assume-unchanged', 'src/fixture.py')
        self.put('src/fixture.py', 'tampered')
        with self.assertRaisesRegex(ValueError, 'SOURCE_BYTES'):
            self.build()

    def test_extra_python_dependency_denied(self):
        self.put('requirements.txt', 'Example[crypto]==1.2.3\nExtra==2.0\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'DIRECT_PIN'):
            self.build()

    def test_mismatch_extra_version_and_duplicate_denied(self):
        for value in ('Example==1.2.3', 'Example[crypto]==2.0', 'Example[crypto]==1.2.3\nexample==1.2.3'):
            self.put('requirements.txt', value)
            self.commit()
            with self.assertRaises(ValueError):
                self.build()

    def test_unpinned_or_url_dependencies_denied(self):
        for value in ('Example>=1.0', 'Example @ https://example.invalid/file', '-r other.txt'):
            with self.assertRaises(ValueError):
                runner.pins([value])

    def test_malformed_and_duplicate_lock_denied(self):
        for data in ('{', '{"lockfileVersion":3,"packages":{"":{}},"extra":NaN}', '{"lockfileVersion":3,"packages":{"":{}},"extra":Infinity}', '{"lockfileVersion":3,"lockfileVersion":3,"packages":{"":{}}}', '{"lockfileVersion":true,"packages":{}}', '{"lockfileVersion":3,"packages":[]}'):
            self.put('package-lock.json', data)
            self.commit()
            with self.assertRaises(ValueError):
                self.build()

    def test_npm_integrity_is_only_declared_metadata(self):
        npm = self.build()['npm']
        self.assertFalse(npm['archives_verified'])
        self.assertEqual(npm['classification'], 'DECLARED_METADATA_ONLY')
        with self.assertRaises(ValueError):
            runner.npm(b'{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"version":"1.0.0","integrity":"sha512-YQ=="}}}')

    def test_real_wheel_hash_and_uncertified_status(self):
        path = self.wheel()
        result = json.loads(runner.build(self.repo, self.sha, path))
        self.assertEqual(result['wheel']['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertTrue(result['wheel']['record_consistent'])
        self.assertEqual(result['status'], 'NOT CERTIFIED')
        self.assertIn('signed provenance', result['missing'])

    def test_forged_or_arbitrary_archive_denied(self):
        with self.assertRaisesRegex(ValueError, 'RECORD_MISMATCH'):
            runner.build(self.repo, self.sha, self.wheel(forged=True))
        path = self.base / 'fake.whl'
        path.write_bytes(b'not a wheel')
        with self.assertRaises(zipfile.BadZipFile):
            runner.build(self.repo, self.sha, path)

    def test_wrong_project_archive_denied(self):
        with self.assertRaises(ValueError):
            runner.wheel_info(self.wheel().read_bytes(), {'name': 'other', 'version': '1.0.0'})

    def test_symlink_input_and_parent_denied(self):
        link = self.base / 'link'
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(OSError):
            runner.read(link / 'requirements.txt')
        path = self.base / 'linked.whl'
        path.symlink_to(self.wheel())
        with self.assertRaises(OSError):
            runner.build(self.repo, self.sha, path)

    def test_tracked_symlink_denied(self):
        path = self.repo / 'src/fixture.py'
        path.unlink()
        path.symlink_to('../requirements.txt')
        self.commit()
        with self.assertRaises(OSError):
            self.build()

    def test_unsafe_paths_and_traversal_denied(self):
        for path in ('relative', '/etc/hosts', '/tmp/../etc/hosts', '/tmp'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.read(path)

    def test_exclusive_private_output_fsync_no_overwrite(self):
        path = self.base / 'candidate.json'
        with patch.object(runner.os, 'fsync', wraps=os.fsync) as sync:
            runner.write_output(path, b'candidate\n')
            self.assertEqual(sync.call_count, 2)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            runner.write_output(path, b'overwrite')
        self.assertEqual(path.read_bytes(), b'candidate\n')
        link = self.base / 'out-link'
        link.symlink_to(path)
        with self.assertRaises(FileExistsError):
            runner.write_output(link, b'overwrite')

    def test_cli_output_boundary_and_sanitized_failure(self):
        script = ROOT / 'scripts/build-local-v1-supply-chain-candidate.py'
        for output in (self.repo / 'candidate.json', self.base / 'missing' / 'candidate.json'):
            result = subprocess.run(['python3', str(script), '--repo', str(self.repo), '--source-sha', self.sha, '--output', str(output)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b'CANDIDATE_REJECTED\n')
        output = self.base / 'candidate.json'
        result = subprocess.run(['python3', str(script), '--repo', str(self.repo), '--source-sha', self.sha, '--output', str(output)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(output.read_bytes())['status'], 'NOT CERTIFIED')

    def test_git_hooks_and_replacement_refs_cannot_substitute_source(self):
        marker = self.base / 'hook-ran'
        hook = self.base / 'monitor'
        hook.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        hook.chmod(0o700)
        self.git('config', 'core.fsmonitor', str(hook))
        self.build()
        self.assertFalse(marker.exists())
        original_sha = self.sha
        self.put('src/fixture.py', 'substituted')
        self.commit()
        replacement_sha = self.sha
        self.git('update-ref', 'refs/replace/' + original_sha, replacement_sha)
        self.git('update-ref', 'HEAD', original_sha)
        self.sha = original_sha
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse(marker.exists())

    def test_no_external_contact_or_non_git_subprocess(self):
        original = runner.subprocess.run
        commands = []
        def local_only(command, **kwargs):
            self.assertEqual(command[:2], ['git', '--no-optional-locks'])
            self.assertIn(command[9], ('rev-parse', 'status', 'ls-files', 'show'))
            self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'], '')
            self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
            commands.append(command)
            return original(command, **kwargs)
        with patch.object(runner.subprocess, 'run', side_effect=local_only), patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.build()
        self.assertTrue(commands)


if __name__ == '__main__':
    unittest.main()
