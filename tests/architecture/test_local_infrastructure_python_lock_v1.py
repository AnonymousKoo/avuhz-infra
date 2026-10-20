"""Hermetic wheel fixtures exercise byte, graph, source and output denials."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('python_lock', ROOT / 'scripts/verify-local-v1-python-lock.py')
lock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lock)


def wheel(name='demo', requires=(), tag='py3-none-any', bad_record=False, extra=None):
    prefix = name + '-1.0.0.dist-info/'
    payloads = {name + '/__init__.py': b'',
                prefix + 'METADATA': ('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0.0\nRequires-Python: >=3.12\n' +
                                      ''.join('Requires-Dist: ' + r + '\n' for r in requires)).encode(),
                prefix + 'WHEEL': ('Wheel-Version: 1.0\nTag: ' + tag + '\n').encode()}
    if extra:
        payloads[extra] = b'unsafe'
    record = prefix + 'RECORD'
    rows = ['%s,sha256=%s,%s\n' % (n, base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('='), len(b))
            for n, b in payloads.items()]
    payloads[record] = (''.join(rows) + record + ',,\n').encode()
    if bad_record:
        payloads[name + '/__init__.py'] = b'tampered'
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        for n, b in payloads.items():
            archive.writestr(n, b)
    return out.getvalue()


class PythonLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='avuhz-python-lock-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        (self.repo / 'requirements').mkdir()
        self.house = self.base / 'wheels'
        self.house.mkdir()
        self.filename = 'demo-1.0.0-py3-none-any.whl'
        self.install_fixture(wheel())

    def install_fixture(self, data):
        (self.house / self.filename).write_bytes(data)
        self.row = 'demo==1.0.0 --hash=sha256:' + hashlib.sha256(data).hexdigest() + '\n'
        for scope in lock.SCOPES:
            (self.repo / 'requirements' / ('local-v1-' + scope + '.lock')).write_text(self.row)

    def inventory(self):
        return lock.scope_inventory(self.repo, 'runtime', self.house, ['demo==1.0.0'])

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def clean_repo(self):
        (self.repo / 'requirements.txt').write_text('demo==1.0.0\n')
        (self.repo / 'pyproject.toml').write_text('[project]\nname="example"\nversion="1.0.0"\ndependencies=["demo==1.0.0"]\n[build-system]\nrequires=["setuptools>=68"]\nbuild-backend="setuptools.build_meta"\n')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def test_positive_inventory_from_actual_bytes(self):
        result = self.inventory()
        self.assertEqual(result['archives'][0]['sha256'], hashlib.sha256((self.house / self.filename).read_bytes()).hexdigest())
        self.assertEqual(result['edges'], [])

    def test_tampered_archive(self):
        with (self.house / self.filename).open('ab') as stream:
            stream.write(b'tampered')
        with self.assertRaises(ValueError):
            self.inventory()

    def test_missing_archive(self):
        (self.house / self.filename).unlink()
        with self.assertRaises(ValueError):
            self.inventory()

    def test_duplicate_pin(self):
        with self.assertRaises(ValueError):
            lock.lock_rows((self.row * 2).encode())

    def test_unmatched_pin(self):
        (self.repo / 'requirements/local-v1-runtime.lock').write_text(self.row.replace('==1.0.0', '==2.0.0'))
        with self.assertRaises(ValueError):
            self.inventory()

    def test_valid_zip_with_changed_archive_hash(self):
        self.install_fixture(wheel())
        (self.house / self.filename).write_bytes(wheel(requires=['other>=1']))
        with self.assertRaisesRegex(ValueError, 'ARCHIVE_HASH_OR_PIN_MISMATCH'):
            self.inventory()

    def test_missing_transitive_and_extra_pin(self):
        self.install_fixture(wheel(requires=['other>=1']))
        with self.assertRaisesRegex(ValueError, 'MISSING_OR_UNMATCHED_DEPENDENCY'):
            self.inventory()
        self.install_fixture(wheel())
        with self.assertRaisesRegex(ValueError, 'EXTRA_PIN'):
            lock.closure({'demo': {'version': '1.0.0', 'extras': []}}, {'demo': {'provides_extra': [], 'requires_dist': []}}, [])

    def test_transitive_extras_fixed_point(self):
        rows = {n: {'version': '1.0.0', 'extras': ['feature'] if n == 'child' else []}
                for n in ('demo', 'child', 'leaf')}
        archives = {'demo': {'provides_extra': [], 'requires_dist': ['child[feature]>=1']},
                    'child': {'provides_extra': ['feature'], 'requires_dist': ['leaf>=1; extra == "feature"']},
                    'leaf': {'provides_extra': [], 'requires_dist': []}}
        self.assertEqual(lock.closure(rows, archives, ['demo==1.0.0']), [('child', 'leaf'), ('demo', 'child')])
        rows['leaf']['version'] = '0.1.0'
        with self.assertRaises(ValueError):
            lock.closure(rows, archives, ['demo==1.0.0'])

    def test_target_marker_false_is_not_host_resolution(self):
        self.install_fixture(wheel(requires=['other>=1; sys_platform == "win32"']))
        self.assertEqual(self.inventory()['edges'], [])

    def test_unsupported_marker(self):
        self.install_fixture(wheel(requires=['other>=1; platform_release == "anything"']))
        with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_MARKER'):
            self.inventory()

    def test_unknown_marker_and_direct_url_denied(self):
        for dep in ('other; imaginary_field == "yes"', 'other @ https://invalid.example/other.whl'):
            self.install_fixture(wheel(requires=[dep]))
            with self.assertRaises(ValueError):
                self.inventory()

    def test_invalid_zip_and_record(self):
        for data in (b'not a ZIP', wheel(bad_record=True)):
            self.install_fixture(data)
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                self.inventory()

    def test_traversal_and_size_limit(self):
        self.install_fixture(wheel(extra='../escape'))
        with self.assertRaisesRegex(ValueError, 'UNSAFE_ZIP_PATH'):
            self.inventory()
        self.install_fixture(wheel())
        with patch.object(lock.guards, 'WHEEL_INPUT_LIMIT', 10), self.assertRaises(ValueError):
            self.inventory()

    def test_wrong_target_tag(self):
        with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_WHEEL_TAG'):
            lock.inspect_wheel('demo-1.0.0-cp311-cp311-win_amd64.whl', wheel(tag='cp311-cp311-win_amd64'))

    def test_metadata_tag_mismatch(self):
        with self.assertRaises(ValueError):
            lock.inspect_wheel(self.filename, wheel(tag='cp312-cp312-manylinux_2_17_x86_64'))

    def test_extra_and_symlink_archive(self):
        (self.house / 'extra.whl').write_bytes(wheel())
        with self.assertRaises(ValueError):
            self.inventory()
        (self.house / 'extra.whl').unlink()
        (self.house / self.filename).unlink()
        (self.house / self.filename).symlink_to(self.repo / 'requirements/local-v1-runtime.lock')
        with self.assertRaises(ValueError):
            self.inventory()

    def test_duplicate_distribution_archive(self):
        rows = {'demo': {'version': '1.0.0', 'extras': [], 'sha256': hashlib.sha256(wheel()).hexdigest()},
                'other': {'version': '1.0.0', 'extras': [], 'sha256': '0' * 64}}
        (self.house / 'demo-1.0.0-py312-none-any.whl').write_bytes(wheel(tag='py312-none-any'))
        with patch.object(lock, 'lock_rows', return_value=rows), self.assertRaisesRegex(ValueError, 'DUPLICATE_OR_EXTRA_ARCHIVE'):
            self.inventory()

    def test_clean_exact_sha_and_tampered_source(self):
        sha = self.clean_repo()
        lock.guards.clean(self.repo, sha)
        with self.assertRaises(ValueError):
            lock.guards.clean(self.repo, '0' * 40)
        (self.repo / 'requirements.txt').write_text('changed')
        with self.assertRaises(ValueError):
            lock.guards.clean(self.repo, sha)

    def test_determinism_and_false_certificate(self):
        sha = self.clean_repo()
        roots = {'build': ['demo==1.0.0'], 'validation': ['demo==1.0.0']}
        with patch.object(lock, 'ROOTS', roots):
            first = lock.build(self.repo, sha, dict.fromkeys(lock.SCOPES, self.house))
            second = lock.build(self.repo, sha, dict.fromkeys(lock.SCOPES, self.house))
        self.assertEqual(first, second)
        parsed = json.loads(first)
        props = parsed['metadata']['properties']
        self.assertIn({'name': 'avuhz:status', 'value': 'NOT CERTIFIED'}, props)
        self.assertNotIn('"CERTIFIED"', first.decode())
        self.assertNotIn('approved', first.decode().lower())

    def args(self, output):
        return ['--repo', str(self.repo), '--source-sha', '0' * 40,
                '--runtime-wheels', str(self.house), '--build-wheels', str(self.house),
                '--validation-wheels', str(self.house), '--output', str(output)]

    def test_dangerous_output_and_sanitized_exception(self):
        for output in (self.repo / 'out.json', self.base / '..' / 'escape.json'):
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as caught:
                lock.main(self.args(output))
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(err.getvalue(), 'PYTHON_LOCK_CANDIDATE_REJECTED\n')
            self.assertFalse(output.exists())
        with patch.object(lock, 'build', side_effect=RuntimeError('SENSITIVE_EXCEPTION_BODY')):
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                lock.main(self.args(self.base / 'out.json'))
        self.assertNotIn('SENSITIVE', err.getvalue())

    def test_output_exclusive_private_and_symlink(self):
        out = self.base / 'out.json'
        lock.guards.write_output(out, b'candidate')
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            lock.guards.write_output(out, b'overwrite')
        link = self.base / 'link'
        link.symlink_to(out)
        with self.assertRaises(OSError):
            lock.guards.write_output(link, b'overwrite')
        self.assertEqual(out.read_bytes(), b'candidate')

    def test_unverified_host_denied(self):
        with patch.object(lock.platform, 'machine', return_value='aarch64'), self.assertRaises(ValueError):
            lock.host_target()


if __name__ == '__main__':
    unittest.main()
