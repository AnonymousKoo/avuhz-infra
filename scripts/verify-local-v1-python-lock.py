#!/usr/bin/env python3
"""Offline, target-specific unsigned wheel inventory. Never a certificate."""
import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tomllib
import zipfile

# Reuse reviewed stdlib source-byte, descriptor-path, ZIP-header and output guards.
_spec = importlib.util.spec_from_file_location(
    'supply_guards', Path(__file__).with_name('build-local-v1-supply-chain-candidate.py'))
guards = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guards)

TARGET = {'implementation_name': 'cpython', 'implementation_version': '3.12.3',
          'os_name': 'posix', 'platform_machine': 'x86_64',
          'platform_python_implementation': 'CPython', 'platform_release': '',
          'platform_system': 'Linux', 'platform_version': '',
          'python_full_version': '3.12.3', 'python_version': '3.12',
          'sys_platform': 'linux', 'extra': ''}
SCOPES = ('runtime', 'build', 'validation')
ROOTS = {'build': ['pip==24.3.1', 'setuptools==68.1.2', 'wheel==0.45.1', 'packaging==24.2'],
         'validation': ['packaging==24.2']}
MAX_METADATA = 1024 * 1024


def packaging_api():
    # packaging is an explicit separately hash-locked validation prerequisite.
    import packaging
    if packaging.__version__ != "24.2":
        raise ValueError("LOCKED_PACKAGING_REQUIRED")
    from packaging.requirements import Requirement
    from packaging.tags import Tag, cpython_tags, compatible_tags
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.specifiers import SpecifierSet
    return Requirement, Tag, cpython_tags, compatible_tags, canonicalize_name, parse_wheel_filename, SpecifierSet


def target_tags():
    _, _, cp, compatible, _, _, _ = packaging_api()
    platforms = ['manylinux_2_%d_x86_64' % minor for minor in range(39, 4, -1)]
    platforms += ['manylinux2014_x86_64', 'manylinux2010_x86_64', 'manylinux1_x86_64']
    return set(cp((3, 12), ['cp312'], platforms)) | set(compatible((3, 12), 'cp312', platforms))


def host_target():
    if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 12, 3)
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or platform.libc_ver() != ('glibc', '2.39')):
        raise ValueError('UNVERIFIED_HOST_TARGET')


def lock_rows(data):
    requirement, _, _, _, canonical, _, _ = packaging_api()
    rows = {}
    for line in data.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+(?:\[[a-z0-9,-]+\])?==[0-9][A-Za-z0-9.!+]*) --hash=sha256:([0-9a-f]{64})', line)
        if not match:
            raise ValueError('INVALID_LOCK_ROW')
        req = requirement(match[1])
        name = canonical(req.name)
        if name in rows:
            raise ValueError('DUPLICATE_PIN')
        rows[name] = {'version': next(iter(req.specifier)).version,
                      'extras': sorted(req.extras), 'sha256': match[2]}
    if not rows:
        raise ValueError('EMPTY_LOCK')
    return rows


def inspect_wheel(filename, data):
    _, _, _, _, canonical, parse_filename, specifier = packaging_api()
    guards.wheel_headers(data)
    name, version, build, tags = parse_filename(filename)
    if build or not tags or not tags.issubset(target_tags()):
        raise ValueError('UNSUPPORTED_WHEEL_TAG')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [e.filename for e in entries]
        if len(set(n.casefold() for n in names)) != len(names):
            raise ValueError('DUPLICATE_ZIP_PATH')
        files = set()
        total = 0
        for entry in entries:
            path = entry.filename.rstrip('/') if entry.is_dir() else entry.filename
            if (not path or not re.fullmatch(r'[A-Za-z0-9._/ +()-]+', path)
                    or any(p in ('', '.', '..') for p in path.split('/'))
                    or entry.orig_filename != entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16)
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError('UNSAFE_ZIP_PATH')
            if not entry.is_dir():
                files.add(path)
        if any('/'.join(n.split('/')[:i]) in files for n in names for i in range(1, len(n.split('/')))):
            raise ValueError('ZIP_PATH_COLLISION')

        def consume(member, limit):
            nonlocal total
            out = bytearray()
            with archive.open(member) as stream:
                while block := stream.read(65536):
                    total += len(block)
                    out.extend(block)
                    if len(out) > limit or total > guards.WHEEL_TOTAL_LIMIT:
                        raise ValueError('WHEEL_SIZE_LIMIT')
            return bytes(out)

        records = [n for n in files if n.endswith('.dist-info/RECORD')]
        if len(records) != 1:
            raise ValueError('INVALID_RECORD')
        record = records[0]
        prefix = record.rsplit('/', 1)[0]
        expected_prefix = str(name).replace('-', '_') + '-' + str(version) + '.dist-info'
        if prefix != expected_prefix:
            raise ValueError('DIST_INFO_MISMATCH')
        if any('.dist-info/' in n and not n.startswith(prefix + '/') for n in files):
            raise ValueError('EXTRA_DIST_INFO')
        metadata = BytesParser().parsebytes(consume(prefix + '/METADATA', MAX_METADATA))
        for field in ('Name', 'Version', 'Metadata-Version'):
            if len(metadata.get_all(field, [])) != 1:
                raise ValueError('AMBIGUOUS_METADATA')
        if canonical(metadata['Name']) != name or metadata['Version'] != str(version):
            raise ValueError('METADATA_IDENTITY_MISMATCH')
        python_requires = metadata.get_all('Requires-Python', [])
        if len(python_requires) > 1 or (python_requires and not specifier(python_requires[0]).contains('3.12.3')):
            raise ValueError('PYTHON_VERSION_MISMATCH')
        wheel = BytesParser().parsebytes(consume(prefix + '/WHEEL', MAX_METADATA))
        from packaging.tags import parse_tag
        declared_tags = set()
        for tag in wheel.get_all('Tag', []):
            declared_tags.update(parse_tag(tag))
        if declared_tags != tags or wheel.get_all('Wheel-Version') != ['1.0']:
            raise ValueError('WHEEL_METADATA_TAG_MISMATCH')
        seen = set()
        for row in csv.reader(io.StringIO(consume(record, MAX_METADATA).decode('utf-8'))):
            if len(row) != 3 or row[0] not in files or row[0] in seen:
                raise ValueError('INVALID_RECORD')
            member, claimed, size = row
            seen.add(member)
            if member == record:
                if claimed or size:
                    raise ValueError('INVALID_SELF_RECORD')
            else:
                payload = consume(member, guards.WHEEL_ENTRY_LIMIT)
                hashed = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip('=')
                if claimed != 'sha256=' + hashed or size != str(len(payload)):
                    raise ValueError('RECORD_MISMATCH')
        if seen != files:
            raise ValueError('INCOMPLETE_RECORD')
    return {'name': str(name), 'version': str(version), 'filename': filename,
            'sha256': hashlib.sha256(data).hexdigest(), 'tags': sorted(map(str, tags)),
            'requires_python': python_requires[0] if python_requires else '',
            'requires_dist': sorted(metadata.get_all('Requires-Dist', [])),
            'provides_extra': sorted(metadata.get_all('Provides-Extra', []))}


def active(req, extras):
    if req.url:
        raise ValueError('URL_DEPENDENCY_DENIED')
    if req.marker is None:
        return True
    # Reject host-specific/unknown marker fields rather than silently inheriting host values.
    from packaging._parser import Variable
    def check(tree):
        for node in tree:
            if isinstance(node, list):
                check(node)
            elif isinstance(node, tuple):
                for part in node:
                    if isinstance(part, Variable) and part.value not in TARGET:
                        raise ValueError('UNSUPPORTED_MARKER')
                    if isinstance(part, Variable) and part.value in ('platform_release', 'platform_version'):
                        raise ValueError('UNSUPPORTED_MARKER')
    check(req.marker._markers)
    return any(req.marker.evaluate(dict(TARGET, extra=extra)) for extra in {''} | set(extras))


def closure(rows, archives, roots):
    requirement, _, _, _, canonical, _, _ = packaging_api()
    selected, extras, edges = set(), {}, set()
    pending = [(None, requirement(root)) for root in roots]
    while pending:
        parent, req = pending.pop()
        name = canonical(req.name)
        if not active(req, extras.get(parent, set())):
            continue
        if name not in rows or name not in archives or not req.specifier.contains(rows[name]['version']):
            raise ValueError('MISSING_OR_UNMATCHED_DEPENDENCY')
        if req.extras - set(archives[name]['provides_extra']):
            raise ValueError('UNDECLARED_EXTRA')
        if parent:
            edges.add((parent, name))
        previous = extras.get(name, set())
        added = set(req.extras) - previous
        if name in selected and not added:
            continue
        selected.add(name)
        extras[name] = previous | set(req.extras)
        pending.extend((name, requirement(text)) for text in archives[name]['requires_dist'])
    if selected != set(rows):
        raise ValueError('EXTRA_PIN')
    if any(set(rows[n]['extras']) != extras[n] for n in rows):
        raise ValueError('LOCK_EXTRA_MISMATCH')
    return sorted(edges)


def scope_inventory(lock_data, wheelhouse, roots):
    rows = lock_rows(lock_data)
    parent, name = guards.safe_parent(wheelhouse)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    archives = {}
    try:
        with os.scandir(fd) as scan:
            entries = sorted(list(scan), key=lambda e: e.name)
        if len(entries) != len(rows) or len(entries) > 100:
            raise ValueError('ARCHIVE_SET_MISMATCH')
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith('.whl'):
                raise ValueError('UNEXPECTED_ARCHIVE')
            data = guards.read(wheelhouse / entry.name, guards.WHEEL_INPUT_LIMIT)
            info = inspect_wheel(entry.name, data)
            name = info['name']
            if name in archives or name not in rows:
                raise ValueError('DUPLICATE_OR_EXTRA_ARCHIVE')
            if (info['version'] != rows[name]['version'] or info['sha256'] != rows[name]['sha256']):
                raise ValueError('ARCHIVE_HASH_OR_PIN_MISMATCH')
            archives[name] = info
    finally:
        os.close(fd)
    edges = closure(rows, archives, roots)
    return {'archives': [archives[n] for n in sorted(archives)],
            'edges': [{'from': a, 'to': b} for a, b in edges],
            'roots': sorted(roots)}


def build(root, sha, wheelhouses):
    host_target()
    tracked = guards.clean(root, sha)
    object_format = guards.git(root, 'rev-parse', '--show-object-format').decode().strip()

    def source(path):
        return guards.read(root / path, MAX_METADATA, expected=tracked[path],
                           object_format=object_format)

    project = tomllib.loads(source('pyproject.toml').decode())
    direct = project['project']['dependencies']
    declared = [s for s in source('requirements.txt').decode().splitlines()
                if s and not s.startswith('#')]
    if guards.pins(declared) != guards.pins(direct):
        raise ValueError('DIRECT_PIN_MISMATCH')
    if project['build-system'] != {'requires': ['setuptools>=68'], 'build-backend': 'setuptools.build_meta'}:
        raise ValueError('UNREVIEWED_BUILD_BACKEND')
    scopes = {s: scope_inventory(source('requirements/local-v1-' + s + '.lock'),
                                 wheelhouses[s], direct if s == 'runtime' else ROOTS[s]) for s in SCOPES}
    # setuptools 68.1.2 build_meta.get_requires_for_build_wheel requests wheel;
    # this explicit reviewed build root is independent of runtime dependencies.
    components, dependencies = [], []
    for scope, inventory in scopes.items():
        for item in inventory['archives']:
            ref = scope + ':' + item['name']
            components.append({'type': 'library', 'bom-ref': ref, 'name': item['name'],
                               'version': item['version'],
                               'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                               'purl': 'pkg:pypi/' + item['name'] + '@' + item['version']})
            dependencies.append({'ref': ref, 'dependsOn': [scope + ':' + e['to'] for e in inventory['edges'] if e['from'] == item['name']]})
    result = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
              'metadata': {'properties': [{'name': 'avuhz:status', 'value': 'NOT CERTIFIED'},
                                         {'name': 'avuhz:source-sha', 'value': sha},
                                         {'name': 'avuhz:evidence', 'value': 'UNSIGNED_CANDIDATE'}]},
              'components': components, 'dependencies': dependencies,
              'properties': [{'name': 'avuhz:inventory', 'value': json.dumps(scopes, sort_keys=True)},
                             {'name': 'avuhz:target', 'value': 'CPython 3.12.3 Linux x86_64 glibc 2.39'},
                             {'name': 'avuhz:missing-proof', 'value': 'human SBOM review; exact-merge CI/PG17; signed provenance; immutable retention; explicit human Gate10 approval'}]}
    guards.clean(root, sha)
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii')


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "PYTHON_LOCK_CANDIDATE_REJECTED\n")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    for scope in SCOPES:
        parser.add_argument('--' + scope + '-wheels', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # Lexical and descriptor checks reject traversal and symlinks; never overwrite.
        if args.output.is_relative_to(args.repo):
            raise ValueError('OUTPUT_INSIDE_SOURCE')
        fd, _ = guards.safe_parent(args.output)
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                raise ValueError('PRIVATE_OUTPUT_DIRECTORY_REQUIRED')
        finally:
            os.close(fd)
        data = build(args.repo, args.source_sha, {s: getattr(args, s + '_wheels') for s in SCOPES})
        guards.write_output(args.output, data)
    except Exception:
        # Never surface filenames, dependency text, provider input or exception bodies.
        parser.exit(2, 'PYTHON_LOCK_CANDIDATE_REJECTED\n')
    print('UNSIGNED_PYTHON_LOCK_CANDIDATE_WRITTEN: NOT CERTIFIED')


if __name__ == '__main__':
    main()
