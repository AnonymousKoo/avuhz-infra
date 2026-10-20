#!/usr/bin/env python3
"""Offline observed-byte inventory; never a release certificate or trusted SBOM."""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import struct
import tomllib
import zipfile
from email.parser import BytesParser

MISSING = [
    'complete Python hash locked transitive dependency graph (including build dependencies)',
    'approved SBOM', 'authenticated exact-merge CI/PG17 proof',
    'signed provenance', 'immutable retention proof', 'explicit human Gate10 approval',
]


def safe_parent(path):
    """Walk from /tmp using descriptors: reject aliases, traversal and symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.parts[:2] != ('/', 'tmp') or len(path.parts) < 3:
        raise ValueError('UNSAFE_PATH')
    fd = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[2:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


WHEEL_INPUT_LIMIT = 32 * 1024 * 1024
WHEEL_ENTRY_LIMIT = 64 * 1024 * 1024
WHEEL_TOTAL_LIMIT = 128 * 1024 * 1024
WHEEL_COUNT_LIMIT = 1024


def read(path, limit=None):
    parent, name = safe_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('NONREGULAR_INPUT')
            if limit is not None and os.fstat(stream.fileno()).st_size > limit:
                raise ValueError('INPUT_TOO_LARGE')
            data = stream.read() if limit is None else stream.read(limit + 1)
            if limit is not None and len(data) > limit:
                raise ValueError('INPUT_TOO_LARGE')
            return data
    finally:
        os.close(parent)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    if args not in (('rev-parse', '--show-object-format'),
                    ('rev-parse', '--show-toplevel'), ('rev-parse', 'HEAD'),
                    ('ls-tree', '-r', '-z', '-l', 'HEAD')):
        raise ValueError('UNSAFE_GIT_OPERATION')
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1',
               GIT_TERMINAL_PROMPT='0', GIT_ALLOW_PROTOCOL='',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    return subprocess.run(['git', '--no-optional-locks', '--no-replace-objects',
                           '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                           '-C', str(root), *args], env=env,
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def clean(root, sha):
    # Only raw object operations: never status/diff/index or worktree conversion.
    parent, name = safe_parent(root)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.close(fd)
    finally:
        os.close(parent)
    object_format = git(root, 'rev-parse', '--show-object-format').decode().strip()
    if object_format not in ('sha1', 'sha256'):
        raise ValueError('UNSUPPORTED_OBJECT_FORMAT')
    if not re.fullmatch('[0-9a-f]{%d}' % (40 if object_format == 'sha1' else 64), sha):
        raise ValueError('INVALID_SHA')
    if git(root, 'rev-parse', '--show-toplevel').decode().strip() != str(root):
        raise ValueError('REPOSITORY_ROOT_REQUIRED')
    if git(root, 'rev-parse', 'HEAD').decode().strip() != sha:
        raise ValueError('SOURCE_PIN_MISMATCH')
    tracked = {}
    for row in git(root, 'ls-tree', '-r', '-z', '-l', 'HEAD').split(b'\0')[:-1]:
        header, raw_path = row.split(b'\t', 1)
        mode, kind, oid, size = header.split()
        path = raw_path.decode('ascii')
        parts = path.split('/')
        if (not path or any(part in ('', '.', '..', '.git') for part in parts)
                or not re.fullmatch(r'[A-Za-z0-9._/+-]+', path) or path in tracked):
            raise ValueError('AMBIGUOUS_SOURCE_PATH')
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise ValueError('NONREGULAR_TRACKED_SOURCE')
        tracked[path] = (mode, oid.decode(), int(size))
    observed = set()
    directories = {path[:i] for path in tracked for i, char in enumerate(path) if char == '/'}

    def walk(directory_fd, prefix=''):
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                path = prefix + entry.name
                if path == '.git':
                    if entry.is_symlink():
                        raise ValueError('UNSAFE_GIT_POINTER')
                    continue
                if entry.name == '.git':
                    raise ValueError('NESTED_GIT')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if path not in directories:
                        raise ValueError('DIRTY_UNTRACKED_DIRECTORY')
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        walk(child, path + '/')
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and path in tracked:
                    mode, oid, size = tracked[path]
                    if (info.st_mode & 0o111) != (0o111 if mode == b'100755' else 0):
                        raise ValueError('SOURCE_MODE_MISMATCH')
                    data = read(root / path)
                    native = hashlib.new(object_format)
                    native.update(b'blob ' + str(len(data)).encode() + b'\0')
                    native.update(data)
                    if len(data) != size or native.hexdigest() != oid:
                        raise ValueError('DIRTY_SOURCE_BYTES_MISMATCH')
                    observed.add(path)
                else:
                    raise ValueError('DIRTY_OR_NONREGULAR_SOURCE')
    parent, name = safe_parent(root)
    try:
        root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            walk(root_fd)
        finally:
            os.close(root_fd)
    finally:
        os.close(parent)
    if observed != set(tracked):
        raise ValueError('DIRTY_MISSING_SOURCE')
    return tracked


def pins(values):
    result = {}
    for value in values:
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9,._-]+\])?==([0-9]+(?:\.[0-9]+)*(?:[a-z]+[0-9]+)?)', value)
        if not match:
            raise ValueError('EXACT_DIRECT_PIN_REQUIRED')
        name, extras, version = match.groups()
        name = re.sub('[-_.]+', '-', name).lower()
        if name in result:
            raise ValueError('DUPLICATE_DEPENDENCY')
        result[name] = {'version': version, 'extras': sorted((extras or '[]')[1:-1].lower().split(',')) if extras else []}
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('INVALID_JSON_CONSTANT')


def npm(data):
    lock = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(lock, dict) or type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] != 3:
        raise ValueError('INVALID_NPM_LOCK')
    packages = lock.get('packages')
    if not isinstance(packages, dict) or not isinstance(packages.get(''), dict):
        raise ValueError('INVALID_NPM_PACKAGES')
    rows = []
    for location, item in sorted(packages.items()):
        if not isinstance(item, dict):
            raise ValueError('INVALID_NPM_ENTRY')
        if not location:
            continue
        if not location.startswith('node_modules/') or '..' in location.split('/') or item.get('link'):
            raise ValueError('UNSUPPORTED_NPM_ENTRY')
        version, integrity = item.get('version'), item.get('integrity')
        if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
            raise ValueError('INVALID_NPM_VERSION')
        if not isinstance(integrity, str) or not re.fullmatch(r'sha512-[A-Za-z0-9+/]+={0,2}', integrity):
            raise ValueError('INVALID_NPM_INTEGRITY')
        if len(base64.b64decode(integrity[7:], validate=True)) != 64:
            raise ValueError('INVALID_NPM_INTEGRITY')
        rows.append({'location': location, 'version': version, 'declared_integrity': integrity})
    return {'classification': 'DECLARED_METADATA_ONLY', 'archives_verified': False, 'packages': rows}


def wheel_headers(data):
    """Bound central directory metadata before ZipFile allocates member objects.

    ZIP64, split archives, trailing bytes and unsupported compression fail closed.
    """
    if len(data) > WHEEL_INPUT_LIMIT:
        raise ValueError('WHEEL_INPUT_TOO_LARGE')
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise zipfile.BadZipFile('missing end record')
    _, disk, start_disk, disk_count, count, length, offset, comment = struct.unpack_from('<4s4H2IH', data, end)
    if (disk or start_disk or disk_count != count or not 0 < count <= WHEEL_COUNT_LIMIT
            or end + 22 + comment != len(data) or offset + length != end):
        raise ValueError('INVALID_WHEEL_DIRECTORY')
    cursor, total = offset, 0
    for _ in range(count):
        if cursor + 46 > end:
            raise ValueError('INVALID_WHEEL_DIRECTORY')
        fields = struct.unpack_from('<4s6H3I5H2I', data, cursor)
        if fields[0] != b'PK\x01\x02' or fields[4] not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or fields[3] & 1:
            raise ValueError('UNSUPPORTED_WHEEL_COMPRESSION')
        size = fields[9]
        total += size
        if size > WHEEL_ENTRY_LIMIT or total > WHEEL_TOTAL_LIMIT:
            raise ValueError('WHEEL_SIZE_LIMIT')
        cursor += 46 + sum(fields[10:13])
        if cursor > end:
            raise ValueError('INVALID_WHEEL_DIRECTORY')
    if cursor != end:
        raise ValueError('INVALID_WHEEL_DIRECTORY')


def wheel_info(data, project):
    """Bounded internal RECORD consistency; no claim of origin authenticity."""
    wheel_headers(data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len({name.casefold() for name in names}) != len(names) or not names:
            raise ValueError('INVALID_WHEEL')
        total = 0
        for entry in archive.infolist():
            parts = entry.filename.split('/')
            if (any(part in ('', '.', '..') for part in parts)
                    or not re.fullmatch(r'[A-Za-z0-9._/+-]+', entry.filename)
                    or entry.orig_filename != entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('UNSAFE_WHEEL_MEMBER')
            total += entry.file_size
            if entry.file_size > WHEEL_ENTRY_LIMIT or total > WHEEL_TOTAL_LIMIT:
                raise ValueError('WHEEL_SIZE_LIMIT')
        # Also deny a file used as a directory prefix.
        if any('/'.join(n.split('/')[:i]) in names for n in names for i in range(1, len(n.split('/')))):
            raise ValueError('WHEEL_PATH_COLLISION')
        consumed = 0

        def chunks(name, limit=WHEEL_ENTRY_LIMIT):
            nonlocal consumed
            actual = 0
            with archive.open(name) as member:
                while True:
                    block = member.read(64 * 1024)
                    if not block:
                        break
                    actual += len(block)
                    consumed += len(block)
                    if actual > limit or consumed > WHEEL_TOTAL_LIMIT:
                        raise ValueError('WHEEL_ACTUAL_SIZE_LIMIT')
                    yield block

        records = [n for n in names if n.endswith('.dist-info/RECORD')]
        if len(records) != 1:
            raise ValueError('WHEEL_RECORD_REQUIRED')
        record = records[0]
        prefix = record.rsplit('/', 1)[0]
        # Parsing metadata/CSV has a smaller allocation budget than payload hashing.
        meta = BytesParser().parsebytes(b''.join(chunks(prefix + '/METADATA', 1024 * 1024)))
        if meta['Name'] != project['name'] or meta['Version'] != project['version'] or prefix + '/WHEEL' not in names:
            raise ValueError('WHEEL_PROJECT_MISMATCH')
        seen = set()
        for row in csv.reader(io.StringIO(b''.join(chunks(record, 1024 * 1024)).decode())):
            if len(row) != 3 or row[0] in seen or row[0] not in names:
                raise ValueError('INVALID_WHEEL_RECORD')
            name, claimed, size = row
            seen.add(name)
            if name == record:
                if claimed or size:
                    raise ValueError('INVALID_WHEEL_SELF_RECORD')
                continue
            hashed, actual_size = hashlib.sha256(), 0
            for block in chunks(name):
                hashed.update(block)
                actual_size += len(block)
            actual = base64.urlsafe_b64encode(hashed.digest()).decode().rstrip('=')
            if claimed != 'sha256=' + actual or size != str(actual_size):
                raise ValueError('WHEEL_RECORD_MISMATCH')
        if seen != set(names):
            raise ValueError('INCOMPLETE_WHEEL_RECORD')
    return {'classification': 'OBSERVED_UNAUTHENTICATED_ARCHIVE', 'sha256': digest(data), 'record_consistent': True}


def build(root, sha, wheel=None):
    root = Path(root)
    tracked = clean(root, sha)
    required = {'requirements.txt', 'pyproject.toml', 'package-lock.json'}
    if not required.issubset(tracked):
        raise ValueError('MISSING_MANIFEST')
    paths = sorted(required | {p for p in tracked if p.startswith(('src/', 'contracts/schemas/'))})
    files = {}
    for path in paths:
        data = read(root / path)
        files[path] = data
    project = tomllib.loads(files['pyproject.toml'].decode())['project']
    requirements = [line.strip() for line in files['requirements.txt'].decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    direct = pins(requirements)
    if direct != pins(project['dependencies']):
        raise ValueError('DIRECT_PIN_MISMATCH')
    archive = wheel_info(read(wheel, WHEEL_INPUT_LIMIT), project) if wheel else {'classification': 'MISSING'}
    result = {'schema_version': 'avuhz.local-v1.supply-chain-candidate.v1',
              'status': 'NOT CERTIFIED', 'classification': 'UNSIGNED_INVENTORY_SBOM_CANDIDATE',
              'source_sha': sha, 'python_direct_pins': direct,
              'python_dependency_scope': 'DECLARED_DIRECT_ONLY',
              'npm': npm(files['package-lock.json']), 'wheel': archive,
              'files': {p: {'sha256': digest(data), 'size': len(data)} for p, data in files.items()},
              'schemas': 'OBSERVED' if any(p.startswith('contracts/schemas/') for p in files) else 'MISSING',
              'missing': MISSING + ([] if wheel else ['real wheel archive'])}
    clean(root, sha)
    return (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def write_output(path, data):
    parent, name = safe_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--wheel', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        # Output must be external to the checkout and may never overwrite anything.
        if args.output.is_relative_to(args.repo):
            raise ValueError('OUTPUT_INSIDE_SOURCE')
        data = build(args.repo, args.source_sha, args.wheel)
        write_output(args.output, data)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, zipfile.BadZipFile, csv.Error):
        parser.exit(2, 'CANDIDATE_REJECTED\n')
    print('UNSIGNED_CANDIDATE_WRITTEN: NOT CERTIFIED')


if __name__ == '__main__':
    main()
