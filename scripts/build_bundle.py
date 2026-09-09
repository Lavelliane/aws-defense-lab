#!/usr/bin/env python3
"""Build a deterministic, allowlisted runtime ZIP. Never package state or credentials."""
from pathlib import Path
import hashlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def build():
    dest = ROOT / '.build/lab.zip'
    dest.parent.mkdir(exist_ok=True)
    paths = []
    for directory in ('app', 'scenarios', 'threat-intel', 'wazuh', 'scripts'):
        for path in (ROOT / directory).rglob('*'):
            if not path.is_file() or path.is_symlink() or '__pycache__' in path.parts:
                continue
            if path.suffix not in ('.py', '.sh', '.json', '.xml', '.txt', '.in', '.csv'):
                continue
            paths.append(path)
    with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    print(f'Runtime bundle: {len(paths)} files; SHA256 {hashlib.sha256(dest.read_bytes()).hexdigest()}')
    return dest

if __name__ == '__main__':
    build()
