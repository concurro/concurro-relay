"""Assemble relocatable macOS arm64 Sponsor or Concurro native runtimes."""

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYTHON = Path('/Library/Frameworks/Python.framework/Versions/3.13')


def copy(source, destination):
    """Copy one existing runtime file without carrying source-tree siblings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def dependencies(path):
    """List non-system Mach-O dependencies of an executable or dylib."""
    result = subprocess.run(['otool', '-L', str(path)], check=True, capture_output=True, text=True)
    found = set()
    for line in result.stdout.splitlines()[1:]:
        name = line.strip().split(' (', 1)[0]
        if name.startswith(('/opt/homebrew/', '/Library/Frameworks/')):
            found.add(Path(name))
    return found


def add_libraries(bundle, roots):
    """Bundle every third-party dynamic library reachable from runtime code."""
    directory = bundle / 'lib'
    queue = list(roots)
    seen = set()
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        for source in dependencies(path):
            target = directory / source.name
            if not target.exists():
                copy(source, target)
                queue.append(target)


def copy_python_framework(bundle):
    """Preserve upstream's signed standard library without installed extras."""
    destination = bundle / 'Python.framework/Versions/3.13'
    resources = PYTHON / '_CodeSignature/CodeResources'
    sealed = plistlib.loads(resources.read_bytes())['files2']
    for name in sorted(sealed):
        source = PYTHON / name
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(source.readlink())
        elif source.is_dir():
            shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)
    copy(PYTHON / 'Python', destination / 'Python')
    copy(resources, destination / '_CodeSignature/CodeResources')
    (bundle / 'libexec').mkdir(parents=True, exist_ok=True)
    subprocess.run(['clang', '-arch', 'arm64', '-O2', str(HERE / 'python_launcher.c'),
                    '-o', str(bundle / 'libexec/python3.13')], check=True)


def assemble(args):
    """Copy only role-required binaries, Python, public circuits, and libraries."""
    source = args.runtime.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    bundle = output / 'native-runtime'
    runtime = bundle / 'runtime'
    binary = args.relay if args.role == 'sponsor' else args.verifier
    executable = output / 'bin' / binary.name
    copy(binary, executable)
    for name in ('HandoffKeyShare', 'HandoffPartyKrrw', 'HandoffPrefix'):
        copy(source / 'DiStefano/build' / name, runtime / 'DiStefano/build' / name)
    copy(source / 'DiStefano/build/emp-tool/libemp-tool.dylib',
         runtime / 'DiStefano/build/emp-tool/libemp-tool.dylib')
    copy(source / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt',
         runtime / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt')
    for name in ('aes128_full.txt', 'sha-256-multiblock-aligned.txt'):
        copy(source / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name,
             runtime / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name)
    for name in ('ModAdd256.txt', 'ModAdd384.txt', 'ModAdd521.txt'):
        copy(source / 'DiStefano/src/2pc/vhdl' / name,
             runtime / 'DiStefano/src/2pc/vhdl' / name)
    for name in ('mascot-party.x', 'libSPDZ.so'):
        copy(source / 'MP-SPDZ' / name, runtime / 'MP-SPDZ' / name)
    shutil.copytree(source / 'MP-SPDZ/Programs', runtime / 'MP-SPDZ/Programs')
    copy(source / 'request-proof/target/release/handoff-request-proof',
         runtime / 'request-proof/target/release/handoff-request-proof')
    shutil.copytree(HERE / 'worker', bundle / 'worker', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    copy(HERE / 'tunnel.py', bundle / 'tunnel.py')
    copy_python_framework(bundle)
    for name in ('cryptography', 'cffi', 'pycparser', '_yaml', 'yaml'):
        path = source / 'pydeps' / name
        if path.exists():
            shutil.copytree(path, bundle / 'pydeps' / name,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for extension in (source / 'pydeps').glob('*.so'):
        copy(extension, bundle / 'pydeps' / extension.name)
    shutil.copytree(args.hpack / 'hpack', bundle / 'pydeps/hpack',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    openssl = Path(args.openssl).resolve()
    copy(openssl, bundle / 'bin/openssl')
    add_libraries(bundle, [executable, bundle / 'libexec/python3.13',
                           bundle / 'bin/openssl',
                           runtime / 'DiStefano/build/HandoffKeyShare',
                           runtime / 'DiStefano/build/HandoffPartyKrrw',
                           runtime / 'DiStefano/build/HandoffPrefix',
                           runtime / 'DiStefano/build/emp-tool/libemp-tool.dylib',
                           runtime / 'MP-SPDZ/mascot-party.x', runtime / 'MP-SPDZ/libSPDZ.so',
                           runtime / 'request-proof/target/release/handoff-request-proof',
                           bundle / 'Python.framework/Versions/3.13/lib/python3.13/lib-dynload/_ssl.cpython-313-darwin.so'])
    wrapper = bundle / 'python'
    wrapper.write_text('''#!/bin/sh
set -eu
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONHOME="$bundle/Python.framework/Versions/3.13"
export PYTHONPATH="$bundle/worker:$bundle/pydeps:$bundle"
export DYLD_LIBRARY_PATH="$bundle/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export PATH="$bundle/bin:/usr/bin:/bin"
exec "$bundle/libexec/python3.13" "$@"
''')
    wrapper.chmod(0o755)
    files = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in output.rglob('*') if path.is_file() and not path.is_symlink()}
    (output / 'manifest.json').write_text(json.dumps({'role': args.role, 'files': files}, indent=2))
    print(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=('sponsor', 'concurro'), required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--relay', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--hpack', type=Path, required=True)
    parser.add_argument('--openssl', default='/opt/homebrew/bin/openssl')
    assemble(parser.parse_args())
