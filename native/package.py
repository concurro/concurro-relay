"""Assemble relocatable macOS arm64 Sponsor or Concurro native runtimes."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

SYSTEM_LIBRARIES = ('/usr/lib/', '/System/Library/')
LOAD_COMMANDS = {'LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB',
                 'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB'}


def copy(source, destination):
    """Copy one existing runtime file without carrying source-tree siblings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def load_commands(path):
    """Read dependency, identity and search-path commands from one Mach-O image."""
    output = subprocess.run(['otool', '-l', str(path)], check=True,
                            capture_output=True, text=True).stdout
    result = {'loads': [], 'id': None, 'rpaths': []}
    for block in output.split('Load command ')[1:]:
        lines = [line.strip() for line in block.splitlines()]
        command = next((line.split(' ', 1)[1] for line in lines
                        if line.startswith('cmd ')), None)
        if command in LOAD_COMMANDS | {'LC_ID_DYLIB'}:
            name = next(line[5:].split(' (offset ', 1)[0] for line in lines
                        if line.startswith('name '))
            if command == 'LC_ID_DYLIB':
                result['id'] = name
            else:
                result['loads'].append(name)
        elif command == 'LC_RPATH':
            result['rpaths'].append(next(line[5:].split(' (offset ', 1)[0]
                                         for line in lines if line.startswith('path ')))
    return result


def source_path(name, image, executable):
    """Expand a source image's absolute or loader-relative path."""
    if name.startswith('/'):
        return Path(name)
    if name.startswith('@loader_path/'):
        return image.parent / name[len('@loader_path/'):]
    if name.startswith('@executable_path/'):
        return executable.parent / name[len('@executable_path/'):]
    raise ValueError(f'unsupported source path {name} in {image}')


def source_dependency(name, image, executable, rpaths):
    """Resolve a source load using local and inherited runpaths."""
    if name.startswith(SYSTEM_LIBRARIES):
        return None
    if name.startswith('@rpath/'):
        candidates = [base / name[len('@rpath/'):] for base in rpaths]
    else:
        candidates = [source_path(name, image, executable)]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(f'{image}: {name} not found in {candidates}')


def add_libraries(bundle, roots):
    """Copy the full library closure, make its load paths local, and sign it."""
    directory = bundle / 'lib'
    queue = [(source, target, source, ()) for source, target in roots]
    targets = {source.resolve(): target for source, target in roots}
    planned = {}
    while queue:
        source, target, executable, inherited_rpaths = queue.pop()
        if target in planned:
            continue
        commands = load_commands(source)
        rpaths = tuple(source_path(rpath, source, executable) for rpath in commands['rpaths'])
        rpaths += inherited_rpaths
        changes = []
        for name in commands['loads']:
            dependency = source_dependency(name, source, executable, rpaths)
            if dependency is None:
                continue
            destination = targets.get(dependency)
            if destination is None:
                destination = directory / dependency.name
                if destination.exists():
                    if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(
                            dependency.read_bytes()).digest():
                        raise ValueError(f'library filename collision: {dependency} and {destination}')
                else:
                    copy(dependency, destination)
                targets[dependency] = destination
                queue.append((dependency, destination, executable, rpaths))
            local = '@loader_path/' + os.path.relpath(destination, target.parent)
            if name != local:
                changes.append((name, local))
        planned[target] = (commands, changes)

    for path, (commands, changes) in planned.items():
        arguments = []
        for old, new in changes:
            arguments.extend(['-change', old, new])
        if commands['id'] is not None:
            local_id = '@loader_path/' + path.name
            if commands['id'] != local_id:
                arguments.extend(['-id', local_id])
        for rpath in commands['rpaths']:
            arguments.extend(['-delete_rpath', rpath])
        if arguments:
            path.chmod(path.stat().st_mode | 0o200)
            subprocess.run(['install_name_tool', *arguments, str(path)], check=True)
        subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                        str(path)], check=True, capture_output=True)
    audit_libraries(bundle, planned)


def audit_libraries(bundle, images):
    """Check that packaged images load signed code only from the bundle or macOS."""
    audited = {path.resolve() for path in images}
    for image in images:
        commands = load_commands(image)
        if commands['rpaths']:
            raise ValueError(f'{image}: rpaths remain: {commands["rpaths"]}')
        if commands['id'] and commands['id'] != '@loader_path/' + image.name:
            raise ValueError(f'{image}: non-local dylib identity {commands["id"]}')
        for name in commands['loads']:
            if name.startswith(SYSTEM_LIBRARIES):
                continue
            if not name.startswith('@loader_path/'):
                raise ValueError(f'{image}: non-local dependency {name}')
            dependency = (image.parent / name[len('@loader_path/'):]).resolve()
            if not dependency.is_relative_to(bundle.resolve()) or not dependency.is_file():
                raise FileNotFoundError(f'{image}: dependency {name} escapes the bundle')
            if dependency not in audited:
                raise ValueError(f'{image}: dependency {name} was not audited')
        subprocess.run(['codesign', '--verify', '--strict', str(image)], check=True,
                       capture_output=True)
        archs = subprocess.run(['lipo', '-archs', str(image)], check=True,
                               capture_output=True, text=True).stdout.split()
        if 'arm64' not in archs:
            raise ValueError(f'{image}: arm64 code is unavailable')


def assemble(args):
    """Copy role-required Rust binaries, native helpers, circuits, and libraries."""
    source = args.runtime.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    bundle = output / 'native-runtime'
    runtime = bundle / 'runtime'
    binary = args.relay if args.role == 'sponsor' else args.verifier
    executable = output / 'bin' / binary.name
    worker = bundle / 'concurro-native-worker'
    openssl = Path(args.openssl).resolve()
    roots = [(binary, executable), (args.worker, worker),
             (openssl, bundle / 'bin/openssl')]
    for name in ('HandoffKeyShare', 'HandoffPartyKrrw',
                 'HandoffPartyKrrwPrepared', 'HandoffPrefix'):
        roots.append((source / 'DiStefano/build' / name,
                      runtime / 'DiStefano/build' / name))
    roots.append((source / 'DiStefano/build/emp-tool/libemp-tool.dylib',
                  runtime / 'DiStefano/build/emp-tool/libemp-tool.dylib'))
    for name in ('mascot-party.x', 'libSPDZ.so'):
        roots.append((source / 'MP-SPDZ' / name, runtime / 'MP-SPDZ' / name))
    roots.append((source / 'request-proof/target/release/handoff-request-proof',
                  runtime / 'request-proof/target/release/handoff-request-proof'))
    for origin, destination in roots:
        copy(origin, destination)
    copy(source / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt',
         runtime / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt')
    for name in ('aes128_full.txt', 'sha-256-multiblock-aligned.txt'):
        copy(source / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name,
             runtime / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name)
    for name in ('ModAdd256.txt', 'ModAdd384.txt', 'ModAdd521.txt'):
        copy(source / 'DiStefano/src/2pc/vhdl' / name,
             runtime / 'DiStefano/src/2pc/vhdl' / name)
    for name in ('Bytecode/concurro_ectf_field-0.bc',
                 'Schedules/concurro_ectf_field.sch'):
        copy(source / 'MP-SPDZ/Programs' / name, runtime / 'MP-SPDZ/Programs' / name)
    copy(Path(__file__).with_name('openssl.cnf'), bundle / 'bin/openssl.cnf')
    add_libraries(bundle, roots)
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
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--openssl', default='/opt/homebrew/bin/openssl')
    assemble(parser.parse_args())
