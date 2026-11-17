"""Assemble relocatable macOS arm64 Sponsor or Concurro native runtimes."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

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
    copy(binary, executable)
    worker = bundle / 'concurro-native-worker'
    copy(args.worker, worker)
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
    for name in ('Bytecode/concurro_ectf_field-0.bc',
                 'Schedules/concurro_ectf_field.sch'):
        copy(source / 'MP-SPDZ/Programs' / name, runtime / 'MP-SPDZ/Programs' / name)
    copy(source / 'request-proof/target/release/handoff-request-proof',
         runtime / 'request-proof/target/release/handoff-request-proof')
    openssl = Path(args.openssl).resolve()
    copy(openssl, bundle / 'bin/openssl')
    add_libraries(bundle, [executable, worker, bundle / 'bin/openssl',
                           runtime / 'DiStefano/build/HandoffKeyShare',
                           runtime / 'DiStefano/build/HandoffPartyKrrw',
                           runtime / 'DiStefano/build/HandoffPrefix',
                           runtime / 'DiStefano/build/emp-tool/libemp-tool.dylib',
                           runtime / 'MP-SPDZ/mascot-party.x', runtime / 'MP-SPDZ/libSPDZ.so',
                           runtime / 'request-proof/target/release/handoff-request-proof'])
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
