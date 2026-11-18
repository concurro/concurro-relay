"""Assemble relocatable Sponsor or Concurro native runtimes for macOS arm64 or Linux x86-64."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

try:
    from . import notices  # imported as native.package (tests)
except ImportError:
    import notices  # run as a script

run = notices.run

SYSTEM_LIBRARIES = ('/usr/lib/', '/System/Library/')
LOAD_COMMANDS = {'LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB',
                 'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB'}
# glibc's own libraries stay with the system; every other dependency is packaged.
GLIBC_LIBRARIES = frozenset({
    'ld-linux-x86-64.so.2', 'libc.so.6', 'libm.so.6', 'libmvec.so.1', 'libpthread.so.0',
    'libdl.so.2', 'librt.so.1', 'libutil.so.1', 'libresolv.so.2', 'libanl.so.1',
})
ELF_INTERPRETER = '/lib64/ld-linux-x86-64.so.2'
HANDOFF_BINARIES = ('HandoffKeyShare', 'HandoffPartyKrrw', 'HandoffPartyKrrwPrepared',
                    'HandoffPrefix')


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
    """Copy the full library closure, make its load paths local, and sign it.

    Returns the copied libraries as (packaged path, system path) pairs.
    """
    directory = bundle / 'lib'
    queue = [(source, target, source, ()) for source, target in roots]
    targets = {source.resolve(): target for source, target in roots}
    planned = {}
    copied = []
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
                    copied.append((destination, dependency))
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
    return sorted(copied)


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


def elf_dynamic(path):
    """Read needed libraries and search paths from one ELF image's dynamic section."""
    result = {'needed': [], 'runpath': [], 'rpath': []}
    for kind, value in re.findall(r'\((NEEDED|RUNPATH|RPATH)\)[^\[]*\[([^\]]*)\]',
                                  run('readelf', '-d', '--wide', path)):
        if kind == 'NEEDED':
            result['needed'].append(value)
        else:
            result[kind.lower()].extend(value.split(':'))
    return result


def elf_resolved(path):
    """Map each library one ELF image loads to the file the build machine's loader picks."""
    resolved = {}
    for line in run('ldd', path).splitlines():
        name, arrow, location = line.strip().partition(' => ')
        if arrow and location.startswith('not found'):
            raise FileNotFoundError(f'{path}: {name} not found')
        if arrow:
            resolved[name] = Path(location.split(' (0x', 1)[0])
    return resolved


def glibc_floor(versions):
    """Return the newest glibc version that `readelf -V` output requires, ignoring weak needs."""
    floor = (2, 2, 5)
    for version, flags in re.findall(r'Name: GLIBC_([0-9.]+)\s+Flags: (\S+)', versions):
        if 'WEAK' not in flags:
            floor = max(floor, tuple(int(part) for part in version.split('.')))
    return '.'.join(map(str, floor))


def add_elf_libraries(package, roots):
    """Copy the non-glibc library closure into `native-runtime/lib` and point every image at it.

    Each packaged image gets a DT_RUNPATH of `$ORIGIN`-relative directories holding its own
    direct dependencies; DT_RUNPATH applies only to an image's direct needs. Returns the
    newest glibc version the package requires and the copied libraries, as
    (packaged path, system path) pairs.
    """
    directory = package / 'native-runtime/lib'
    targets = {source.resolve(): target for source, target in roots}
    queue = list(roots)
    planned = {}
    copied = []
    while queue:
        source, target = queue.pop()
        if target in planned:
            continue
        resolved = elf_resolved(source)
        directories = set()
        for name in elf_dynamic(source)['needed']:
            if name in GLIBC_LIBRARIES:
                continue
            if name not in resolved:
                raise FileNotFoundError(f'{source}: {name} was not resolved')
            dependency = resolved[name].resolve()
            destination = targets.get(dependency)
            if destination is None:
                destination = directory / name
                if destination.exists():
                    if destination.read_bytes() != dependency.read_bytes():
                        raise ValueError(f'library name collision: {dependency} and {destination}')
                else:
                    copy(dependency, destination)
                    copied.append((destination, dependency))
                targets[dependency] = destination
                queue.append((dependency, destination))
            directories.add(os.path.relpath(destination.parent, target.parent))
        planned[target] = sorted(directories)

    for path, directories in planned.items():
        path.chmod(path.stat().st_mode | 0o200)
        runpath = ':'.join('$ORIGIN' if entry == '.' else f'$ORIGIN/{entry}'
                           for entry in directories)
        if runpath:
            subprocess.run(['patchelf', '--set-rpath', runpath, str(path)], check=True)
        else:
            subprocess.run(['patchelf', '--remove-rpath', str(path)], check=True)
    return audit_elf_libraries(package, planned), sorted(copied)


def audit_elf_libraries(package, images):
    """Check that the package's x86-64 images load only packaged libraries or glibc.

    Returns the newest glibc version the package requires.
    """
    root = package.resolve()
    audited = {path.resolve() for path in images}
    floors = []
    for path in sorted(root.rglob('*')):
        if is_elf(path) and path.resolve() not in audited:
            raise ValueError(f'{path}: ELF image was not audited')
    for image in images:
        header = run('readelf', '-h', '-l', '--wide', image)
        if 'Class:                             ELF64' not in header or \
                'Machine:                           Advanced Micro Devices X86-64' not in header:
            raise ValueError(f'{image}: not an x86-64 ELF64 image')
        interpreter = re.search(r'Requesting program interpreter: ([^\]]+)\]', header)
        if interpreter and interpreter.group(1) != ELF_INTERPRETER:
            raise ValueError(f'{image}: interpreter {interpreter.group(1)}')
        dynamic = elf_dynamic(image)
        if dynamic['rpath']:
            raise ValueError(f'{image}: DT_RPATH remains: {dynamic["rpath"]}')
        directories = []
        for entry in dynamic['runpath']:
            if entry != '$ORIGIN' and not entry.startswith('$ORIGIN/'):
                raise ValueError(f'{image}: non-local runpath {entry}')
            directory = (image.parent / entry.removeprefix('$ORIGIN').lstrip('/')).resolve()
            if not directory.is_relative_to(root):
                raise ValueError(f'{image}: runpath {entry} escapes the package')
            directories.append(directory)
        for name in dynamic['needed']:
            if name in GLIBC_LIBRARIES:
                continue
            found = [directory / name for directory in directories if (directory / name).is_file()]
            if not found:
                raise FileNotFoundError(f'{image}: {name} is not in the package')
            if found[0].resolve() not in audited:
                raise ValueError(f'{image}: dependency {name} was not audited')
        floors.append(glibc_floor(run('readelf', '-V', '--wide', image)))
    return max(floors, key=lambda version: tuple(map(int, version.split('.'))))


def find_openssl(path):
    """The OpenSSL executable to package: `path`, or else `openssl` on PATH."""
    found = path or shutil.which('openssl')
    if not found:
        raise FileNotFoundError('openssl is not on PATH; pass --openssl')
    return Path(found).resolve()


def is_elf(path):
    """Whether `path` is a regular ELF file."""
    if path.is_symlink() or not path.is_file():
        return False
    with path.open('rb') as handle:
        return handle.read(4) == b'\x7fELF'


def runtime_images(source, runtime, library):
    """Native helper executables and libraries: (built path, packaged path) pairs.

    `library` is the shared-library suffix of the platform's emp-tool build.
    """
    images = [(source / 'DiStefano/build' / name, runtime / 'DiStefano/build' / name)
              for name in HANDOFF_BINARIES]
    images.append((source / f'DiStefano/build/emp-tool/libemp-tool{library}',
                   runtime / f'DiStefano/build/emp-tool/libemp-tool{library}'))
    images += [(source / 'MP-SPDZ' / name, runtime / 'MP-SPDZ' / name)
               for name in ('mascot-party.x', 'libSPDZ.so')]
    images.append((source / 'request-proof/target/release/handoff-request-proof',
                   runtime / 'request-proof/target/release/handoff-request-proof'))
    return images


def runtime_data(source, runtime):
    """Public circuits and programs the helpers read: (built path, packaged path) pairs."""
    data = [(source / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt',
             runtime / 'DiStefano/handoff-handshake-shares-cached-hkdf.txt')]
    data += [(source / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name,
              runtime / 'DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format' / name)
             for name in ('aes128_full.txt', 'sha-256-multiblock-aligned.txt')]
    data += [(source / 'DiStefano/src/2pc/vhdl' / name, runtime / 'DiStefano/src/2pc/vhdl' / name)
             for name in ('ModAdd256.txt', 'ModAdd384.txt', 'ModAdd521.txt')]
    data += [(source / 'MP-SPDZ/Programs' / name, runtime / 'MP-SPDZ/Programs' / name)
             for name in ('Bytecode/concurro_ectf_field-0.bc', 'Schedules/concurro_ectf_field.sch')]
    data.append((Path(__file__).with_name('openssl.cnf'), runtime.parent / 'bin/openssl.cnf'))
    return data


def assemble(args):
    """Copy role-required Rust binaries, native helpers, circuits, and libraries."""
    source = args.runtime.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    linux = platform.system() == 'Linux'
    bundle = output / 'native-runtime'
    runtime = bundle / 'runtime'
    binary = args.relay if args.role == 'sponsor' else args.verifier
    openssl = find_openssl(args.openssl)
    roots = [(binary, output / 'bin' / binary.name),
             (args.worker, bundle / 'concurro-native-worker'),
             (openssl, bundle / 'bin/openssl')]
    roots += runtime_images(source, runtime, '.so' if linux else '.dylib')
    for origin, destination in roots + runtime_data(source, runtime):
        copy(origin, destination)
    manifest = {'role': args.role}
    if linux:
        glibc, libraries = add_elf_libraries(output, roots)
        manifest['requires'] = {'glibc': glibc}
    else:
        libraries = add_libraries(bundle, roots)
    workspace = notices.RELAY / 'Cargo.toml'
    index = notices.collect(
        output, source, libraries + [(bundle / 'bin/openssl', openssl)],
        [(workspace, binary.name), (workspace, 'concurro-native-worker'),
         (source / 'request-proof/Cargo.toml', 'handoff-request-proof')])
    if args.sources:
        notices.fetch_sources(index, args.sources)
    manifest['files'] = {
        str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in output.rglob('*') if path.is_file() and not path.is_symlink()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=('sponsor', 'concurro'), required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--relay', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--openssl', help='default: openssl on PATH')
    parser.add_argument('--sources', type=Path,
                        help='download the sources of shipped copyleft libraries here')
    assemble(parser.parse_args())
