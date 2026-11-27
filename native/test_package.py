"""Exercise macOS and Linux bundle relocation through transitive dynamic-library chains."""

import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from native import notices, package

# `readelf -V` version needs: a strong GLIBC_2.34, a weak GLIBC_2.39, and a libstdc++ version.
VERSION_NEEDS = """\
Version needs section '.gnu.version_r' contains 3 entries:
 Addr: 0x0000000000000a10  Offset: 0x00000a10  Link: 7 (.dynstr)
  000000: Version: 1  File: libstdc++.so.6  Cnt: 1
  0x0010:   Name: GLIBCXX_3.4.32  Flags: none  Version: 4
  0x0020: Version: 1  File: libc.so.6  Cnt: 2
  0x0030:   Name: GLIBC_2.34  Flags: none  Version: 3
  0x0040:   Name: GLIBC_2.39  Flags: WEAK  Version: 2
"""


@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64',
                     'requires macOS arm64 loader tools')
class PackageTests(unittest.TestCase):
    """Check the package loader behavior with generated, non-production code."""

    def test_relocated_transitive_libraries(self):
        """Resolve source siblings and inherited runpaths before relocation."""
        with tempfile.TemporaryDirectory(prefix='concurro-package-test-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'leaf.c').write_text('int leaf(void) { return 7; }\n')
            (source / 'child.c').write_text(
                'int leaf(void); int child(void) { return leaf(); }\n')
            (source / 'main.c').write_text(
                'int child(void); int main(void) { return child() == 7 ? 0 : 1; }\n')
            leaf = source / 'libleaf.dylib'
            child = source / 'libchild.dylib'
            main = source / 'client'
            subprocess.run(['clang', '-arch', 'arm64', '-dynamiclib',
                            str(source / 'leaf.c'), '-install_name',
                            '@rpath/libleaf.dylib', '-o', str(leaf)], check=True)
            subprocess.run(['clang', '-arch', 'arm64', '-dynamiclib',
                            str(source / 'child.c'), '-L', str(source), '-lleaf',
                            '-install_name', '@loader_path/libchild.dylib',
                            '-o', str(child)], check=True)
            subprocess.run(['clang', '-arch', 'arm64', str(source / 'main.c'),
                            '-L', str(source), '-lchild', '-Wl,-rpath,' + str(source),
                            '-o', str(main)], check=True)
            self.assertIn('@loader_path/libchild.dylib', package.load_commands(main)['loads'])
            self.assertIn('@rpath/libleaf.dylib', package.load_commands(child)['loads'])

            bundle = root / 'package/native-runtime'
            executable = bundle / 'bin/client'
            package.copy(main, executable)
            package.add_libraries(bundle, [(main, executable)])
            shutil.move(source, root / 'hidden source')
            self.assertFalse(source.exists())
            relocated = root / 'relocated package'
            shutil.move(root / 'package', relocated)
            subprocess.run([str(relocated / 'native-runtime/bin/client')], check=True,
                           env={'PATH': '/usr/bin:/bin',
                                'DYLD_LIBRARY_PATH': str(root / 'missing')})


class GlibcFloorTests(unittest.TestCase):
    """Derive the glibc baseline from ELF version needs."""

    def test_weak_needs_do_not_raise_the_floor(self):
        """A weak GLIBC_2.39 need is optional at load time; the strong 2.34 is the floor."""
        self.assertEqual(package.glibc_floor(VERSION_NEEDS), '2.34')
        self.assertEqual(package.glibc_floor(VERSION_NEEDS.replace('WEAK', 'none')), '2.39')
        self.assertEqual(package.glibc_floor(''), '2.2.5')


class NoticeTests(unittest.TestCase):
    """Record third-party notices and source provenance."""

    def test_native_checkouts(self):
        """Each git checkout gets its URL, commit, overlays and license files, if it has any."""
        with tempfile.TemporaryDirectory(prefix='concurro-native-notice-test-') as temporary:
            runtime = Path(temporary) / 'runtime'
            for name, files in (('DiStefano', {'LICENSE': 'MPL'}),
                                ('DiStefano/src/emp-tool', {'LICENSE': 'MIT'}),
                                ('MP-SPDZ', {}), ('MP-SPDZ/deps/kit', {'ref/LICENSE': 'BSD'})):
                repository = runtime / name
                repository.mkdir(parents=True)
                for file, text in {'README': name, **files}.items():
                    (repository / file).parent.mkdir(parents=True, exist_ok=True)
                    (repository / file).write_text(text)
                for command in (['init', '-q'], ['add', '.'],
                                ['-c', 'user.name=t', '-c', 'user.email=t@invalid', '-c',
                                 'commit.gpgsign=false', 'commit', '-qm', name],
                                ['remote', 'add', 'origin', f'https://example.invalid/{name}']):
                    subprocess.run(['git', *command], cwd=repository, check=True)
            licenses = Path(temporary) / 'licenses'
            entries = {entry['name']: entry for entry in notices.native_notices(licenses, runtime)}
            self.assertEqual(set(entries), {'DiStefano', 'DiStefano/src/emp-tool', 'MP-SPDZ',
                                            'MP-SPDZ/deps/kit'})
            self.assertEqual(entries['DiStefano']['url'], 'https://example.invalid/DiStefano')
            self.assertRegex(entries['DiStefano']['commit'], r'^[0-9a-f]{40}$')
            self.assertIn('native/sources/DiStefano', entries['DiStefano']['modified_by'])
            self.assertEqual(entries['DiStefano']['notices'], ['native/DiStefano/LICENSE'])
            self.assertEqual(entries['MP-SPDZ']['notices'], [])
            self.assertEqual(entries['MP-SPDZ/deps/kit']['notices'],
                             ['native/MP-SPDZ/deps/kit/LICENSE'])
            self.assertEqual((licenses / 'native/DiStefano/LICENSE').read_text(), 'MPL')

    @unittest.skipUnless(shutil.which('cargo') and (notices.RELAY / 'upstream/tlsn').is_dir(),
                         'requires cargo and scripts/upstream.sh')
    def test_rust_crates(self):
        """The relay's crates come with license files and pinned sources, no local paths."""
        with tempfile.TemporaryDirectory(prefix='concurro-rust-notice-test-') as temporary:
            licenses = Path(temporary) / 'licenses'
            entries = notices.rust_notices(
                licenses, [(notices.RELAY / 'Cargo.toml', 'concurro-relay')],
                {notices.RELAY / 'upstream'})
            crates = {entry['name']: entry for entry in entries}
            self.assertNotIn('concurro-relay-protocol', crates)
            self.assertTrue(crates['tokio']['source'].startswith('registry+'))
            self.assertTrue(crates['tokio']['notices'])
            self.assertTrue(all((licenses / file).is_file() for entry in entries
                                for file in entry['notices']))
            self.assertEqual(crates['tlsn-core']['source'],
                             'git+https://github.com/tlsnotary/tlsn#'
                             '40a069565a2eaecbb5e691dbc634be20e8498daf')
            self.assertEqual(crates['tlsn-core']['modified_by'], ['patches/tlsn'])
            self.assertNotIn(str(Path.home()), json.dumps(entries))

    def test_download_checks_sha256(self):
        """A source download is kept only if it matches the recorded SHA-256."""
        with tempfile.TemporaryDirectory(prefix='concurro-download-test-') as temporary:
            origin = Path(temporary) / 'gmp-6.3.0.tar.xz'
            origin.write_bytes(b'source')
            digest = hashlib.sha256(b'source').hexdigest()
            notices.download(origin.as_uri(), digest, Path(temporary) / 'kept')
            self.assertEqual((Path(temporary) / 'kept').read_bytes(), b'source')
            with self.assertRaisesRegex(ValueError, 'expected 0+'):
                notices.download(origin.as_uri(), '0' * 64, Path(temporary) / 'refused')
            self.assertFalse((Path(temporary) / 'refused').exists())

    @unittest.skipUnless(sys.platform == 'darwin' and Path('/opt/homebrew/opt/gmp').is_dir(),
                         'requires Homebrew gmp on macOS')
    def test_homebrew_keg(self):
        """A Homebrew dylib maps to its keg's formula, license files and checksummed source."""
        with tempfile.TemporaryDirectory(prefix='concurro-homebrew-notice-test-') as temporary:
            library = Path('/opt/homebrew/opt/gmp/lib/libgmp.10.dylib').resolve()
            package_root = Path(temporary) / 'package'
            packaged = package_root / 'native-runtime/lib/libgmp.10.dylib'
            entry, = notices.system_notices(package_root / 'licenses', package_root,
                                            [(packaged, library)])
            self.assertEqual((entry['formula'], entry['version']), ('gmp', library.parts[-3]))
            self.assertIn('LGPL-3.0-or-later', entry['license'])
            self.assertTrue(entry['source_shipped'])
            self.assertRegex(entry['source'][0]['sha256'], r'^[0-9a-f]{64}$')
            self.assertIn('system/gmp/COPYING.LESSERv3', entry['notices'])


class OpenSslTests(unittest.TestCase):
    """Pick the OpenSSL executable to package."""

    def test_override_then_path(self):
        """--openssl wins; otherwise `openssl` on PATH; otherwise a clear error."""
        self.assertEqual(package.find_openssl('/bin/sh'), Path('/bin/sh').resolve())
        with tempfile.TemporaryDirectory(prefix='concurro-openssl-test-') as temporary:
            tool = Path(temporary) / 'openssl'
            tool.write_text('#!/bin/sh\n')
            tool.chmod(0o755)
            with unittest.mock.patch.dict(os.environ, {'PATH': temporary}):
                self.assertEqual(package.find_openssl(None), tool.resolve())
            with unittest.mock.patch.dict(os.environ, {'PATH': str(Path(temporary) / 'none')}):
                with self.assertRaisesRegex(FileNotFoundError, 'not on PATH; pass --openssl'):
                    package.find_openssl(None)


@unittest.skipUnless(sys.platform == 'linux' and platform.machine() == 'x86_64'
                     and all(shutil.which(tool) for tool in ('c++', 'cc', 'ldd', 'readelf',
                                                             'patchelf', 'dpkg-query')),
                     'requires Debian-family Linux x86-64 with a compiler, ldd, readelf and patchelf')
class ElfPackageTests(unittest.TestCase):
    """Package generated ELF images and load them from a relocated directory."""

    def build(self, root):
        """A C++ client loading libchild, which loads libleaf, all found by build-tree runpaths."""
        source = root / 'source'
        source.mkdir()
        (source / 'leaf.c').write_text('int leaf(void) { return 7; }\n')
        (source / 'child.c').write_text('int leaf(void); int child(void) { return leaf(); }\n')
        (source / 'main.cpp').write_text(
            '#include <string>\nextern "C" int child(void);\n'
            'int main() { return std::to_string(child()) == "7" ? 0 : 1; }\n')
        subprocess.run(['cc', '-shared', '-fPIC', str(source / 'leaf.c'), '-o',
                        str(source / 'libleaf.so')], check=True)
        subprocess.run(['cc', '-shared', '-fPIC', str(source / 'child.c'), '-L', str(source),
                        '-lleaf', '-Wl,-rpath,' + str(source), '-o', str(source / 'libchild.so')],
                       check=True)
        subprocess.run(['c++', str(source / 'main.cpp'), '-L', str(source), '-lchild',
                        '-Wl,-rpath,' + str(source), '-o', str(source / 'client')], check=True)
        return source

    def test_relocated_transitive_libraries(self):
        """Bundle the closure, including libstdc++, and load only bundled copies after a move."""
        with tempfile.TemporaryDirectory(prefix='concurro-elf-package-test-') as temporary:
            root = Path(temporary)
            source = self.build(root)
            client = root / 'package/bin/client'
            package.copy(source / 'client', client)
            floor, copied = package.add_elf_libraries(root / 'package',
                                                      [(source / 'client', client)])
            self.assertRegex(floor, r'^2\.\d+$')
            self.assertEqual({path.name for path, _ in copied},
                             {'libchild.so', 'libleaf.so', 'libstdc++.so.6', 'libgcc_s.so.1'})
            library = root / 'package/native-runtime/lib'
            self.assertEqual({path.name for path in library.iterdir()},
                             {'libchild.so', 'libleaf.so', 'libstdc++.so.6', 'libgcc_s.so.1'})
            self.assertEqual(package.elf_dynamic(client)['runpath'],
                             ['$ORIGIN/../native-runtime/lib'])
            self.assertEqual(package.elf_dynamic(library / 'libchild.so')['runpath'], ['$ORIGIN'])

            shutil.move(source, root / 'hidden source')
            relocated = root / 'relocated package'
            shutil.move(root / 'package', relocated)
            environment = {'PATH': '/usr/bin:/bin', 'LD_LIBRARY_PATH': str(root / 'missing')}
            subprocess.run([str(relocated / 'bin/client')], check=True, env=environment)
            loads = package.run('ldd', relocated / 'bin/client')
            for name in ('libchild.so', 'libleaf.so', 'libstdc++.so.6', 'libgcc_s.so.1'):
                self.assertIn(f'{name} => {relocated}/bin/../native-runtime/lib/{name}', loads)

    def test_debian_notices(self):
        """Bundled system libraries get their Debian copyright, license texts and versions."""
        with tempfile.TemporaryDirectory(prefix='concurro-elf-notice-test-') as temporary:
            root = Path(temporary)
            source = self.build(root)
            client = root / 'package/bin/client'
            package.copy(source / 'client', client)
            _, copied = package.add_elf_libraries(root / 'package', [(source / 'client', client)])
            system = [(path, origin) for path, origin in copied if origin.is_relative_to('/usr')]
            licenses = root / 'package/licenses'
            entries = notices.system_notices(licenses, root / 'package', system)
            self.assertEqual({entry['package'] for entry in entries}, {'libstdc++6', 'libgcc-s1'})
            self.assertTrue(all(entry['source'].startswith('gcc-') and entry['source_shipped']
                                for entry in entries))
            self.assertIn('GCC Runtime Library Exception',
                          (licenses / 'system/libstdc++6/copyright').read_text())
            self.assertTrue((licenses / 'common-licenses/GPL-3').is_file())
            with self.assertRaises(subprocess.CalledProcessError):
                notices.system_notices(licenses, root / 'package', [
                    (root / 'package/native-runtime/lib/libleaf.so', source / 'libleaf.so')])

    def test_audit_rejects_unpackaged_loads(self):
        """A build-tree runpath, a missing dependency, or an unaudited image is refused."""
        with tempfile.TemporaryDirectory(prefix='concurro-elf-audit-test-') as temporary:
            root = Path(temporary)
            source = self.build(root)
            client = root / 'package/bin/client'
            package.copy(source / 'client', client)
            with self.assertRaisesRegex(ValueError, 'non-local runpath'):
                package.audit_elf_libraries(root / 'package', [client])
            subprocess.run(['patchelf', '--set-rpath', '$ORIGIN', str(client)], check=True)
            with self.assertRaisesRegex(FileNotFoundError, 'libchild.so is not in the package'):
                package.audit_elf_libraries(root / 'package', [client])
            package.copy(source / 'libleaf.so', root / 'package/stray/libleaf.so')
            with self.assertRaisesRegex(ValueError, 'was not audited'):
                package.audit_elf_libraries(root / 'package', [client])


if __name__ == '__main__':
    unittest.main()
