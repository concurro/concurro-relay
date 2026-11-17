"""Exercise macOS bundle relocation through a transitive dynamic-library chain."""

import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from native import package


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


if __name__ == '__main__':
    unittest.main()
