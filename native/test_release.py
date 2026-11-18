"""Check the Sponsor release archive, its checksum file and dist manifest fragment agree."""

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from native.plan import planned

NAME = 'concurro-relay-aarch64-apple-darwin'
ARCHIVE = f'{NAME}.tar.gz'
PLATFORM = 'aarch64-apple-darwin'
EPOCH = 1700000000
# The archive's entry in `dist plan --output-format=json` (dist 0.34.0).
PLAN = {
    'dist_version': '0.34.0',
    'announcement_tag': 'v0.1.0',
    'artifacts': {
        ARCHIVE: {
            'name': ARCHIVE,
            'kind': 'executable-zip',
            'target_triples': [PLATFORM],
            'assets': [{'id': f'{NAME}-exe-concurro-relay', 'name': 'concurro-relay',
                        'path': 'concurro-relay', 'kind': 'executable'}],
            'checksum': f'{ARCHIVE}.sha256',
        },
        'source.tar.gz': {'name': 'source.tar.gz', 'kind': 'source-tarball'},
    },
}
SCRIPT = Path(__file__).with_name('release.py')
LINUX = 'concurro-relay-x86_64-unknown-linux-gnu'


class ReleaseTests(unittest.TestCase):
    """Run release.py on a synthetic package, as build-sponsor.yml does."""

    def setUp(self):
        """Create an isolated package and dist plan for each archive test."""
        temporary = tempfile.TemporaryDirectory(prefix='concurro-release-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.package = self.root / 'sponsor'
        files = {'bin/concurro-relay': b'relay', 'native-runtime/lib/libhelper.dylib': b'helper',
                 'native-runtime/circuits/prefix.txt': b'circuit', 'manifest.json': b'{}\n'}
        for relative, data in files.items():
            path = self.package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.package / 'bin/concurro-relay').chmod(0o755)
        self.plan = self.root / 'plan.json'
        self.plan.write_text(json.dumps(PLAN))

    def release(self, output, *extra):
        """Run release.py into OUTPUT and return the archive path."""
        result = subprocess.run(
            [sys.executable, '-I', str(SCRIPT), '--package', str(self.package), '--name', NAME,
             '--output', str(output), '--version', '0.1.0', '--commit', 'c0ffee',
             '--platform', PLATFORM, '--epoch', str(EPOCH), '--plan', str(self.plan), *extra],
            check=True, capture_output=True, text=True)
        return Path(result.stdout.splitlines()[0])

    def test_third_party_sources(self):
        """--sources writes a separate checksummed archive that dist's fragment leaves out."""
        sources = self.root / 'sources'
        sources.mkdir()
        (sources / 'gmp_6.3.0+dfsg-3.dsc').write_text('dsc')
        (sources / 'gmp_6.3.0+dfsg.orig.tar.xz').write_bytes(b'orig')
        archive = self.release(self.root / 'distrib', '--sources', str(sources))
        extra = archive.with_name(f'{NAME}-third-party-sources.tar.gz')
        digest = hashlib.sha256(extra.read_bytes()).hexdigest()
        self.assertEqual(extra.with_name(f'{extra.name}.sha256').read_text(),
                         f'{digest}  {extra.name}\n')
        with tarfile.open(extra) as tar:
            self.assertEqual(tar.getnames(), [
                f'{NAME}-third-party-sources', f'{NAME}-third-party-sources/gmp_6.3.0+dfsg-3.dsc',
                f'{NAME}-third-party-sources/gmp_6.3.0+dfsg.orig.tar.xz'])
        fragment = archive.with_name(f'{PLATFORM}-dist-manifest.json').read_text()
        self.assertNotIn('third-party-sources', fragment)

    def test_checksums_agree(self):
        """The `.sha256` file and the manifest fragment both carry the archive's digest."""
        archive = self.release(self.root / 'distrib')
        self.assertEqual(archive, (self.root / 'distrib' / ARCHIVE).resolve())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(archive.with_name(f'{ARCHIVE}.sha256').read_text(), f'{digest}  {ARCHIVE}\n')
        fragment = json.loads(archive.with_name(f'{PLATFORM}-dist-manifest.json').read_text())
        expected = json.loads(json.dumps(PLAN))
        expected['artifacts'][ARCHIVE]['checksums'] = {'sha256': digest}
        self.assertEqual(fragment, expected)

    def test_layout(self):
        """One top directory holds the package, release.json added, with fixed owners and times."""
        archive = self.release(self.root / 'distrib')
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            self.assertEqual([member.name for member in members], [
                NAME, f'{NAME}/bin', f'{NAME}/bin/concurro-relay', f'{NAME}/manifest.json',
                f'{NAME}/native-runtime', f'{NAME}/native-runtime/circuits',
                f'{NAME}/native-runtime/circuits/prefix.txt', f'{NAME}/native-runtime/lib',
                f'{NAME}/native-runtime/lib/libhelper.dylib', f'{NAME}/release.json'])
            for member in members:
                self.assertEqual((member.mtime, member.uid, member.gid, member.uname, member.gname),
                                 (EPOCH, 0, 0, '', ''), member.name)
            self.assertEqual(tar.getmember(f'{NAME}/bin/concurro-relay').mode & 0o777, 0o755)
            self.assertEqual(json.load(tar.extractfile(f'{NAME}/release.json')), {
                'name': 'concurro-relay', 'version': '0.1.0', 'commit': 'c0ffee',
                'platform': PLATFORM})
        with gzip.open(archive) as stream:
            stream.read()
        self.assertEqual(int.from_bytes(archive.read_bytes()[4:8], 'little'), EPOCH)

    def test_reproducible(self):
        """Two runs on the same package produce the same archive bytes."""
        first = self.release(self.root / 'first').read_bytes()
        second = self.release(self.root / 'second').read_bytes()
        self.assertEqual(first, second)

    def test_build_path_refused(self):
        """A file containing a forbidden build path stops the release before archiving."""
        (self.package / 'native-runtime/lib/libhelper.dylib').write_bytes(b'x/Users/builder/y')
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.release(self.root / 'distrib', '--forbid', '/Users/builder')
        self.assertIn('native-runtime/lib/libhelper.dylib contains build path', raised.exception.stderr)
        self.assertFalse((self.root / 'distrib' / ARCHIVE).exists())


class PlanTests(unittest.TestCase):
    """Find each target's planned archive, as both build-sponsor.yml jobs do."""

    def test_each_target_finds_its_archive(self):
        """The release version and the archive whose target triples include the target."""
        plan = json.loads(json.dumps(PLAN))
        plan['releases'] = [{'app_name': 'concurro-relay', 'app_version': '0.1.1'}]
        plan['artifacts'][f'{LINUX}.tar.gz'] = {
            'name': f'{LINUX}.tar.gz', 'kind': 'executable-zip',
            'target_triples': ['x86_64-unknown-linux-gnu']}
        self.assertEqual(planned(plan, PLATFORM), ('0.1.1', NAME))
        self.assertEqual(planned(plan, 'x86_64-unknown-linux-gnu'), ('0.1.1', LINUX))
        with self.assertRaises(ValueError):
            planned(plan, 'x86_64-pc-windows-msvc')


if __name__ == '__main__':
    unittest.main()
