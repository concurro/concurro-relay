"""Third-party notices and source provenance for a packaged Sponsor or Concurro runtime.

`collect` writes `licenses/` into a package: license and notice files, and `third-party.json`
recording where every third-party component came from:
- system: libraries and OpenSSL copied from Debian packages (Linux) or Homebrew kegs (macOS);
- native: the git checkouts the native helpers were built from;
- rust: the crates compiled into the packaged Rust binaries.
A component without a license file is recorded with an empty `notices` list and printed.
"""

import hashlib
import json
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

NOTICE = re.compile(r'(?i)^(licen[cs]e|copying|notice|copyright|unlicense)')
# Shipped libraries whose own license is copyleft, so the package's source is published with
# the release: GMP (LGPL-3+ or GPL-2+), and Debian's GCC runtime (GPL-3+ with the GCC Runtime
# Library Exception). Debian source package or Homebrew formula names.
COPYLEFT = re.compile(r'^(gmp|gcc-\d+)$')
RELAY = Path(__file__).resolve().parent.parent
# Concurro's changes to upstream sources, in the concurro-relay source of the release.
OVERLAYS = {
    'DiStefano': ['native/sources/DiStefano', 'native/patches/DiStefano-Krrw-prepared.patch',
                  'native/linux-amd64-patches (Linux)'],
    'MP-SPDZ': ['native/sources/MP-SPDZ', 'native/linux-amd64-patches/MP-SPDZ-CONFIG.mine (Linux)'],
    'mpz2': ['patches/mpz2', 'native/patches/mpz2-base-seeds.patch (request-proof)'],
    'tlsn': ['patches/tlsn'],
    'rangeset': ['patches/rangeset'],
}
README = """# Third-party components

`third-party.json` records every third-party component in this package and where it came from:

- `system`: shared libraries and OpenSSL, with their Debian package or Homebrew formula
  versions; their notices are in `system/` (Debian copyright files reference
  `common-licenses/`).
- `native`: the upstream git checkouts the native helpers were built from, by URL and commit;
  their license files are in `native/`.
- `rust`: the crates compiled into the Rust binaries; their license files are in `rust/`.

Concurro's changes to upstream sources (`modified_by`) are in the concurro-relay source at the
commit in `release.json`, also published as the release's `source.tar.gz`. Components marked
`source_shipped` are published with each release as `<archive>-third-party-sources.tar.gz`.
"""


def run(*command, cwd=None):
    """Return one tool's standard output."""
    return subprocess.run([str(part) for part in command], check=True, capture_output=True,
                          text=True, cwd=cwd).stdout


def notice_files(directory):
    """License and notice files directly in `directory`."""
    return sorted(path for path in directory.iterdir() if path.is_file() and NOTICE.match(path.name))


def keep(files, destination):
    """Copy `files` into `destination`; return their names."""
    destination.mkdir(parents=True, exist_ok=True)
    for path in files:
        shutil.copy2(path, destination / path.name)
    return [path.name for path in files]


def debian(licenses, packaged, system):
    """The Debian package that provides `system`, its copyright and referenced license texts."""
    owner = run('dpkg-query', '--search', system).split(':', 1)[0].split(',')[0]
    version, source, source_version = run(
        'dpkg-query', '--show', '--showformat=${Version}\t${source:Package}\t${source:Version}',
        owner).split('\t')
    copyright = Path('/usr/share/doc', owner, 'copyright').resolve()
    (licenses / 'system' / owner).mkdir(parents=True, exist_ok=True)
    shutil.copy2(copyright, licenses / 'system' / owner / 'copyright')
    for name in re.findall(r'/usr/share/common-licenses/([\w.+-]*\w)', copyright.read_text()):
        text = Path('/usr/share/common-licenses', name)
        if text.exists():
            (licenses / 'common-licenses').mkdir(exist_ok=True)
            shutil.copy2(text.resolve(), licenses / 'common-licenses' / name)
    return {'file': packaged, 'package': owner, 'version': version, 'source': source,
            'source_version': source_version, 'source_shipped': bool(COPYLEFT.match(source)),
            'notices': [f'system/{owner}/copyright']}


def homebrew(licenses, packaged, system):
    """The Homebrew keg that provides `system`: license files, SBOM and exact source."""
    parts = system.parts
    cellar = parts.index('Cellar')
    formula, version = parts[cellar + 1], parts[cellar + 2]
    keg = Path(*parts[:cellar + 3])
    info, = json.loads(run('brew', 'info', '--json=v2', formula))['formulae']
    sbom = json.loads((keg / 'sbom.spdx.json').read_text())
    sources = [{'url': item['downloadLocation'], 'sha256': checksum['checksumValue']}
               for item in sbom['packages'] if item['downloadLocation'].startswith('http')
               and 'ghcr.io' not in item['downloadLocation']
               for checksum in item.get('checksums', []) if checksum['algorithm'] == 'SHA256']
    if not sources:
        raise ValueError(f'{keg}: the SBOM records no checksummed source')
    files = keep(notice_files(keg) + [keg / 'sbom.spdx.json'], licenses / 'system' / formula)
    return {'file': packaged, 'formula': formula, 'version': version, 'license': info['license'],
            'source': sources, 'source_shipped': bool(COPYLEFT.match(formula)),
            'notices': [f'system/{formula}/{name}' for name in files if name != 'sbom.spdx.json']}


def system_notices(licenses, package, files):
    """Entries for (packaged path, system path) pairs, from Debian or Homebrew metadata."""
    entries = {}
    for packaged, system in files:
        relative = str(packaged.relative_to(package))
        entry = (homebrew if 'Cellar' in system.parts else debian)(licenses, relative, system)
        entries[relative] = entry
    return [entries[name] for name in sorted(entries)]


def native_notices(licenses, runtime):
    """Entries for the git checkouts under the DiStefano and MP-SPDZ build trees."""
    entries = []
    for top in ('DiStefano', 'MP-SPDZ'):
        for marker in sorted((runtime / top).rglob('.git')):
            repository = marker.parent
            name = str(repository.relative_to(runtime))
            found = notice_files(repository) or [
                path for child in sorted(repository.iterdir()) if child.is_dir()
                and not (child / '.git').exists() for path in notice_files(child)]
            files = keep(found, licenses / 'native' / name)
            entries.append({
                'name': name,
                'url': run('git', 'config', '--get', 'remote.origin.url', cwd=repository).strip(),
                'commit': run('git', 'rev-parse', 'HEAD', cwd=repository).strip(),
                'modified_by': OVERLAYS.get(name, []),
                'notices': [f'native/{name}/{file}' for file in files]})
    return entries


def upstream_pins():
    """Pinned path dependencies prepared by scripts/upstream.sh: name -> source string."""
    pins = {}
    for kind, name, first, second in re.findall(
            r'^(from_git|from_crate) (\S+) (\S+) (\S+)$',
            (RELAY / 'scripts/upstream.sh').read_text(), re.MULTILINE):
        pins[name] = (f'git+{first}#{second}' if kind == 'from_git'
                      else f'crates.io {name} {first} (sha256 {second})')
    return pins


def crate_root(manifest, pins, upstreams):
    """The top of a crate's source tree, and its pinned upstream name if it is one.

    Pinned path dependencies are checkouts named after their pin in one of `upstreams`;
    registry and git crates end at the directory holding `.cargo-ok` or `.git`.
    """
    for candidate in [manifest.parent, *manifest.parent.parents]:
        if candidate.name in pins and candidate.parent in upstreams:
            return candidate, candidate.name
        if (candidate / '.cargo-ok').exists() or (candidate / '.git').exists():
            return candidate, None
    return manifest.parent, None


def rust_notices(licenses, binaries, upstreams):
    """Entries for the third-party crates compiled into (Cargo.toml, binary name) pairs."""
    host = re.search(r'^host: (\S+)$', run('rustc', '-vV'), re.MULTILINE).group(1)
    pins = upstream_pins()
    crates = {}
    for manifest, binary in binaries:
        metadata = json.loads(run('cargo', 'metadata', '--format-version', '1', '--locked',
                                  '--manifest-path', manifest, '--filter-platform', host))
        packages = {package['id']: package for package in metadata['packages']}
        nodes = {node['id']: node for node in metadata['resolve']['nodes']}
        members = set(metadata['workspace_members'])
        root, = [package['id'] for package in metadata['packages'] if any(
            target['name'] == binary and 'bin' in target['kind'] for target in package['targets'])]
        stack, seen = [root], set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack += [dependency['pkg'] for dependency in nodes[current]['deps']
                      if any(kind['kind'] is None for kind in dependency['dep_kinds'])]
        for identifier in seen - members:
            package = packages[identifier]
            if any('proc-macro' in target['kind'] for target in package['targets']):
                continue
            crates[(package['name'], package['version'])] = package
    entries = []
    for (name, version), package in sorted(crates.items()):
        manifest = Path(package['manifest_path'])
        top, pinned = crate_root(manifest, pins, upstreams)
        found = []
        if package.get('license_file') and (manifest.parent / package['license_file']).is_file():
            found.append(manifest.parent / package['license_file'])
        for directory in [manifest.parent, *manifest.parent.parents]:
            found += notice_files(directory)
            if found or directory == top:
                break
        files = keep(sorted(set(found)), licenses / 'rust' / f'{name}-{version}')
        entries.append({
            'name': name, 'version': version, 'license': package['license'],
            'source': package['source'] or pins.get(pinned, 'path'),
            'modified_by': OVERLAYS.get(pinned, []),
            'notices': [f'rust/{name}-{version}/{file}' for file in files]})
    return entries


def collect(package, runtime, system, binaries):
    """Write `licenses/` for `package`; return the `third-party.json` index."""
    licenses = package / 'licenses'
    index = {'system': system_notices(licenses, package, system),
             'native': native_notices(licenses, runtime),
             'rust': rust_notices(licenses, binaries, {RELAY / 'upstream', runtime})}
    (licenses / 'third-party.json').write_text(json.dumps(index, indent=2) + '\n')
    (licenses / 'README.md').write_text(README)
    for section, entries in index.items():
        for entry in entries:
            if not entry['notices']:
                print(f'no license file: {section} {entry.get("name") or entry.get("file")} '
                      f'(declared: {entry.get("license")})')
    return index


def fetch_sources(index, directory):
    """Download the exact sources of the `source_shipped` system components into `directory`."""
    directory.mkdir(parents=True, exist_ok=False)
    debian_sources = sorted({(entry['source'], entry['source_version'])
                             for entry in index['system']
                             if entry['source_shipped'] and 'package' in entry})
    for source, version in debian_sources:
        subprocess.run(['apt-get', 'source', '--download-only', f'{source}={version}'],
                       cwd=directory, check=True, stdout=subprocess.DEVNULL)
    downloads = {(item['url'], item['sha256']) for entry in index['system']
                 if entry['source_shipped'] and 'formula' in entry for item in entry['source']}
    for url, sha256 in sorted(downloads):
        download(url, sha256, directory / url.rsplit('/', 1)[1])


def download(url, sha256, destination):
    """Download `url` to `destination`, refusing content whose SHA-256 is not `sha256`."""
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise ValueError(f'{url}: SHA-256 {digest}, expected {sha256}')
    destination.write_bytes(data)
