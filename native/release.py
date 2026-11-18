"""Audit a packaged Sponsor runtime and archive it as the release asset dist planned."""

import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path


def audit(package, forbidden):
    """Refuse a package whose files contain any build-machine path, such as a home directory."""
    needles = [value.encode() for value in forbidden if value]
    for path in sorted(package.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        for needle in needles:
            if needle in data:
                raise ValueError(f'{path.relative_to(package)} contains build path {needle.decode()}')


def archive(package, name, epoch, directory):
    """Write `directory/name.tar.gz` deterministically, with sorted entries, fixed times and owners."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for path in [package, *sorted(package.rglob('*'))]:
            info = tar.gettarinfo(path, arcname=str(Path(name) / path.relative_to(package)))
            info.mtime, info.uid, info.gid, info.uname, info.gname = epoch, 0, 0, '', ''
            if info.isfile():
                with path.open('rb') as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
    output = directory / f'{name}.tar.gz'
    with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as gz:
        gz.write(buffer.getvalue())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n')
    return output, digest


def record(plan, output, digest, platform):
    """Write dist's plan back as a manifest fragment carrying the archive's SHA-256.

    dist merges every `*dist-manifest.json` in its output directory, so its unified
    checksum file and release then cover the archive this script built.
    """
    manifest = json.loads(plan.read_text())
    manifest['artifacts'][output.name].setdefault('checksums', {})['sha256'] = digest
    output.with_name(f'{platform}-dist-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    """Audit, identify and archive one packaged Sponsor runtime from command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--name', required=True, help='archive name without .tar.gz, from the dist plan')
    parser.add_argument('--output', type=Path, required=True, help='directory for the archive and checksum')
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--epoch', type=int, required=True, help='commit time, for archive entries')
    parser.add_argument('--forbid', action='append', default=[], help='build path absent from the package')
    parser.add_argument('--plan', type=Path, help="dist's plan, to record the archive checksum for dist")
    parser.add_argument('--sources', type=Path,
                        help='third-party source packages, archived as NAME-third-party-sources')
    args = parser.parse_args()
    package = args.package.resolve()
    audit(package, args.forbid)
    (package / 'release.json').write_text(json.dumps(
        {'name': 'concurro-relay', 'version': args.version, 'commit': args.commit,
         'platform': args.platform}, indent=2) + '\n')
    args.output.mkdir(parents=True, exist_ok=True)
    output, digest = archive(package, args.name, args.epoch, args.output.resolve())
    if args.plan:
        record(args.plan, output, digest, args.platform)
    print(output)
    if args.sources:
        print(archive(args.sources.resolve(), f'{args.name}-third-party-sources', args.epoch,
                      args.output.resolve())[0])


if __name__ == '__main__':
    main()
