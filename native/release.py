"""Audit a packaged Sponsor runtime and archive it as a release asset with its checksum."""

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


def archive(package, name, epoch):
    """Write `name.tar.gz` deterministically: sorted entries, fixed times and owners."""
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
    output = package.parent / f'{name}.tar.gz'
    with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as gz:
        gz.write(buffer.getvalue())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n')
    return output


def main():
    """Audit, identify and archive one packaged Sponsor runtime from command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--epoch', type=int, required=True, help='commit time, for archive entries')
    parser.add_argument('--forbid', action='append', default=[], help='build path absent from the package')
    args = parser.parse_args()
    package = args.package.resolve()
    audit(package, args.forbid)
    (package / 'release.json').write_text(json.dumps(
        {'name': 'concurro-relay', 'version': args.version, 'commit': args.commit,
         'platform': args.platform}, indent=2) + '\n')
    print(archive(package, f'concurro-relay-{args.version}-{args.platform}', args.epoch))


if __name__ == '__main__':
    main()
