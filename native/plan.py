"""Print the version and archive name dist planned for one target, as GitHub env lines."""

import json
import sys


def planned(plan, target):
    """The single release's version and the target's archive name without `.tar.gz`."""
    release, = plan['releases']
    archive, = [name for name, artifact in plan['artifacts'].items()
                if artifact['kind'] == 'executable-zip' and target in artifact['target_triples']]
    return release['app_version'], archive.removesuffix('.tar.gz')


if __name__ == '__main__':
    with open(sys.argv[1]) as handle:
        version, archive = planned(json.load(handle), sys.argv[2])
    print(f'VERSION={version}')
    print(f'ARCHIVE={archive}')
