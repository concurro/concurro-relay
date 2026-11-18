"""Assemble the Linux amd64 hosted verifier runtime from qualified ELF inputs.

The hosted image provides the helpers' shared libraries (Dockerfile.amd64-runtime); the
downloadable Sponsor and Concurro packages carry theirs (package.py).
"""

import argparse
from pathlib import Path

from package import copy, find_openssl, runtime_data, runtime_images


def assemble(args):
    """Copy only the binaries and public circuits used by the hosted native runtime."""
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    bundle = output / "native-runtime"
    runtime = bundle / "runtime"
    sources = [
        (args.hosted, output / "bin/concurro-relay-hosted"),
        (args.bridge, output / "bin/responses-bridge"),
        (args.worker, bundle / "concurro-native-worker"),
        (find_openssl(args.openssl), bundle / "bin/openssl"),
    ]
    sources += runtime_images(args.runtime.resolve(), runtime, ".so")
    sources += runtime_data(args.runtime.resolve(), runtime)
    for origin, destination in sources:
        copy(origin, destination)
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True, help="the native build directory")
    parser.add_argument("--hosted", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--openssl", help="default: openssl on PATH")
    assemble(parser.parse_args())
