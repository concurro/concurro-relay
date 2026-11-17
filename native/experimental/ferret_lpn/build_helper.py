"""Compile an experimental KRRW helper against the pinned source-build libraries."""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    """Build only the changed helper translation unit and retain its inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers-default", type=int, default=1)
    args = parser.parse_args()
    source = args.source.resolve()
    reference = args.reference.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    flags_file = reference / "build/CMakeFiles/HandoffPartyKrrw.dir/flags.make"
    flags = {line.split(" = ", 1)[0]: line.split(" = ", 1)[1].strip()
             for line in flags_file.read_text().splitlines() if " = " in line}
    includes = flags["CXX_INCLUDES"].replace(str(reference / "src"), str(source / "src"))
    object_file = output / "HandoffPartyKrrw.cpp.o"
    binary = output / "HandoffPartyKrrw"
    compile_command = ["/usr/bin/c++", *shlex.split(flags["CXX_DEFINES"]),
                       f"-DHANDOFF_LPN_WORKERS_DEFAULT={args.workers_default}",
                       *shlex.split(includes), *shlex.split(flags["CXX_FLAGS"]),
                       "-c", str(source / "src/2pc/HandoffPartyKrrw.cpp"),
                       "-o", str(object_file)]
    with (output / "compile.log").open("w") as log:
        subprocess.run(compile_command, check=True, stdout=log, stderr=subprocess.STDOUT)
    link = shlex.split((reference / "build/CMakeFiles/HandoffPartyKrrw.dir/link.txt").read_text())
    link = [str(object_file) if item == "CMakeFiles/HandoffPartyKrrw.dir/2pc/HandoffPartyKrrw.cpp.o"
            else str(binary) if item == "HandoffPartyKrrw" else item for item in link]
    with (output / "link.log").open("w") as log:
        subprocess.run(link, cwd=reference / "build", check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    subprocess.run(["install_name_tool", "-change",
                    str(reference / "build/emp-tool/libemp-tool.dylib"),
                    "@loader_path/emp-tool/libemp-tool.dylib", str(binary)], check=True)
    changed = ("src/2pc/HandoffPartyKrrw.cpp", "src/ssl/Util.inl",
               "src/emp-ot/emp-ot/ferret/ferret_cot.hpp",
               "src/emp-ot/emp-ot/ferret/lpn_f2.h")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    (output / "build.json").write_text(json.dumps({
        "source": str(source), "reference": str(reference),
        "workers_default": args.workers_default,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
        "compiler_version": subprocess.check_output(
            ["/usr/bin/c++", "--version"], text=True).strip(),
        "source_sha256": {name: digest(source / name) for name in changed},
        "reference_sha256": {name: digest(reference / name) for name in changed},
        "compile_command": compile_command, "link_command": link,
        "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
    }, indent=2) + "\n")
    print(binary)


if __name__ == "__main__":
    main()
