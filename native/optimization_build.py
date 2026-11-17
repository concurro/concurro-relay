"""Build isolated release-profile variants and package the accepted runtime."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


VARIANTS = (
    ("default-16", "false", "16"),
    ("thin-16", "thin", "16"),
    ("default-1", "false", "1"),
    ("thin-1", "thin", "1"),
)
BINARIES = ("concurro-relay", "dev-verifier", "concurro-native-worker")


def digest(path):
    """Return SHA-256 for one frozen binary or manifest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    """Record isolated build elapsed time and package IDs for each variant."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    source_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
    tracked_diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=repo)
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=repo
    ).decode().split("\0")
    manifests = [repo / "Cargo.toml", repo / "Cargo.lock",
                 *sorted((repo / "crates").glob("*/Cargo.toml"))]
    source_inputs = {
        "head_commit": source,
        "head_tree": source_tree,
        "tracked_diff_sha256": hashlib.sha256(tracked_diff).hexdigest(),
        "tracked_diff_bytes": len(tracked_diff),
        "untracked_sha256": {name: digest(repo / name) for name in untracked if name},
        "manifest_sha256": {str(path.relative_to(repo)): digest(path) for path in manifests},
    }
    toolchain = subprocess.check_output(["rustc", "-vV"], cwd=repo, text=True)
    results = []
    for name, lto, units in VARIANTS:
        directory = output / name
        directory.mkdir()
        target = directory / "target"
        environment = os.environ.copy()
        environment.update({"CARGO_TARGET_DIR": str(target),
                            "CARGO_PROFILE_RELEASE_LTO": lto,
                            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": units})
        build = ["cargo", "build", "--release", "--locked", "-vv",
                 "--bin", "concurro-relay", "--bin", "dev-verifier",
                 "--bin", "concurro-native-worker"]
        started = time.perf_counter()
        with (directory / "build.log").open("w") as log:
            completed = subprocess.run(build, cwd=repo, env=environment,
                                       stdout=log, stderr=subprocess.STDOUT)
        elapsed = round(time.perf_counter() - started, 3)
        if completed.returncode:
            raise RuntimeError(f"{name} build exited {completed.returncode}")
        binaries = {binary: {"bytes": (target / "release" / binary).stat().st_size,
                             "sha256": digest(target / "release" / binary)}
                    for binary in BINARIES}
        packages = {}
        for role in ("sponsor", "concurro"):
            package = directory / role
            command = [sys.executable, str(repo / "native/package.py"),
                       "--role", role, "--runtime", str(args.runtime),
                       "--output", str(package),
                       "--relay", str(target / "release/concurro-relay"),
                       "--verifier", str(target / "release/dev-verifier"),
                       "--worker", str(target / "release/concurro-native-worker")]
            with (directory / f"package-{role}.log").open("w") as log:
                subprocess.run(command, cwd=repo, check=True, stdout=log,
                               stderr=subprocess.STDOUT)
            packages[role] = {"path": str(package),
                              "manifest_sha256": digest(package / "manifest.json")}
        row = {"variant": name, "lto": lto, "codegen_units": int(units),
               "build_seconds": elapsed, "target": str(target),
               "binaries": binaries, "packages": packages}
        results.append(row)
        (output / "builds.json").write_text(json.dumps(
            {"source": source, "source_inputs": source_inputs,
             "toolchain": toolchain, "command": build,
             "variants": results}, indent=2) + "\n")
        print(json.dumps({"variant": name, "build_seconds": elapsed}), flush=True)


if __name__ == "__main__":
    main()
