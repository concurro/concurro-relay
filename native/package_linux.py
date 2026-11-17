"""Assemble the Linux amd64 hosted verifier runtime from qualified ELF inputs."""

import argparse
import shutil
from pathlib import Path

from package import copy


def assemble(args):
    """Copy only the binaries and public circuits used by the hosted native runtime."""
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(output)
    runtime = output / "native-runtime/runtime"
    sources = [
        (args.hosted, output / "bin/concurro-relay-hosted"),
        (args.bridge, output / "bin/responses-bridge"),
        (args.worker, output / "native-runtime/concurro-native-worker"),
        (args.openssl, output / "native-runtime/bin/openssl"),
        (Path(__file__).with_name("openssl.cnf"), output / "native-runtime/bin/openssl.cnf"),
        (args.handshake_circuit,
         runtime / "DiStefano/handoff-handshake-shares-cached-hkdf.txt"),
        (args.distefano_build / "emp-tool/libemp-tool.so",
         runtime / "DiStefano/build/emp-tool/libemp-tool.so"),
        (args.mp_spdz / "mascot-party.x", runtime / "MP-SPDZ/mascot-party.x"),
        (args.mp_spdz / "libSPDZ.so", runtime / "MP-SPDZ/libSPDZ.so"),
        (args.request_proof, runtime / "request-proof/target/release/handoff-request-proof"),
    ]
    sources += [
        (args.distefano_build / name, runtime / "DiStefano/build" / name)
        for name in ("HandoffKeyShare", "HandoffPartyKrrw",
                     "HandoffPartyKrrwPrepared", "HandoffPrefix")
    ]
    sources += [
        (args.distefano / "src/emp-tool/emp-tool/circuits/files/bristol_format" / name,
         runtime / "DiStefano/src/emp-tool/emp-tool/circuits/files/bristol_format" / name)
        for name in ("aes128_full.txt", "sha-256-multiblock-aligned.txt")
    ]
    sources += [
        (args.distefano / "src/2pc/vhdl" / name, runtime / "DiStefano/src/2pc/vhdl" / name)
        for name in ("ModAdd256.txt", "ModAdd384.txt", "ModAdd521.txt")
    ]
    sources += [
        (args.mp_spdz / "Programs" / name, runtime / "MP-SPDZ/Programs" / name)
        for name in ("Bytecode/concurro_ectf_field-0.bc", "Schedules/concurro_ectf_field.sch")
    ]
    for origin, destination in sources:
        copy(origin, destination)
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hosted", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path(shutil.which("openssl") or "openssl"))
    parser.add_argument("--distefano", type=Path, required=True)
    parser.add_argument("--distefano-build", type=Path, required=True)
    parser.add_argument("--handshake-circuit", type=Path, required=True)
    parser.add_argument("--mp-spdz", type=Path, required=True)
    parser.add_argument("--request-proof", type=Path, required=True)
    assemble(parser.parse_args())
