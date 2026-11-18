use std::env;
use std::path::PathBuf;
use std::process::Command;

/// A required build input set by the native build recipe.
fn input(name: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed={name}");
    PathBuf::from(env::var(name).unwrap_or_else(|_| panic!("{name} is required")))
}

/// Build the pinned malicious base OT bridge for the request proof binary.
///
/// `HANDOFF_BUILD_ROOT` holds the prepared DiStefano and MP-SPDZ sources,
/// `HANDOFF_LIBOTE2_BUILD` the libOTe build tree and `HANDOFF_LIBOTE2_INCLUDE`
/// its installed headers. `CXX`, `HANDOFF_CXXFLAGS` and `HANDOFF_LIBRARY_PATH`
/// optionally select the compiler, extra flags and libsodium's directory.
fn main() {
    let root = input("HANDOFF_BUILD_ROOT");
    let build = input("HANDOFF_LIBOTE2_BUILD");
    let install = input("HANDOFF_LIBOTE2_INCLUDE");
    let source = root.join("DiStefano/src/2pc");
    let libote = root.join("MP-SPDZ/deps/libOTe2");
    let output = PathBuf::from(env::var("OUT_DIR").expect("Cargo output directory"));
    let files = [
        source.join("HandoffBaseOT.cpp"),
        PathBuf::from("src/mrr_base_ot.cpp"),
    ];
    let objects = [output.join("HandoffBaseOT.o"), output.join("mrr_base_ot.o")];
    let includes = [
        build.clone(),
        build.join("cryptoTools"),
        source.clone(),
        libote.clone(),
        libote.join("cryptoTools"),
        libote.join("cryptoTools/thirdparty"),
        libote.join("out/coproto"),
        libote.join("out/macoro"),
        build.join("coproto"),
        build.join("macoro"),
        install,
    ];
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-env-changed=HANDOFF_CXXFLAGS");
    let compiler = env::var("CXX").unwrap_or_else(|_| "c++".into());
    let flags = env::var("HANDOFF_CXXFLAGS").unwrap_or_default();
    for (file, object) in files.iter().zip(objects.iter()) {
        println!("cargo:rerun-if-changed={}", file.display());
        let mut command = Command::new(&compiler);
        command.args(["-std=c++20", "-O2", "-c"]);
        command.args(flags.split_whitespace());
        for include in &includes {
            command.arg(format!("-I{}", include.display()));
        }
        assert!(
            command
                .arg(file)
                .arg("-o")
                .arg(object)
                .status()
                .expect("C++ compiler")
                .success()
        );
    }
    let archive = output.join("libhandoff_mrr_bridge.a");
    assert!(
        Command::new("ar")
            .arg("crs")
            .arg(&archive)
            .args(&objects)
            .status()
            .expect("archive tool")
            .success()
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=handoff_mrr_bridge");
    for library in [
        build.join("libOTe"),
        build.join("cryptoTools/cryptoTools"),
        build.join("coproto/coproto"),
        build.join("macoro/macoro"),
    ] {
        println!("cargo:rustc-link-search=native={}", library.display());
    }
    println!("cargo:rerun-if-env-changed=HANDOFF_LIBRARY_PATH");
    if let Ok(path) = env::var("HANDOFF_LIBRARY_PATH") {
        println!("cargo:rustc-link-search=native={path}");
    }
    for library in ["libOTe", "cryptoTools", "coproto", "macoro"] {
        println!("cargo:rustc-link-lib=static={library}");
    }
    println!("cargo:rustc-link-lib=dylib=sodium");
    let runtime = if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        "c++"
    } else {
        "stdc++"
    };
    println!("cargo:rustc-link-lib=dylib={runtime}");
}
