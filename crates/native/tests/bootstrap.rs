//! Live phase-3 fixture parity, explicitly selected with an accepted package path.

use anyhow::{Context, Result, ensure};
use concurro_relay_native::{
    NativeRole,
    bootstrap::{self, BootstrapOptions},
    helpers::{self, Runtime},
};
use concurro_relay_native_transport::tunnel::{Role, Tunnel};
use concurro_relay_tls13::handshake::Profile;
use serde_json::{Value, json};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncBufReadExt,
    net::UnixListener,
    process::{Child, Command},
    time,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Own the accepted package and fresh certificate fixture for one route.
struct Fixture {
    bundle: PathBuf,
    python: PathBuf,
    script: PathBuf,
    root: PathBuf,
    ca: PathBuf,
    key: PathBuf,
    profile: Profile,
}

impl Fixture {
    /// Generate a CA and route-specific leaf so both roles authenticate real TLS.
    fn new(bundle: PathBuf, profile: Profile) -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = env::var_os("CONCURRO_PHASE3_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| env::temp_dir().join("concurro-phase3"))
            .join(format!(
                "{}-{stamp}",
                if profile == Profile::Codex {
                    "codex"
                } else {
                    "claude"
                }
            ));
        fs::create_dir_all(&root)?;
        let python = bundle.join("python");
        let script = Path::new(ROOT).join("../../native/phase3_fixture.py");
        let ca = root.join("ca.pem");
        let ca_key = root.join("ca.key");
        let csr = root.join("server.csr");
        let key = root.join("server.key");
        let cert = root.join("server.pem");
        let host = if profile == Profile::Codex {
            "chatgpt.com"
        } else {
            "api.anthropic.com"
        };
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Phase3 CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-keyout",
            ])
            .arg(&ca_key)
            .arg("-out")
            .arg(&ca)
            .output()?;
        ensure!(
            output.status.success(),
            "fixture CA: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                &format!("/CN={host}"),
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&csr)
            .output()?;
        ensure!(
            output.status.success(),
            "fixture CSR: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ext = root.join("extensions.txt");
        fs::write(
            &ext,
            format!(
                "subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n"
            ),
        )?;
        let output = std::process::Command::new("openssl")
            .args(["x509", "-req", "-days", "1", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(&ca)
            .arg("-CAkey")
            .arg(&ca_key)
            .arg("-CAcreateserial")
            .arg("-extfile")
            .arg(&ext)
            .arg("-out")
            .arg(&cert)
            .output()?;
        ensure!(
            output.status.success(),
            "fixture leaf: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(Self {
            bundle,
            python,
            script,
            root,
            ca,
            key,
            profile,
        })
    }
    /// Python route spelling.
    fn route(&self) -> &'static str {
        if self.profile == Profile::Codex {
            "codex"
        } else {
            "claude_h2"
        }
    }
    /// Spawn a single connection TLS server and read its selected port.
    async fn provider(&self, run: &Path) -> Result<(Child, u16)> {
        let mut child = Command::new(&self.python)
            .arg(&self.script)
            .arg("provider")
            .arg("--route")
            .arg(self.route())
            .arg("--ca")
            .arg(self.root.join("server.pem"))
            .arg("--key")
            .arg(&self.key)
            .arg("--output")
            .arg(run)
            .stdout(Stdio::piped())
            .stderr(fs::File::create(run.join("provider.log"))?)
            .kill_on_drop(true)
            .spawn()?;
        let mut line = String::new();
        time::timeout(
            Duration::from_secs(10),
            tokio::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line),
        )
        .await??;
        let port = serde_json::from_str::<Value>(&line)?["port"]
            .as_u64()
            .context("provider port missing")?;
        Ok((child, u16::try_from(port)?))
    }
    /// Use the accepted helper package belonging to each local role.
    fn runtime(&self, run: &Path, name: &str, role: NativeRole) -> Runtime {
        let package = if role == NativeRole::Sponsor {
            "sponsor"
        } else {
            "concurro"
        };
        Runtime {
            root: self
                .bundle
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(package)
                .join("native-runtime/runtime"),
            output: run.join(name),
            circuit_cache: self.root.join("public-circuits"),
            benchmark_timeout: Duration::from_secs(900),
        }
    }
    /// Build an explicitly selected development bootstrap configuration.
    fn options(&self, run: &Path, name: &str, role: NativeRole, port: u16) -> BootstrapOptions {
        BootstrapOptions {
            role,
            profile: self.profile,
            runtime: self.runtime(run, name, role),
            provider_host: "127.0.0.1".into(),
            provider_port: port,
            provider_ca: self.ca.clone(),
            credential: None,
            account: None,
            codex_headers: Vec::new(),
            claude_template: None,
        }
    }
}

/// Compare both mixed pairings and both Rust roles for each provider profile.
#[tokio::test]
#[ignore = "requires CONCURRO_PHASE3_FIXTURE_BUNDLE with accepted native helpers"]
async fn mixed_and_rust_bootstrap() -> Result<()> {
    let bundle = PathBuf::from(
        env::var_os("CONCURRO_PHASE3_FIXTURE_BUNDLE").context("accepted bundle path missing")?,
    );
    for profile in [Profile::Codex, Profile::ClaudeH2] {
        let fixture = Fixture::new(bundle.clone(), profile)?;
        let mixed_sponsor = run_case(&fixture, true, false, "rust-sponsor-python-concurro").await?;
        let mixed_concurro =
            run_case(&fixture, false, true, "python-sponsor-rust-concurro").await?;
        let both = run_case(&fixture, true, true, "both-rust").await?;
        for pair in [&mixed_sponsor, &mixed_concurro, &both] {
            ensure!(
                pair.0["h2"] == pair.1["h2"]
                    && pair.0["h3"] == pair.1["h3"]
                    && pair.0["session_id"] == pair.1["session_id"],
                "transcript mismatch"
            );
            ensure!(
                pair.0["handshake_public"] == pair.1["handshake_public"],
                "public circuit output mismatch"
            );
            ensure!(
                pair.0["prefix_public"] == pair.1["prefix_public"],
                "protected prefix public output mismatch"
            );
            ensure!(
                pair.0["prefix_key_commitment"] == pair.1["prefix_key_commitment"],
                "application key commitment mismatch"
            );
            ensure!(
                pair.0["prefix_forwarded"] == true && pair.1["prefix_forwarded"] == true,
                "protected prefix was not forwarded"
            );
            ensure!(
                pair.1["application_epoch_ready"] == true,
                "Concurro application epoch was not initialized"
            );
            ensure!(
                pair.0["server_finished_verified"] == true
                    && pair.1["server_finished_verified"] == true,
                "server Finished unverified"
            );
            ensure!(
                pair.0["client_finished_sent"] == true && pair.1["client_finished_sent"] == true,
                "client Finished unsent"
            );
        }
        ensure!(
            mixed_sponsor.0["events"] == both.0["events"],
            "Sponsor event order differs"
        );
        ensure!(
            mixed_concurro.1["events"] == both.1["events"],
            "Concurro event order differs"
        );
        ensure!(
            mixed_concurro.0["events"] == both.0["events"],
            "Python/Rust Sponsor event order differs"
        );
        ensure!(
            mixed_sponsor.1["events"] == both.1["events"],
            "Python/Rust Concurro event order differs"
        );
        let (parallel_a, parallel_b) = tokio::try_join!(
            run_case(&fixture, true, true, "parallel-a"),
            run_case(&fixture, true, true, "parallel-b")
        )?;
        ensure!(
            parallel_a.0["session_id"] != parallel_b.0["session_id"],
            "parallel sessions reused identity"
        );
        for pair in [parallel_a, parallel_b] {
            ensure!(
                pair.0["handshake_public"] == pair.1["handshake_public"],
                "parallel public output mismatch"
            );
            ensure!(
                pair.0["prefix_public"] == pair.1["prefix_public"],
                "parallel prefix output mismatch"
            );
            ensure!(pair.0["h3"] == pair.1["h3"], "parallel transcript mismatch");
        }
        let cache_runtime = fixture.runtime(&fixture.root, "cache-check", NativeRole::Sponsor);
        let (first, second) = tokio::try_join!(
            helpers::prefix_circuit(&cache_runtime, fixture.route(), 32, 16, 1),
            helpers::prefix_circuit(&cache_runtime, fixture.route(), 32, 16, 1)
        )?;
        ensure!(
            first == second && first.metadata()?.len() > 0,
            "public prefix cache failed"
        );
    }
    Ok(())
}

/// A rejected provider certificate terminates both roles before prefix release.
#[tokio::test]
#[ignore = "requires CONCURRO_PHASE3_FIXTURE_BUNDLE with accepted native helpers"]
async fn untrusted_provider_aborts_bootstrap() -> Result<()> {
    let bundle = PathBuf::from(
        env::var_os("CONCURRO_PHASE3_FIXTURE_BUNDLE").context("accepted bundle path missing")?,
    );
    let fixture = Fixture::new(bundle.clone(), Profile::Codex)?;
    let unrelated_ca = Fixture::new(bundle, Profile::ClaudeH2)?.ca;
    let run = fixture.root.join("untrusted-provider");
    fs::create_dir_all(&run)?;
    let (mut provider, port) = fixture.provider(&run).await?;
    let (sponsor_control, concurro_control) = tokio::io::duplex(1_000_000);
    let (sponsor_aux, concurro_aux) = tokio::io::duplex(1_000_000);
    let sponsor_tunnel = Arc::new(Tunnel::start(sponsor_aux, Role::Sponsor));
    let concurro_tunnel = Arc::new(Tunnel::start(concurro_aux, Role::Concurro));
    let sponsor = bootstrap::run(
        sponsor_control,
        Some(sponsor_tunnel),
        fixture.options(&run, "sponsor", NativeRole::Sponsor, port),
    );
    let mut options = fixture.options(&run, "concurro", NativeRole::Concurro, port);
    options.provider_ca = unrelated_ca;
    let concurro = bootstrap::run(concurro_control, Some(concurro_tunnel), options);
    let (sponsor, concurro) = time::timeout(Duration::from_secs(120), async {
        tokio::join!(sponsor, concurro)
    })
    .await?;
    ensure!(
        sponsor.is_err(),
        "Sponsor continued after peer certificate rejection"
    );
    let error = concurro
        .err()
        .context("Concurro accepted untrusted provider")?;
    ensure!(
        format!("{error:#}").contains("certificate rejected"),
        "unexpected Concurro error: {error:#}"
    );
    ensure!(
        !run.join("provider-prefix.json").exists(),
        "untrusted provider received protected prefix"
    );
    let _ = provider.kill().await;
    let _ = provider.wait().await;
    Ok(())
}

/// Run one fresh session and retain all evidence on failure.
async fn run_case(
    fixture: &Fixture,
    sponsor_rust: bool,
    concurro_rust: bool,
    name: &str,
) -> Result<(Value, Value)> {
    let run = fixture.root.join(name);
    fs::create_dir_all(&run)?;
    let (mut provider, port) = fixture.provider(&run).await?;
    let pair = if sponsor_rust && concurro_rust {
        let (sponsor_control, concurro_control) = tokio::io::duplex(1_000_000);
        let (sponsor_aux, concurro_aux) = tokio::io::duplex(1_000_000);
        let sponsor_tunnel = Arc::new(Tunnel::start(sponsor_aux, Role::Sponsor));
        let concurro_tunnel = Arc::new(Tunnel::start(concurro_aux, Role::Concurro));
        let sponsor = bootstrap::run(
            sponsor_control,
            Some(sponsor_tunnel),
            fixture.options(&run, "sponsor", NativeRole::Sponsor, port),
        );
        let concurro = bootstrap::run(
            concurro_control,
            Some(concurro_tunnel),
            fixture.options(&run, "concurro", NativeRole::Concurro, port),
        );
        let (sponsor, concurro) = tokio::try_join!(sponsor, concurro)?;
        (
            serde_json::to_value(sponsor)?,
            serde_json::to_value(concurro)?,
        )
    } else {
        let rust_role = if sponsor_rust {
            NativeRole::Sponsor
        } else {
            NativeRole::Concurro
        };
        let python_role = if sponsor_rust {
            NativeRole::Concurro
        } else {
            NativeRole::Sponsor
        };
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sockets = PathBuf::from("/tmp").join(format!("p3-{:x}-{stamp:x}", std::process::id()));
        fs::create_dir(&sockets)?;
        let control_path = sockets.join("control.sock");
        let aux_path = sockets.join("aux.sock");
        let control_listener = UnixListener::bind(&control_path)?;
        let aux_listener = UnixListener::bind(&aux_path)?;
        let python_name = if python_role == NativeRole::Sponsor {
            "sponsor"
        } else {
            "concurro"
        };
        let python_output = run.join(python_name);
        fs::create_dir_all(&python_output)?;
        let runtime = fixture.runtime(&run, python_name, python_role);
        let mut python = Command::new(&fixture.python)
            .arg(&fixture.script)
            .arg("peer")
            .arg("--role")
            .arg(python_name)
            .arg("--route")
            .arg(fixture.route())
            .arg("--runtime")
            .arg(&runtime.root)
            .arg("--output")
            .arg(&python_output)
            .arg("--control")
            .arg(&control_path)
            .arg("--aux")
            .arg(&aux_path)
            .arg("--provider-port")
            .arg(port.to_string())
            .arg("--cache")
            .arg(fixture.root.join("public-circuits"))
            .arg("--ca")
            .arg(&fixture.ca)
            .stdout(fs::File::create(run.join("python-stdout.log"))?)
            .stderr(fs::File::create(run.join("python-stderr.log"))?)
            .kill_on_drop(true)
            .spawn()?;
        let (rust_control, _) =
            time::timeout(Duration::from_secs(15), control_listener.accept()).await??;
        let (rust_aux, _) = time::timeout(Duration::from_secs(15), aux_listener.accept()).await??;
        let tunnel = Arc::new(Tunnel::start(
            rust_aux,
            if rust_role == NativeRole::Sponsor {
                Role::Sponsor
            } else {
                Role::Concurro
            },
        ));
        let rust_name = if rust_role == NativeRole::Sponsor {
            "sponsor"
        } else {
            "concurro"
        };
        let rust = bootstrap::run(
            rust_control,
            Some(tunnel),
            fixture.options(&run, rust_name, rust_role, port),
        );
        let rust_result = rust.await;
        let status = time::timeout(
            Duration::from_secs(if rust_result.is_ok() { 900 } else { 5 }),
            python.wait(),
        )
        .await
        .context("Python peer timeout")??;
        let rust = rust_result.with_context(|| {
            format!(
                "Rust bootstrap failed; Python exit {status}; evidence: {}",
                run.display()
            )
        })?;
        ensure!(
            status.success(),
            "Python peer failed: {status}; evidence: {}",
            run.display()
        );
        let reference: Value =
            serde_json::from_slice(&fs::read(python_output.join("phase3-result.json"))?)?;
        fs::remove_file(control_path)?;
        fs::remove_file(aux_path)?;
        fs::remove_dir(sockets)?;
        if sponsor_rust {
            (serde_json::to_value(rust)?, reference)
        } else {
            (reference, serde_json::to_value(rust)?)
        }
    };
    let status = time::timeout(Duration::from_secs(10), provider.wait())
        .await
        .context("provider fixture timeout")??;
    ensure!(
        status.success(),
        "provider fixture failed: {status}; evidence: {}",
        run.display()
    );
    let provider_prefix: Value =
        serde_json::from_slice(&fs::read(run.join("provider-prefix.json"))?)?;
    let expected = if fixture.profile == Profile::Codex {
        "47"
    } else {
        "50"
    };
    ensure!(
        provider_prefix["first_byte"] == expected,
        "provider did not receive the protected request prefix"
    );
    fs::write(
        run.join("comparison.json"),
        serde_json::to_vec_pretty(&json!({"sponsor": pair.0, "concurro": pair.1}))?,
    )?;
    Ok(pair)
}
