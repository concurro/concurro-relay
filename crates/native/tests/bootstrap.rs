//! Native bootstrap integration tests with accepted external helpers.

use anyhow::{Context, Result, ensure};
use concurro_relay_native::{
    NativeLimits, NativeRole,
    bootstrap::{self, BootstrapOptions},
    helpers::{self, Peer, Runtime},
    proof,
};
use concurro_relay_native_transport::tunnel::{Role, Tunnel};
use concurro_relay_provider_protocol::{
    HttpProvider,
    codex::{RequestBinding, RequestClaim},
    tls_key_update::Template,
};
use concurro_relay_tls13::{
    handshake::Profile,
    record::{self, Epoch},
};
use ring::digest;
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
    process::{Child, Command},
    time,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Own the accepted package and fresh certificate fixture for one route.
struct Fixture {
    bundle: PathBuf,
    script: PathBuf,
    root: PathBuf,
    ca: PathBuf,
    key: PathBuf,
    profile: Profile,
    /// HTTP provider whose certificate and prefix are exercised.
    http_provider: HttpProvider,
}

impl Fixture {
    /// Generate a CA and route-specific leaf so both roles authenticate real TLS.
    fn new(bundle: PathBuf, profile: Profile, http_provider: HttpProvider) -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = env::var_os("CONCURRO_PHASE3_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| env::temp_dir().join("concurro-phase3"))
            .join(format!(
                "{}-{stamp}",
                if profile == Profile::Codex {
                    "codex"
                } else {
                    http_provider.hostname()
                }
            ));
        fs::create_dir_all(&root)?;
        let script = Path::new(ROOT).join("../../native/bootstrap_provider.py");
        let ca = root.join("ca.pem");
        let ca_key = root.join("ca.key");
        let csr = root.join("server.csr");
        let key = root.join("server.key");
        let cert = root.join("server.pem");
        let host = if profile == Profile::Codex {
            "chatgpt.com"
        } else {
            http_provider.hostname()
        };
        // An installed openssl.cnf can add its own CA extensions; LibreSSL then repeats the
        // ones below, and webpki rejects a repeated extension. Only these flags apply.
        let config = root.join("openssl.cnf");
        fs::write(&config, "[req]\ndistinguished_name = dn\n[dn]\n")?;
        let output = std::process::Command::new("openssl")
            .arg("req")
            .arg("-config")
            .arg(&config)
            .args([
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
            .arg("req")
            .arg("-config")
            .arg(&config)
            .args([
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
            script,
            root,
            ca,
            key,
            profile,
            http_provider,
        })
    }
    /// Provider ALPN profile label.
    fn route(&self) -> &'static str {
        if self.profile == Profile::Codex {
            "codex"
        } else {
            "claude_h2"
        }
    }
    /// Spawn a single connection TLS server and read its selected port.
    async fn provider(&self, run: &Path) -> Result<(Child, u16)> {
        let mut child = Command::new("python3")
            .arg(&self.script)
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
            limits: NativeLimits::DEFAULT,
            benchmark_timeout: Duration::from_secs(900),
        }
    }
    /// Build an explicitly selected development bootstrap configuration.
    fn options(&self, run: &Path, name: &str, role: NativeRole, port: u16) -> BootstrapOptions {
        BootstrapOptions {
            provider: self.http_provider,
            role,
            profile: self.profile,
            runtime: self.runtime(run, name, role),
            provider_host: "127.0.0.1".into(),
            provider_port: port,
            provider_ca: self.ca.clone(),
            credential: None,
            account: None,
            codex_headers: Vec::new(),
            http_template: (self.profile == Profile::TlsKeyUpdate).then(|| {
                let mut template = Template::fixture_default();
                template.provider = self.http_provider;
                if self.http_provider == HttpProvider::Antigravity {
                    template.path = b"/v1internal:streamGenerateContent?alt=sse".to_vec();
                }
                template
            }),
        }
    }
}

/// Check both native roles, parallel sessions, and the public prefix cache.
#[tokio::test]
#[ignore = "requires CONCURRO_PHASE3_FIXTURE_BUNDLE with accepted native helpers"]
async fn rust_bootstrap() -> Result<()> {
    let bundle = PathBuf::from(
        env::var_os("CONCURRO_PHASE3_FIXTURE_BUNDLE").context("accepted bundle path missing")?,
    );
    for (profile, provider) in [
        (Profile::Codex, HttpProvider::Claude),
        (Profile::TlsKeyUpdate, HttpProvider::Claude),
        (Profile::TlsKeyUpdate, HttpProvider::Antigravity),
    ] {
        let fixture = Fixture::new(bundle.clone(), profile, provider)?;
        let pair = run_case(&fixture, "both-rust").await?;
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
        let (parallel_a, parallel_b) = tokio::try_join!(
            run_case(&fixture, "parallel-a"),
            run_case(&fixture, "parallel-b")
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
            first.path() == second.path() && first.path().metadata()?.len() > 0,
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
    let fixture = Fixture::new(bundle.clone(), Profile::Codex, HttpProvider::Claude)?;
    let unrelated_ca = Fixture::new(bundle, Profile::TlsKeyUpdate, HttpProvider::Claude)?.ca;
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

/// Each role's packaged request-proof helper proves, then verifies, two successive records.
#[tokio::test]
#[ignore = "requires CONCURRO_PHASE3_FIXTURE_BUNDLE with accepted native helpers"]
async fn packaged_request_proof() -> Result<()> {
    let bundle = PathBuf::from(
        env::var_os("CONCURRO_PHASE3_FIXTURE_BUNDLE").context("accepted bundle path missing")?,
    );
    let fixture = Fixture::new(bundle, Profile::Codex, HttpProvider::Claude)?;
    let run = fixture.root.join("request-proof");
    let sponsor_runtime = fixture.runtime(&run, "sponsor", NativeRole::Sponsor);
    let concurro_runtime = fixture.runtime(&run, "concurro", NativeRole::Concurro);
    fs::create_dir_all(&sponsor_runtime.output)?;
    fs::create_dir_all(&concurro_runtime.output)?;
    let (sponsor_control, concurro_control) = tokio::io::duplex(1_000_000);
    let (sponsor_aux, concurro_aux) = tokio::io::duplex(1_000_000);
    let sponsor_tunnel = Arc::new(Tunnel::start(sponsor_aux, Role::Sponsor));
    let concurro_tunnel = Arc::new(Tunnel::start(concurro_aux, Role::Concurro));
    let mut sponsor = Peer::new(sponsor_control);
    let mut concurro = Peer::new(concurro_control);
    // A synthetic session: the commitment the protected prefix would publish for this key.
    let secret = [7; 32];
    let key = record::expand::<16>(&secret, b"key")?;
    let iv = record::expand::<12>(&secret, b"iv")?;
    let (h2, h3) = ([2; 32], [3; 32]);
    let commitment = digest::digest(
        &digest::SHA256,
        &[
            b"Concurro/Handoff/v1/request-key".as_slice(),
            &h2,
            &h3,
            &key,
            &iv,
        ]
        .concat(),
    );
    let binding = RequestBinding {
        h2,
        h3,
        key_commitment: commitment.as_ref().try_into()?,
    };
    let mut records = Epoch::new(secret)?;
    for (turn, plaintext) in [b"first request".as_slice(), b"continuation"]
        .into_iter()
        .enumerate()
    {
        let turn = u64::try_from(turn)?;
        let wire = records.encrypt(plaintext, 23)?;
        let proved = RequestClaim::new(&binding, &key, &iv, turn, plaintext, &wire);
        let audited = RequestClaim::new(&binding, &[0; 16], &[0; 12], turn, plaintext, &wire);
        let (traffic, _) = time::timeout(Duration::from_secs(300), async {
            tokio::try_join!(
                proof::request(
                    &mut sponsor,
                    NativeRole::Sponsor,
                    &sponsor_tunnel,
                    &sponsor_runtime,
                    &audited,
                    turn
                ),
                proof::request(
                    &mut concurro,
                    NativeRole::Concurro,
                    &concurro_tunnel,
                    &concurro_runtime,
                    &proved,
                    turn
                ),
            )
        })
        .await
        .context("request proof timeout")?
        .with_context(|| format!("request proof {turn}; evidence: {}", run.display()))?;
        let traffic = traffic.context("Sponsor proof proxy carried nothing")?;
        ensure!(
            traffic.concurro_to_sponsor > 0 && traffic.sponsor_to_concurro > 0,
            "request proof {turn} exchanged no bytes"
        );
    }
    Ok(())
}

/// Run one fresh Rust pair and retain public evidence on failure.
async fn run_case(fixture: &Fixture, name: &str) -> Result<(Value, Value)> {
    let run = fixture.root.join(name);
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
    let concurro = bootstrap::run(
        concurro_control,
        Some(concurro_tunnel),
        fixture.options(&run, "concurro", NativeRole::Concurro, port),
    );
    let (sponsor, concurro) = tokio::try_join!(sponsor, concurro)?;
    let pair = (
        serde_json::to_value(sponsor)?,
        serde_json::to_value(concurro)?,
    );
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
