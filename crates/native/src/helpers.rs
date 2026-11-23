//! Session-owned adapters for the accepted native handshake helpers.

use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use concurro_relay_native_transport::{
    control::{self, Message},
    tunnel::{Claim, Registration, Tunnel},
};
use num_bigint::{BigInt, BigUint, Sign};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::oneshot,
    task::{self, JoinSet},
    time::{self, Duration},
};

use crate::{NativeLimits, NativeRole};

mod cache;

pub use cache::{Circuit, prefix_circuit};

const P256_PRIME: &str =
    "115792089210356248762697446949407573530086143415290314195533631308867097853951";
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// Accepted external binaries and public circuit sources for one session.
#[derive(Clone, Debug)]
pub struct Runtime {
    /// Packaged runtime directory containing DiStefano and MP-SPDZ.
    pub root: PathBuf,
    /// Private session evidence and helper work directory.
    pub output: PathBuf,
    /// Shared, public generated-circuit cache.
    pub circuit_cache: PathBuf,
    /// Resource bounds for this session.
    pub limits: NativeLimits,
    /// Longer helper timeout selected explicitly for benchmark runs.
    pub benchmark_timeout: Duration,
}

impl Runtime {
    /// Resolve a binary or circuit in the accepted DiStefano package.
    pub fn distefano(&self, path: &str) -> PathBuf {
        self.root.join("DiStefano").join(path)
    }

    /// Resolve a binary or program in the accepted MP-SPDZ package.
    pub fn mp_spdz(&self, path: &str) -> PathBuf {
        self.root.join("MP-SPDZ").join(path)
    }

    /// Start bundled OpenSSL with its package-local configuration.
    pub fn openssl(&self) -> Command {
        let binary = self
            .root
            .parent()
            .expect("packaged runtime has a parent directory")
            .join("bin/openssl");
        let mut command = Command::new(&binary);
        command.env("OPENSSL_CONF", binary.with_file_name("openssl.cnf"));
        command
    }

    /// Resolve the accepted public handshake circuit.
    pub fn handshake_circuit(&self) -> PathBuf {
        self.distefano("handoff-handshake-shares-cached-hkdf.txt")
    }

    /// Ensure session evidence exists without blocking the async I/O executor.
    pub async fn prepare(&self) -> Result<()> {
        let output = self.output.clone();
        task::spawn_blocking(move || -> Result<()> {
            fs::create_dir_all(&output)?;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}

/// Typed exact control operations shared by the helper adapters.
pub struct Peer<C> {
    /// Authenticated inner control stream.
    pub stream: C,
    /// Ordered message kinds observed for fixture comparison, until taken.
    events: Option<Vec<String>>,
}

impl<C> Peer<C> {
    /// Exchange control messages over `stream`, recording their kinds.
    pub fn new(stream: C) -> Self {
        Self {
            stream,
            events: Some(Vec::new()),
        }
    }

    /// Stop recording and return the message kinds recorded so far.
    pub fn take_events(&mut self) -> Vec<String> {
        self.events.take().unwrap_or_default()
    }

    /// Record one message kind while recording.
    fn record(&mut self, direction: &str, kind: &str) {
        if let Some(events) = &mut self.events {
            events.push(format!("{direction}:{kind}"));
        }
    }
}

impl<C: AsyncRead + AsyncWrite + Unpin> Peer<C> {
    /// Send one Python-compatible control message.
    pub async fn send(
        &mut self,
        kind: &str,
        data: &[u8],
        metadata: Map<String, Value>,
    ) -> Result<()> {
        control::send(
            &mut self.stream,
            &Message {
                kind: kind.into(),
                data: data.into(),
                metadata,
            },
        )
        .await?;
        self.record("send", kind);
        Ok(())
    }

    /// Receive the next message, requiring the expected kind.
    pub async fn receive(&mut self, kind: &str) -> Result<Message> {
        let message = control::receive(&mut self.stream).await?;
        ensure!(
            message.kind == kind,
            "expected {kind}, got {}",
            message.kind
        );
        self.record("receive", kind);
        Ok(message)
    }

    /// Receive the next message when the protocol permits several kinds.
    pub async fn receive_any(&mut self) -> Result<Message> {
        let message = control::receive(&mut self.stream).await?;
        self.record("receive", &message.kind);
        Ok(message)
    }
}

/// Make a fresh MASCOT transport certificate and bind its peer to the authenticated role.
pub async fn exchange_mascot_identity<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    role: NativeRole,
    runtime: &Runtime,
) -> Result<()> {
    let party = party_number(role);
    let directory = runtime.output.join("mascot-certs");
    tokio::fs::create_dir(&directory)
        .await
        .context("create fresh MASCOT identity directory")?;
    tokio::fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).await?;
    let key = directory.join(format!("P{party}.key"));
    let cert = directory.join(format!("P{party}.pem"));
    let status = runtime
        .openssl()
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "1",
            "-subj",
            &format!("/CN=P{party}"),
            "-addext",
            &format!("subjectAltName=DNS:P{party}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .context("generate MASCOT certificate")?;
    ensure!(
        status.status.success(),
        "MASCOT certificate generation failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    tokio::fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).await?;
    let cert_bytes = tokio::fs::read(&cert).await?;
    peer.send(
        "mascot_certificate",
        &cert_bytes,
        metadata("party", json!(party)),
    )
    .await?;
    let other = peer.receive("mascot_certificate").await?;
    let opposite = 1 - party;
    ensure!(
        other.metadata.get("party") == Some(&json!(opposite)),
        "MASCOT peer certificate party differs from authenticated role"
    );
    let peer_cert = directory.join(format!("P{opposite}.pem"));
    tokio::fs::write(&peer_cert, &other.data).await?;
    let checked = runtime
        .openssl()
        .args(["x509", "-in"])
        .arg(&peer_cert)
        .args(["-noout", "-subject", "-nameopt", "RFC2253"])
        .stdin(Stdio::null())
        .output()
        .await?;
    ensure!(checked.status.success(), "invalid MASCOT peer certificate");
    let subject = String::from_utf8(checked.stdout)?;
    ensure!(
        subject.trim() == format!("subject=CN=P{opposite}"),
        "MASCOT peer certificate subject differs from authenticated role"
    );
    Ok(())
}

/// Child key-share process with private stdin and exact public outputs.
pub struct KeyShare {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl KeyShare {
    /// Read the public offer from a fresh helper process.
    pub async fn start(runtime: &Runtime) -> Result<(Self, [u8; 69])> {
        let mut child = Command::new(runtime.distefano("build/HandoffKeyShare"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("start HandoffKeyShare")?;
        let stdin = child.stdin.take().context("key-share stdin missing")?;
        let mut stdout = child.stdout.take().context("key-share stdout missing")?;
        let mut offer = [0; 69];
        time::timeout(HELPER_TIMEOUT, stdout.read_exact(&mut offer))
            .await
            .context("key-share offer timeout")??;
        Ok((
            Self {
                child,
                stdin,
                stdout,
            },
            offer,
        ))
    }

    /// Complete committed public DH and return the joint P-256 point.
    pub async fn joint<C: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        peer: &mut Peer<C>,
        role: NativeRole,
        offer: [u8; 69],
    ) -> Result<([u8; 65], [u8; 32])> {
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow!("nonce generation failed"))?;
        peer.send("nonce", &nonce, Map::new()).await?;
        let other_nonce = peer.receive("nonce").await?.data;
        ensure!(other_nonce.len() == 16, "peer nonce length mismatch");
        let nonces = if role == NativeRole::Sponsor {
            [&nonce[..], &other_nonce].concat()
        } else {
            [&other_nonce[..], &nonce].concat()
        };
        let session = sha256(&nonces);
        let commitment = sha256(&[b"Concurro/joint-dh/v1".as_slice(), &session, &offer].concat());
        peer.send("dh_commit", &commitment, Map::new()).await?;
        let other_commit = peer.receive("dh_commit").await?.data;
        peer.send("dh_offer", &offer, Map::new()).await?;
        let other_offer = peer.receive("dh_offer").await?.data;
        ensure!(
            other_offer.len() == 69
                && other_commit
                    == sha256(
                        &[b"Concurro/joint-dh/v1".as_slice(), &session, &other_offer].concat()
                    ),
            "peer DH offer differs from commitment"
        );
        self.stdin.write_all(&other_offer).await?;
        self.stdin.flush().await?;
        let mut joint = [0; 65];
        time::timeout(HELPER_TIMEOUT, self.stdout.read_exact(&mut joint))
            .await
            .context("joint key-share timeout")??;
        ensure!(joint[0] == 4, "native joint key-share failed");
        let hash = sha256(&joint);
        peer.send("joint_hash", &hash, Map::new()).await?;
        ensure!(
            peer.receive("joint_hash").await?.data == hash,
            "joint public key differs"
        );
        Ok((joint, session))
    }

    /// Finish the helper after sending the provider's P-256 point.
    pub async fn contribution(mut self, point: [u8; 65]) -> Result<[u8; 64]> {
        self.stdin
            .write_all(&[&[0, 0x17, 0, 0x41][..], &point].concat())
            .await?;
        drop(self.stdin);
        let mut contribution = [0; 64];
        time::timeout(HELPER_TIMEOUT, self.stdout.read_exact(&mut contribution))
            .await
            .context("private contribution timeout")??;
        let status = time::timeout(HELPER_TIMEOUT, self.child.wait())
            .await
            .context("key-share exit timeout")??;
        ensure!(
            status.success(),
            "native P-256 contribution failed: {status}"
        );
        Ok(contribution)
    }
}

/// Run fresh checked MASCOT conversion and exchange its session binding.
pub async fn arithmetic_share<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    role: NativeRole,
    runtime: &Runtime,
    tunnel: Option<&Arc<Tunnel>>,
    point: [u8; 64],
    session: [u8; 32],
    h2: [u8; 32],
) -> Result<[u8; 32]> {
    // The tunnel listener MASCOT uses, held until it finishes.
    let mut _registration = None;
    let mut _claim = None;
    let (coordination, mapped, own) = if role == NativeRole::Sponsor {
        let reservation = StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let base = reservation.local_addr()?.port();
        let registration = register(tunnel, base).await?;
        let mapped = registration.port();
        _registration = Some(registration);
        peer.send(
            "mascot_port",
            &[],
            serde_json::from_value(
                json!({"base": base, "mapped": mapped, "session": hex::encode(session)}),
            )?,
        )
        .await?;
        drop(reservation);
        (base, mapped, None)
    } else {
        let assigned = peer.receive("mascot_port").await?;
        ensure!(
            assigned.metadata.get("session") == Some(&json!(hex::encode(session))),
            "MASCOT port session differs"
        );
        let mapped = port_field(&assigned, "mapped")?;
        _claim = Some(claim(tunnel, mapped)?);
        let reservation = StdTcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let own = reservation.local_addr()?.port();
        drop(reservation);
        (mapped, mapped, Some(own))
    };
    eprintln!(
        "NATIVE_MASCOT_PORT role={role:?} session={} coordination={coordination} mapped={mapped} own={own:?}",
        hex::encode(session)
    );
    let runtime_dir = runtime.output.join(format!("{}-mascot", role_name(role)));
    let data = runtime_dir.join("Player-Data");
    let source = runtime.mp_spdz("Programs");
    let certs = runtime.output.join("mascot-certs");
    let party = party_number(role);
    task::spawn_blocking(move || -> Result<()> {
        fs::create_dir_all(&data)?;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        symlink(source, runtime_dir.join("Programs"))?;
        for peer in 0..=1 {
            fs::copy(
                certs.join(format!("P{peer}.pem")),
                data.join(format!("P{peer}.pem")),
            )?;
        }
        fs::copy(
            certs.join(format!("P{party}.key")),
            data.join(format!("P{party}.key")),
        )?;
        Ok(())
    })
    .await??;
    let status = runtime
        .openssl()
        .arg("rehash")
        .arg(
            runtime
                .output
                .join(format!("{}-mascot/Player-Data", role_name(role))),
        )
        .stdin(Stdio::null())
        .output()
        .await?;
    ensure!(status.status.success(), "MASCOT certificate rehash failed");
    let mut command = Command::new(runtime.mp_spdz("mascot-party.x"));
    let sponsor_host = env::var("HANDOFF_SPONSOR_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    if let Some(own) = own {
        command.arg("-mp").arg(own.to_string());
    }
    command
        .args(["-N", "2", "-I", "-P", P256_PRIME, "-S", "128", "-pn"])
        .arg(coordination.to_string())
        .args(["-h", &sponsor_host, "-p"])
        .arg(party.to_string())
        .arg("concurro_ectf_field")
        .current_dir(runtime.output.join(format!("{}-mascot", role_name(role))))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if role == NativeRole::Concurro {
        command.env("HANDOFF_MASCOT_PROXY_PORT", coordination.to_string());
    }
    let mut child = command.spawn().context("start checked MASCOT conversion")?;
    let coordinates = format!(
        "{}\n{}\n",
        BigUint::from_bytes_be(&point[..32]),
        BigUint::from_bytes_be(&point[32..])
    );
    child
        .stdin
        .take()
        .context("MASCOT stdin missing")?
        .write_all(coordinates.as_bytes())
        .await?;
    let output = time::timeout(
        runtime.benchmark_timeout.max(Duration::from_secs(120)),
        child.wait_with_output(),
    )
    .await
    .context("MASCOT conversion timeout")??;
    tokio::fs::write(
        runtime
            .output
            .join(format!("{}-arithmetic-metrics.log", role_name(role))),
        &output.stderr,
    )
    .await?;
    ensure!(
        output.status.success(),
        "checked arithmetic conversion failed for {}: {}",
        role_name(role),
        output.status
    );
    let stdout = String::from_utf8(output.stdout)?;
    ensure!(
        stdout.lines().any(|line| line == "valid 1"),
        "checked arithmetic validation missing"
    );
    let decimal = stdout
        .lines()
        .find_map(|line| line.strip_prefix("share "))
        .context("checked arithmetic private output missing")?;
    let signed = BigInt::parse_bytes(decimal.as_bytes(), 10).context("invalid arithmetic share")?;
    let prime = BigInt::from_biguint(
        Sign::Plus,
        BigUint::parse_bytes(P256_PRIME.as_bytes(), 10).unwrap(),
    );
    let reduced = ((signed % &prime) + &prime) % &prime;
    let bytes = reduced.to_biguint().unwrap().to_bytes_be();
    ensure!(bytes.len() <= 32, "arithmetic share overflow");
    let mut share = [0; 32];
    share[32 - bytes.len()..].copy_from_slice(&bytes);
    let binding = sha256(
        &[
            b"Concurro/Handoff/v1/checked-ectf".as_slice(),
            &session,
            &h2,
        ]
        .concat(),
    );
    peer.send("arithmetic_complete", &binding, Map::new())
        .await?;
    ensure!(
        peer.receive("arithmetic_complete").await?.data == binding,
        "arithmetic session binding differs"
    );
    Ok(share)
}

/// Public circuit identity and role-private input for one fresh MPC execution.
pub struct CircuitSpec<'a> {
    /// Accepted public circuit file.
    pub circuit: &'a Path,
    /// Exact role-private bytes sent to the helper's stdin.
    pub private: &'a [u8],
    /// Phase label bound into the helper session digest.
    pub phase: &'a str,
    /// Joint key-share session identifier.
    pub session: [u8; 32],
}

/// One fresh authenticated MPC helper held between setup and private input.
struct MpcRun {
    /// Child process killed if the session is dropped.
    child: Child,
    /// Private input pipe, retained only for a prepared run.
    stdin: Option<ChildStdin>,
    /// Output and diagnostic-log drain tasks.
    drains: JoinSet<Result<Option<Vec<u8>>>>,
    /// One bound deadline for setup and completion.
    deadline: time::Instant,
    /// Party label for failure evidence.
    party: &'static str,
    /// Bound circuit phase.
    phase: String,
    /// The Sponsor's tunnel registration, held until the helper finishes.
    _registration: Option<Registration>,
    /// Concurro's tunnel listener, held until the helper finishes.
    _claim: Option<Claim>,
}

impl MpcRun {
    /// Launch and authenticate one helper; optionally await input-independent preparation.
    async fn launch<C: AsyncRead + AsyncWrite + Unpin>(
        peer: &mut Peer<C>,
        role: NativeRole,
        runtime: &Runtime,
        tunnel: Option<&Arc<Tunnel>>,
        circuit: &Path,
        phase: &str,
        session: [u8; 32],
        prepared: bool,
        private: Option<&[u8]>,
    ) -> Result<Self> {
        let work = circuit_workspace(
            runtime,
            &runtime
                .output
                .join(format!("{}-circuit-work", role_name(role))),
        )
        .await?;
        let digest = sha256(&tokio::fs::read(circuit).await?);
        let binding = hex::encode(sha256(
            &[
                b"Concurro/Handoff/MPC/v1".as_slice(),
                &session,
                phase.as_bytes(),
                &digest,
            ]
            .concat(),
        ));
        let party = if role == NativeRole::Sponsor {
            "1"
        } else {
            "2"
        };
        let binary = if prepared {
            "build/HandoffPartyKrrwPrepared"
        } else {
            "build/HandoffPartyKrrw"
        };
        let mut command = Command::new(runtime.distefano(binary));
        command
            .arg(party)
            .arg(circuit)
            .current_dir(work)
            .env("HANDOFF_MPC_SESSION_BINDING", binding)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut claimed = None;
        if role == NativeRole::Concurro {
            let assignment = peer.receive("mpc_port").await?;
            ensure!(
                assignment.metadata.get("phase") == Some(&json!(phase)),
                "MPC phase mismatch"
            );
            let port = assignment
                .metadata
                .get("port")
                .and_then(Value::as_str)
                .context("MPC port missing")?
                .parse()?;
            claimed = Some(claim(tunnel, port)?);
            command.arg(port.to_string());
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start {phase} MPC"))?;
        let mut stdin = child.stdin.take().context("MPC stdin missing")?;
        let mut stdout = child.stdout.take().context("MPC stdout missing")?;
        let stderr = child.stderr.take().context("MPC stderr missing")?;
        let log = runtime
            .output
            .join(format!("{}-{phase}-mpc.log", role_name(role)));
        let (ready_tx, ready_rx) = oneshot::channel();
        let (prepared_tx, prepared_rx) = oneshot::channel();
        let mut drains = JoinSet::new();
        drains.spawn(async move {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await?;
            Ok::<Option<Vec<u8>>, anyhow::Error>(Some(bytes))
        });
        drains.spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            let mut file = tokio::fs::File::create(log).await?;
            let mut ready_tx = Some(ready_tx);
            let mut prepared_tx = Some(prepared_tx);
            while let Some(line) = lines.next_line().await? {
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
                if let Some(text) = line.split("HANDOFF_READY ").nth(1) {
                    let port = text
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<u16>().ok());
                    if let (Some(sender), Some(port)) = (ready_tx.take(), port) {
                        let _ = sender.send(port);
                    }
                }
                if line == "HANDOFF_PREPARED" {
                    if let Some(sender) = prepared_tx.take() {
                        let _ = sender.send(());
                    }
                }
            }
            Ok::<Option<Vec<u8>>, anyhow::Error>(None)
        });
        let stdin = if let Some(private) = private {
            stdin.write_all(private).await?;
            drop(stdin);
            None
        } else {
            Some(stdin)
        };
        let deadline = time::Instant::now()
            + runtime
                .benchmark_timeout
                .max(if role == NativeRole::Sponsor {
                    Duration::from_secs(180)
                } else {
                    Duration::from_secs(120)
                });
        let mut registered = None;
        if role == NativeRole::Sponsor {
            let port = time::timeout_at(deadline, ready_rx)
                .await
                .context("MPC sponsor did not bind")?
                .context("MPC sponsor exited before readiness")?;
            let registration = register(tunnel, port).await?;
            peer.send(
                "mpc_port",
                &[],
                serde_json::from_value(
                    json!({"port": registration.port().to_string(), "phase": phase}),
                )?,
            )
            .await?;
            registered = Some(registration);
        }
        if prepared {
            time::timeout_at(deadline, prepared_rx)
                .await
                .context("MPC preparation timeout")?
                .context("MPC helper exited before preparation")?;
        }
        Ok(Self {
            child,
            stdin,
            drains,
            deadline,
            party,
            phase: phase.to_owned(),
            _registration: registered,
            _claim: claimed,
        })
    }

    /// Supply any deferred input, collect output, and compare both parties' hashes.
    async fn finish<C: AsyncRead + AsyncWrite + Unpin>(
        mut self,
        peer: &mut Peer<C>,
        private: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match (self.stdin.take(), private) {
            (Some(mut stdin), Some(bytes)) => {
                stdin.write_all(bytes).await?;
                drop(stdin);
            }
            (None, None) => {}
            _ => bail!("MPC private input state mismatch"),
        }
        let status = match time::timeout_at(self.deadline, self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.start_kill()?;
                self.child.wait().await?;
                bail!("MPC completion timeout");
            }
        };
        let output = time::timeout_at(self.deadline, async {
            let mut output = None;
            while let Some(result) = self.drains.join_next().await {
                if let Some(bytes) = result?? {
                    output = Some(bytes);
                }
            }
            output.context("MPC stdout missing")
        })
        .await
        .context("MPC output drain timeout")??;
        ensure!(
            status.success() && output.first() == Some(&1),
            "{} MPC failed: party {}, exit {}, bytes {}",
            self.phase,
            self.party,
            status,
            output.len()
        );
        let hash = sha256(&output);
        peer.send("mpc_hash", &hash, metadata("phase", json!(self.phase)))
            .await?;
        let other = peer.receive("mpc_hash").await?;
        ensure!(
            other.metadata.get("phase") == Some(&json!(self.phase)) && other.data == hash,
            "{} MPC public outputs differ",
            self.phase
        );
        Ok(output)
    }
}

/// A bound prefix MPC whose fresh preprocessing completed before provider connect.
pub struct PreparedCircuit {
    /// The prepared helper.
    run: MpcRun,
    /// The cached circuit it runs, kept until it finishes.
    _circuit: Circuit,
}

impl PreparedCircuit {
    /// Prepare one bound prefix circuit without private TLS or credential inputs.
    pub async fn start<C: AsyncRead + AsyncWrite + Unpin>(
        peer: &mut Peer<C>,
        role: NativeRole,
        runtime: &Runtime,
        tunnel: Option<&Arc<Tunnel>>,
        circuit: Circuit,
        session: [u8; 32],
    ) -> Result<Self> {
        let run = MpcRun::launch(
            peer,
            role,
            runtime,
            tunnel,
            circuit.path(),
            "prefix",
            session,
            true,
            None,
        )
        .await?;
        Ok(Self {
            run,
            _circuit: circuit,
        })
    }

    /// Supply private input after handshake verification and check identical public output.
    pub async fn finish<C: AsyncRead + AsyncWrite + Unpin>(
        self,
        peer: &mut Peer<C>,
        private: &[u8],
    ) -> Result<Vec<u8>> {
        self.run.finish(peer, Some(private)).await
    }
}

/// Run the accepted two-party circuit and compare exact public output hashes.
pub async fn circuit_pair<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    role: NativeRole,
    runtime: &Runtime,
    tunnel: Option<&Arc<Tunnel>>,
    spec: CircuitSpec<'_>,
) -> Result<Vec<u8>> {
    let run = MpcRun::launch(
        peer,
        role,
        runtime,
        tunnel,
        spec.circuit,
        spec.phase,
        spec.session,
        false,
        Some(spec.private),
    )
    .await?;
    run.finish(peer, None).await
}

/// Make the circuit's relative public dependencies available in private work space.
async fn circuit_workspace(runtime: &Runtime, directory: &Path) -> Result<PathBuf> {
    let runtime = runtime.clone();
    let directory = directory.to_owned();
    task::spawn_blocking(move || circuit_workspace_sync(&runtime, &directory)).await?
}

/// Perform circuit workspace preparation on a blocking thread.
fn circuit_workspace_sync(runtime: &Runtime, directory: &Path) -> Result<PathBuf> {
    let source = directory.join("src");
    let work = source.join("build");
    fs::create_dir_all(work.join("data"))?;
    for name in ["emp-tool", "2pc"] {
        let link = source.join(name);
        if !link.exists() {
            symlink(runtime.distefano(&format!("src/{name}")), &link)?;
        }
    }
    Ok(work)
}

/// Expose Sponsor-local `port` to Concurro's helper.
pub async fn register(tunnel: Option<&Arc<Tunnel>>, port: u16) -> Result<Registration> {
    tunnel
        .context("Sponsor tunnel missing")?
        .register(port)
        .await
}

/// Take the tunnel listener the Sponsor named for Concurro's helper.
pub fn claim(tunnel: Option<&Arc<Tunnel>>, port: u16) -> Result<Claim> {
    tunnel.context("Concurro tunnel missing")?.claim(port)
}

/// Convert a role into its MASCOT party number.
fn party_number(role: NativeRole) -> u8 {
    if role == NativeRole::Sponsor { 0 } else { 1 }
}

/// Convert a role into the helper file prefix.
fn role_name(role: NativeRole) -> &'static str {
    if role == NativeRole::Sponsor {
        "sponsor"
    } else {
        "concurro"
    }
}

/// Extract a numeric control port with its wire range checked.
fn port_field(message: &Message, key: &str) -> Result<u16> {
    let value = message
        .metadata
        .get(key)
        .and_then(Value::as_u64)
        .context("control port missing")?;
    Ok(u16::try_from(value)?)
}

/// Produce one JSON metadata field.
pub fn metadata(key: &str, value: Value) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(key.into(), value);
    map
}

/// Compute SHA-256 over exact protocol bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::{CircuitSpec, KeyShare, Peer, Runtime, circuit_pair, prefix_circuit};
    use crate::{NativeLimits, NativeRole};
    use concurro_relay_native_transport::tunnel::{Role, Tunnel};
    use std::{
        fs,
        os::{fd::AsRawFd, unix::fs::PermissionsExt},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    /// Make a fresh fake helper root for failure and cancellation checks.
    fn runtime() -> Runtime {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("native-helper-test-{stamp}"));
        fs::create_dir_all(root.join("DiStefano/build")).unwrap();
        Runtime {
            output: root.join("output"),
            circuit_cache: root.join("cache"),
            limits: NativeLimits::DEFAULT,
            root,
            benchmark_timeout: Duration::ZERO,
        }
    }

    /// Report unavailable helpers and failed offer writers without a fallback.
    #[tokio::test]
    async fn unavailable_and_failed_keyshare() {
        let runtime = runtime();
        let error = KeyShare::start(&runtime).await.err().unwrap().to_string();
        assert!(error.contains("start HandoffKeyShare"));
        let path = runtime.distefano("build/HandoffKeyShare");
        fs::write(&path, b"#!/bin/sh\nexit 7\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let error = KeyShare::start(&runtime).await.err().unwrap().to_string();
        assert!(error.contains("early eof") || error.contains("key-share offer"));
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Dropping an active helper closes the session-owned child process.
    #[tokio::test]
    async fn cancelled_keyshare_stops_child() {
        let runtime = runtime();
        let path = runtime.distefano("build/HandoffKeyShare");
        fs::write(&path, b"#!/bin/sh\nprintf '%069d' 0\nexec sleep 60\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let (helper, offer) = KeyShare::start(&runtime).await.unwrap();
        assert_eq!(offer.len(), 69);
        let pid = helper.child.id().unwrap() as i32;
        drop(helper);
        let gone = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                // SAFETY: positive pid belongs to the just-created fake helper.
                if unsafe { libc::kill(pid, 0) } == -1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(gone.is_ok(), "cancelled helper process survived");
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Cancelling a waiter must release its file handle without starting a generator.
    #[tokio::test]
    async fn cancelled_prefix_lock_waiter() {
        let runtime = runtime();
        fs::create_dir_all(&runtime.circuit_cache).unwrap();
        let lock_path = runtime.circuit_cache.join("codex-32-16-1.txt.lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .unwrap();
        // SAFETY: flock receives the live test file descriptor.
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let task_runtime = runtime.clone();
        let waiter =
            tokio::spawn(async move { prefix_circuit(&task_runtime, "codex", 32, 16, 1).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished());
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        drop(lock);
        assert!(!runtime.circuit_cache.join("codex-32-16-1.txt").exists());
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Cancelling a running generator kills it, releases the lock, and publishes no partial file.
    #[tokio::test]
    async fn cancelled_prefix_generator() {
        let runtime = runtime();
        fs::create_dir_all(runtime.distefano("src/emp-tool")).unwrap();
        fs::create_dir_all(runtime.distefano("src/2pc")).unwrap();
        let helper = runtime.distefano("build/HandoffPrefix");
        let pid_file = runtime.root.join("generator.pid");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nexec sleep 60\n",
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let task_runtime = runtime.clone();
        let generator =
            tokio::spawn(async move { prefix_circuit(&task_runtime, "codex", 32, 16, 1).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        generator.abort();
        assert!(generator.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                // SAFETY: positive pid belongs to this test's generator.
                if unsafe { libc::kill(pid, 0) } == -1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let path = runtime.circuit_cache.join("codex-32-16-1.txt");
        assert!(!path.exists());
        fs::write(&helper, b"#!/bin/sh\nprintf 'public' > \"$5\"\n").unwrap();
        assert_eq!(
            prefix_circuit(&runtime, "codex", 32, 16, 1)
                .await
                .unwrap()
                .path(),
            path
        );
        assert_eq!(fs::read(path).unwrap(), b"public");
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Cold distinct keys use separate workspaces; two calls for one key publish once.
    #[tokio::test]
    async fn cold_prefix_keys_and_single_publication() {
        let runtime = runtime();
        fs::create_dir_all(runtime.distefano("src/emp-tool")).unwrap();
        fs::create_dir_all(runtime.distefano("src/2pc")).unwrap();
        let helper = runtime.distefano("build/HandoffPrefix");
        let calls = runtime.root.join("prefix-calls.log");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\npwd >> '{}'\nprintf 'public' > \"$5\"\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let (one, two) = tokio::try_join!(
            prefix_circuit(&runtime, "codex", 32, 16, 1),
            prefix_circuit(&runtime, "codex", 33, 16, 1),
        )
        .unwrap();
        assert_ne!(one.path(), two.path());
        assert_eq!(fs::read(one.path()).unwrap(), b"public");
        assert_eq!(fs::read(two.path()).unwrap(), b"public");
        let (three, again) = tokio::try_join!(
            prefix_circuit(&runtime, "codex", 34, 16, 1),
            prefix_circuit(&runtime, "codex", 34, 16, 1),
        )
        .unwrap();
        assert_eq!(three.path(), again.path());
        let workspaces: Vec<_> = fs::read_to_string(calls)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(workspaces.len(), 3);
        assert_eq!(
            workspaces
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Drain a public output larger than a pipe while waiting for both helpers to exit.
    #[tokio::test]
    async fn circuit_pair_drains_large_public_output() {
        let sponsor_runtime = runtime();
        let concurro_runtime = Runtime {
            output: sponsor_runtime.root.join("concurro-output"),
            ..sponsor_runtime.clone()
        };
        sponsor_runtime.prepare().await.unwrap();
        concurro_runtime.prepare().await.unwrap();
        fs::create_dir_all(sponsor_runtime.distefano("src/emp-tool")).unwrap();
        fs::create_dir_all(sponsor_runtime.distefano("src/2pc")).unwrap();
        let helper = sponsor_runtime.distefano("build/HandoffPartyKrrw");
        fs::write(&helper, b"#!/usr/bin/env python3\nimport socket,sys\nif sys.argv[1] == '1':\n s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen()\n print('HANDOFF_READY',s.getsockname()[1],file=sys.stderr,flush=True)\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'\\x01'+b'x'*200000)\nsys.stdout.buffer.flush()\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let circuit = sponsor_runtime.root.join("fake-circuit.txt");
        fs::write(&circuit, b"public circuit").unwrap();
        let (sponsor_control, concurro_control) = tokio::io::duplex(1024);
        let (sponsor_aux, concurro_aux) = tokio::io::duplex(1024);
        let sponsor_tunnel = Arc::new(Tunnel::start(sponsor_aux, Role::Sponsor));
        let concurro_tunnel = Arc::new(Tunnel::start(concurro_aux, Role::Concurro));
        let mut sponsor = Peer::new(sponsor_control);
        let mut concurro = Peer::new(concurro_control);
        let sponsor_spec = CircuitSpec {
            circuit: &circuit,
            private: b"sponsor private",
            phase: "test",
            session: [7; 32],
        };
        let concurro_spec = CircuitSpec {
            circuit: &circuit,
            private: b"concurro private",
            phase: "test",
            session: [7; 32],
        };
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::try_join!(
                circuit_pair(
                    &mut sponsor,
                    NativeRole::Sponsor,
                    &sponsor_runtime,
                    Some(&sponsor_tunnel),
                    sponsor_spec
                ),
                circuit_pair(
                    &mut concurro,
                    NativeRole::Concurro,
                    &concurro_runtime,
                    Some(&concurro_tunnel),
                    concurro_spec
                ),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.0, result.1);
        assert_eq!(result.0.len(), 200001);
        assert_eq!(result.0[0], 1);
        fs::remove_dir_all(sponsor_runtime.root).unwrap();
    }

    /// An error after readiness stops the child and its two pipe-drain tasks.
    #[tokio::test]
    async fn circuit_readiness_error_stops_child() {
        let runtime = runtime();
        runtime.prepare().await.unwrap();
        fs::create_dir_all(runtime.distefano("src/emp-tool")).unwrap();
        fs::create_dir_all(runtime.distefano("src/2pc")).unwrap();
        let pid_file = runtime.root.join("mpc.pid");
        let helper = runtime.distefano("build/HandoffPartyKrrw");
        fs::write(&helper, format!("#!/usr/bin/env python3\nimport os,socket,sys,time\nopen('{}','w').write(str(os.getpid()))\ns=socket.socket();s.bind(('127.0.0.1',0));s.listen()\nprint('HANDOFF_READY',s.getsockname()[1],file=sys.stderr,flush=True)\ntime.sleep(60)\n", pid_file.display())).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let circuit = runtime.root.join("fake-circuit.txt");
        fs::write(&circuit, b"public circuit").unwrap();
        let (stream, _other) = tokio::io::duplex(1024);
        let mut peer = Peer::new(stream);
        let spec = CircuitSpec {
            circuit: &circuit,
            private: b"private",
            phase: "test",
            session: [7; 32],
        };
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            circuit_pair(&mut peer, NativeRole::Sponsor, &runtime, None, spec),
        )
        .await
        .unwrap()
        .err()
        .unwrap();
        assert!(error.to_string().contains("Sponsor tunnel missing"));
        let pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                // SAFETY: positive pid belongs to this test's fake MPC helper.
                if unsafe { libc::kill(pid, 0) } == -1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            fs::read_to_string(runtime.output.join("sponsor-test-mpc.log"))
                .unwrap()
                .contains("HANDOFF_READY")
        );
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// Make a fake prefix generator writing its lengths, and a runtime
    /// keeping `limit` circuits.
    fn generating(limit: usize) -> Runtime {
        let mut runtime = runtime();
        runtime.limits.cached_circuits = limit.try_into().unwrap();
        fs::create_dir_all(runtime.distefano("src/emp-tool")).unwrap();
        fs::create_dir_all(runtime.distefano("src/2pc")).unwrap();
        let helper = runtime.distefano("build/HandoffPrefix");
        fs::write(&helper, b"#!/bin/sh\nprintf \"$2\" > \"$5\"\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        runtime
    }

    /// The circuits a cache holds, by their first length.
    fn cached(runtime: &Runtime) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&runtime.circuit_cache)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".txt"))
            .collect();
        names.sort();
        names
    }

    /// Beyond the limit the least recently used circuit nobody holds goes,
    /// along with abandoned generator output; one in use stays.
    #[tokio::test]
    async fn cache_evicts_least_recently_used() {
        let runtime = generating(2);
        let held = prefix_circuit(&runtime, "codex", 32, 16, 1).await.unwrap();
        drop(prefix_circuit(&runtime, "codex", 33, 16, 1).await.unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
        fs::write(runtime.circuit_cache.join("codex-99-16-1.tmp"), b"stale").unwrap();
        fs::write(runtime.circuit_cache.join("codex-99-16-1.txt.lock"), b"").unwrap();
        // 32 is older but held, so 33 goes.
        drop(prefix_circuit(&runtime, "codex", 34, 16, 1).await.unwrap());
        assert_eq!(cached(&runtime), ["codex-32-16-1.txt", "codex-34-16-1.txt"]);
        assert!(!runtime.circuit_cache.join("codex-99-16-1.tmp").exists());
        assert!(
            !runtime
                .circuit_cache
                .join("codex-33-16-1.txt.lock")
                .exists()
        );
        assert!(
            !runtime
                .circuit_cache
                .join("workspace/codex-33-16-1.txt")
                .exists()
        );
        assert_eq!(fs::read(held.path()).unwrap(), b"32");
        drop(held);
        // Using 34 again makes 32 the least recently used.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(prefix_circuit(&runtime, "codex", 34, 16, 1).await.unwrap());
        drop(prefix_circuit(&runtime, "codex", 35, 16, 1).await.unwrap());
        assert_eq!(cached(&runtime), ["codex-34-16-1.txt", "codex-35-16-1.txt"]);
        fs::remove_dir_all(runtime.root).unwrap();
    }

    /// A cache directory others can write to, or a link, is refused.
    #[tokio::test]
    async fn cache_directory_must_be_private() {
        let runtime = generating(2);
        fs::create_dir_all(&runtime.circuit_cache).unwrap();
        fs::set_permissions(&runtime.circuit_cache, fs::Permissions::from_mode(0o777)).unwrap();
        let error = prefix_circuit(&runtime, "codex", 32, 16, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("writable by other users"), "{error}");
        fs::remove_dir(&runtime.circuit_cache).unwrap();
        let elsewhere = runtime.root.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &runtime.circuit_cache).unwrap();
        let error = prefix_circuit(&runtime, "codex", 32, 16, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("is not a directory"), "{error}");
        fs::remove_dir_all(runtime.root).unwrap();
    }
}
