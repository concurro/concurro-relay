//! Runs one TLS 1.3 role on the existing authenticated relay link pair.

use std::{
    collections::HashSet,
    env, fs,
    num::{NonZeroU64, NonZeroUsize},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::UnixListener,
    process::Command,
    signal::unix::{SignalKind, signal},
    sync::{mpsc::UnboundedSender, oneshot, watch},
    time::{self, Duration},
};

use concurro_relay_native_transport::tunnel;
use concurro_relay_protocol::{identity, route::Route};

pub mod bootstrap;
pub mod helpers;
pub mod ingress;
pub mod proof;
pub mod session;
pub mod worker;
pub use concurro_relay_native_transport as transport;

static WORKER_GROUPS: OnceLock<Mutex<HashSet<i32>>> = OnceLock::new();

/// Own the native worker process group and its local bridge sockets.
struct NativeSession {
    /// Private directory containing this session's Unix sockets.
    socket_dir: PathBuf,
    control_path: PathBuf,
    auxiliary_path: PathBuf,
    worker_group: Option<i32>,
}

impl NativeSession {
    /// Create a private short socket directory apart from the evidence path.
    fn create(output_root: PathBuf) -> Result<(Self, PathBuf)> {
        let id = u64::from_be_bytes(identity::random());
        let session = output_root.join(format!("concurro-native-{id:016x}"));
        fs::create_dir_all(&session)?;
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700))?;
        let socket_dir = env::temp_dir().join(format!("cn-{id:016x}"));
        fs::create_dir(&socket_dir)?;
        let control_path = socket_dir.join("control.sock");
        let auxiliary_path = socket_dir.join("aux.sock");
        let native = Self::new(socket_dir.clone(), control_path, auxiliary_path);
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))?;
        Ok((native, session))
    }

    /// Track sockets before spawning, so startup errors remove them too.
    fn new(socket_dir: PathBuf, control_path: PathBuf, auxiliary_path: PathBuf) -> Self {
        Self {
            socket_dir,
            control_path,
            auxiliary_path,
            worker_group: None,
        }
    }

    /// Register the isolated process group after a successful spawn.
    fn worker(&mut self, pid: i32) {
        WORKER_GROUPS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(pid);
        self.worker_group = Some(pid);
    }

    /// Stop the worker and every native subprocess in its group.
    fn stop(&mut self) {
        if let Some(pid) = self.worker_group.take() {
            // SAFETY: pid is the positive process-group leader returned by spawn.
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            WORKER_GROUPS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .remove(&pid);
        }
    }
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_file(&self.control_path);
        let _ = fs::remove_file(&self.auxiliary_path);
        let _ = fs::remove_dir(&self.socket_dir);
    }
}

/// Stop every native worker group before the process exits on a signal.
pub fn stop_workers() {
    for pid in WORKER_GROUPS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .iter()
    {
        // SAFETY: each pid was registered from an isolated native worker group.
        unsafe { libc::killpg(*pid, libc::SIGKILL) };
    }
}

/// Wait for an ordinary terminal interrupt or service termination.
pub async fn shutdown_signal() -> Result<()> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
    Ok(())
}

/// The local role to run on an authenticated relay link.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum NativeRole {
    /// The credential-owning relay process.
    Sponsor,
    /// The verifier-side process.
    Concurro,
}

/// A request Concurro asks the Sponsor to approve before any of it reaches
/// the provider. Released bytes must match the retained wire body decoded into `prompt`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct NativeRequest {
    /// Review number on this TLS connection.
    pub request: u64,
    /// Decoded HTTP request body or WebSocket message text.
    pub prompt: String,
    /// Digest of the prompt bytes.
    pub sha256: String,
    /// Provider path, for HTTP routes.
    pub path: Option<String>,
    /// Public request headers, for HTTP routes; never the credential.
    pub headers: Vec<(String, String)>,
    /// Identifier of the Sponsor's native session.
    pub session_id: String,
}

/// The Sponsor's answer to a [`NativeRequest`].
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct NativeVerdict {
    /// The review number answered.
    pub request: u64,
    pub accept: bool,
    /// Why, as told to Concurro.
    pub reason: Option<String>,
}

/// A request awaiting the Sponsor's verdict.
#[derive(Debug)]
pub struct Review {
    pub request: NativeRequest,
    pub reply: oneshot::Sender<NativeVerdict>,
}

/// Concurro-reported provider usage for an approved request.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct NativeAudit {
    /// The review number of the request the usage belongs to.
    pub request: u64,
    /// Digest of the request's prompt bytes.
    pub sha256: String,
    /// Provider usage relayed by Concurro; Sponsor cannot verify this field.
    pub usage: Option<Value>,
    /// Identifier of the Sponsor's native session.
    pub session_id: String,
}

/// Resource bounds for native sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLimits {
    /// Longest Sponsor credential Concurro builds a prefix circuit for.
    pub credential_bytes: NonZeroUsize,
    /// MiB of generated prefix circuits kept in the shared cache.
    pub circuit_cache_mib: NonZeroU64,
    /// Helper channels Concurro may hold open to the Sponsor at once.
    pub tunnel_channels: NonZeroUsize,
}

impl NativeLimits {
    /// Bounds used unless configured.
    pub const DEFAULT: Self = Self {
        credential_bytes: NonZeroUsize::new(4096).unwrap(),
        circuit_cache_mib: NonZeroU64::new(8192).unwrap(),
        tunnel_channels: tunnel::CHANNELS,
    };
}

impl Default for NativeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl NativeRole {
    /// The role name understood by the bundled worker.
    fn argument(self) -> &'static str {
        match self {
            Self::Sponsor => "sponsor",
            Self::Concurro => "concurro",
        }
    }
}

/// Public session details and the Sponsor's local credential, when applicable.
pub struct NativeOptions {
    /// Which native role this process runs.
    pub role: NativeRole,
    /// Provider route served by this session.
    pub route: Route,
    /// Provider TCP destination; TLS certificate identity is route-bound.
    pub provider_host: String,
    /// Provider TCP port.
    pub provider_port: u16,
    /// CA file used to verify the provider certificate.
    pub provider_ca: PathBuf,
    /// Local CLI ingress address on Concurro.
    pub listen: Option<String>,
    /// Sponsor-only provider credential.
    pub token: Option<String>,
    /// Sponsor-selected ChatGPT account or Antigravity subscription project.
    pub account: Option<String>,
    /// Sponsor-side stream of per-request native audit events.
    pub audit: Option<UnboundedSender<NativeAudit>>,
    /// Sponsor-side requests awaiting approval; without it every request is
    /// rejected.
    pub review: Option<UnboundedSender<Review>>,
    /// Concurro-side stream of bound local CLI ingress addresses.
    pub ready: Option<UnboundedSender<String>>,
    /// Resource bounds for the session.
    pub limits: NativeLimits,
}

/// Locate the self-contained worker and native runtime beside the executable.
pub fn bundle() -> Result<PathBuf> {
    if let Some(bundle) = env::var_os("CONCURRO_NATIVE_BUNDLE") {
        return Ok(PathBuf::from(bundle));
    }
    Ok(env::current_exe()?
        .parent()
        .context("executable has no directory")?
        .join("../native-runtime"))
}

/// Bridge the two authenticated link streams to one bundled native role.
pub async fn bridge<C, P>(control: C, auxiliary: P, options: NativeOptions) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let bundle = bundle()?;
    let output = env::var_os("CONCURRO_NATIVE_OUTPUT").map(PathBuf::from);
    // Without a configured output root, circuits live in the user's cache
    // rather than the shared temporary directory.
    let circuit_cache = output
        .clone()
        .or_else(|| dirs::cache_dir().map(|cache| cache.join("concurro-relay")))
        .unwrap_or_else(env::temp_dir)
        .join("public-circuits");
    let output_root = output.unwrap_or_else(env::temp_dir);
    let (mut native_session, session) = NativeSession::create(output_root)?;
    let control_path = native_session.control_path.clone();
    let auxiliary_path = native_session.auxiliary_path.clone();
    let control_listener = UnixListener::bind(&control_path)?;
    let auxiliary_listener = UnixListener::bind(&auxiliary_path)?;
    let worker = env::var_os("CONCURRO_NATIVE_RUST_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| bundle.join("concurro-native-worker"));
    let mut command = Command::new(worker);
    command.as_std_mut().process_group(0);
    command
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", bundle.join("bin").display()),
        )
        .arg("--role")
        .arg(options.role.argument())
        .arg("--route")
        .arg(match options.route {
            Route::ChatgptSubscription => "codex",
            Route::ClaudeSubscription | Route::AntigravitySubscription => "tls_key_update",
        })
        .arg("--provider")
        .arg(if options.route == Route::AntigravitySubscription {
            "antigravity"
        } else {
            "claude"
        })
        .arg("--control")
        .arg(&control_path)
        .arg("--aux")
        .arg(&auxiliary_path)
        .arg("--runtime")
        .arg(bundle.join("runtime"))
        .arg("--output")
        .arg(&session)
        .arg("--provider-host")
        .arg(&options.provider_host)
        .arg("--provider-port")
        .arg(options.provider_port.to_string())
        .arg("--provider-ca")
        .arg(&options.provider_ca)
        .arg("--circuit-cache")
        .arg(&circuit_cache)
        .arg("--max-credential-bytes")
        .arg(options.limits.credential_bytes.to_string())
        .arg("--circuit-cache-mib")
        .arg(options.limits.circuit_cache_mib.to_string())
        .arg("--max-tunnel-channels")
        .arg(options.limits.tunnel_channels.to_string());
    if let Some(listen) = &options.listen {
        command.arg("--listen").arg(listen);
    }
    if options.token.is_some() {
        command.stdin(std::process::Stdio::piped());
    } else {
        command.stdin(std::process::Stdio::null());
    }
    command.stdout(std::process::Stdio::piped());
    command.kill_on_drop(true);
    let mut worker = command.spawn().context("start bundled native TLS worker")?;
    native_session.worker(worker.id().context("native worker has no pid")? as i32);
    let mut stdin = worker.stdin.take();
    if let (Some(token), Some(stdin)) = (options.token, &mut stdin) {
        let mut line = serde_json::to_vec(&json!({"token": token, "account": options.account}))?;
        line.push(b'\n');
        stdin.write_all(&line).await?;
    }
    // Set once the worker is gone, when a pending review has nothing left to
    // decide.
    let (stop, stopped) = watch::channel(false);
    let mut stdout_task = {
        let stdout = worker
            .stdout
            .take()
            .expect("native worker has piped stdout");
        let (audit, review, ready) = (options.audit, options.review, options.ready);
        let mut stopped = stopped;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Some(line) = lines.next_line().await? {
                if let Some(address) = line.strip_prefix("NATIVE_READY ") {
                    eprintln!("{line}");
                    if let Some(sender) = &ready {
                        let _ = sender.send(address.to_owned());
                    }
                } else if line.starts_with("NATIVE_CANCEL ") {
                    eprintln!("{line}");
                } else if let Some(value) = line.strip_prefix("NATIVE_REVIEW ") {
                    let request: NativeRequest = serde_json::from_str(value)?;
                    let Some(verdict) = decide(review.as_ref(), request, &mut stopped).await else {
                        break;
                    };
                    let mut answer = serde_json::to_vec(&verdict)?;
                    answer.push(b'\n');
                    stdin
                        .as_mut()
                        .context("native worker has no decision pipe")?
                        .write_all(&answer)
                        .await?;
                } else if let Some(value) = line.strip_prefix("NATIVE_AUDIT ")
                    && let Some(sender) = &audit
                {
                    let event = serde_json::from_str(value)?;
                    let _ = sender.send(event);
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    };
    let result: Result<()> = async {
        let (worker_control, _) = time::timeout(Duration::from_secs(30), control_listener.accept())
            .await
            .context("native worker did not connect its control socket")??;
        let (worker_auxiliary, _) =
            time::timeout(Duration::from_secs(30), auxiliary_listener.accept())
                .await
                .context("native worker did not connect its auxiliary socket")??;
        let copied = forward(control, auxiliary, worker_control, worker_auxiliary);
        tokio::pin!(copied);
        tokio::select! {
            copied = &mut copied => {
                copied?;
                let status = time::timeout(Duration::from_millis(500), worker.wait())
                    .await.context("native link closed while its worker remained active")??;
                ensure!(status.success(), "native worker exited with {status}");
            }
            status = worker.wait() => {
                let status = status?;
                time::timeout(Duration::from_secs(5), &mut copied)
                    .await.context("native worker left its link open after exit")??;
                ensure!(status.success(), "native worker exited with {status}");
            }
        }
        Ok(())
    }
    .await;
    native_session.stop();
    let _ = time::timeout(Duration::from_secs(5), worker.wait()).await;
    let _ = stop.send(true);
    // A worker which ended while its request was reviewed leaves the review
    // waiting; nothing is left to decide.
    let audit_result = match time::timeout(Duration::from_secs(5), &mut stdout_task).await {
        Ok(finished) => finished?,
        Err(_) => {
            stdout_task.abort();
            Ok(())
        }
    };
    result?;
    audit_result
}

/// Copies between the link's two streams and the worker's until the link
/// closes, or until the worker has closed both of its streams and all it
/// wrote was delivered.
async fn forward<C, A, W, X>(
    control: C,
    auxiliary: A,
    worker_control: W,
    worker_auxiliary: X,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite,
    A: AsyncRead + AsyncWrite,
    W: AsyncRead + AsyncWrite,
    X: AsyncRead + AsyncWrite,
{
    let (mut control_read, mut control_write) = io::split(control);
    let (mut auxiliary_read, mut auxiliary_write) = io::split(auxiliary);
    let (mut worker_control_read, mut worker_control_write) = io::split(worker_control);
    let (mut worker_auxiliary_read, mut worker_auxiliary_write) = io::split(worker_auxiliary);
    let to_worker = async {
        tokio::select! {
            result = io::copy(&mut control_read, &mut worker_control_write) => result,
            result = io::copy(&mut auxiliary_read, &mut worker_auxiliary_write) => result,
        }
    };
    let from_worker = async {
        tokio::try_join!(
            io::copy(&mut worker_control_read, &mut control_write),
            io::copy(&mut worker_auxiliary_read, &mut auxiliary_write),
        )
    };
    tokio::select! {
        result = to_worker => result.map(drop),
        result = from_worker => result.map(drop),
    }
}

/// Asks `review` for a verdict on `request`, rejecting it when nobody
/// answers, or gives up on it, withdrawing the question, once `stopped`.
async fn decide(
    review: Option<&UnboundedSender<Review>>,
    request: NativeRequest,
    stopped: &mut watch::Receiver<bool>,
) -> Option<NativeVerdict> {
    let number = request.request;
    let (reply, verdict) = oneshot::channel();
    let asked = review.is_some_and(|review| review.send(Review { request, reply }).is_ok());
    tokio::select! {
        verdict = verdict => Some(match verdict {
            Ok(verdict) if asked => verdict,
            _ => NativeVerdict {
                request: number,
                accept: false,
                reason: Some("the Sponsor has no reviewer".into()),
            },
        }),
        _ = stopped.wait_for(|stopped| *stopped) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt},
        time::Duration,
    };

    use tokio::{net::UnixListener, process::Command, time};

    use super::{NativeSession, identity};

    /// Keep socket paths short and clean each session without deleting evidence.
    #[tokio::test]
    async fn socket_paths_and_independent_cleanup() {
        let root = env::temp_dir()
            .join(format!(
                "native-phase1-{:016x}",
                u64::from_be_bytes(identity::random())
            ))
            .join("e".repeat(160));
        let (first, first_evidence) = NativeSession::create(root.clone()).unwrap();
        let (second, second_evidence) = NativeSession::create(root.clone()).unwrap();
        assert!(first.control_path.as_os_str().as_bytes().len() < 104);
        assert_eq!(
            fs::metadata(&first.socket_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let first_control = UnixListener::bind(&first.control_path).unwrap();
        let first_auxiliary = UnixListener::bind(&first.auxiliary_path).unwrap();
        let second_control = UnixListener::bind(&second.control_path).unwrap();
        let first_socket_dir = first.socket_dir.clone();
        let second_socket_dir = second.socket_dir.clone();
        drop((first_control, first_auxiliary, second_control));
        drop(first);
        assert!(!first_socket_dir.exists());
        assert!(second_socket_dir.exists());
        assert!(first_evidence.exists());
        drop(second);
        assert!(!second_socket_dir.exists());
        assert!(second_evidence.exists());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    /// Stop an isolated worker process group as the bridge does on cancellation.
    #[tokio::test]
    async fn worker_process_group_cleanup() {
        let root = env::temp_dir().join(format!(
            "native-process-test-{:016x}",
            u64::from_be_bytes(identity::random())
        ));
        let (mut session, _) = NativeSession::create(root.clone()).unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        assert_ne!(pid, unsafe { libc::getpgrp() });
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        session.worker(pid);
        session.stop();
        let status = time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        drop(session);
        fs::remove_dir_all(root).unwrap();
    }

    /// Without a reviewer to answer, a request is rejected.
    #[tokio::test]
    async fn unanswered_requests_are_rejected() {
        let request = crate::NativeRequest {
            request: 2,
            prompt: "{}".into(),
            sha256: "abc".into(),
            path: None,
            headers: Vec::new(),
            session_id: "session".into(),
        };
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let verdict = super::decide(None, request.clone(), &mut stopped).await;
        assert!(verdict.is_some_and(|verdict| !verdict.accept && verdict.request == 2));
        let (review, reviews) = tokio::sync::mpsc::unbounded_channel();
        drop(reviews);
        let verdict = super::decide(Some(&review), request.clone(), &mut stopped).await;
        assert!(!verdict.unwrap().accept);

        // A review still waiting when the worker stops is withdrawn.
        let (review, mut reviews) = tokio::sync::mpsc::unbounded_channel();
        let deciding =
            tokio::spawn(async move { super::decide(Some(&review), request, &mut stopped).await });
        let pending: crate::Review = reviews.recv().await.unwrap();
        stop.send(true).unwrap();
        assert!(deciding.await.unwrap().is_none());
        assert!(pending.reply.is_closed());
    }

    /// What a worker wrote before it closed both streams reaches the link,
    /// whichever of its streams closes first and however slowly the link
    /// reads.
    #[tokio::test]
    async fn a_closing_worker_delivers_what_it_wrote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (control, mut link_control) = tokio::io::duplex(64);
        let (auxiliary, _link_auxiliary) = tokio::io::duplex(64);
        let (worker_control, mut worker_control_end) = tokio::io::duplex(64);
        let (worker_auxiliary, worker_auxiliary_end) = tokio::io::duplex(64);
        let forwarding = tokio::spawn(super::forward(
            control,
            auxiliary,
            worker_control,
            worker_auxiliary,
        ));
        let written = vec![7; 10_000];
        let worker = {
            let written = written.clone();
            tokio::spawn(async move {
                drop(worker_auxiliary_end);
                worker_control_end.write_all(&written).await.unwrap();
            })
        };
        let mut delivered = vec![0; written.len()];
        link_control.read_exact(&mut delivered).await.unwrap();
        worker.await.unwrap();
        forwarding.await.unwrap().unwrap();
        assert!(delivered == written);
    }
}
