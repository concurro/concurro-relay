//! Request-only QuickSilver helper through the existing authenticated tunnel.

use std::{io, process::Stdio, sync::Arc};

use anyhow::{Context, Result, ensure};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_provider_protocol::codex::RequestClaim;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::oneshot,
    task::JoinSet,
    time::{self, Duration},
};

use crate::{
    NativeRole,
    helpers::{Peer, Runtime},
};

/// Directional bytes through Sponsor's authenticated proof proxy.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ProofTraffic {
    /// Bytes from the Concurro prover to Sponsor verifier.
    pub concurro_to_sponsor: u64,
    /// Bytes from Sponsor verifier to Concurro prover.
    pub sponsor_to_concurro: u64,
}

/// Run one fresh proof; Sponsor releases the exact TLS record only after success.
pub async fn request<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    role: NativeRole,
    tunnel: &Arc<Tunnel>,
    runtime: &Runtime,
    claim: &RequestClaim,
    turn: u64,
) -> Result<Option<ProofTraffic>> {
    let name = if role == NativeRole::Sponsor {
        "sponsor"
    } else {
        "concurro"
    };
    let log_name = format!("{name}-request-{turn}-proof.log");
    let log = runtime.output.join(&log_name);
    let port = if role == NativeRole::Concurro {
        let assignment = peer.receive("proof_port").await?;
        ensure!(
            assignment.metadata.get("turn") == Some(&json!(turn)),
            "request proof turn mismatch"
        );
        Some(
            assignment
                .metadata
                .get("port")
                .and_then(Value::as_str)
                .context("request proof port missing")?
                .parse::<u16>()?,
        )
    } else {
        None
    };
    let mut command = Command::new(
        runtime
            .root
            .join("request-proof/target/release/handoff-request-proof"),
    );
    command.arg(if role == NativeRole::Sponsor {
        "verifier"
    } else {
        "prover"
    });
    if let Some(port) = port {
        command.arg(port.to_string());
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("start handoff-request-proof")?;
    let stderr = child
        .stderr
        .take()
        .context("request proof stderr missing")?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut file = tokio::fs::File::create(log).await?;
        let mut ready = Some(ready_tx);
        let mut completed = false;
        while let Some(line) = lines.next_line().await? {
            file.write_all(line.as_bytes()).await?;
            file.write_all(b"\n").await?;
            if let Some(port) = line
                .split("REQUEST_READY ")
                .nth(1)
                .and_then(|text| text.split_whitespace().next())
                .and_then(|text| text.parse::<u16>().ok())
                && let Some(sender) = ready.take()
            {
                let _ = sender.send(port);
            }
            completed |= line.contains("REQUEST_OK");
        }
        Ok::<_, anyhow::Error>((Some(completed), None))
    });
    let mut input = child.stdin.take().context("request proof stdin missing")?;
    // A helper which exits before reading its claim closes the pipe; its exit status and log,
    // reported below, say why, rather than the broken pipe.
    let undelivered = match input.write_all(&serde_json::to_vec(claim)?).await {
        Ok(()) => None,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Some(error),
        Err(error) => return Err(error).context("send the request claim to the proof helper"),
    };
    drop(input);
    let deadline = runtime.benchmark_timeout.max(Duration::from_secs(90));
    let proxy = if role == NativeRole::Sponsor {
        let local = time::timeout(Duration::from_secs(30), ready_rx)
            .await
            .context("request verifier did not bind")?
            .context("request verifier exited before readiness")?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let mapped = tunnel.register(listener.local_addr()?.port()).await?;
        tasks.spawn(async move {
            let (mut remote, _) = listener.accept().await?;
            let mut verifier = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, local)).await?;
            let (concurro_to_sponsor, sponsor_to_concurro) =
                tokio::io::copy_bidirectional(&mut remote, &mut verifier).await?;
            Ok::<_, anyhow::Error>((
                None,
                Some(ProofTraffic {
                    concurro_to_sponsor,
                    sponsor_to_concurro,
                }),
            ))
        });
        peer.send(
            "proof_port",
            &[],
            serde_json::from_value(json!({"port": mapped.to_string(), "turn": turn}))?,
        )
        .await?;
        true
    } else {
        false
    };
    let status = time::timeout(deadline, child.wait())
        .await
        .context("request proof timeout")??;
    let mut completed = false;
    let mut traffic = None;
    time::timeout(Duration::from_secs(5), async {
        while let Some(result) = tasks.join_next().await {
            let (log_completed, proxy_traffic) = result??;
            completed |= log_completed.unwrap_or(false);
            traffic = traffic.or(proxy_traffic);
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("request proof tasks did not close")??;
    let delivery = undelivered
        .as_ref()
        .map(|error| format!("; its claim was not delivered: {error}"))
        .unwrap_or_default();
    ensure!(
        status.success() && completed && undelivered.is_none(),
        "request-{turn} proof failed for {name}: {status}{delivery}; see {log_name} in the session output"
    );
    ensure!(!proxy || traffic.is_some(), "request proof proxy missing");
    Ok(traffic)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use concurro_relay_native_transport::{
        control::{self, Message},
        tunnel::{Role, Tunnel},
    };
    use concurro_relay_provider_protocol::codex::{RequestBinding, RequestClaim};
    use serde_json::json;
    use tokio::{
        io::duplex,
        time::{self, Duration},
    };

    use super::{NativeRole, Peer, Runtime, request};

    /// Create a disposable fake proof runtime with a direct process to reap.
    fn fake_runtime(script: &str) -> (PathBuf, Runtime) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("proof-scope-{}-{stamp}", process::id()));
        let binary = root.join("request-proof/target/release/handoff-request-proof");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::create_dir_all(root.join("output")).unwrap();
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = Runtime {
            root: root.clone(),
            output: root.join("output"),
            circuit_cache: root.join("cache"),
            benchmark_timeout: Duration::from_secs(1),
        };
        (root, runtime)
    }

    /// Use a valid claim while the fake helper determines the result.
    fn claim() -> RequestClaim {
        claim_of(b"request")
    }

    /// A valid claim for `request`.
    fn claim_of(request: &[u8]) -> RequestClaim {
        RequestClaim::new(
            &RequestBinding {
                h2: [1; 32],
                h3: [2; 32],
                key_commitment: [3; 32],
            },
            &[4; 16],
            &[5; 12],
            1,
            request,
            b"record",
        )
    }

    /// Cancellation before and after readiness kills the helper and its proxy task.
    #[tokio::test]
    async fn sponsor_cancellation_scopes_tasks() {
        for ready in [false, true] {
            let script = if ready {
                "#!/bin/sh\necho $$ > \"$(dirname \"$0\")/pid\"\necho 'REQUEST_READY 9' >&2\nexec sleep 60\n"
            } else {
                "#!/bin/sh\necho $$ > \"$(dirname \"$0\")/pid\"\nexec sleep 60\n"
            };
            let (root, runtime) = fake_runtime(script);
            let (control_local, mut control_remote) = duplex(4096);
            let (aux_sponsor, aux_concurro) = duplex(4096);
            let tunnel = Arc::new(Tunnel::start(aux_sponsor, Role::Sponsor));
            let other = Tunnel::start(aux_concurro, Role::Concurro);
            let worker_tunnel = tunnel.clone();
            let worker = tokio::spawn(async move {
                let mut peer = Peer {
                    stream: control_local,
                    events: Vec::new(),
                };
                request(
                    &mut peer,
                    NativeRole::Sponsor,
                    &worker_tunnel,
                    &runtime,
                    &claim(),
                    1,
                )
                .await
            });
            let pid_file = root.join("request-proof/target/release/pid");
            time::timeout(Duration::from_secs(3), async {
                while !pid_file.exists() {
                    time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if ready {
                let port = time::timeout(
                    Duration::from_secs(3),
                    control::receive(&mut control_remote),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(port.kind, "proof_port");
            }
            let pid: i32 = fs::read_to_string(pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            worker.abort();
            let _ = worker.await;
            time::timeout(Duration::from_secs(3), async {
                while unsafe { libc::kill(pid, 0) } == 0 {
                    time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            drop(other);
            drop(tunnel);
            fs::remove_dir_all(root).unwrap();
        }
    }

    /// A failed helper, one omitting REQUEST_OK, or one exiting before reading its claim cannot
    /// release a request, and the error reports how the helper ended.
    #[tokio::test]
    async fn prover_rejects_failure_and_missing_marker() {
        // More than a pipe buffer: the write blocks until the helper exits without reading it.
        let unread = claim_of(&vec![6; 1 << 20]);
        for (script, claim, expected) in [
            (
                "#!/bin/sh\necho failed >&2\nexit 1\n",
                claim(),
                "exit status: 1",
            ),
            (
                "#!/bin/sh\necho completed >&2\nexit 0\n",
                claim(),
                "exit status: 0",
            ),
            (
                "#!/bin/sh\nexit 3\n",
                unread,
                "exit status: 3; its claim was not delivered: Broken pipe",
            ),
        ] {
            let (root, runtime) = fake_runtime(script);
            let (control_local, mut control_remote) = duplex(4096);
            control::send(
                &mut control_remote,
                &Message {
                    kind: "proof_port".into(),
                    data: Vec::new(),
                    metadata: serde_json::from_value(json!({"turn": 1, "port": "9"})).unwrap(),
                },
            )
            .await
            .unwrap();
            let (aux, _unused) = duplex(4096);
            let tunnel = Arc::new(Tunnel::start(aux, Role::Concurro));
            let mut peer = Peer {
                stream: control_local,
                events: Vec::new(),
            };
            let result = request(
                &mut peer,
                NativeRole::Concurro,
                &tunnel,
                &runtime,
                &claim,
                1,
            )
            .await;
            let error = format!("{:#}", result.unwrap_err());
            assert!(
                error.starts_with("request-1 proof failed for concurro: ")
                    && error.contains(expected),
                "expected {expected:?}, got: {error}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}
