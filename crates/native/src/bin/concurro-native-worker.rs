//! Bundled Rust native worker for Sponsor and Concurro sessions.

use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use concurro_relay_native::{
    NativeRole,
    bootstrap::{self, BootstrapOptions},
    helpers::{self, Peer, Runtime},
    ingress, session,
    worker::{ParentGate, WorkerConfig, WorkerRoute},
};
use concurro_relay_native_transport::{
    control::{self, Message},
    tunnel::{Role, Tunnel},
};
use concurro_relay_protocol::identity;
use concurro_relay_tls13::handshake::Profile;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UnixStream,
    sync::{mpsc, oneshot},
    time,
};

/// Connect one role, retain its bootstrap and process provider continuations.
#[tokio::main]
async fn main() -> Result<()> {
    let config = WorkerConfig::parse();
    let profile = match config.route {
        WorkerRoute::Codex => Profile::Codex,
        WorkerRoute::ClaudeH2 => Profile::ClaudeH2,
    };
    let runtime = Runtime {
        root: config.runtime.clone(),
        output: config.output.clone(),
        circuit_cache: config
            .output
            .parent()
            .context("session output has no parent")?
            .join("public-circuits"),
        benchmark_timeout: Duration::from_secs(
            env::var("HANDOFF_BENCHMARK_TIMEOUT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(900),
        ),
    };
    runtime.prepare().await?;
    let control = UnixStream::connect(&config.control)
        .await
        .context("connect native control")?;
    let auxiliary = UnixStream::connect(&config.aux)
        .await
        .context("connect native auxiliary")?;
    let tunnel = Arc::new(Tunnel::start(
        auxiliary,
        if config.role == NativeRole::Sponsor {
            Role::Sponsor
        } else {
            Role::Concurro
        },
    ));
    let mut identity_peer = Peer {
        stream: control,
        events: Vec::new(),
    };
    helpers::exchange_mascot_identity(&mut identity_peer, config.role, &runtime).await?;
    let mut control = identity_peer.stream;
    if config.role == NativeRole::Sponsor {
        // The credential comes first; verdicts on requests follow, a line each.
        let mut answers = BufReader::new(tokio::io::stdin()).lines();
        let input = answers
            .next_line()
            .await?
            .context("Sponsor credential missing")?;
        let credential: Value = serde_json::from_str(&input).context("Sponsor credential JSON")?;
        let token = credential["token"]
            .as_str()
            .context("Sponsor token missing")?
            .as_bytes()
            .to_vec();
        let account = credential["account"].as_str().map(str::to_owned);
        control::send(
            &mut control,
            &Message {
                kind: "native_shape".into(),
                data: Vec::new(),
                metadata: serde_json::from_value(
                    json!({"length": token.len(), "account": account, "completion_ack": true}),
                )?,
            },
        )
        .await?;
        let template = control::receive(&mut control).await?;
        if template.kind != "native_template" {
            bail!("expected native_template")
        }
        let completion_ack = template.metadata.get("completion_ack") == Some(&json!(true));
        let mut gate = ParentGate { answers };
        let session_id = hex::encode(identity::random::<16>());
        let mut peer = Peer {
            stream: control,
            events: Vec::new(),
        };
        let first = if profile == Profile::ClaudeH2 {
            match session::sponsor_first(&mut peer, &mut gate, &runtime, &session_id).await? {
                Some(first) => Some(first),
                // Nothing of the session reached the provider. Concurro ends
                // the link once it has the rejection.
                None => {
                    let _ =
                        time::timeout(Duration::from_secs(30), control::receive(&mut peer.stream))
                            .await;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let options = BootstrapOptions {
            role: config.role,
            profile,
            runtime: runtime.clone(),
            provider_host: config.provider_host,
            provider_port: config.provider_port,
            provider_ca: config.provider_ca,
            credential: Some(token),
            account,
            codex_headers: Vec::new(),
            claude_template: first.as_ref().and_then(|first| first.template().cloned()),
        };
        let session =
            bootstrap::start_after_identity(peer.stream, Some(tunnel.clone()), options).await?;
        session::sponsor(
            session,
            tunnel,
            runtime,
            completion_ack,
            &mut gate,
            &session_id,
            first,
        )
        .await
    } else {
        let shape = control::receive(&mut control).await?;
        if shape.kind != "native_shape" {
            bail!("expected native_shape")
        }
        let account = shape
            .metadata
            .get("account")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let completion_ack = shape.metadata.get("completion_ack") == Some(&json!(true));
        let listener = ingress::bind(&config.listen).await?;
        println!("NATIVE_READY {}", listener.local_addr()?);
        if config.route == WorkerRoute::ClaudeH2 {
            let compact = env::var("CONCURRO_CLAUDE_MESSAGE_THREADS").as_deref() != Ok("0");
            let mut first = ingress::claude::accept(&listener).await?;
            if compact {
                session::claude_beta_template(&mut first.template);
            }
            control::send(
                &mut control,
                &Message {
                    kind: "native_template".into(),
                    data: Vec::new(),
                    metadata: {
                        let mut metadata = first.template.metadata()?;
                        metadata.insert("completion_ack".into(), json!(true));
                        metadata
                    },
                },
            )
            .await?;
            let mut peer = Peer {
                stream: control,
                events: Vec::new(),
            };
            let reviewed = tokio::select! {
                reviewed = session::claude_review_first(&mut peer, &first.body, &first.template, compact) => reviewed,
                () = first.watch_disconnect() => {
                    println!("NATIVE_CANCEL cli_disconnect");
                    bail!("NATIVE_CANCEL cli_disconnect");
                }
            };
            match reviewed {
                Ok(()) => {}
                // Nothing of the session reached the provider.
                Err(error) if error.is::<session::Rejected>() => {
                    return first.refuse(&error.to_string()).await;
                }
                Err(error) => return Err(error),
            }
            let options = BootstrapOptions {
                role: config.role,
                profile,
                runtime: runtime.clone(),
                provider_host: config.provider_host,
                provider_port: config.provider_port,
                provider_ca: config.provider_ca,
                credential: None,
                account,
                codex_headers: Vec::new(),
                claude_template: Some(first.template.clone()),
            };
            let session = tokio::select! {
                result = bootstrap::start_after_identity(peer.stream, Some(tunnel.clone()), options) => result?,
                () = first.watch_disconnect() => {
                    println!("NATIVE_CANCEL cli_disconnect");
                    bail!("NATIVE_CANCEL cli_disconnect");
                }
            };
            let (turns_tx, turns_rx) = mpsc::channel(8);
            let mut coordinator = tokio::spawn(session::claude_concurro(
                session,
                tunnel,
                runtime,
                turns_rx,
                completion_ack,
                compact,
            ));
            let test_turns = env::var("CONCURRO_NATIVE_TEST_TURNS_CLAUDE")
                .ok()
                .or_else(|| env::var("CONCURRO_NATIVE_TEST_TURNS").ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            tokio::select! {
                served = ingress::claude::serve(&listener, first, turns_tx.clone(), test_turns) => {
                    drop(turns_tx);
                    match served {
                        Ok(()) => coordinator.await??,
                        Err(error) => {
                            if error.to_string().starts_with("NATIVE_CANCEL ") { println!("{error}"); }
                            coordinator.abort();
                            return Err(error)
                        }
                    }
                }
                result = &mut coordinator => result??,
            }
            return Ok(());
        }
        let first = ingress::accept(&listener).await?;
        let headers: Vec<_> = first
            .headers
            .iter()
            .map(|(name, value)| json!([name, value]))
            .collect();
        control::send(
            &mut control,
            &Message {
                kind: "native_template".into(),
                data: Vec::new(),
                metadata: serde_json::from_value(
                    json!({"headers":headers, "completion_ack":true}),
                )?,
            },
        )
        .await?;
        let options = BootstrapOptions {
            role: config.role,
            profile,
            runtime: runtime.clone(),
            provider_host: config.provider_host,
            provider_port: config.provider_port,
            provider_ca: config.provider_ca,
            credential: None,
            account,
            codex_headers: first.headers.clone(),
            claude_template: None,
        };
        let session = tokio::select! {
            result = bootstrap::start_after_identity(control, Some(tunnel.clone()), options) => result?,
            () = first.watch_disconnect() => {
                println!("NATIVE_CANCEL cli_disconnect");
                bail!("NATIVE_CANCEL cli_disconnect");
            }
        };
        let (turns_tx, turns_rx) = mpsc::channel(8);
        let (upgrade_tx, upgrade_rx) = oneshot::channel();
        let mut coordinator = tokio::spawn(session::concurro(
            session,
            tunnel,
            runtime,
            turns_rx,
            upgrade_tx,
            completion_ack,
        ));
        let test_turns = env::var("CONCURRO_NATIVE_TEST_TURNS_CODEX")
            .ok()
            .or_else(|| env::var("CONCURRO_NATIVE_TEST_TURNS").ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        tokio::select! {
            served = ingress::serve(&listener, first, turns_tx.clone(), upgrade_rx, test_turns) => {
                drop(turns_tx);
                match served {
                    Ok(()) => coordinator.await??,
                    Err(error) => {
                        if error.to_string().starts_with("NATIVE_CANCEL ") { println!("{error}"); }
                        coordinator.abort();
                        return Err(error)
                    }
                }
            }
            result = &mut coordinator => result??,
        }
        Ok(())
    }
}
