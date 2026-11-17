//! Resumable Codex role coordinators after one protected TLS bootstrap.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_protocol::{identity, ws};
use concurro_relay_provider_protocol::{
    claude::{self as claude_protocol, AuditFrame},
    codex::{self, RequestBinding, RequestClaim, Responses},
};
use concurro_relay_tls13::record::{self, ApplicationRecords};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use crate::{
    NativeRole,
    bootstrap::{self, Application, Session},
    helpers::{self, Peer, Runtime},
    proof,
};

mod claude;
pub use claude::beta_template as claude_beta_template;
pub use claude::concurro as claude_concurro;

/// One request from the local Codex WebSocket and its authenticated event reply.
pub struct CodexTurn {
    /// Exact client JSON sent to the provider.
    pub request: Value,
    /// Normalized local JSON text for the proved prompt.
    pub text: String,
    /// Authenticated provider events and one terminal marker.
    pub reply: mpsc::Sender<Result<CodexEvent>>,
}

/// One authenticated event or successful completion for local ingress.
pub enum CodexEvent {
    /// Provider JSON event forwarded as text.
    Data(Vec<u8>),
    /// Terminal response event was forwarded.
    Done,
}

/// One local Claude request and its authenticated streaming reply.
pub struct ClaudeTurn {
    /// Public path and headers for this request.
    pub template: claude_protocol::Template,
    /// Exact JSON request body.
    pub body: Vec<u8>,
    /// Immediate authenticated response events.
    pub reply: mpsc::Sender<Result<ClaudeEvent>>,
}

/// One authenticated Claude response effect for local ingress.
pub enum ClaudeEvent {
    /// Validated HTTP status and content type.
    Start(u16, String),
    /// Authenticated provider body bytes before stream completion.
    Data(Vec<u8>),
    /// Final DATA or HEADERS END_STREAM was validated.
    Done,
    /// Provider error body is complete; acknowledge finished local framing.
    ProviderError(oneshot::Sender<()>),
}

/// Sponsor gates every provider write on a matching request proof.
pub async fn sponsor<C: AsyncRead + AsyncWrite + Unpin>(
    session: Session<C>,
    tunnel: Arc<Tunnel>,
    runtime: Runtime,
    completion_ack: bool,
) -> Result<()> {
    let Session {
        mut peer,
        result,
        application,
        h2,
        h3,
        session_id,
        key_commitment,
    } = session;
    let Application::Sponsor {
        mut provider,
        tail,
        claude_template,
        credential_length,
    } = application
    else {
        bail!("Sponsor session role mismatch")
    };
    let mut claude_audit = claude_template
        .map(|template| claude_protocol::SponsorAudit::new(credential_length, template))
        .transpose()?;
    let mut indexed_headers_accepted = 0usize;
    let mut next = 0u64;
    let mut pending = Vec::new();
    let mut frame = Vec::new();
    let mut prompts: Vec<Value> = Vec::new();
    let mut pending_prompts = VecDeque::new();
    let mut usage = Vec::new();
    loop {
        let message = peer.receive_any().await?;
        match message.kind.as_str() {
            "request_offer" => {
                ensure!(
                    message.metadata.get("sequence") == Some(&json!(next))
                        && message.metadata.get("turn") == Some(&json!(next)),
                    "unproved or repeated client record sequence"
                );
                let plaintext = STANDARD.decode(
                    message
                        .metadata
                        .get("plaintext")
                        .and_then(Value::as_str)
                        .context("request plaintext missing")?,
                )?;
                let binding = RequestBinding {
                    h2,
                    h3,
                    key_commitment,
                };
                let claim = RequestClaim::new(
                    &binding,
                    &[0; 16],
                    &[0; 12],
                    next,
                    &plaintext,
                    &message.data,
                );
                let traffic = proof::request(
                    &mut peer,
                    NativeRole::Sponsor,
                    &tunnel,
                    &runtime,
                    &claim,
                    next,
                )
                .await?;
                let mut prompt = None;
                let release = if let Some(audit) = &mut claude_audit {
                    match audit.accept(&plaintext)? {
                        AuditFrame::Control | AuditFrame::Partial => true,
                        AuditFrame::Headers => {
                            indexed_headers_accepted += 1;
                            false
                        }
                        AuditFrame::Prompt(_, body) => {
                            prompt = Some(String::from_utf8(body)?);
                            true
                        }
                    }
                } else if next == 0 {
                    codex::audited_payload(&plaintext, next, &tail)?;
                    true
                } else {
                    frame.extend(&plaintext);
                    let declared = codex::frame_length(&frame)?;
                    ensure!(
                        declared.is_none_or(|length| frame.len() <= length),
                        "WebSocket request exceeds declared frame"
                    );
                    if declared == Some(frame.len()) {
                        prompt = codex::audited_payload(&frame, next, &tail)?;
                        frame.clear();
                        true
                    } else {
                        false
                    }
                };
                pending.push(message.data.clone());
                if let Some(text) = prompt {
                    let entry = json!({"turn": next, "sha256": hex::encode(helpers::sha256(text.as_bytes())),
                        "wire_sha256": hex::encode(helpers::sha256(&message.data)), "proof": "QuickSilver/real-OT",
                        "proof_traffic": traffic, "text": text});
                    pending_prompts.push_back(entry.clone());
                    let mut report_entry = entry;
                    if std::env::var("CONCURRO_NATIVE_AUDIT_TEXT").as_deref() != Ok("1") {
                        report_entry.as_object_mut().unwrap().remove("text");
                    }
                    prompts.push(report_entry);
                }
                if release {
                    for wire in pending.drain(..) {
                        provider.write_all(&wire).await?;
                    }
                }
                peer.send(
                    "request_accepted",
                    &helpers::sha256(&message.data),
                    helpers::metadata("turn", json!(next)),
                )
                .await?;
                next += 1;
            }
            "h2_template" if claude_audit.is_some() => {
                claude_audit
                    .as_mut()
                    .unwrap()
                    .template(claude_protocol::Template::from_metadata(&message.metadata)?);
            }
            "need_server_record" => {
                ensure!(
                    pending.is_empty() && frame.is_empty(),
                    "provider response requested before complete proved request"
                );
                let wire = bootstrap::read_tls_record(&mut provider).await?;
                peer.send("server_record", &wire, Map::new()).await?;
            }
            "audit_usage" => {
                let entry = pending_prompts
                    .pop_front()
                    .context("provider usage arrived without a proved request")?;
                let value = message
                    .metadata
                    .get("usage")
                    .cloned()
                    .unwrap_or(Value::Null);
                usage.push(json!({"source": "Concurro-reported provider field", "value": value}));
                let audit = json!({"turn": entry["turn"], "prompt": entry["text"], "sha256": entry["sha256"],
                    "proof": entry["proof"], "usage": value, "session_id": hex::encode(session_id)});
                println!("NATIVE_AUDIT {}", serde_json::to_string(&audit)?);
            }
            "complete" => {
                ensure!(
                    pending.is_empty() && pending_prompts.is_empty(),
                    "incomplete audited continuation"
                );
                break;
            }
            other => bail!("unexpected sponsor control message {other}"),
        }
    }
    let report = json!({"route": result.route, "h2": result.h2, "h3": result.h3,
        "session_id": result.session_id, "prefix_key_commitment": result.prefix_key_commitment,
        "prompts": prompts, "usage": usage, "request_proof_records": next,
        "protected_bootstrap_count": 1, "provider_connection_count": 1,
        "indexed_headers_accepted": indexed_headers_accepted});
    tokio::fs::write(
        runtime.output.join("sponsor-result.json"),
        serde_json::to_vec_pretty(&report)?,
    )
    .await?;
    if completion_ack {
        peer.send("complete_ack", &[], Map::new()).await?;
        peer.receive("complete_done").await?;
    }
    Ok(())
}

/// Concurro proves requests and only forwards authenticated provider responses.
pub async fn concurro<C: AsyncRead + AsyncWrite + Unpin>(
    session: Session<C>,
    tunnel: Arc<Tunnel>,
    runtime: Runtime,
    mut turns: mpsc::Receiver<CodexTurn>,
    upgrade: oneshot::Sender<Result<()>>,
    completion_ack: bool,
) -> Result<()> {
    let Session {
        peer,
        result,
        application,
        h2,
        h3,
        key_commitment,
        ..
    } = session;
    let Application::Concurro {
        records,
        tail,
        credential_length: _,
    } = application
    else {
        bail!("Concurro session role mismatch")
    };
    let mut link = Forwarded {
        peer,
        records: *records,
        tunnel,
        runtime: &runtime,
        h2,
        h3,
        key_commitment,
        turn: 0,
        proof_time: Duration::ZERO,
        buffer: Vec::new(),
    };
    let upgrade_started = Instant::now();
    let mut provider_head_status = None;
    let mut provider_head_sha256 = None;
    let upgraded = async {
        tokio::fs::write(
            runtime.output.join("codex-upgrade-phase.json"),
            serde_json::to_vec_pretty(&json!({
                "phase": "sending_tail",
                "tail_bytes": tail.len(),
                "tail_sha256": hex::encode(helpers::sha256(&tail)),
                "header_names": tail.split(|byte| *byte == b'\n').filter_map(|line| {
                    line.split(|byte| *byte == b':').next().filter(|name| !name.is_empty())
                        .map(|name| String::from_utf8_lossy(name).trim().to_owned())
                }).collect::<Vec<_>>(),
            }))?,
        )
        .await?;
        link.send(&tail).await?;
        tokio::fs::write(
            runtime.output.join("codex-upgrade-phase.json"),
            serde_json::to_vec_pretty(&json!({"phase":"awaiting_http_head",
                "proof_records":link.turn,"proof_seconds":link.proof_time.as_secs_f64()}))?,
        )
        .await?;
        let head = link.read_http_head().await?;
        provider_head_status = std::str::from_utf8(&head)?
            .split_whitespace()
            .nth(1)
            .and_then(|status| status.parse::<u16>().ok());
        provider_head_sha256 = Some(hex::encode(helpers::sha256(&head)));
        let key = tail
            .windows(19)
            .position(|part| part == b"Sec-WebSocket-Key: ")
            .context("upgrade key missing")?
            + 19;
        let end = tail[key..]
            .windows(2)
            .position(|part| part == b"\r\n")
            .context("upgrade key unterminated")?
            + key;
        let accept = base64::engine::general_purpose::STANDARD.encode(
            ring::digest::digest(
                &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                &[&tail[key..end], b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].concat(),
            )
            .as_ref(),
        );
        codex::upgrade_response(&head, &accept)?;
        Ok(())
    }
    .await;
    tokio::fs::write(
        runtime.output.join("codex-upgrade.json"),
        serde_json::to_vec_pretty(&json!({
            "status": provider_head_status,
            "head_sha256": provider_head_sha256,
            "request_tail_bytes": tail.len(),
            "request_tail_sha256": hex::encode(helpers::sha256(&tail)),
            "proof_records": link.turn,
            "proof_seconds": link.proof_time.as_secs_f64(),
            "elapsed_seconds": upgrade_started.elapsed().as_secs_f64(),
            "error": upgraded.as_ref().err().map(ToString::to_string),
        }))?,
    )
    .await?;
    let upgrade_ok = upgraded.is_ok();
    let _ = upgrade.send(upgraded);
    ensure!(upgrade_ok, "provider WebSocket upgrade failed");
    let mut responses = Vec::new();
    let mut inbox = Responses::default();
    if !link.buffer.is_empty() {
        inbox.push(&std::mem::take(&mut link.buffer))?;
    }
    while let Some(turn) = turns.recv().await {
        let outcome = async {
            ensure!(
                turn.request["type"] == "response.create",
                "unexpected local Responses request"
            );
            let previous = turn.request["previous_response_id"]
                .as_str()
                .map(str::to_owned);
            let frame = ws::text_frame(&turn.text, identity::random());
            let asked = inbox.asking(previous);
            link.send(&frame).await?;
            loop {
                let completed = inbox.take_turn(&asked)?;
                for event in inbox.drain_events() {
                    turn.reply
                        .send(Ok(CodexEvent::Data(event)))
                        .await
                        .context("local Codex listener closed")?;
                }
                if let Some(done) = completed {
                    for event in &done.events {
                        turn.reply
                            .send(Ok(CodexEvent::Data(event.clone())))
                            .await
                            .context("local Codex listener closed")?;
                    }
                    break Ok(done);
                }
                if let Some(ping) = inbox.waiting_ping() {
                    let pong = ws::pong_frame(&ping, identity::random());
                    link.send(&pong).await?;
                    inbox.answer_ping(&ping);
                }
                inbox.push(&link.read_application().await?)?;
            }
        }
        .await;
        match outcome {
            Ok(done) => {
                link.peer
                    .send(
                        "audit_usage",
                        &[],
                        helpers::metadata("usage", done.usage.clone().unwrap_or(Value::Null)),
                    )
                    .await?;
                responses.push(json!({"id": done.response_id, "usage": done.usage}));
                let _ = turn.reply.send(Ok(CodexEvent::Done)).await;
            }
            Err(error) => {
                let _ = turn.reply.send(Err(error)).await;
                return Err(anyhow::anyhow!("Codex turn failed"));
            }
        }
    }
    link.peer.send("complete", &[], Map::new()).await?;
    if completion_ack {
        link.peer.receive("complete_ack").await?;
    }
    let report = json!({"route":"codex", "status":101, "responses": responses,
        "h2": result.h2, "h3": result.h3, "session_id": result.session_id,
        "prefix_key_commitment": result.prefix_key_commitment,
        "client_records_sent":link.turn, "protected_bootstrap_count":1});
    tokio::fs::write(
        runtime.output.join("concurro-result.json"),
        serde_json::to_vec_pretty(&report)?,
    )
    .await?;
    if completion_ack {
        link.peer.send("complete_done", &[], Map::new()).await?;
    }
    Ok(())
}

/// One Concurro connection with persistent record counters and control peer.
struct Forwarded<'a, C> {
    /// Authenticated control peer shared with Sponsor.
    peer: Peer<C>,
    /// Application traffic epochs and post-handshake state.
    records: ApplicationRecords,
    /// Authenticated helper transport for request proofs.
    tunnel: Arc<Tunnel>,
    /// Session-specific native helper paths.
    runtime: &'a Runtime,
    /// Public hello hash.
    h2: [u8; 32],
    /// Authenticated server transcript hash.
    h3: [u8; 32],
    /// Protected application-key commitment.
    key_commitment: [u8; 32],
    /// Next proved request record number.
    turn: u64,
    /// Time spent inside request proofs on this connection.
    proof_time: Duration,
    /// Application bytes retained after the HTTP upgrade head.
    buffer: Vec<u8>,
}

impl<C: AsyncRead + AsyncWrite + Unpin> Forwarded<'_, C> {
    /// Encrypt and prove each exact client TLS record before requesting release.
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        for plaintext in bytes.chunks(16_384) {
            let (secret, sequence) = self.records.client_state();
            let key = record::expand::<16>(secret, b"key")?;
            let iv = record::expand::<12>(secret, b"iv")?;
            let wire = self.records.send(plaintext)?;
            let binding = RequestBinding {
                h2: self.h2,
                h3: self.h3,
                key_commitment: self.key_commitment,
            };
            let claim = RequestClaim::new(&binding, &key, &iv, sequence, plaintext, &wire);
            let metadata = serde_json::from_value(
                json!({"plaintext": STANDARD.encode(plaintext), "sequence": self.turn, "turn": self.turn}),
            )?;
            self.peer.send("request_offer", &wire, metadata).await?;
            let proof_started = Instant::now();
            proof::request(
                &mut self.peer,
                NativeRole::Concurro,
                &self.tunnel,
                self.runtime,
                &claim,
                self.turn,
            )
            .await?;
            self.proof_time += proof_started.elapsed();
            let accepted = self.peer.receive("request_accepted").await?;
            ensure!(
                accepted.metadata.get("turn") == Some(&json!(self.turn))
                    && accepted.data == helpers::sha256(&wire),
                "Sponsor forwarded record differs from proved bytes"
            );
            self.turn += 1;
        }
        Ok(())
    }

    /// Request the next TLS record and retain authenticated application bytes.
    async fn read_application(&mut self) -> Result<Vec<u8>> {
        loop {
            self.peer
                .send("need_server_record", &[], Map::new())
                .await?;
            let wire = self.peer.receive("server_record").await?.data;
            if let Some(bytes) = self.records.receive(&wire)? {
                return Ok(bytes);
            }
        }
    }

    /// Read an authenticated HTTP upgrade head across arbitrary TLS record boundaries.
    async fn read_http_head(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(end) = self.buffer.windows(4).position(|part| part == b"\r\n\r\n") {
                let head: Vec<_> = self.buffer.drain(..end + 4).collect();
                return Ok(head);
            }
            let bytes = self.read_application().await?;
            self.buffer.extend(bytes);
            tokio::fs::write(
                self.runtime.output.join("codex-upgrade-phase.json"),
                serde_json::to_vec_pretty(&json!({"phase":"reading_http_head",
                    "buffer_bytes":self.buffer.len(),"buffer_sha256":hex::encode(helpers::sha256(&self.buffer))}))?,
            )
            .await?;
        }
    }
}
