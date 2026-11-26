//! Resumable Codex role coordinators after one protected TLS bootstrap.

use std::{
    collections::VecDeque,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_native_transport::{control::Message, tunnel::Tunnel};
use concurro_relay_protocol::{identity, ws};
use concurro_relay_provider_protocol::{
    HttpProvider,
    codex::{self, RequestBinding, RequestClaim, Responses},
    tls_key_update::{self as http_protocol, AuditFrame},
};
use concurro_relay_tls13::record::{self, ApplicationRecords};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use crate::{
    NativeAudit, NativeRequest, NativeRole, NativeVerdict,
    bootstrap::{self, Application, Session},
    helpers::{self, Peer, Runtime},
    proof,
    worker::WorkerEvent,
};

mod providers;
mod tls_key_update;
pub use providers::configure_template;
pub use tls_key_update::concurro as tls_key_update_concurro;
pub use tls_key_update::review_first as http_review_first;

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

/// One local HTTP/2 request and its authenticated streaming reply.
pub struct HttpTurn {
    /// Public path and headers for this request.
    pub template: http_protocol::Template,
    /// Exact JSON request body.
    pub body: Vec<u8>,
    /// Immediate authenticated response events.
    pub reply: mpsc::Sender<Result<HttpEvent>>,
}

/// One authenticated HTTP/2 response effect for local ingress.
pub enum HttpEvent {
    /// Validated HTTP status and content type.
    Start(u16, String),
    /// Authenticated provider body bytes before stream completion.
    Data(Vec<u8>),
    /// Final DATA or HEADERS END_STREAM was validated.
    Done,
    /// Provider error body is complete; acknowledge finished local framing.
    ProviderError(oneshot::Sender<()>),
}

/// Asks the Sponsor whether a request may reach the provider.
pub trait Gate {
    /// The Sponsor's verdict on `request`.
    fn decide(&mut self, request: &NativeRequest) -> impl Future<Output = Result<NativeVerdict>>;
}

/// The Sponsor's approval of a request, against which proved bytes are checked.
struct Approved {
    request: u64,
    body: Vec<u8>,
    template: Option<http_protocol::Template>,
}

/// Which request the Sponsor reviews next and what it last approved.
#[derive(Default)]
struct Approvals {
    reviewed: u64,
    approved: Option<Approved>,
}

impl Approvals {
    /// Admits review `request`, which must be the next and arrive with
    /// nothing approved but unsent.
    fn review(&mut self, request: u64) -> Result<()> {
        ensure!(request == self.reviewed, "unexpected request review number");
        ensure!(
            self.approved.is_none(),
            "request reviewed before the approved one was sent"
        );
        self.reviewed += 1;
        Ok(())
    }

    /// Admits the public template of the approved request.
    fn template(&self, template: &http_protocol::Template) -> Result<()> {
        let approved = self
            .approved
            .as_ref()
            .context("request template not approved")?;
        ensure!(
            approved.template.as_ref() == Some(template),
            "request template differs from the approved one"
        );
        Ok(())
    }

    /// Admits `sent`, the body proved so far, sent with `template`.
    fn partial(&self, sent: &[u8], template: Option<&http_protocol::Template>) -> Result<()> {
        let approved = self
            .approved
            .as_ref()
            .context("request body not approved")?;
        ensure!(
            approved.template.as_ref() == template && approved.body.starts_with(sent),
            "proved request differs from the approved one"
        );
        Ok(())
    }

    /// Admits the complete proved `body`, returning its review number.
    fn complete(&mut self, body: &[u8], template: Option<&http_protocol::Template>) -> Result<u64> {
        self.partial(body, template)?;
        let approved = self
            .approved
            .as_ref()
            .context("request body not approved")?;
        ensure!(
            approved.body.len() == body.len(),
            "proved request differs from the approved one"
        );
        let request = approved.request;
        self.approved = None;
        Ok(request)
    }
}

/// Receives the review `first` begins, has `gate` decide it, records the
/// decision before Concurro is answered, and keeps an approval in
/// `approvals`. Returns the record.
async fn review_request<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    first: Message,
    gate: &mut impl Gate,
    runtime: &Runtime,
    session_id: &str,
    provider: Option<HttpProvider>,
    approvals: &mut Approvals,
) -> Result<Value> {
    let (number, prompt, metadata) = receive_review(peer, first).await?;
    approvals.review(number)?;
    let template = if let Some(provider) = provider {
        let template = http_protocol::Template::from_metadata(
            metadata
                .get("template")
                .and_then(Value::as_object)
                .context("reviewed HTTP/2 template missing")?,
        )?;
        ensure!(
            template.provider == provider,
            "reviewed HTTP provider differs from session"
        );
        Some(template)
    } else {
        None
    };
    let prompt = String::from_utf8(prompt).context("reviewed request is not text")?;
    let request = NativeRequest {
        request: number,
        sha256: hex::encode(helpers::sha256(prompt.as_bytes())),
        path: template
            .as_ref()
            .map(|template| String::from_utf8_lossy(&template.path).into_owned()),
        headers: template
            .iter()
            .flat_map(|template| &template.headers)
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )
            })
            .collect(),
        session_id: session_id.to_owned(),
        prompt,
    };
    let verdict = gate.decide(&request).await?;
    ensure!(
        verdict.request == number,
        "Sponsor verdict answers another request"
    );
    let mut entry = json!({"request": number, "sha256": request.sha256,
        "path": request.path, "accept": verdict.accept, "reason": verdict.reason});
    if std::env::var("CONCURRO_NATIVE_AUDIT_TEXT").as_deref() == Ok("1") {
        entry["text"] = json!(request.prompt);
        entry["headers"] = json!(request.headers);
    }
    let mut line = serde_json::to_vec(&entry)?;
    line.push(b'\n');
    let mut record = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime.output.join("sponsor-requests.jsonl"))
        .await?;
    record.write_all(&line).await?;
    // Written through before Concurro hears the decision.
    record.flush().await?;
    if verdict.accept {
        approvals.approved = Some(Approved {
            request: number,
            body: request.prompt.into_bytes(),
            template,
        });
        peer.send(
            "request_approved",
            &[],
            helpers::metadata("request", json!(number)),
        )
        .await?;
    } else {
        let mut answer = helpers::metadata("request", json!(number));
        answer.insert("reason".into(), json!(verdict.reason));
        peer.send("request_rejected", &[], answer).await?;
    }
    Ok(entry)
}

/// An HTTP/2 session's first request, approved before the TLS bootstrap.
pub struct FirstApproval {
    approvals: Approvals,
    entry: Value,
}

impl FirstApproval {
    /// The approved path and public headers, which the bootstrap prefix
    /// must carry.
    pub fn template(&self) -> Option<&http_protocol::Template> {
        self.approvals.approved.as_ref()?.template.as_ref()
    }
}

/// Has the Sponsor review an HTTP/2 session's first request before the TLS
/// bootstrap, whose prefix carries that request's HEADERS. Returns the
/// approval, or `None` when the request was rejected and the session ends.
pub async fn sponsor_first<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    gate: &mut impl Gate,
    runtime: &Runtime,
    session_id: &str,
    provider: HttpProvider,
) -> Result<Option<FirstApproval>> {
    let message = peer.receive("request_review").await?;
    let mut approvals = Approvals::default();
    let entry = review_request(
        peer,
        message,
        gate,
        runtime,
        session_id,
        Some(provider),
        &mut approvals,
    )
    .await?;
    Ok(if approvals.approved.is_some() {
        Some(FirstApproval { approvals, entry })
    } else {
        None
    })
}

/// Sponsor gates every provider write on its approval and a matching
/// request proof. An HTTP/2 session's `first` request was approved before
/// the bootstrap.
pub async fn sponsor<C: AsyncRead + AsyncWrite + Unpin>(
    session: Session<C>,
    tunnel: Arc<Tunnel>,
    runtime: Runtime,
    completion_ack: bool,
    gate: &mut impl Gate,
    session_id: &str,
    first: Option<FirstApproval>,
) -> Result<()> {
    let session_provider = session.result.provider;
    let Session {
        mut peer,
        result,
        application,
        h2,
        h3,
        key_commitment,
        ..
    } = session;
    let Application::Sponsor {
        mut provider,
        tail,
        http_template,
        credential_length,
    } = application
    else {
        bail!("Sponsor session role mismatch")
    };
    let mut http_audit = http_template
        .map(|template| http_protocol::SponsorAudit::new(credential_length, template))
        .transpose()?;
    ensure!(
        http_audit.is_none() || first.is_some(),
        "HTTP/2 session without an approved first request"
    );
    let (mut approvals, mut prompts) = match first {
        Some(first) => (first.approvals, vec![first.entry]),
        None => (Approvals::default(), Vec::new()),
    };
    let mut indexed_headers_accepted = 0usize;
    let mut next = 0u64;
    let mut pending = Vec::new();
    let mut frame = Vec::new();
    // Sent requests awaiting usage: review number and prompt digest.
    let mut sent: VecDeque<(u64, String)> = VecDeque::new();
    let mut usage = Vec::new();
    loop {
        let message = peer.receive_any().await?;
        match message.kind.as_str() {
            "request_review" => {
                prompts.push(
                    review_request(
                        &mut peer,
                        message,
                        gate,
                        &runtime,
                        session_id,
                        session_provider,
                        &mut approvals,
                    )
                    .await?,
                );
            }
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
                proof::request(
                    &mut peer,
                    NativeRole::Sponsor,
                    &tunnel,
                    &runtime,
                    &claim,
                    next,
                )
                .await?;
                let mut completed = None;
                let release = if let Some(audit) = &mut http_audit {
                    match audit.accept(&plaintext)? {
                        AuditFrame::Control => true,
                        AuditFrame::Headers(stream) => {
                            approvals.partial(&[], audit.template_for(stream))?;
                            indexed_headers_accepted += 1;
                            false
                        }
                        AuditFrame::Partial(stream) => {
                            approvals.partial(audit.body(), audit.template_for(stream))?;
                            true
                        }
                        AuditFrame::Prompt(stream, body) => {
                            let number = approvals.complete(&body, audit.template_for(stream))?;
                            completed = Some((number, helpers::sha256(&body)));
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
                        if let Some(text) = codex::audited_payload(&frame, next, &tail)? {
                            let number = approvals.complete(text.as_bytes(), None)?;
                            completed = Some((number, helpers::sha256(text.as_bytes())));
                        }
                        frame.clear();
                        true
                    } else {
                        false
                    }
                };
                pending.push(message.data.clone());
                if let Some((number, digest)) = completed {
                    sent.push_back((number, hex::encode(digest)));
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
            "h2_template" if http_audit.is_some() => {
                let template = http_protocol::Template::from_metadata(&message.metadata)?;
                approvals.template(&template)?;
                http_audit.as_mut().unwrap().template(template)?;
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
                let number = message
                    .metadata
                    .get("request")
                    .and_then(Value::as_u64)
                    .context("provider usage names no request")?;
                // Requests sent before it without usage, such as retried
                // attempts, get none.
                while sent.front().is_some_and(|(request, _)| *request < number) {
                    sent.pop_front();
                }
                let (request, sha256) = sent
                    .pop_front()
                    .filter(|(request, _)| *request == number)
                    .context("provider usage arrived for a request that was not sent")?;
                let value = message
                    .metadata
                    .get("usage")
                    .cloned()
                    .unwrap_or(Value::Null);
                usage.push(json!({"source": "Concurro-reported provider field",
                    "request": request, "value": value}));
                let audit = NativeAudit {
                    request,
                    sha256,
                    usage: Some(value).filter(|value| !value.is_null()),
                    session_id: session_id.to_owned(),
                };
                println!("{}", WorkerEvent::Audit(audit).line()?);
            }
            "complete" => {
                ensure!(
                    pending.is_empty() && frame.is_empty() && approvals.approved.is_none(),
                    "incomplete approved request"
                );
                break;
            }
            other => bail!("unexpected sponsor control message {other}"),
        }
    }
    let report = json!({"route": result.route, "provider": result.provider, "h2": result.h2, "h3": result.h3,
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
        reviews: 0,
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
            let request = link.review(turn.text.as_bytes(), None).await?;
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
                    break Ok((request, done));
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
            Ok((request, done)) => {
                let mut metadata =
                    helpers::metadata("usage", done.usage.clone().unwrap_or(Value::Null));
                metadata.insert("request".into(), json!(request));
                link.peer.send("audit_usage", &[], metadata).await?;
                responses.push(json!({"id": done.response_id, "usage": done.usage}));
                let _ = turn.reply.send(Ok(CodexEvent::Done)).await;
            }
            // Nothing of a rejected request was sent, so later turns can
            // follow on this connection.
            Err(error) if error.is::<Rejected>() => {
                let event = json!({"type": "error", "status": 403,
                    "error": {"type": "permission_error", "message": error.to_string()}});
                turn.reply
                    .send(Ok(CodexEvent::Data(serde_json::to_vec(&event)?)))
                    .await
                    .context("local Codex listener closed")?;
                turn.reply
                    .send(Ok(CodexEvent::Done))
                    .await
                    .context("local Codex listener closed")?;
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
    /// Number of the next request the Sponsor reviews.
    reviews: u64,
}

/// The most prompt bytes one review message carries, so that it stays
/// within the control message limit once encoded.
const REVIEW_PART: usize = 512 * 1024;

/// Sends request `number`, `prompt` sent with `template`, for review, in
/// parts of [`REVIEW_PART`] bytes.
async fn send_review<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    number: u64,
    prompt: &[u8],
    template: Option<&http_protocol::Template>,
) -> Result<()> {
    let mut parts = prompt.chunks(REVIEW_PART);
    let mut metadata = helpers::metadata("request", json!(number));
    metadata.insert("length".into(), json!(prompt.len()));
    if let Some(template) = template {
        metadata.insert("template".into(), Value::Object(template.metadata()?));
    }
    peer.send("request_review", parts.next().unwrap_or_default(), metadata)
        .await?;
    for part in parts {
        peer.send(
            "request_review_part",
            part,
            helpers::metadata("request", json!(number)),
        )
        .await?;
    }
    Ok(())
}

/// Asks the Sponsor to approve request `number`, `prompt` sent with
/// `template`, failing with [`Rejected`] when it does not.
async fn ask_review<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    number: u64,
    prompt: &[u8],
    template: Option<&http_protocol::Template>,
) -> Result<()> {
    send_review(peer, number, prompt, template).await?;
    let answer = peer.receive_any().await?;
    ensure!(
        answer.metadata.get("request") == Some(&json!(number)),
        "Sponsor answered another request review"
    );
    match answer.kind.as_str() {
        "request_approved" => Ok(()),
        "request_rejected" => {
            let reason = answer.metadata.get("reason").and_then(Value::as_str);
            Err(Rejected(reason.unwrap_or("no reason given").to_owned()).into())
        }
        other => bail!("expected a request review answer, got {other}"),
    }
}

/// Receives the rest of the review `first` begins, returning the request's
/// number, its prompt and the review's metadata.
async fn receive_review<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    first: Message,
) -> Result<(u64, Vec<u8>, Map<String, Value>)> {
    let number = first
        .metadata
        .get("request")
        .and_then(Value::as_u64)
        .context("request review number missing")?;
    let length = first
        .metadata
        .get("length")
        .and_then(Value::as_u64)
        .context("request review length missing")?;
    let mut prompt = first.data;
    while (prompt.len() as u64) < length {
        let part = peer.receive("request_review_part").await?;
        ensure!(
            part.metadata.get("request") == Some(&json!(number)) && !part.data.is_empty(),
            "invalid request review part"
        );
        prompt.extend(part.data);
    }
    ensure!(
        prompt.len() as u64 == length,
        "request review exceeds its length"
    );
    Ok((number, prompt, first.metadata))
}

/// The Sponsor rejected a request; none of it was sent.
#[derive(Debug)]
pub struct Rejected(pub String);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the Sponsor rejected this request: {}", self.0)
    }
}

impl std::error::Error for Rejected {}

impl<C: AsyncRead + AsyncWrite + Unpin> Forwarded<'_, C> {
    /// Asks the Sponsor to approve `prompt`, sent with `template`, before
    /// any of it is sent, returning its review number.
    async fn review(
        &mut self,
        prompt: &[u8],
        template: Option<&http_protocol::Template>,
    ) -> Result<u64> {
        let number = self.reviews;
        self.reviews += 1;
        ask_review(&mut self.peer, number, prompt, template).await?;
        Ok(number)
    }

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

#[cfg(test)]
mod tests {
    use concurro_relay_provider_protocol::{HttpProvider, tls_key_update::Template};
    use serde_json::json;

    use std::{env, time::Duration};

    use anyhow::Result;

    use super::{
        Approvals, Approved, Gate, Rejected, http_review_first, receive_review, send_review,
        sponsor_first,
    };
    use crate::{
        NativeRequest, NativeVerdict,
        helpers::{Peer, Runtime},
    };

    /// Answers every request with `accept`, keeping what it was asked.
    struct Fixed {
        accept: bool,
        asked: Vec<NativeRequest>,
    }

    impl Gate for Fixed {
        async fn decide(&mut self, request: &NativeRequest) -> Result<NativeVerdict> {
            self.asked.push(request.clone());
            Ok(NativeVerdict {
                request: request.request,
                accept: self.accept,
                reason: (!self.accept).then(|| "off topic".into()),
            })
        }
    }

    /// The first HTTP/2 request is reviewed, recorded and answered before
    /// any bootstrap, as the provider body Concurro will send.
    #[tokio::test]
    async fn the_first_claude_request_is_reviewed_before_bootstrap() {
        let output = env::temp_dir().join(format!(
            "first-review-{}",
            hex::encode(concurro_relay_protocol::identity::random::<8>())
        ));
        std::fs::create_dir_all(&output).unwrap();
        let runtime = Runtime {
            root: output.clone(),
            output: output.clone(),
            circuit_cache: output.clone(),
            limits: crate::NativeLimits::DEFAULT,
            benchmark_timeout: Duration::from_secs(1),
        };
        let template = Template::fixture_default();
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        for accept in [true, false] {
            let (mut concurro, mut sponsor) = peers();
            let asking = {
                let template = template.clone();
                tokio::spawn(async move {
                    http_review_first(&mut concurro, body, &template, true).await
                })
            };
            let mut gate = Fixed {
                accept,
                asked: Vec::new(),
            };
            let first = sponsor_first(
                &mut sponsor,
                &mut gate,
                &runtime,
                "session",
                HttpProvider::Claude,
            )
            .await
            .unwrap();
            let asked = asking.await.unwrap();
            let request = &gate.asked[0];
            assert_eq!(request.request, 0);
            assert_eq!(request.path.as_deref(), Some("/v1/messages"));
            assert!(request.prompt.contains(r#""thread":{"type":"create"}"#));
            assert_eq!(request.headers.len(), template.headers.len());
            if accept {
                asked.unwrap();
                assert_eq!(first.unwrap().template(), Some(&template));
            } else {
                assert!(asked.unwrap_err().is::<Rejected>());
                assert!(first.is_none());
            }
        }
        let recorded = std::fs::read_to_string(output.join("sponsor-requests.jsonl")).unwrap();
        assert_eq!(recorded.lines().count(), 2);
        std::fs::remove_dir_all(output).unwrap();
    }

    /// A connected pair of control peers.
    fn peers() -> (Peer<tokio::io::DuplexStream>, Peer<tokio::io::DuplexStream>) {
        let (one, other) = tokio::io::duplex(1 << 16);
        (Peer::new(one), Peer::new(other))
    }

    /// Provider mismatches are refused before the Sponsor is asked to approve.
    #[tokio::test]
    async fn reviews_are_bound_to_session_provider() {
        for request in [0, 1] {
            let (mut sender, mut receiver) = peers();
            let template = Template {
                provider: HttpProvider::Antigravity,
                path: b"/v1internal:streamGenerateContent?alt=sse".to_vec(),
                headers: Vec::new(),
            };
            send_review(&mut sender, request, b"{}", Some(&template))
                .await
                .unwrap();
            let first = receiver.receive("request_review").await.unwrap();
            let mut approvals = Approvals::default();
            approvals.reviewed = request;
            let mut gate = Fixed {
                accept: true,
                asked: Vec::new(),
            };
            let runtime = Runtime {
                root: env::temp_dir(),
                output: env::temp_dir(),
                circuit_cache: env::temp_dir(),
                limits: crate::NativeLimits::DEFAULT,
                benchmark_timeout: Duration::from_secs(30),
            };
            let error = super::review_request(
                &mut receiver,
                first,
                &mut gate,
                &runtime,
                "session",
                Some(HttpProvider::Claude),
                &mut approvals,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("provider differs from session"));
            assert!(gate.asked.is_empty());
        }
    }

    /// A prompt beyond one control message arrives whole, with its template.
    #[tokio::test]
    async fn large_and_empty_reviews_arrive_whole() {
        let template = Template::fixture_default();
        for size in [0, 10, 1_300_000] {
            let prompt: Vec<u8> = (0..size).map(|at| b'a' + (at % 26) as u8).collect();
            let (mut sender, mut receiver) = peers();
            let sending = {
                let (prompt, template) = (prompt.clone(), template.clone());
                tokio::spawn(
                    async move { send_review(&mut sender, 3, &prompt, Some(&template)).await },
                )
            };
            let first = receiver.receive("request_review").await.unwrap();
            let (number, received, metadata) = receive_review(&mut receiver, first).await.unwrap();
            sending.await.unwrap().unwrap();
            assert_eq!((number, received.len()), (3, prompt.len()));
            assert!(received == prompt);
            let sent = Template::from_metadata(metadata["template"].as_object().unwrap());
            assert_eq!(sent.unwrap(), template);
        }
    }

    /// Parts of another request, or beyond the declared length, are refused.
    #[tokio::test]
    async fn review_parts_must_match() {
        let (mut sender, mut receiver) = peers();
        let mut metadata = crate::helpers::metadata("request", json!(0));
        metadata.insert("length".into(), json!(4));
        sender
            .send("request_review", b"ab", metadata)
            .await
            .unwrap();
        sender
            .send(
                "request_review_part",
                b"cde",
                crate::helpers::metadata("request", json!(0)),
            )
            .await
            .unwrap();
        let first = receiver.receive("request_review").await.unwrap();
        assert!(receive_review(&mut receiver, first).await.is_err());

        let mut metadata = crate::helpers::metadata("request", json!(1));
        metadata.insert("length".into(), json!(4));
        sender
            .send("request_review", b"ab", metadata)
            .await
            .unwrap();
        sender
            .send(
                "request_review_part",
                b"cd",
                crate::helpers::metadata("request", json!(2)),
            )
            .await
            .unwrap();
        let first = receiver.receive("request_review").await.unwrap();
        assert!(receive_review(&mut receiver, first).await.is_err());
    }

    fn approved(body: &[u8], template: Option<Template>) -> Approvals {
        let mut approvals = Approvals::default();
        approvals.review(0).unwrap();
        approvals.approved = Some(Approved {
            request: 0,
            body: body.to_vec(),
            template,
        });
        approvals
    }

    /// Only the approved body, in order and in full, is admitted.
    #[test]
    fn only_the_approved_body_is_released() {
        let template = Template::fixture_default();
        let mut approvals = approved(b"{\"a\":1}", Some(template.clone()));
        approvals.partial(b"{\"a\"", Some(&template)).unwrap();
        assert!(approvals.partial(b"{\"b\"", Some(&template)).is_err());
        assert!(approvals.complete(b"{\"a\"", Some(&template)).is_err());
        assert_eq!(
            approvals.complete(b"{\"a\":1}", Some(&template)).unwrap(),
            0
        );
        assert!(approvals.partial(b"{", Some(&template)).is_err());
    }

    /// A request sent with another template than the approved one is refused.
    #[test]
    fn the_approved_template_is_required() {
        let template = Template::fixture_default();
        let mut other = template.clone();
        other.path = b"/v1/messages/batches".to_vec();
        let mut approvals = approved(b"{}", Some(template.clone()));
        approvals.template(&template).unwrap();
        assert!(approvals.template(&other).is_err());
        assert!(approvals.complete(b"{}", Some(&other)).is_err());
        assert!(approvals.complete(b"{}", None).is_err());
        assert!(Approvals::default().template(&template).is_err());
    }

    /// Reviews come in order, and not while an approved request is unsent.
    #[test]
    fn reviews_are_sequential() {
        let mut approvals = approved(b"{}", None);
        assert!(approvals.review(1).is_err());
        approvals.complete(b"{}", None).unwrap();
        assert!(approvals.review(2).is_err());
        approvals.review(1).unwrap();
        assert!(Approvals::default().complete(b"{}", None).is_err());
    }
}
