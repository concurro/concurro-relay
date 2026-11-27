//! HTTP/2 turns over the shared proved TLS record connection.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_provider_protocol::tls_key_update::{
    IndexedConnection, ResponseEvent, ResponseReader, Template,
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use super::{
    Forwarded, HttpEvent, HttpTurn, Rejected,
    providers::{ProviderState, configure_template},
};
use crate::{
    bootstrap::{Application, Session},
    helpers::{self, Peer, Runtime},
    ingress,
};

/// One HTTP/2 response as it is being authenticated and forwarded.
struct ResponseState {
    /// Validated HTTP status, when headers arrived.
    status: Option<u16>,
    /// Decoded provider response headers.
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Complete response body retained for usage or error evidence.
    body: Vec<u8>,
    /// Terminal H2 stream marker was received.
    done: bool,
    /// A successful SSE response has begun forwarding to the local client.
    streaming: bool,
    /// Time from request start to the first authenticated response DATA.
    first_data_seconds: Option<f64>,
}

impl ResponseState {
    /// Begin an unanswered H2 response stream.
    fn new() -> Self {
        Self {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            done: false,
            streaming: false,
            first_data_seconds: None,
        }
    }
}

/// Apply H2 response effects before requesting more provider records.
async fn deliver<C: AsyncRead + AsyncWrite + Unpin>(
    events: Vec<ResponseEvent>,
    link: &mut Forwarded<'_, C>,
    reply: &mpsc::Sender<Result<HttpEvent>>,
    response: &mut ResponseState,
    started: Instant,
) -> Result<()> {
    for event in events {
        match event {
            ResponseEvent::Headers(status, headers) => {
                ensure!(
                    response.status.is_none(),
                    "duplicate HTTP/2 response headers"
                );
                let content_type = headers
                    .iter()
                    .find(|(name, _)| name == b"content-type")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                    .unwrap_or_else(|| "application/octet-stream".to_owned());
                response.status = Some(status);
                response.headers = headers;
                response.streaming = status == 200 && content_type.contains("text/event-stream");
                if response.streaming {
                    reply
                        .send(Ok(HttpEvent::Start(status, content_type)))
                        .await
                        .context("local listener closed")?;
                }
            }
            ResponseEvent::Data(bytes) => {
                response
                    .first_data_seconds
                    .get_or_insert_with(|| started.elapsed().as_secs_f64());
                response.body.extend_from_slice(&bytes);
                if response.streaming {
                    reply
                        .send(Ok(HttpEvent::Data(bytes)))
                        .await
                        .context("local listener closed")?;
                }
            }
            ResponseEvent::Send(wire) => link.send(&wire).await?,
            ResponseEvent::Done => response.done = true,
        }
    }
    Ok(())
}

/// Append a sanitized turn event before another provider action can fail.
async fn journal(runtime: &Runtime, event: &Value) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(runtime.output.join("http-turns.jsonl"))
        .await?;
    file.write_all(&serde_json::to_vec(event)?).await?;
    file.write_all(b"\n").await?;
    Ok(())
}

/// Prove one provider-bound body and collect its authenticated H2 response.
async fn exchange<C: AsyncRead + AsyncWrite + Unpin>(
    link: &mut Forwarded<'_, C>,
    state: &mut IndexedConnection,
    reader: &mut ResponseReader,
    turn: &HttpTurn,
    template: &Template,
    body: &[u8],
    first: bool,
    started: Instant,
) -> Result<(u64, u32, ResponseState)> {
    // The first request was approved before the bootstrap.
    let request = if first {
        0
    } else {
        link.review(body, Some(template)).await?
    };
    let stream = if first {
        1
    } else {
        link.peer
            .send("h2_template", &[], template.metadata()?)
            .await?;
        let (stream, headers) = state.later_headers(0, template)?;
        link.send(&headers).await?;
        stream
    };
    reader.stream(stream);
    let mut response = ResponseState::new();
    let mut offset = 0;
    while offset < body.len() {
        while state.connection_window <= 0 || state.stream_window <= 0 {
            let bytes = link.read_application().await?;
            let events = reader.push(&bytes, state)?;
            deliver(events, link, &turn.reply, &mut response, started).await?;
            ensure!(
                !response.done,
                "provider ended during HTTP/2 request upload"
            );
        }
        let size = (body.len() - offset)
            .min(16_375)
            .min(state.connection_window as usize)
            .min(state.stream_window as usize);
        state.consume_window(size)?;
        offset += size;
        let wire = state.data_chunk(
            stream,
            &body[offset - size..offset],
            offset == body.len(),
            0,
        )?;
        link.send(&wire).await?;
    }
    if !link.buffer.is_empty() {
        let bytes = std::mem::take(&mut link.buffer);
        let events = reader.push(&bytes, state)?;
        deliver(events, link, &turn.reply, &mut response, started).await?;
    }
    while !response.done {
        let bytes = link.read_application().await?;
        let events = reader.push(&bytes, state)?;
        deliver(events, link, &turn.reply, &mut response, started).await?;
    }
    Ok((request, stream, response))
}

/// Answers the local CLI's request with the Sponsor's rejection.
async fn reject(turn: &HttpTurn, error: &anyhow::Error) -> Result<()> {
    let body = ingress::tls_key_update::rejection(turn.template.provider, &error.to_string())?;
    turn.reply
        .send(Ok(HttpEvent::Start(403, "application/json".into())))
        .await
        .context("local listener closed")?;
    turn.reply
        .send(Ok(HttpEvent::Data(body)))
        .await
        .context("local listener closed")?;
    turn.reply
        .send(Ok(HttpEvent::Done))
        .await
        .context("local listener closed")
}

/// Has the Sponsor approve a session's first request, `body` sent with
/// `template`, before the TLS bootstrap: its HEADERS go out with the
/// bootstrap prefix. Fails with [`Rejected`] when the Sponsor rejects it.
pub async fn review_first<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    body: &[u8],
    template: &Template,
    compact: bool,
    account: Option<&str>,
) -> Result<()> {
    let provider = ProviderState::new(template.provider, compact, account);
    let prepared = provider.prepare(body, template)?;
    super::ask_review(
        peer,
        0,
        &template.encoded_body(&prepared.body)?,
        Some(template),
    )
    .await
}

/// Complete successive HTTP/2 streams without another TLS bootstrap.
pub async fn concurro<C: AsyncRead + AsyncWrite + Unpin>(
    session: Session<C>,
    tunnel: Arc<Tunnel>,
    runtime: Runtime,
    mut turns: mpsc::Receiver<HttpTurn>,
    completion_ack: bool,
    compact: bool,
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
        credential_length,
        ..
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
        reviews: 1,
    };
    let mut state = IndexedConnection::new(credential_length)?;
    let mut reader = ResponseReader::new();
    let mut responses = Vec::new();
    let mut turn_index = 0usize;
    let mut request_index = 0usize;
    let provider = result
        .provider
        .context("HTTP provider missing from session")?;
    let mut provider_state = ProviderState::new(provider, compact, result.account.as_deref());
    while let Some(turn) = turns.recv().await {
        let outcome = async {
            let mut template = turn.template.clone();
            configure_template(&mut template, compact);
            let source_bytes = turn.body.len();
            let mut prepared = provider_state.prepare(&turn.body, &template)?;
            loop {
                let wire_body = template.encoded_body(&prepared.body)?;
                let started = Instant::now();
                let proofs_before = link.turn;
                let proof_time_before = link.proof_time;
                journal(
                    &runtime,
                    &json!({"event":"request_start", "turn":turn_index,
                    "attempt":request_index, "mode":prepared.mode, "parent":prepared.parent,
                    "decision":prepared.decision, "mismatch":prepared.mismatch,
                    "cli_body_bytes":source_bytes, "provider_body_bytes":wire_body.len(), "provider_json_bytes":prepared.body.len(),
                    "provider_body_sha256":hex::encode(helpers::sha256(&wire_body))}),
                )
                .await?;
                let result = exchange(
                    &mut link,
                    &mut state,
                    &mut reader,
                    &turn,
                    &template,
                    &wire_body,
                    request_index == 0,
                    started,
                )
                .await;
                let (request, stream, response) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        journal(
                            &runtime,
                            &json!({"event":"request_failed", "turn":turn_index,
                            "attempt":request_index, "error":format!("{error:#}"),
                            "proof_records":link.turn - proofs_before,
                            "proof_seconds":(link.proof_time - proof_time_before).as_secs_f64(),
                            "elapsed_seconds":started.elapsed().as_secs_f64()}),
                        )
                        .await?;
                        return Err(error);
                    }
                };
                let status = response.status.context("HTTP/2 response status missing")?;
                let error: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
                journal(
                    &runtime,
                    &json!({"event":"request_end", "turn":turn_index,
                    "attempt":request_index, "stream":stream, "mode":prepared.mode,
                    "status":status, "first_data_seconds":response.first_data_seconds,
                    "elapsed_seconds":started.elapsed().as_secs_f64(),
                    "proof_records":link.turn - proofs_before,
                    "proof_seconds":(link.proof_time - proof_time_before).as_secs_f64(),
                    "response_bytes":response.body.len(),
                    "error_code":provider.error_code(&error)}),
                )
                .await?;
                request_index += 1;
                if provider_state.replay(&mut prepared, status, &error)? {
                    continue;
                }
                let content_type = response
                    .headers
                    .iter()
                    .find(|(name, _)| name == b"content-type")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                    .unwrap_or_default();
                if status != 200 || !content_type.contains("text/event-stream") {
                    let evidence = json!({"status":status, "content_type":content_type,
                        "error_type":provider.error_kind(&error),
                        "error_code":provider.error_code(&error),
                        "response_sha256":hex::encode(helpers::sha256(&response.body))});
                    tokio::fs::write(
                        runtime
                            .output
                            .join(format!("provider-error-{turn_index}.json")),
                        serde_json::to_vec_pretty(&evidence)?,
                    )
                    .await?;
                    turn.reply
                        .send(Ok(HttpEvent::Start(status, content_type.clone())))
                        .await
                        .context("local listener closed")?;
                    turn.reply
                        .send(Ok(HttpEvent::Data(response.body)))
                        .await
                        .context("local listener closed")?;
                    let (finished, acknowledged) = oneshot::channel();
                    turn.reply
                        .send(Ok(HttpEvent::ProviderError(finished)))
                        .await
                        .context("local listener closed")?;
                    acknowledged
                        .await
                        .context("local HTTP error response unfinished")?;
                    bail!("provider returned HTTP {status} {content_type}");
                }
                let summary = provider.summarize(status, &response.headers, &response.body)?;
                provider_state.complete(
                    &prepared,
                    &template,
                    summary.message_id.clone(),
                    &response.body,
                );
                journal(
                    &runtime,
                    &json!({"event":"message_complete", "turn":turn_index,
                    "attempt":request_index - 1, "message_id":summary.message_id,
                    "thread_parent_ready":provider_state.ready(),
                    "usage":summary.usage, "provider_tool_uses":summary.tool_uses}),
                )
                .await?;
                link.peer
                    .send(
                        "audit_usage",
                        &[],
                        serde_json::from_value(
                            json!({"usage":summary.usage.clone(), "request":request}),
                        )?,
                    )
                    .await?;
                responses.push(json!({"stream":stream, "message_id":summary.message_id,
                    "usage":summary.usage, "status":status, "cli_body_bytes":source_bytes,
                    "provider_body_bytes":wire_body.len(), "provider_json_bytes":prepared.body.len(), "mode":prepared.mode,
                    "parent":prepared.parent, "proof_records":link.turn - proofs_before,
                    "proof_seconds":(link.proof_time - proof_time_before).as_secs_f64(),
                    "provider_tool_uses":summary.tool_uses}));
                turn.reply
                    .send(Ok(HttpEvent::Done))
                    .await
                    .context("local listener closed")?;
                break;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match outcome {
            Ok(()) => {}
            // Nothing of a rejected request was sent, so later requests can
            // follow on this connection.
            Err(error) if error.is::<Rejected>() => reject(&turn, &error).await?,
            Err(error) => {
                let _ = turn.reply.send(Err(error)).await;
                return Err(anyhow::anyhow!("HTTP/2 turn failed"));
            }
        }
        turn_index += 1;
    }
    link.peer.send("complete", &[], Map::new()).await?;
    if completion_ack {
        link.peer.receive("complete_ack").await?;
    }
    let report = json!({"route":"tls_key_update", "provider":provider, "status":200, "responses":responses,
        "h2":result.h2, "h3":result.h3, "session_id":result.session_id,
        "prefix_key_commitment":result.prefix_key_commitment,
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
