//! Claude HTTP/2 turns over the shared proved TLS record connection.

use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_provider_protocol::claude::{
    self, IndexedConnection, ResponseEvent, ResponseReader,
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use super::{ClaudeEvent, ClaudeTurn, Forwarded};
use crate::{
    bootstrap::{Application, Session},
    helpers::{self, Runtime},
};

/// One Claude response as it is being authenticated and forwarded.
struct ResponseState {
    /// Validated HTTP status, when headers arrived.
    status: Option<u16>,
    /// Decoded provider response headers.
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Complete response body retained for usage or error evidence.
    body: Vec<u8>,
    /// Terminal H2 stream marker was received.
    done: bool,
}

impl ResponseState {
    /// Begin an unanswered H2 response stream.
    fn new() -> Self {
        Self {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            done: false,
        }
    }
}

/// Apply H2 response effects before requesting more provider records.
async fn deliver<C: AsyncRead + AsyncWrite + Unpin>(
    events: Vec<ResponseEvent>,
    link: &mut Forwarded<'_, C>,
    reply: &mpsc::Sender<Result<ClaudeEvent>>,
    response: &mut ResponseState,
) -> Result<()> {
    for event in events {
        match event {
            ResponseEvent::Headers(status, headers) => {
                ensure!(
                    response.status.is_none(),
                    "duplicate Claude response headers"
                );
                let content_type = headers
                    .iter()
                    .find(|(name, _)| name == b"content-type")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                    .unwrap_or_else(|| "application/octet-stream".to_owned());
                response.status = Some(status);
                response.headers = headers;
                reply
                    .send(Ok(ClaudeEvent::Start(status, content_type)))
                    .await
                    .context("local Claude listener closed")?;
            }
            ResponseEvent::Data(bytes) => {
                response.body.extend_from_slice(&bytes);
                reply
                    .send(Ok(ClaudeEvent::Data(bytes)))
                    .await
                    .context("local Claude listener closed")?;
            }
            ResponseEvent::Send(wire) => link.send(&wire).await?,
            ResponseEvent::Done => response.done = true,
        }
    }
    Ok(())
}

/// Complete successive Claude HTTP/2 streams without another TLS bootstrap.
pub async fn concurro<C: AsyncRead + AsyncWrite + Unpin>(
    session: Session<C>,
    tunnel: Arc<Tunnel>,
    runtime: Runtime,
    mut turns: mpsc::Receiver<ClaudeTurn>,
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
        buffer: Vec::new(),
    };
    let mut state = IndexedConnection::new(credential_length)?;
    let mut reader = ResponseReader::new();
    let mut responses = Vec::new();
    let mut turn_index = 0usize;
    while let Some(turn) = turns.recv().await {
        let outcome = async {
            let proofs_before = link.turn;
            let stream = if turn_index == 0 {
                1
            } else {
                link.peer
                    .send("h2_template", &[], turn.template.metadata()?)
                    .await?;
                let (stream, headers) = state.later_headers(0, &turn.template)?;
                link.send(&headers).await?;
                stream
            };
            reader.stream(stream);
            serde_json::from_slice::<Value>(&turn.body)
                .context("Claude request body is not JSON")?;
            let mut response = ResponseState::new();
            let mut offset = 0;
            while offset < turn.body.len() {
                while state.connection_window <= 0 || state.stream_window <= 0 {
                    let bytes = link.read_application().await?;
                    let events = reader.push(&bytes, &mut state)?;
                    deliver(events, &mut link, &turn.reply, &mut response).await?;
                    ensure!(
                        !response.done,
                        "provider ended during Claude request upload"
                    );
                }
                let size = (turn.body.len() - offset)
                    .min(16_375)
                    .min(state.connection_window as usize)
                    .min(state.stream_window as usize);
                state.consume_window(size)?;
                offset += size;
                let wire = state.data_chunk(
                    stream,
                    &turn.body[offset - size..offset],
                    offset == turn.body.len(),
                    0,
                )?;
                link.send(&wire).await?;
            }
            if !link.buffer.is_empty() {
                let bytes = std::mem::take(&mut link.buffer);
                let events = reader.push(&bytes, &mut state)?;
                deliver(events, &mut link, &turn.reply, &mut response).await?;
            }
            while !response.done {
                let bytes = link.read_application().await?;
                let events = reader.push(&bytes, &mut state)?;
                deliver(events, &mut link, &turn.reply, &mut response).await?;
            }
            let status = response.status.context("Claude response status missing")?;
            let content_type = response
                .headers
                .iter()
                .find(|(name, _)| name == b"content-type")
                .map(|(_, value)| value.as_slice())
                .unwrap_or_default();
            if !content_type
                .windows(b"text/event-stream".len())
                .any(|part| part == b"text/event-stream")
            {
                let content_type = String::from_utf8_lossy(content_type).into_owned();
                let error: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
                let error_type = error["error"]["type"].as_str();
                let evidence = json!({"status":status, "content_type":content_type,
                    "error_type":error_type,
                    "response_sha256":hex::encode(helpers::sha256(&response.body))});
                tokio::fs::write(
                    runtime.output.join("provider-error.json"),
                    serde_json::to_vec_pretty(&evidence)?,
                )
                .await?;
                let (finished, acknowledged) = oneshot::channel();
                turn.reply
                    .send(Ok(ClaudeEvent::ProviderError(finished)))
                    .await
                    .context("local Claude listener closed")?;
                acknowledged
                    .await
                    .context("local Claude error response unfinished")?;
                bail!("provider returned HTTP {status} {content_type} error_type={error_type:?}");
            }
            let summary = claude::summarize_sse(status, &response.headers, &response.body)?;
            link.peer
                .send(
                    "audit_usage",
                    &[],
                    serde_json::from_value(json!({"usage":summary.usage.clone()}))?,
                )
                .await?;
            responses.push(json!({"stream":stream, "message_id":summary.message_id,
                "usage":summary.usage, "status":status, "body_bytes":turn.body.len(),
                "proof_records":link.turn - proofs_before}));
            turn.reply
                .send(Ok(ClaudeEvent::Done))
                .await
                .context("local Claude listener closed")?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = outcome {
            let _ = turn.reply.send(Err(error)).await;
            return Err(anyhow::anyhow!("Claude turn failed"));
        }
        turn_index += 1;
    }
    link.peer.send("complete", &[], Map::new()).await?;
    if completion_ack {
        link.peer.receive("complete_ack").await?;
    }
    let report = json!({"route":"claude_h2", "status":200, "responses":responses,
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
