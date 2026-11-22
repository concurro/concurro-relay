//! Signed private inference dispatch to native Claude and Codex ingress.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use concurro_relay_hosted_api::{
    claim::SessionClaim,
    dispatch::{
        CHATGPT_SUBSCRIPTION, CLAIM_HEADER, CLAUDE_SUBSCRIPTION, ModelRequest, REQUEST_HEADER,
    },
};
use concurro_relay_protocol::ws::FINAL_EVENTS;
use concurro_relay_provider_protocol::{claude::SseSummarizer, codex};
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Request, Response, StatusCode,
    body::{Bytes, Frame, Incoming},
    client::conn::http1,
    header::{self, HeaderValue},
};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::{net::TcpStream, sync::OwnedMutexGuard};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    App,
    http::{self, Failure, Outcome, ResponseStream},
    lease,
};

const LOCAL_BEARER: HeaderValue = HeaderValue::from_static("Bearer local-relay-placeholder");
const MAX_BODY: usize = 48 * 1024 * 1024;

/// Native ingress protocol selected by the private endpoint.
pub enum Provider {
    Claude,
    Codex,
}

impl Provider {
    /// Exact approved subscription route for this provider.
    fn route(&self) -> &'static str {
        match self {
            Self::Claude => CLAUDE_SUBSCRIPTION,
            Self::Codex => CHATGPT_SUBSCRIPTION,
        }
    }
}

/// A provider call that already spent its durable admission and holds its session.
struct Call {
    app: Arc<App>,
    claim: SessionClaim,
    request_id: String,
    _session: OwnedMutexGuard<()>,
}

impl Call {
    /// Persist observed usage once, including partial counts on interruption.
    fn charge(&self, usage: Option<&Value>, terminal: bool) -> Result<()> {
        let Some(usage) = usage else {
            return Ok(());
        };
        let input = usage["input_tokens"].as_u64();
        let output = usage["output_tokens"].as_u64();
        if input.is_none() && output.is_none() {
            return Ok(());
        }
        self.app.journal.lock().expect("claim journal lock").charge(
            &self.claim.jti,
            &self.request_id,
            input
                .unwrap_or_default()
                .saturating_add(output.unwrap_or_default()),
            terminal && input.is_some() && output.is_some(),
        )
    }
}

/// Check the claim and request model before taking a link or spending allowance.
pub async fn handle(app: Arc<App>, provider: Provider, request: Request<Incoming>) -> Outcome {
    let (parts, body) = request.into_parts();
    let compact =
        http::unique_header(&parts.headers, CLAIM_HEADER).ok_or_else(lease::claim_refused)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claim = app
        .keys
        .verify(compact, now)
        .map_err(|_| lease::claim_refused())?;
    if claim.route != provider.route() || lease::binding(&app, &claim).is_none() {
        return Err(lease::claim_refused());
    }
    let request_id = http::unique_header(&parts.headers, REQUEST_HEADER)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Failure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request_id",
                "one exchange request ID required",
            )
        })?
        .to_owned();
    let body = http::bytes(body, MAX_BODY).await?;
    let model: ModelRequest = serde_json::from_slice(&body).map_err(|_| invalid_body())?;
    if !claim.models.contains(&model.model) {
        return Err(lease::claim_refused());
    }
    let codex = match provider {
        Provider::Claude => None,
        Provider::Codex => Some(CodexRequest::parse(&body)?),
    };

    let gate = app
        .journal
        .lock()
        .expect("claim journal lock")
        .session(&claim.sub);
    let session = tokio::time::timeout(lease::remaining(claim.exp), gate.lock_owned())
        .await
        .map_err(|_| lease::claim_refused())?;
    let endpoint = lease::admit(&app, &claim, &request_id).await?;
    let call = Call {
        app,
        claim,
        request_id,
        _session: session,
    };
    match codex {
        Some(request) => dispatch_codex(endpoint, request, call).await,
        None => dispatch_claude(endpoint, parts.headers, body, call).await,
    }
}

/// Forward the original Messages JSON and stream the native response with an SSE usage tap.
async fn dispatch_claude(
    endpoint: SocketAddr,
    headers: HeaderMap,
    body: Bytes,
    call: Call,
) -> Outcome {
    let mut request = Request::post("/v1/messages")
        .body(Full::new(body))
        .map_err(|error| Failure::unavailable(error.into()))?;
    for (name, value) in &headers {
        if !name.as_str().starts_with("x-concurro-")
            && !matches!(
                name.as_str(),
                "authorization" | "host" | "connection" | "transfer-encoding" | "content-length"
            )
        {
            request.headers_mut().append(name, value.clone());
        }
    }
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, LOCAL_BEARER);
    let stream = TcpStream::connect(endpoint)
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    let (mut native, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    let connection = AbortOnDropHandle::new(tokio::spawn(connection));
    let response = native
        .send_request(request)
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    let (mut parts, mut upstream) = response.into_parts();
    parts.headers.remove(header::CONNECTION);
    parts.headers.remove(header::TRANSFER_ENCODING);
    let mut tap = (parts.status == StatusCode::OK
        && parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/event-stream")))
    .then(SseSummarizer::default);
    if tap.is_some() {
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    let (sender, body) = http::streaming();
    tokio::spawn(async move {
        let mut parse_ok = true;
        let result = async {
            loop {
                let frame = tokio::select! {
                    biased;
                    () = sender.closed() => return Ok(()),
                    frame = upstream.frame() => frame,
                };
                let Some(frame) = frame else {
                    break;
                };
                let frame = frame?;
                if parse_ok
                    && let Some(bytes) = frame.data_ref()
                    && let Some(tap) = tap.as_mut()
                {
                    parse_ok = tap.push(bytes).is_ok();
                }
                if parse_ok && let Some(summary) = tap.as_ref().and_then(SseSummarizer::completed) {
                    call.charge(Some(&summary.usage), true)?;
                    tap = None;
                }
                if sender.send(Ok(frame)).await.is_err() {
                    return Ok(());
                }
            }
            let terminal = tap.as_mut().filter(|_| parse_ok).and_then(|tap| {
                tap.finish().ok()?;
                tap.completed()
            });
            if let Some(summary) = terminal {
                call.charge(Some(&summary.usage), true)?;
                tap = None;
            }
            Ok(())
        }
        .await;
        connection.abort();
        let _ = connection.await;
        let observed = tap.map_or(Ok(()), |tap| call.charge(Some(&tap.usage()), false));
        stream_error(&sender, result.and(observed)).await;
    });
    Ok(Response::from_parts(parts, body))
}

/// Responses JSON prepared for the retained native WebSocket.
struct CodexRequest {
    event: String,
    streaming: bool,
}

impl CodexRequest {
    /// Convert the dispatch body to a response.create payload.
    fn parse(bytes: &[u8]) -> Result<Self, Failure> {
        let mut request: Value = serde_json::from_slice(bytes).map_err(|_| invalid_body())?;
        let fields = request.as_object_mut().ok_or_else(invalid_body)?;
        if fields.remove("background") == Some(Value::Bool(true)) {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                "unsupported_transport",
                "background Responses are unavailable over the retained provider WebSocket",
            ));
        }
        let streaming = fields.remove("stream") == Some(Value::Bool(true));
        fields.insert("type".into(), Value::String("response.create".into()));
        Ok(Self {
            event: request.to_string(),
            streaming,
        })
    }
}

/// Carry a Responses request over native Codex WS, rendering the result as HTTP.
async fn dispatch_codex(endpoint: SocketAddr, request: CodexRequest, call: Call) -> Outcome {
    let mut upgrade = format!("ws://{endpoint}/v1/responses")
        .into_client_request()
        .map_err(|error| Failure::unavailable(error.into()))?;
    upgrade
        .headers_mut()
        .insert(header::AUTHORIZATION, LOCAL_BEARER);
    let stream = TcpStream::connect(endpoint)
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    let (mut ws, _) = client_async(upgrade, stream)
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    ws.send(Message::Text(request.event.into()))
        .await
        .map_err(|error| Failure::unavailable(error.into()))?;
    if !request.streaming {
        let terminal = codex_events(&mut ws, &call, None)
            .await
            .map_err(Failure::unavailable)?;
        return Ok(http::json(terminal.get("response").unwrap_or(&terminal)));
    }
    let (sender, body) = http::streaming();
    tokio::spawn(async move {
        let result = codex_events(&mut ws, &call, Some(&sender))
            .await
            .map(|_| ());
        stream_error(&sender, result).await;
    });
    let mut response = Response::new(body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Forward Codex events as they arrive, settling usage from the authenticated terminal event.
async fn codex_events(
    socket: &mut WebSocketStream<TcpStream>,
    call: &Call,
    sender: Option<&ResponseStream>,
) -> Result<Value> {
    loop {
        let message = if let Some(sender) = sender {
            tokio::select! {
                biased;
                () = sender.closed() => return Ok(Value::Null),
                message = socket.next() => message,
            }
        } else {
            socket.next().await
        };
        let Some(message) = message else {
            bail!("native Codex response ended before a terminal event");
        };
        let Message::Text(raw) = message? else {
            continue;
        };
        let event: Value = serde_json::from_str(&raw)?;
        let kind = event["type"].as_str().context("Codex event type missing")?;
        let terminal = FINAL_EVENTS.contains(&kind);
        if terminal {
            call.charge(codex::terminal_usage(&event), true)?;
        }
        if let Some(sender) = sender
            && sender
                .send(Ok(Frame::data(Bytes::from(format!(
                    "event: {kind}\ndata: {raw}\n\n"
                )))))
                .await
                .is_err()
        {
            return Ok(Value::Null);
        }
        if terminal {
            return Ok(event);
        }
    }
}

/// An interrupted stream must not look like a complete upstream response.
async fn stream_error(sender: &ResponseStream, result: Result<()>) {
    if let Err(error) = result {
        eprintln!("hosted inference stream ended: {error:#}");
        let _ = sender.send(Err(error)).await;
    }
}

/// Reject malformed dispatch JSON without exposing its content.
fn invalid_body() -> Failure {
    Failure::new(
        StatusCode::BAD_REQUEST,
        "invalid_body",
        "expected provider JSON with a model",
    )
}
