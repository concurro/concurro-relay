//! A mock inference provider: TLS 1.2, a standard HTTP/1.1 parser, bearer
//! auth, and an SSE response carrying a tool call. It also accepts a
//! WebSocket upgrade and answers each message with a response's events.

use std::{
    collections::HashSet,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{
        AUTHORIZATION, CONNECTION, CONTENT_TYPE, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE,
    },
    server::conn::http1,
    service::service_fn,
    upgrade::{self, Upgraded},
};
use hyper_util::rt::TokioIo;
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer},
    version::TLS12,
};
use serde_json::{Value, json};
use tlsn_server_fixture_certs::{SERVER_CERT_DER, SERVER_KEY_DER};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::derive_accept_key, protocol::Role},
};

/// Request header selecting the approximate response body size.
pub const RESPONSE_BYTES_HEADER: &str = "x-spike-response-bytes";

/// Request header asking the provider to wait this many milliseconds before
/// it responds.
pub const DELAY_HEADER: &str = "x-spike-delay-ms";

/// Upgrade request header making the provider depart from the protocol on
/// its WebSocket connection, in one of the ways named below.
pub const MISBEHAVE_HEADER: &str = "x-spike-misbehave";

/// Send a ping before each response.
pub const PING: &str = "ping";

/// Send a ping after starting each response, and send nothing more of the
/// response until the pong arrives.
pub const PING_GATED: &str = "ping-gated";

/// Send a ping a moment after each response has ended, and drop the
/// connection unless a pong is the next message to arrive.
pub const PING_IDLE: &str = "ping-idle";

/// How long after a response its [`PING_IDLE`] ping is sent.
const IDLE_PING_DELAY: Duration = Duration::from_millis(100);

/// Drop the connection in place of completing a response.
pub const CLOSE: &str = "close";

/// Send a WebSocket close in place of completing a response, and keep the
/// connection open for a while after it.
pub const CLOSE_HELD: &str = "close-held";

/// Run each response under an id which can not be continued.
pub const FORGED_ID: &str = "forged-id";

/// The id used under [`FORGED_ID`].
pub const FORGED_RESPONSE: &str = "resp_forged";

/// Complete each response under another id than it started with.
pub const MIXED_ID: &str = "mixed-id";

/// Complete each response twice.
pub const DUPLICATE_END: &str = "duplicate-end";

/// Send one more output event after each response has completed.
pub const STALE_EVENT: &str = "stale-event";

/// Start each response as continuing a response the request did not name.
pub const WRONG_PARENT: &str = "wrong-parent";

/// Id of the message in every successful response.
pub const MESSAGE_ID: &str = "msg_mock";

/// Length of the token prefix a lenient provider authenticates on.
pub const LENIENT_PREFIX: usize = 16;

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub token: String,
    /// Authenticate on a token prefix only, modelling a provider whose
    /// credentials are not fixed-length.
    pub lenient: bool,
}

pub async fn serve(listener: TcpListener, config: ProviderConfig) -> Result<()> {
    let tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS12])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(SERVER_CERT_DER)],
            PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into()),
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    loop {
        let (socket, _) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let (acceptor, config) = (acceptor.clone(), config.clone());
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(socket).await {
                let service = service_fn(|request| handle(request, &config));
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            }
        });
    }
}

async fn handle(
    request: Request<Incoming>,
    config: &ProviderConfig,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let websocket = header(UPGRADE.as_str())
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case("websocket"))
        .then(|| {
            derive_accept_key(
                header(SEC_WEBSOCKET_KEY.as_str())
                    .unwrap_or_default()
                    .as_bytes(),
            )
        });
    let misbehaviour = header(MISBEHAVE_HEADER).map(str::to_owned);
    let presented = header(AUTHORIZATION.as_str()).unwrap_or_default();
    let authorized = if config.lenient {
        presented.starts_with(&format!("Bearer {}", &config.token[..LENIENT_PREFIX]))
    } else {
        presented == format!("Bearer {}", config.token)
    };
    let size = header(RESPONSE_BYTES_HEADER)
        .and_then(|value| value.parse().ok())
        .unwrap_or(2048);
    let saw_evil = request.headers().contains_key("x-evil");
    if let Some(delay) = header(DELAY_HEADER).and_then(|value| value.parse().ok()) {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    if authorized && let Some(accept) = websocket {
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade::on(request).await {
                let socket =
                    WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None)
                        .await;
                let _ = converse(socket, size, misbehaviour.as_deref()).await;
            }
        });
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_ACCEPT, accept)
            .body(Full::default())
            .expect("response is valid"));
    }

    let (status, content_type, body) = if authorized {
        let zstd = header("content-encoding") == Some("zstd");
        let body = request
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes())
            .unwrap_or_default();
        let body = if zstd {
            zstd::decode_all(&body[..]).unwrap_or_default()
        } else {
            body.to_vec()
        };
        (
            StatusCode::OK,
            "text/event-stream",
            events(size, &body, saw_evil),
        )
    } else {
        let error = r#"{"error":{"type":"authentication_error"}}"#.to_owned();
        (StatusCode::UNAUTHORIZED, "application/json", error)
    };
    Ok(Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body)))
        .expect("response is valid"))
}

/// Answers each message on `socket` with the events of a response of about
/// `size` bytes. A response may continue only one issued on this
/// connection.
async fn converse(
    mut socket: WebSocketStream<TokioIo<Upgraded>>,
    size: usize,
    misbehaviour: Option<&str>,
) -> Result<()> {
    static ISSUED: AtomicUsize = AtomicUsize::new(0);
    let event = |event: Value| Message::Text(event.to_string().into());
    let mut issued = HashSet::new();
    while let Some(message) = socket.next().await {
        let Message::Text(text) = message? else {
            continue;
        };
        let request: Value = serde_json::from_str(text.as_str()).unwrap_or_default();
        let previous = request["previous_response_id"].as_str();
        if previous.is_some_and(|id| !issued.contains(id)) {
            socket
                .send(event(
                    json!({"type": "error", "error": {"code": "previous_response_not_found"}}),
                ))
                .await?;
            continue;
        }
        let issue = format!("resp_mock_{}", ISSUED.fetch_add(1, Ordering::Relaxed));
        let id = if misbehaviour == Some(FORGED_ID) {
            FORGED_RESPONSE
        } else {
            &issue
        };
        if misbehaviour == Some(PING) {
            socket.send(Message::Ping("spike".into())).await?;
        }
        socket
            .send(event(json!({"type": "codex.rate_limits"})))
            .await?;
        let parent = if misbehaviour == Some(WRONG_PARENT) {
            Some("resp_other")
        } else {
            previous
        };
        let created = json!({"id": id, "previous_response_id": parent, "store": request["store"]});
        socket
            .send(event(
                json!({"type": "response.created", "sequence_number": 0, "response": created}),
            ))
            .await?;
        if misbehaviour == Some(PING_GATED) {
            socket.send(Message::Ping("gate".into())).await?;
            while !matches!(socket.next().await, Some(Ok(Message::Pong(_))) | None) {}
        }
        let deltas = size / 256;
        let delta = |sequence: usize| {
            event(
                json!({"type": "response.output_text.delta", "sequence_number": sequence, "delta": "x".repeat(200)}),
            )
        };
        for sequence in 1..=deltas {
            socket.send(delta(sequence)).await?;
        }
        match misbehaviour {
            Some(CLOSE) => return Ok(socket.close(None).await?),
            Some(CLOSE_HELD) => {
                socket.send(Message::Close(None)).await?;
                tokio::time::sleep(Duration::from_secs(5)).await;
                return Ok(());
            }
            _ => {}
        }
        let completed = event(json!({
            "type": "response.completed",
            "sequence_number": deltas + 1,
            "response": {
                "id": if misbehaviour == Some(MIXED_ID) { "resp_other" } else { id },
                "previous_response_id": previous,
                "store": request["store"],
                "input_bytes": text.len(),
            },
        }));
        socket.send(completed.clone()).await?;
        match misbehaviour {
            Some(DUPLICATE_END) => socket.send(completed).await?,
            Some(STALE_EVENT) => socket.send(delta(deltas)).await?,
            _ => {}
        }
        issued.insert(issue);
        if misbehaviour == Some(PING_IDLE) {
            tokio::time::sleep(IDLE_PING_DELAY).await;
            socket.send(Message::Ping("idle".into())).await?;
            if !matches!(socket.next().await, Some(Ok(Message::Pong(_)))) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// The SSE stream for a processed request `body`, reporting which model it
/// asked for so tests can tell which body the provider acted on.
fn events(size: usize, body: &[u8], saw_evil: bool) -> String {
    let model = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value["model"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut out = String::from(
        "event: response.output_item.done\ndata: {\"type\":\"function_call\",\"name\":\"shell\",\"arguments\":\"{\\\"command\\\":\\\"ls\\\"}\"}\n\n",
    );
    let delta = format!(
        "event: response.output_text.delta\ndata: {{\"delta\":\"{}\"}}\n\n",
        "x".repeat(200)
    );
    while out.len() < size {
        out.push_str(&delta);
    }
    let completed = serde_json::json!({
        "message": {"id": MESSAGE_ID},
        "processed_model": model,
        "usage": {"input_bytes": body.len()},
        "saw_x_evil": saw_evil,
    });
    out.push_str(&format!("event: response.completed\ndata: {completed}\n\n"));
    out
}
