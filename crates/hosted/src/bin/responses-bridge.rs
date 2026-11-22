//! Local Codex WebSocket ingress that admits every Responses turn through agentgateway.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use concurro_relay_protocol::ws::FINAL_EVENTS;
use concurro_relay_verifier::accept;
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Uri, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time,
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{Request as UpgradeRequest, Response as UpgradeResponse},
        protocol::WebSocketConfig,
    },
};

/// WebSocket listener and the real gateway HTTP endpoint.
#[derive(Parser)]
struct Args {
    /// Listener to expose through the same TLS edge as the inference gateway.
    #[arg(long, default_value = "127.0.0.1:7451")]
    listen: SocketAddr,
    /// Actual agentgateway inference URL, used for every admitted POST.
    #[arg(long)]
    gateway: Uri,
    /// Seconds a CLI connection has to finish its WebSocket upgrade.
    #[arg(long, default_value = "10")]
    handshake_timeout_secs: NonZeroU64,
    /// Turns a CLI may queue while one is in flight; one more closes its
    /// connection.
    #[arg(long, default_value = "8")]
    queued_turns: NonZeroUsize,
    /// Bytes a CLI's WebSocket message may have.
    #[arg(long, default_value = "16777216")]
    max_message_bytes: NonZeroUsize,
    /// CLI connections open at once; more are closed as they arrive.
    #[arg(long, default_value = "1024")]
    max_connections: NonZeroUsize,
}

/// How long a connection may take to upgrade, and how many turns it may
/// queue.
#[derive(Clone, Copy)]
struct Limits {
    handshake: Duration,
    queued: usize,
    message_bytes: usize,
    connections: usize,
}

/// Turns waiting for the one in flight, at most `limit` of them.
struct Queue {
    turns: VecDeque<Message>,
    limit: usize,
}

/// Outcome of one gateway-admitted Responses turn.
enum TurnOutcome {
    /// The gateway returned a complete response or a classified refusal.
    Finished {
        /// Gateway HTTP status.
        status: u16,
        /// Number of provider events relayed to Codex.
        events: usize,
        /// Sanitized refusal category, if the turn was denied.
        category: Option<&'static str>,
        /// A disconnected non-generating warmup finished without a client.
        detached: bool,
    },
    /// Codex canceled or disconnected while the gateway request was active.
    Cancelled,
}

/// Carry one CLI WebSocket session through separately admitted gateway POSTs.
async fn client(stream: TcpStream, gateway: Arc<Uri>, limits: Limits) -> Result<()> {
    let mut authorization = None;
    let upgrade = accept_hdr_async_with_config(
        stream,
        |request: &UpgradeRequest, response: UpgradeResponse| {
            if request.uri().path() == "/v1/responses" {
                authorization = request.headers().get("authorization").cloned();
            }
            Ok(response)
        },
        Some(
            WebSocketConfig::default()
                .max_message_size(Some(limits.message_bytes))
                .max_frame_size(Some(limits.message_bytes)),
        ),
    );
    let socket = time::timeout(limits.handshake, upgrade)
        .await
        .context("Codex WebSocket upgrade timed out")??;
    let authorization = authorization.context("Codex virtual key missing")?;
    let (mut sink, mut source) = socket.split();
    let mut queued = Queue {
        turns: VecDeque::new(),
        limit: limits.queued,
    };
    let mut sequence = 0_u64;
    loop {
        let incoming = if let Some(message) = queued.turns.pop_front() {
            Some(Ok(message))
        } else {
            source.next().await
        };
        let Some(message) = incoming else { break };
        let Message::Text(raw) = message? else {
            continue;
        };
        let mut request: Value = serde_json::from_str(&raw)?;
        match request["type"].as_str() {
            Some("response.cancel") => break,
            Some("response.create") => {}
            _ => bail!("unsupported Codex WebSocket request"),
        }
        sequence += 1;
        let previous = request["previous_response_id"].as_str().map(str::to_owned);
        let input_types: Vec<_> = request["input"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item["type"].as_str().map(str::to_owned))
            .collect();
        let generate = request["generate"].as_bool();
        let warmup = generate == Some(false);
        if request["background"] == true {
            sink.send(Message::Text(
                json!({"type":"error","error":{
                "type":"unsupported_transport","code":"unsupported_transport",
                "message":"background Responses are unavailable over WebSocket"}})
                .to_string()
                .into(),
            ))
            .await?;
            continue;
        }
        let fields = request.as_object_mut().context("invalid Codex request")?;
        fields.remove("type");
        fields.remove("stream_id");
        fields.remove("background");
        request["stream"] = Value::Bool(true);
        let body = serde_json::to_vec(&request)?;
        let started = Instant::now();
        match forward(
            &mut sink,
            &mut source,
            &mut queued,
            &gateway,
            &authorization,
            body.clone(),
            warmup,
        )
        .await?
        {
            TurnOutcome::Finished {
                status,
                events,
                category,
                detached,
            } => {
                println!(
                    "{}",
                    json!({"kind":"codex_gateway_turn","sequence":sequence,
                    "previous_response_id":previous,"input_types":input_types,
                    "body_bytes":body.len(),"gateway_status":status,"events":events,
                    "category":category,"generate":generate,"detached":detached})
                );
                if status != 200 {
                    break;
                }
            }
            TurnOutcome::Cancelled => {
                println!(
                    "{}",
                    json!({"kind":"codex_gateway_cancel","sequence":sequence,
                    "previous_response_id":previous,"body_bytes":body.len(),
                    "input_types":input_types,"generate":generate,
                    "elapsed_ms":started.elapsed().as_millis()})
                );
                break;
            }
        }
    }
    Ok(())
}

/// Queue another turn, while `queued` has room, or stop the active gateway
/// request on cancellation, disconnect or a full queue.
async fn active_message(
    incoming: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    sink: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    queued: &mut Queue,
) -> Result<bool> {
    let limit = queued.limit;
    match incoming {
        Some(Ok(Message::Text(raw))) => {
            let request: Value = serde_json::from_str(&raw)?;
            match request["type"].as_str() {
                Some("response.cancel") => {
                    eprintln!("Codex sent response.cancel");
                    Ok(false)
                }
                Some("response.create") if queued.turns.len() >= limit => {
                    eprintln!("Codex queued more than {limit} turns");
                    sink.send(Message::Text(
                        json!({"type":"error","error":{
                        "type":"too_many_queued_turns","code":"too_many_queued_turns",
                        "message":format!("at most {limit} turns may wait for the one in flight")}})
                        .to_string()
                        .into(),
                    ))
                    .await?;
                    Ok(false)
                }
                Some("response.create") => {
                    queued.turns.push_back(Message::Text(raw));
                    Ok(true)
                }
                _ => bail!("unsupported Codex WebSocket request"),
            }
        }
        Some(Ok(Message::Close(_))) => {
            eprintln!("Codex closed WebSocket");
            Ok(false)
        }
        None => {
            eprintln!("Codex WebSocket reached EOF");
            Ok(false)
        }
        Some(Err(error)) => {
            eprintln!("Codex WebSocket read failed: {error}");
            Ok(false)
        }
        Some(Ok(Message::Ping(payload))) => {
            sink.send(Message::Pong(payload)).await?;
            Ok(true)
        }
        Some(Ok(_)) => Ok(true),
    }
}

/// Classify a gateway refusal without forwarding raw provider or identity details.
fn denial_category(status: u16, body: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    if status == 401 {
        return "auth";
    }
    if status == 403 && text.contains("model") {
        return "model_denied";
    }
    if status == 429 && text.contains("budget") {
        return "budget_denied";
    }
    match status {
        403 => "forbidden",
        429 => "rate_limited",
        502..=504 => "unavailable",
        _ => "gateway_http_error",
    }
}

/// Send one Responses POST to agentgateway and relay its sanitized SSE events unchanged.
async fn forward(
    sink: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    source: &mut SplitStream<WebSocketStream<TcpStream>>,
    queued: &mut Queue,
    gateway: &Uri,
    authorization: &hyper::http::HeaderValue,
    body: Vec<u8>,
    warmup: bool,
) -> Result<TurnOutcome> {
    ensure!(
        gateway.scheme_str() == Some("http"),
        "gateway URL must use local HTTP"
    );
    let authority = gateway.authority().context("gateway authority missing")?;
    let stream = TcpStream::connect(authority.as_str()).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    let connection = tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("gateway HTTP connection ended: {error}");
        }
    });
    let outcome = async {
        // Codex may close a non-generating warmup while native setup is still running.
        let mut detached = false;
        let request = Request::post("/v1/responses")
            .header("host", authority.as_str())
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .body(Full::new(Bytes::from(body)))?;
        let response = sender.send_request(request);
        tokio::pin!(response);
        let mut response = loop {
            if detached {
                break response.await?;
            }
            tokio::select! {
                ready = &mut response => break ready?,
                incoming = source.next() => {
                    if warmup && matches!(&incoming, None | Some(Ok(Message::Close(_))) | Some(Err(_))) {
                        detached = true;
                        continue;
                    }
                    if !active_message(incoming, sink, queued).await? { return Ok(TurnOutcome::Cancelled); }
                }
            }
        };
        let status = response.status().as_u16();
        let mut pending = Vec::new();
        let mut events = 0;
        let mut final_event = None;
        loop {
            let frame = if final_event.is_some() || detached {
                response.body_mut().frame().await
            } else {
                tokio::select! {
                    frame = response.body_mut().frame() => frame,
                    incoming = source.next() => {
                        if warmup && matches!(&incoming, None | Some(Ok(Message::Close(_))) | Some(Err(_))) {
                            detached = true;
                            continue;
                        }
                        if !active_message(incoming, sink, queued).await? { return Ok(TurnOutcome::Cancelled); }
                        continue;
                    }
                }
            };
            let Some(frame) = frame else { break };
            let frame = frame?;
            let Ok(data) = frame.into_data() else { continue };
            pending.extend_from_slice(&data);
            ensure!(pending.len() <= if status == 200 { 8 * 1024 * 1024 } else { 16 * 1024 },
                "gateway response event too large");
            if status != 200 { continue; }
            while let Some(end) = pending.windows(2).position(|bytes| bytes == b"\n\n") {
                let raw = pending.drain(..end + 2).collect::<Vec<_>>();
                let payload = raw.split(|byte| *byte == b'\n')
                    .find_map(|line| line.strip_prefix(b"data:").map(|value| value.trim_ascii()))
                    .context("gateway SSE event lacks data")?;
                if payload == b"[DONE]" { continue; }
                let event: Value = serde_json::from_slice(payload)?;
                let kind = event["type"].as_str().context("gateway event type missing")?;
                events += 1;
                if FINAL_EVENTS.contains(&kind) {
                    final_event = Some(String::from_utf8(payload.to_vec())?);
                } else if final_event.is_none() && !detached {
                    sink.send(Message::Text(String::from_utf8(payload.to_vec())?.into())).await?;
                }
            }
        }
        if status == 200 {
            let terminal = final_event.context("gateway response ended without a terminal event")?;
            if !detached {
                sink.send(Message::Text(terminal.into())).await?;
            }
            return Ok(TurnOutcome::Finished { status, events, category: None, detached });
        }
        let category = denial_category(status, &pending);
        if !detached { sink.send(Message::Text(json!({"type":"error","error":{
            "type":category,"code":category,
            "message":format!("gateway rejected request (HTTP {status}: {category})"),
            "status":status}}).to_string().into())).await?; }
        Ok(TurnOutcome::Finished { status, events, category: Some(category), detached })
    }.await;
    connection.abort();
    outcome
}

/// Start the public WebSocket ingress while agentgateway remains the admission authority.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;
    let gateway = Arc::new(args.gateway);
    let limits = Limits {
        handshake: Duration::from_secs(args.handshake_timeout_secs.get()),
        queued: args.queued_turns.get(),
        message_bytes: args.max_message_bytes.get(),
        connections: args.max_connections.get(),
    };
    println!("RESPONSES_BRIDGE_READY {}", listener.local_addr()?);
    serve(listener, gateway, limits).await
}

/// Carries each CLI connection on `listener` to `gateway`, up to the
/// connection limit at once.
async fn serve(listener: TcpListener, gateway: Arc<Uri>, limits: Limits) -> ! {
    let open = Arc::new(Semaphore::new(limits.connections));
    loop {
        let stream = accept::next_connection(&listener).await;
        let Ok(place) = open.clone().try_acquire_owned() else {
            continue;
        };
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let _place = place;
            if let Err(error) = client(stream, gateway, limits).await {
                eprintln!("Codex gateway WebSocket ended: {error:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc, time::Duration};

    use futures::StreamExt;
    use serde_json::Value;
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, TcpStream},
    };
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    };

    use super::{Limits, Queue, active_message, client, serve};

    /// A connected WebSocket pair: the bridge's end and the CLI's.
    async fn sockets() -> (WebSocketStream<TcpStream>, WebSocketStream<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cli = TcpStream::connect(address).await.unwrap();
        let (bridge, _) = listener.accept().await.unwrap();
        (
            WebSocketStream::from_raw_socket(bridge, Role::Server, None).await,
            WebSocketStream::from_raw_socket(cli, Role::Client, None).await,
        )
    }

    /// Turns queue up to the limit, and one more is refused and ends the
    /// connection's turn.
    #[tokio::test]
    async fn queued_turns_are_bounded() {
        let (bridge, mut cli) = sockets().await;
        let (mut sink, _source) = bridge.split();
        let mut queued = Queue {
            turns: VecDeque::new(),
            limit: 2,
        };
        let turn = || Some(Ok(Message::Text(r#"{"type":"response.create"}"#.into())));
        for _ in 0..2 {
            assert!(
                active_message(turn(), &mut sink, &mut queued)
                    .await
                    .unwrap()
            );
        }
        assert!(
            !active_message(turn(), &mut sink, &mut queued)
                .await
                .unwrap()
        );
        assert_eq!(queued.turns.len(), 2);
        let Some(Ok(Message::Text(refusal))) = cli.next().await else {
            panic!("the CLI was not told");
        };
        let refusal: Value = serde_json::from_str(&refusal).unwrap();
        assert_eq!(refusal["error"]["code"], "too_many_queued_turns");
        cli.close(None).await.unwrap();
    }

    /// A connection which never upgrades is closed once the limit passes.
    #[tokio::test]
    async fn a_silent_connection_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limits = Limits {
            handshake: Duration::from_millis(200),
            queued: 8,
            message_bytes: 16 << 20,
            connections: 1024,
        };
        let serving = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            client(
                stream,
                Arc::new("http://127.0.0.1:9/".parse().unwrap()),
                limits,
            )
            .await
        });
        let mut silent = TcpStream::connect(address).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(5), serving).await;
        assert!(ended.unwrap().unwrap().is_err());
        let mut byte = [0];
        assert!(matches!(silent.read(&mut byte).await, Ok(0) | Err(_)));
    }

    /// Connections beyond the limit are closed as they arrive.
    #[tokio::test]
    async fn connections_beyond_the_limit_are_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limits = Limits {
            handshake: Duration::from_secs(10),
            queued: 8,
            message_bytes: 16 << 20,
            connections: 1,
        };
        tokio::spawn(serve(
            listener,
            Arc::new("http://127.0.0.1:9/".parse().unwrap()),
            limits,
        ));
        let mut first = TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut second = TcpStream::connect(address).await.unwrap();
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(2), second.read(&mut byte)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
        let kept = tokio::time::timeout(Duration::from_millis(300), first.read(&mut byte)).await;
        assert!(kept.is_err(), "the first connection was closed");
    }

    /// A message beyond the size limit ends the connection.
    #[tokio::test]
    async fn an_oversized_message_ends_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limits = Limits {
            handshake: Duration::from_secs(10),
            queued: 8,
            message_bytes: 64,
            connections: 1024,
        };
        let serving = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            client(
                stream,
                Arc::new("http://127.0.0.1:9/".parse().unwrap()),
                limits,
            )
            .await
        });
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(format!("ws://{address}/v1/responses"))
            .header("host", address.to_string())
            .header("authorization", "Bearer key")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header(
                "sec-websocket-key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut cli, _) = tokio_tungstenite::client_async(request, stream)
            .await
            .unwrap();
        use futures::SinkExt;
        // Valid on its own: within the limit it would end the session cleanly.
        let cancel = format!(
            r#"{{"type":"response.cancel","pad":"{}"}}"#,
            "x".repeat(100)
        );
        cli.send(Message::Text(cancel.into())).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(5), serving).await;
        assert!(ended.unwrap().unwrap().is_err());
    }

    /// A limit of 0, which would stop the bridge serving, is refused.
    #[test]
    fn zero_limits_are_refused() {
        use clap::Parser;

        let required = ["responses-bridge", "--gateway=http://127.0.0.1:9/"];
        assert!(super::Args::try_parse_from(required).is_ok());
        for limit in [
            "--handshake-timeout-secs=0",
            "--queued-turns=0",
            "--max-message-bytes=0",
            "--max-connections=0",
        ] {
            let mut arguments = required.to_vec();
            arguments.push(limit);
            assert!(super::Args::try_parse_from(arguments).is_err(), "{limit}");
        }
    }
}
