//! Local Codex WebSocket ingress with one owner for queued and active turns.

use std::{collections::VecDeque, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_protocol::ws::FINAL_EVENTS;
use concurro_relay_provider_protocol::codex;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};

use crate::session::{CodexEvent, CodexTurn};

pub mod claude;

const PLACEHOLDER: &str = "local-relay-placeholder";

/// Parsed local upgrade whose response waits for provider authentication.
pub struct Upgrade {
    /// Accepted public CLI headers added to the provider upgrade.
    pub headers: Vec<(String, String)>,
    /// Local CLI TCP stream.
    stream: TcpStream,
    /// WebSocket accept value for this local request.
    accept: String,
}

impl Upgrade {
    /// Wait for the local CLI to close without consuming early WebSocket bytes.
    pub async fn watch_disconnect(&self) {
        watch_disconnect(&self.stream).await;
    }
}

/// Wait for TCP peer closure while retaining any buffered application bytes.
async fn watch_disconnect(stream: &TcpStream) {
    loop {
        if stream.readable().await.is_err() {
            return;
        }
        let mut byte = [0];
        match stream.peek(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Bind the per-session loopback listener.
pub async fn bind(address: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(address).await?)
}

/// Accept and parse one local CLI upgrade, answering harmless preflight requests.
pub async fn accept(listener: &TcpListener) -> Result<Upgrade> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            head.push(byte[0]);
            ensure!(head.len() <= 64 * 1024, "local HTTP request head too large");
        }
        let request = std::str::from_utf8(&head)?;
        let mut lines = request.split("\r\n");
        let start = lines.next().context("local HTTP request line missing")?;
        if start == "OPTIONS /v1/responses HTTP/1.1" {
            stream.write_all(b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: authorization, content-type\r\nContent-Length: 0\r\n\r\n").await?;
            continue;
        }
        ensure!(
            start == "GET /v1/responses HTTP/1.1",
            "unexpected local Codex route"
        );
        let mut key = None;
        let mut authorized = false;
        let mut websocket = false;
        let mut public = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').context("invalid local HTTP header")?;
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorized = value == format!("Bearer {PLACEHOLDER}"),
                "upgrade" => websocket = value.eq_ignore_ascii_case("websocket"),
                "sec-websocket-key" => key = Some(value.to_owned()),
                "host"
                | "connection"
                | "sec-websocket-version"
                | "sec-websocket-extensions"
                | "proxy-authorization"
                | "x-api-key"
                | "cookie"
                | "chatgpt-account-id"
                | "content-length" => {}
                _ => public.push((name.to_owned(), value.to_owned())),
            }
        }
        ensure!(authorized && websocket, "local Codex upgrade denied");
        let key = key.context("local WebSocket key missing")?;
        ensure!(
            STANDARD.decode(&key)?.len() == 16,
            "invalid local WebSocket key"
        );
        let accept = STANDARD.encode(
            ring::digest::digest(
                &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                &[key.as_bytes(), b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].concat(),
            )
            .as_ref(),
        );
        return Ok(Upgrade {
            headers: public,
            stream,
            accept,
        });
    }
}

/// Run local clients sequentially while retaining one provider session across idle reconnects.
pub async fn serve(
    listener: &TcpListener,
    mut first: Upgrade,
    turns: mpsc::Sender<CodexTurn>,
    mut upgrade: oneshot::Receiver<Result<()>>,
    test_turns: usize,
) -> Result<()> {
    let mut completed = 0;
    let result = tokio::select! {
        result = &mut upgrade => result.context("provider upgrade was canceled")?,
        () = first.watch_disconnect() => {
            bail!("NATIVE_CANCEL cli_disconnect");
        }
    };
    if result.is_err() {
        first
            .stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return result;
    }
    loop {
        first.stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", first.accept).as_bytes()).await?;
        let outcome = client(first.stream, &turns, test_turns, &mut completed).await?;
        if outcome == ClientEnd::Limit {
            break;
        }
        first = accept(listener).await?;
    }
    Ok(())
}

/// Why one local WebSocket ended.
#[derive(Eq, PartialEq)]
enum ClientEnd {
    /// CLI disconnected with no active or queued turn.
    Idle,
    /// Explicit fixture turn limit was reached.
    Limit,
}

/// Own the queue and active receiver in one task so cancellation cannot race handoff.
async fn client(
    stream: TcpStream,
    turns: &mpsc::Sender<CodexTurn>,
    test_turns: usize,
    completed: &mut usize,
) -> Result<ClientEnd> {
    let socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    let (mut sink, mut source) = socket.split();
    let mut queued: VecDeque<(Value, String)> = VecDeque::new();
    let mut active: Option<mpsc::Receiver<Result<CodexEvent>>> = None;
    let mut count_active = false;
    let mut terminal_sent = false;
    loop {
        if active.is_none()
            && let Some((request, text)) = queued.pop_front()
        {
            count_active = request["generate"] != false;
            terminal_sent = false;
            let (reply, receiver) = mpsc::channel(32);
            turns
                .send(CodexTurn {
                    request,
                    text,
                    reply,
                })
                .await
                .context("native Codex session closed")?;
            active = Some(receiver);
        }
        tokio::select! {
            incoming = source.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    let request: Value = serde_json::from_str(text.as_str())?;
                    match request["type"].as_str() {
                        Some("response.create") => queued.push_back((request, codex::normalize_request(text.as_str())?)),
                        Some("response.cancel") => {
                            if active.is_some() || !queued.is_empty() { bail!("NATIVE_CANCEL codex_cancel"); }
                        }
                        _ => bail!("unexpected local Responses request"),
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    if active.is_some() && !terminal_sent || !queued.is_empty() { bail!("NATIVE_CANCEL codex_disconnect"); }
                    return Ok(ClientEnd::Idle);
                }
                Some(Ok(Message::Ping(payload))) => sink.send(Message::Pong(payload)).await?,
                Some(Ok(_)) => {},
                Some(Err(error)) => {
                    if active.is_some() && !terminal_sent || !queued.is_empty() { bail!("NATIVE_CANCEL codex_disconnect: {error}"); }
                    return Ok(ClientEnd::Idle);
                }
            },
            event = async { active.as_mut().unwrap().recv().await }, if active.is_some() => {
                match event.context("native Codex turn canceled")?? {
                    CodexEvent::Data(bytes) => {
                        terminal_sent = serde_json::from_slice::<Value>(&bytes).ok()
                            .and_then(|event| event["type"].as_str().map(str::to_owned))
                            .is_some_and(|kind| FINAL_EVENTS.contains(&kind.as_str()));
                        sink.send(Message::Text(String::from_utf8(bytes)?.into())).await?;
                    }
                    CodexEvent::Done => {
                        active = None;
                        if count_active { *completed += 1; }
                        if test_turns > 0 && *completed >= test_turns {
                            sink.send(Message::Close(None)).await?;
                            return Ok(ClientEnd::Limit);
                        }
                    }
                }
            }
        }
    }
}
