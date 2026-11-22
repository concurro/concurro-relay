//! Local Claude HTTP ingress with immediate authenticated response forwarding.

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_provider_protocol::claude::Template;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

use crate::session::{ClaudeEvent, ClaudeTurn};

use super::watch_disconnect;

const PLACEHOLDER: &str = "local-relay-placeholder";

/// One parsed local CLI request retained through provider bootstrap.
pub struct Request {
    /// Local TCP socket for the eventual chunked response.
    stream: TcpStream,
    /// Public provider path and approved headers.
    pub template: Template,
    /// Exact CLI JSON body to prove as H2 DATA.
    pub body: Vec<u8>,
}

impl Request {
    /// Detect CLI closure before the first provider response without consuming bytes.
    pub async fn watch_disconnect(&self) {
        watch_disconnect(&self.stream).await;
    }

    /// Answers this request with the Sponsor's rejection, `reason`, when no
    /// session was started for it.
    pub async fn refuse(mut self, reason: &str) -> Result<()> {
        respond(&mut self.stream, "403 Forbidden", &rejection(reason)?).await
    }
}

/// The error body which tells a CLI the Sponsor rejected its request.
pub fn rejection(reason: &str) -> Result<Vec<u8>> {
    error_body("permission_error", reason)
}

/// An error body of the provider's `kind`, saying `message`.
fn error_body(kind: &str, message: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({"type": "error",
        "error": {"type": kind, "message": message}}))?)
}

/// Answers on `stream` with `status` and the JSON error `body`, and closes it.
async fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) -> Result<()> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    Ok(stream.shutdown().await?)
}

/// Accept one complete local Claude POST, including its JSON body. A request
/// the relay does not serve is answered with an error, and the next awaited.
pub async fn accept(listener: &TcpListener) -> Result<Request> {
    loop {
        let (stream, _) = listener.accept().await?;
        if let Some(request) = read(stream).await? {
            return Ok(request);
        }
    }
}

/// Reads one local Claude POST from `stream`, or answers it with an error
/// when its path or headers are not served.
async fn read(mut stream: TcpStream) -> Result<Option<Request>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        ensure!(head.len() <= 64 * 1024, "local HTTP request head too large");
    }
    let text = std::str::from_utf8(&head)?;
    let mut lines = text.split("\r\n");
    let start = lines.next().context("Claude request line missing")?;
    let mut parts = start.split(' ');
    ensure!(
        parts.next() == Some("POST"),
        "unexpected local Claude method"
    );
    let path = parts.next().context("Claude path missing")?;
    ensure!(
        parts.next() == Some("HTTP/1.1") && parts.next().is_none(),
        "unexpected local Claude HTTP version"
    );
    let mut authorized = false;
    let mut length = None;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .context("invalid local Claude header")?;
        let value = value.trim();
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "authorization" => authorized = value == format!("Bearer {PLACEHOLDER}"),
            "content-length" => length = Some(value.parse::<usize>()?),
            "host"
            | "connection"
            | "transfer-encoding"
            | "accept-encoding"
            | "proxy-authorization"
            | "x-api-key" => {}
            _ => headers.push((lower.into_bytes(), value.as_bytes().to_vec())),
        }
    }
    ensure!(authorized, "local Claude request denied");
    let length = length.context("Claude Content-Length missing")?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice::<serde_json::Value>(&body).context("Claude request is not JSON")?;
    let template = Template {
        path: path.as_bytes().to_vec(),
        headers,
    };
    if let Err(error) = template.public_headers() {
        // The CLI may have gone; the session carries on either way.
        let body = error_body("invalid_request_error", &format!("{error:#}"))?;
        let _ = respond(&mut stream, "400 Bad Request", &body).await;
        return Ok(None);
    }
    Ok(Some(Request {
        stream,
        template,
        body,
    }))
}

/// Forward each authenticated response fragment on the local HTTP connection.
pub async fn serve(
    listener: &TcpListener,
    mut first: Request,
    turns: mpsc::Sender<ClaudeTurn>,
    test_turns: usize,
) -> Result<()> {
    let mut completed = 0;
    loop {
        let (reply, mut events) = mpsc::channel(32);
        turns
            .send(ClaudeTurn {
                template: first.template.clone(),
                body: first.body,
                reply,
            })
            .await
            .context("native Claude session closed")?;
        let mut started = false;
        loop {
            let event = tokio::select! {
                event = events.recv() => event.context("native Claude response ended")??,
                () = watch_disconnect(&first.stream) => bail!("NATIVE_CANCEL cli_disconnect"),
            };
            match event {
                ClaudeEvent::Start(status, content_type) => {
                    ensure!(!started, "duplicate Claude response head");
                    first.stream.write_all(format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    ).as_bytes()).await.context("NATIVE_CANCEL cli_write_failed")?;
                    started = true;
                }
                ClaudeEvent::Data(bytes) => {
                    ensure!(started, "Claude DATA preceded response headers");
                    if !bytes.is_empty() {
                        first
                            .stream
                            .write_all(format!("{:X}\r\n", bytes.len()).as_bytes())
                            .await
                            .context("NATIVE_CANCEL cli_write_failed")?;
                        first
                            .stream
                            .write_all(&bytes)
                            .await
                            .context("NATIVE_CANCEL cli_write_failed")?;
                        first
                            .stream
                            .write_all(b"\r\n")
                            .await
                            .context("NATIVE_CANCEL cli_write_failed")?;
                    }
                }
                ClaudeEvent::Done | ClaudeEvent::ProviderError(_) => {
                    ensure!(started, "Claude response ended before headers");
                    first
                        .stream
                        .write_all(b"0\r\n\r\n")
                        .await
                        .context("NATIVE_CANCEL cli_write_failed")?;
                    if let ClaudeEvent::ProviderError(acknowledge) = event {
                        let _ = acknowledge.send(());
                        return Ok(());
                    }
                    completed += 1;
                    break;
                }
            }
        }
        if test_turns > 0 && completed >= test_turns {
            return Ok(());
        }
        first = accept(listener).await?;
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        time::{self, Duration},
    };

    use super::{accept, serve};
    use crate::session::ClaudeEvent;

    /// Forward authenticated SSE before the provider turn reaches END_STREAM.
    #[tokio::test]
    async fn early_sse_reaches_local_client() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (turns_tx, mut turns_rx) = mpsc::channel(2);
        let server = tokio::spawn(async move {
            let first = accept(&listener).await.unwrap();
            serve(&listener, first, turns_tx, 1).await
        });
        let provider = tokio::spawn(async move {
            let turn = turns_rx.recv().await.unwrap();
            assert_eq!(turn.body, b"{}");
            turn.reply
                .send(Ok(ClaudeEvent::Start(200, "text/event-stream".into())))
                .await
                .unwrap();
            turn.reply
                .send(Ok(ClaudeEvent::Data(b"data: early\n\n".to_vec())))
                .await
                .unwrap();
            time::sleep(Duration::from_millis(300)).await;
            turn.reply.send(Ok(ClaudeEvent::Done)).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer local-relay-placeholder\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        let mut seen = Vec::new();
        time::timeout(Duration::from_millis(200), async {
            while !seen
                .windows(b"data: early".len())
                .any(|part| part == b"data: early")
            {
                let mut chunk = [0; 128];
                let size = client.read(&mut chunk).await.unwrap();
                assert!(size > 0);
                seen.extend_from_slice(&chunk[..size]);
            }
        })
        .await
        .unwrap();
        assert!(!provider.is_finished());
        provider.await.unwrap();
        server.await.unwrap().unwrap();
    }

    /// A closed local socket cancels a response still awaiting authenticated DATA.
    #[tokio::test]
    async fn streaming_disconnect_cancels_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (turns_tx, mut turns_rx) = mpsc::channel(2);
        let server = tokio::spawn(async move {
            let first = accept(&listener).await.unwrap();
            serve(&listener, first, turns_tx, 0).await
        });
        let provider = tokio::spawn(async move {
            let turn = turns_rx.recv().await.unwrap();
            turn.reply
                .send(Ok(ClaudeEvent::Start(200, "text/event-stream".into())))
                .await
                .unwrap();
            time::sleep(Duration::from_secs(1)).await;
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer local-relay-placeholder\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        let mut head = [0; 128];
        assert!(client.read(&mut head).await.unwrap() > 0);
        drop(client);
        let error = time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("NATIVE_CANCEL cli_disconnect")
        );
        provider.abort();
    }

    /// A request rejected before any session gets a complete 403 answer.
    #[tokio::test]
    async fn a_refused_request_gets_a_403() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            accept(&listener)
                .await
                .unwrap()
                .refuse("the Sponsor rejected this request: off topic")
                .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer local-relay-placeholder\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).await.unwrap();
        server.await.unwrap().unwrap();
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        let body = answer.split("\r\n\r\n").nth(1).unwrap();
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["error"]["type"], "permission_error");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .ends_with("off topic")
        );
    }

    /// A request the relay does not serve is answered with an error, and the
    /// next request, as Claude Code sends it, is accepted.
    #[tokio::test]
    async fn an_unserved_request_is_answered_and_the_next_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move { accept(&listener).await.unwrap() });
        let mut unserved = TcpStream::connect(address).await.unwrap();
        unserved.write_all(b"POST /v1/messages/count_tokens?beta=true HTTP/1.1\r\nAuthorization: Bearer local-relay-placeholder\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        let mut answer = String::new();
        unserved.read_to_string(&mut answer).await.unwrap();
        assert!(
            answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{answer}"
        );
        assert!(answer.contains("unsupported Claude request path"));
        let mut served = TcpStream::connect(address).await.unwrap();
        served.write_all(b"POST /v1/messages?beta=true HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer local-relay-placeholder\r\nContent-Type: application/json\r\nAnthropic-Version: 2023-06-01\r\nAnthropic-Beta: claude-code-20250219,oauth-2025-04-20\r\nX-App: cli\r\nUser-Agent: claude-cli/2.0.0 (external, cli)\r\nConnection: keep-alive\r\nAccept-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        let request = accepting.await.unwrap();
        assert_eq!(request.template.path, b"/v1/messages?beta=true");
        assert!(request.template.headers.iter().all(|(name, _)| !matches!(
            name.as_slice(),
            b"host" | b"connection" | b"accept-encoding"
        )));
    }
}
