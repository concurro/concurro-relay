//! Stands in for the Concurro gateway in an agent loop: serves a real
//! harness, has a relay perform each inference request, and returns the
//! response only once it is verified. A harness which upgrades to a
//! WebSocket has a relay carry the connection, turn by turn.
//!
//! Each link serves one request or connection at a time and is dropped
//! after any failure.

use std::{
    collections::HashSet,
    convert::Infallible,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use concurro_relay_protocol::{
    meter::{Counters, Metered},
    route::Route,
    wire::{self, Job},
};
use concurro_relay_verifier::{
    accept::Accepted,
    exchange::{Expect, Verdict},
    link::Link,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE},
    server::conn::http1,
    service::service_fn,
    upgrade,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    time::{self, Instant},
};
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        handshake::derive_accept_key,
        protocol::{CloseFrame, Role, frame::coding::CloseCode},
    },
};

use crate::jobs;

/// Start of a relay's refusal of a thread continuation whose parent it
/// never received.
const UNKNOWN_THREAD_PARENT: &str = "thread parent was not issued to this relay";

/// Longest one exchange may take before the harness is told it failed.
const EXCHANGE_LIMIT: Duration = Duration::from_secs(600);

/// Longest reason a WebSocket close may carry, in bytes.
const MAX_CLOSE_REASON: usize = 123;

/// Response headers passed on to the harness.
const PASSED_ON: [&str; 3] = ["content-type", "request-id", "retry-after"];

/// A relay's connection to the gateway.
pub type Connection = TlsStream<TcpStream>;

/// A relay link with the traffic it has carried.
struct RelayLink {
    link: Link<Metered<Connection>>,
    traffic: Counters,
}

/// What a relay did with a job, and the traffic the exchange cost it.
pub struct Performed {
    pub verdict: Verdict,
    /// Bytes the relay sent to and received from the gateway.
    pub upload: u64,
    pub download: u64,
}

pub struct Gateway {
    route: Route,
    expect: Expect,
    /// Relay links waiting to serve a request, and where to return them.
    idle: Mutex<mpsc::UnboundedReceiver<RelayLink>>,
    returned: mpsc::UnboundedSender<RelayLink>,
    zstd: bool,
    served: AtomicUsize,
    /// Ids of the messages in responses this gateway has verified.
    verified_messages: SyncMutex<HashSet<String>>,
}

impl Gateway {
    /// A gateway for `route` which uses the relay links arriving on
    /// `accepted`, and with `zstd` compresses request bodies before they
    /// are sent and proven.
    pub fn new(route: Route, expect: Expect, zstd: bool, mut accepted: mpsc::UnboundedReceiver<Accepted<Connection>>) -> Arc<Self> {
        let (returned, idle) = mpsc::unbounded_channel();
        let ready = returned.clone();
        tokio::spawn(async move {
            while let Some(Accepted { relay, control, proofs, .. }) = accepted.recv().await {
                eprintln!("link opened by {relay}");
                let traffic = Counters::default();
                let link = Link::new(Metered::new(control, traffic.clone()), Metered::new(proofs, traffic.clone()));
                let _ = ready.send(RelayLink { link, traffic });
            }
        });
        Arc::new(Self {
            route,
            expect,
            idle: Mutex::new(idle),
            returned,
            zstd,
            served: AtomicUsize::new(0),
            verified_messages: SyncMutex::default(),
        })
    }

    /// Has a relay perform `job` and verifies the outcome.
    pub async fn perform(&self, job: &Job) -> Result<Performed> {
        let RelayLink { link, traffic } = self.idle.lock().await.recv().await.context("no relay is connected")?;
        let (upload, download) = (traffic.read(), traffic.written());
        // A link which times out is dropped along with the exchange.
        let (verdict, link) = time::timeout(EXCHANGE_LIMIT, link.exchange(job, &self.expect))
            .await
            .context("exchange exceeded its time limit")?;
        if let Some(link) = link {
            let _ = self.returned.send(RelayLink { link, traffic: traffic.clone() });
        }
        Ok(Performed { verdict: verdict?, upload: traffic.read() - upload, download: traffic.written() - download })
    }

    /// Has a relay carry the WebSocket connection `harness` to the provider
    /// with the upgrade request `job`, logging each turn under `label`.
    pub async fn carry<H>(&self, harness: &mut WebSocketStream<H>, job: &Job, label: &str) -> Result<()>
    where
        H: AsyncRead + AsyncWrite + Unpin,
    {
        let RelayLink { mut link, traffic } = self.idle.lock().await.recv().await.context("no relay is connected")?;
        // A link which failed is dropped along with the connection.
        link.carry(harness, job, &self.expect, label, &traffic).await?;
        let _ = self.returned.send(RelayLink { link, traffic });
        Ok(())
    }

    /// Accepts a harness's WebSocket upgrade for `path` and has a relay
    /// carry the connection.
    fn upgrade(self: &Arc<Self>, request: Request<Incoming>, path: &str) -> Response<Full<Bytes>> {
        let key = request.headers().get(SEC_WEBSOCKET_KEY).map(|key| key.as_bytes()).unwrap_or_default();
        let accept = derive_accept_key(key);
        let headers = request.headers().iter().filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)));
        let job = match jobs::job(self.route, path, headers, String::new()) {
            Ok(job) => job,
            Err(error) => return failure(StatusCode::BAD_REQUEST, &format!("{error:#}")),
        };
        let label = format!("ws#{}", self.served.fetch_add(1, Ordering::Relaxed) + 1);
        let gateway = self.clone();
        tokio::spawn(async move {
            let Ok(upgraded) = upgrade::on(request).await else { return };
            let mut harness = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
            eprintln!("{label} upgrade from the harness: {}", job.path);
            let (code, reason) = match gateway.carry(&mut harness, &job, &label).await {
                Ok(()) => (CloseCode::Normal, String::new()),
                Err(error) => {
                    eprintln!("{label} failed: {error:#}");
                    (CloseCode::Error, format!("{error:#}"))
                }
            };
            let mut end = reason.len().min(MAX_CLOSE_REASON);
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            let _ = harness.close(Some(CloseFrame { code, reason: reason[..end].to_owned().into() })).await;
            eprintln!("{label} closed");
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_ACCEPT, accept)
            .body(Full::default())
            .expect("response is valid")
    }

    /// Serves the harness's requests arriving on `listener` until it fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (socket, _) = listener.accept().await?;
            let gateway = self.clone();
            tokio::spawn(async move {
                let service = service_fn(|request| gateway.handle(request));
                let _ = http1::Builder::new().serve_connection(TokioIo::new(socket), service).with_upgrades().await;
            });
        }
    }

    async fn handle(self: &Arc<Self>, request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = request.uri().path_and_query().map_or("/", |path| path.as_str()).to_owned();
        if request.headers().get(UPGRADE).is_some_and(|protocol| protocol.as_bytes().eq_ignore_ascii_case(b"websocket")) {
            return Ok(self.upgrade(request, &path));
        }
        if request.method() != Method::POST {
            // Connectivity probes.
            return Ok(reply(StatusCode::OK, &[], Bytes::new()));
        }
        if !jobs::is_inference(self.route, &path) {
            eprintln!("not an inference request: POST {path}");
            return Ok(failure(StatusCode::NOT_FOUND, "not an inference request"));
        }

        let number = self.served.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(match self.exchange(request, &path, number).await {
            Ok(response) => response,
            Err(error) => {
                eprintln!("#{number} failed: {error:#}");
                failure(StatusCode::BAD_GATEWAY, &format!("{error:#}"))
            }
        })
    }

    /// Has a relay perform the harness's request and returns the verified
    /// response.
    async fn exchange(&self, request: Request<Incoming>, path: &str, number: usize) -> Result<Response<Full<Bytes>>> {
        let (parts, body) = request.into_parts();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| Ok((name.as_str(), value.to_str()?)))
            .collect::<Result<Vec<_>>>()?;
        let body = String::from_utf8(body.collect().await?.to_bytes().to_vec())?;
        let fields: Value = serde_json::from_str(&body).unwrap_or_default();
        let model = fields["model"].as_str().unwrap_or_default().to_owned();
        // A thread continuation must build on a response this gateway
        // verified, since the request no longer carries the conversation.
        let thread = match (fields["thread"]["type"].as_str(), fields["thread"]["previous_message_id"].as_str()) {
            (Some("continue"), Some(previous)) => {
                if !self.verified_messages.lock().expect("lock is not poisoned").contains(previous) {
                    eprintln!("#{number} refused: thread continues {previous}, which this gateway did not verify");
                    return Ok(thread_not_found());
                }
                "continue"
            }
            (Some(kind), _) => kind,
            (None, _) => "none",
        };
        let mut job = jobs::job(self.route, path, headers, body)?;
        let plain = job.body.len();
        if self.zstd {
            job.compress()?;
        }
        eprintln!("#{number} request: model={model} thread={thread} body={plain} bytes, sent as {} bytes", job.body.len());

        let started = Instant::now();
        let Performed { verdict, upload, download } = self.perform(&job).await?;
        let response = match verdict {
            Verdict::Verified(response) => response,
            Verdict::Refused(reason) if reason.starts_with(UNKNOWN_THREAD_PARENT) => {
                eprintln!("#{number} refused by the relay: {reason}");
                return Ok(thread_not_found());
            }
            Verdict::Refused(reason) => return Err(anyhow!("relay refused the request: {reason}")),
            Verdict::Rejected(reason) => return Err(anyhow!("exchange rejected: {reason}")),
        };

        if let Some(id) = wire::message_id(&response.body) {
            self.verified_messages.lock().expect("lock is not poisoned").insert(id);
        }
        let phases: Vec<String> = response.laps.iter().map(|(name, s)| format!("{name} {s:.2}s")).collect();
        eprintln!(
            "#{number} verified: status={} total={:.2}s ({}) relay→gateway={:.1} MB gateway→relay={:.1} MB body={} bytes",
            response.status,
            started.elapsed().as_secs_f64(),
            phases.join(", "),
            upload as f64 / 1e6,
            download as f64 / 1e6,
            response.body.len(),
        );

        let passed_on: Vec<(&str, &str)> = response
            .headers
            .iter()
            .filter(|(name, _)| PASSED_ON.contains(&name.as_str()) || name.starts_with("anthropic-ratelimit-"))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let status = StatusCode::from_u16(response.status)?;
        Ok(reply(status, &passed_on, Bytes::from(response.body)))
    }
}

fn reply(status: StatusCode, headers: &[(&str, &str)], body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(*name, *value);
    }
    response.body(Full::new(body)).expect("response is valid")
}

/// The provider's own answer for a thread it can not continue, which tells
/// the harness to resend the full conversation in a new thread.
fn thread_not_found() -> Response<Full<Bytes>> {
    let body = json!({
        "type": "error",
        "error": {
            "type": "not_found_error",
            "message": "thread parent was not verified by this gateway",
            "details": {"error_code": "thread_not_found"},
        },
    });
    reply(StatusCode::NOT_FOUND, &[("content-type", "application/json")], Bytes::from(body.to_string()))
}

fn failure(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = json!({"type": "error", "error": {"type": "api_error", "message": message}});
    reply(status, &[("content-type", "application/json")], Bytes::from(body.to_string()))
}
