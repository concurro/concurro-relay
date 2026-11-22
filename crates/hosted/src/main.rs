//! Hosted Rust verifier for owner-approved, admitted subscription relay turns.

mod pool;
mod registry;

use std::{
    fs,
    future::Future,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use concurro_relay_native::{self as native, NativeOptions, NativeRole};
use concurro_relay_protocol::{
    link::{Notice, Order},
    route::Route,
    wire,
    ws::FINAL_EVENTS,
};
use concurro_relay_verifier::accept::{self, Accepted, Acceptor, Limits};
use futures::{SinkExt, StreamExt};
use pool::{Lease, Task};
use registry::{Binding, HostedRegistry};
use rustls::{ServerConfig, crypto::ring as rustls_ring, pki_types::CertificateDer};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};

type RelayLink = Accepted<TlsStream<TcpStream>>;
type Pool = pool::Pool<TlsStream<TcpStream>>;

/// Hosted verifier listeners, durable registry, and native provider settings.
#[derive(Parser)]
struct Args {
    /// TLS listener to which Sponsor relays connect.
    #[arg(long, default_value = "0.0.0.0:7443")]
    relay_listen: SocketAddr,
    /// Private listener shared only with Exchange and Vault.
    #[arg(long, default_value = "0.0.0.0:7450")]
    private_listen: SocketAddr,
    /// Persisted relay certificate.
    #[arg(long)]
    certificate: PathBuf,
    /// Persisted relay TLS private key.
    #[arg(long)]
    private_key: PathBuf,
    /// Durable owner-approved registry.
    #[arg(long)]
    registry: PathBuf,
    /// Shared private service bearer file.
    #[arg(long)]
    service_token: PathBuf,
    /// Public owner page for entering the Sponsor registration code.
    #[arg(long)]
    verification_url: String,
    /// Provider TCP host; the native worker validates its route-bound certificate.
    #[arg(long, default_value = "api.anthropic.com")]
    provider_host: String,
    /// Provider TCP port.
    #[arg(long, default_value_t = 443)]
    provider_port: u16,
    /// ChatGPT provider TCP host for the Codex route.
    #[arg(long, default_value = "chatgpt.com")]
    codex_provider_host: String,
    /// ChatGPT provider TCP port.
    #[arg(long, default_value_t = 443)]
    codex_provider_port: u16,
    /// Provider certificate trust roots.
    #[arg(long, default_value = "/etc/ssl/certs/ca-certificates.crt")]
    provider_ca: PathBuf,
    /// Seconds a relay connection has to finish its TLS handshake.
    #[arg(long, default_value = "10")]
    handshake_timeout_secs: NonZeroU64,
    /// Seconds one connection of a relay link waits for the other.
    #[arg(long, default_value = "30")]
    half_link_timeout_secs: NonZeroU64,
    /// Relay connections open at once before their relay is known; more are
    /// closed as they arrive.
    #[arg(long, default_value = "1024")]
    max_pending_connections: NonZeroUsize,
    /// Unapproved relay registrations kept; a new one evicts the oldest.
    #[arg(long, default_value = "1000")]
    pending_registrations: NonZeroUsize,
    /// Bytes a relay's registered name may have.
    #[arg(long, default_value = "256")]
    relay_name_max_bytes: NonZeroUsize,
    /// Unix start time; live telemetry before it is unknown.
    #[arg(skip)]
    started: f64,
}

/// Private authenticated request identity supplied by Exchange after its one-use claim.
#[derive(Deserialize)]
struct Dispatch {
    session: String,
    turn: String,
    user_id: u64,
    route: String,
    entry_id: String,
    record_id: String,
    relay_id: String,
    version: u64,
    deadline: f64,
    /// Task the turn belongs to, reported to the relay's owner while leased.
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    issue: Option<u64>,
}

/// Owner-authenticated Vault approval, carrying the immutable record identity.
#[derive(Deserialize)]
#[serde(untagged)]
enum Approval {
    /// Original Claude-only owner request.
    One {
        code: String,
        #[serde(flatten)]
        binding: Binding,
    },
    /// One owner approval of every route registered by a Sponsor.
    Routes {
        code: String,
        bindings: Vec<Binding>,
    },
}

/// Release one retained task session when Exchange retires its turn.
#[derive(Deserialize)]
struct Release {
    /// Exchange session whose authority ended.
    session: String,
    /// Frozen turn whose native session must stop.
    turn: String,
    /// Session deadline bounding the cancellation tombstone.
    deadline: f64,
}

/// Owner-authenticated Vault read of the live state of that owner's relays.
#[derive(Deserialize)]
struct StatusQuery {
    user_id: u64,
    /// Relay IDs of the owner's current Vault approvals.
    relays: Vec<String>,
}

/// Owner-authenticated Vault lookup of a displayed Sponsor code.
#[derive(Deserialize)]
struct PendingQuery {
    code: String,
}

/// One bounded HTTP request head on the private service listener.
struct Head {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Head {
    /// Return one unique header value, refusing ambiguity.
    fn header(&self, name: &str) -> Result<&str> {
        let mut values = self.headers.iter().filter(|(key, _)| key == name);
        let value = values.next().context("required private header missing")?;
        ensure!(values.next().is_none(), "duplicate private header");
        Ok(&value.1)
    }
}

/// Load an operator-provisioned TLS identity without generating a new trust root.
fn tls(certificate: &PathBuf, private_key: &PathBuf) -> Result<TlsAcceptor> {
    let certificates: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut fs::read(certificate)?.as_slice())
            .collect::<std::result::Result<_, _>>()?;
    ensure!(!certificates.is_empty(), "relay certificate is empty");
    let key = rustls_pemfile::private_key(&mut fs::read(private_key)?.as_slice())?
        .context("relay TLS private key is missing")?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls_ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Read a private HTTP head without consuming request body bytes.
async fn read_head(stream: &mut TcpStream) -> Result<Head> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        ensure!(bytes.len() <= 64 * 1024, "private request head too large");
    }
    let text = std::str::from_utf8(&bytes)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().context("private request line missing")?;
    let mut start = request.split(' ');
    let method = start.next().context("private method missing")?.to_owned();
    let path = start.next().context("private path missing")?.to_owned();
    ensure!(
        start.next() == Some("HTTP/1.1") && start.next().is_none(),
        "unsupported private HTTP request"
    );
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').context("invalid private header")?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(Head {
        method,
        path,
        headers,
    })
}

/// Read the bounded JSON body of a private control operation.
async fn json_body<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream, head: &Head) -> Result<T> {
    ensure!(
        !head
            .headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding"),
        "unsupported private framing"
    );
    let length: usize = head.header("content-length")?.parse()?;
    ensure!(length <= 64 * 1024, "private control body too large");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// Send a fixed private result without echoing submitted identity or provider data.
async fn answer(stream: &mut TcpStream, status: u16, value: serde_json::Value) -> Result<()> {
    let body = serde_json::to_vec(&value)?;
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Bad Request",
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(&body).await?;
    Ok(())
}

/// Authenticate a request from the private Exchange or owner-authenticated Vault.
fn authorized(head: &Head, token: &str) -> bool {
    head.header("x-concurro-verifier-auth")
        .is_ok_and(|supplied| {
            ring::constant_time::verify_slices_are_equal(
                supplied.as_bytes(),
                format!("Bearer {token}").as_bytes(),
            )
            .is_ok()
        })
}

/// Current Unix time for task deadlines and cancellation expiry.
fn now_seconds() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}

/// Current Unix time for liveness telemetry, which tolerates a clock before the epoch.
fn clock() -> f64 {
    now_seconds().unwrap_or_default()
}

/// Bound every phase of a native task, including startup, by its admitted deadline.
async fn admitted<T>(deadline: f64, work: impl Future<Output = Result<T>>) -> Result<T> {
    let remaining = (deadline - now_seconds()?).max(0.0);
    tokio::time::timeout(Duration::from_secs_f64(remaining), work)
        .await
        .context("admitted turn deadline ended")?
}

/// Run the existing native Concurro worker on one leased authenticated link.
async fn run_lease(
    mut link: RelayLink,
    binding: Binding,
    args: Arc<Args>,
    address: watch::Sender<Option<SocketAddr>>,
) -> Result<()> {
    let (route, provider_host, provider_port) = match binding.route.as_str() {
        "claude-subscription" => (
            Route::ClaudeSubscription,
            &args.provider_host,
            args.provider_port,
        ),
        "chatgpt-subscription" => (
            Route::ChatgptSubscription,
            &args.codex_provider_host,
            args.codex_provider_port,
        ),
        _ => bail!("unsupported hosted route"),
    };
    wire::send(
        &mut link.control,
        &Order::NativeStart {
            route,
            provider_host: provider_host.clone(),
            provider_port,
        },
    )
    .await?;
    match wire::recv::<_, Notice>(&mut link.control).await? {
        Notice::NativeReady => {}
        Notice::Refused(reason) => bail!("Sponsor refused native session: {reason}"),
        answer => bail!("unexpected Sponsor answer: {answer:?}"),
    }
    let (ready, mut bound) = mpsc::unbounded_channel();
    let bridge = native::bridge(
        link.control,
        link.proofs,
        NativeOptions {
            role: NativeRole::Concurro,
            route,
            provider_host: provider_host.clone(),
            provider_port,
            provider_ca: args.provider_ca.clone(),
            listen: Some("127.0.0.1:0".into()),
            token: None,
            account: None,
            audit: None,
            review: None,
            ready: Some(ready),
        },
    );
    tokio::pin!(bridge);
    tokio::select! {
        endpoint = bound.recv() => {
            let endpoint: SocketAddr = endpoint.context("native worker did not bind")?.parse()?;
            eprintln!("hosted native session ready for owner={} record={}", binding.user_id, binding.record_id);
            let _ = address.send(Some(endpoint));
            bridge.await
        }
        result = &mut bridge => result,
    }
}

/// Reserve one live link for one task identity and await its native ingress.
async fn lease(
    pool: Arc<Mutex<Pool>>,
    registry: Arc<HostedRegistry>,
    args: Arc<Args>,
    dispatch: &Dispatch,
) -> Result<SocketAddr> {
    let now = now_seconds()?;
    ensure!(
        matches!(
            dispatch.route.as_str(),
            "claude-subscription" | "chatgpt-subscription"
        ) && dispatch.user_id > 0
            && dispatch.version > 0
            && !dispatch.session.is_empty()
            && !dispatch.turn.is_empty()
            && dispatch.deadline > now,
        "private inference authority unavailable"
    );
    let key = (dispatch.session.clone(), dispatch.turn.clone());
    let mut pool_guard = pool.lock().await;
    pool_guard.cancelled.retain(|_, expiry| *expiry > now);
    ensure!(
        !pool_guard.cancelled.contains_key(&key),
        "admitted turn was released"
    );
    let existing = pool_guard.leases.get(&key).cloned();
    let mut address = if let Some(existing) = existing {
        ensure!(
            existing.binding.user_id == dispatch.user_id
                && existing.binding.route == dispatch.route
                && existing.binding.entry_id == dispatch.entry_id
                && existing.binding.record_id == dispatch.record_id
                && existing.binding.version == dispatch.version
                && existing.relay == dispatch.relay_id
                && (existing.deadline - dispatch.deadline).abs() < 1e-6
                && registry
                    .binding_for(&existing.relay, &dispatch.route)
                    .as_ref()
                    == Some(&existing.binding),
            "retained task binding changed"
        );
        existing.address
    } else {
        // A candidate whose relay disconnected meanwhile is skipped for the next one.
        let (slot, binding, link) = loop {
            let (slot, binding) = pool_guard
                .ready_slots()
                .find_map(|slot| {
                    registry
                        .binding_for(&slot.0, &dispatch.route)
                        .and_then(|binding| {
                            (binding.user_id == dispatch.user_id
                                && binding.route == dispatch.route
                                && binding.entry_id == dispatch.entry_id
                                && binding.record_id == dispatch.record_id
                                && binding.version == dispatch.version
                                && slot.0 == dispatch.relay_id)
                                .then(|| (slot.clone(), binding))
                        })
                })
                .context("no live relay link for exact record")?;
            if let Some(link) = pool_guard.take(&slot, now).await {
                break (slot, binding, link);
            }
        };
        let number = link.number;
        let (sender, receiver) = watch::channel(None);
        let state = pool.clone();
        let task_key = key.clone();
        let worker_args = args.clone();
        let deadline = dispatch.deadline;
        let lease_binding = binding.clone();
        let worker = tokio::spawn(async move {
            if let Err(error) =
                admitted(deadline, run_lease(link, binding, worker_args, sender)).await
            {
                eprintln!("hosted native session ended: {error:#}");
            }
            state.lock().await.finish(&task_key, number, clock());
        });
        pool_guard.leases.insert(
            key,
            Lease {
                relay: slot.0.clone(),
                slot: slot.clone(),
                number,
                deadline,
                started: now,
                task: dispatch
                    .repository
                    .clone()
                    .zip(dispatch.issue)
                    .map(|(repository, issue)| Task { repository, issue }),
                binding: lease_binding,
                address: receiver.clone(),
                abort: worker.abort_handle(),
            },
        );
        receiver
    };
    drop(pool_guard);
    loop {
        if let Some(endpoint) = *address.borrow_and_update() {
            return Ok(endpoint);
        }
        address
            .changed()
            .await
            .context("native session did not start")?;
    }
}

/// Connect one Exchange-claimed request to its retained native ingress.
async fn dispatch(
    head: &Head,
    pool: Arc<Mutex<Pool>>,
    registry: Arc<HostedRegistry>,
    args: Arc<Args>,
) -> Result<TcpStream> {
    ensure!(
        head.method == "POST" && head.path == "/dispatch/v1/messages",
        "unsupported hosted route"
    );
    ensure!(
        !head
            .headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding"),
        "unsupported hosted framing"
    );
    let binding: Dispatch = serde_json::from_str(head.header("x-concurro-binding")?)?;
    let endpoint = lease(pool, registry, args, &binding).await?;
    let mut worker = TcpStream::connect(endpoint).await?;
    worker
        .write_all(
            b"POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer local-relay-placeholder\r\n",
        )
        .await?;
    for (name, value) in &head.headers {
        if name.starts_with("x-concurro-")
            || matches!(name.as_str(), "authorization" | "host" | "connection")
        {
            continue;
        }
        worker
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    worker.write_all(b"Connection: close\r\n\r\n").await?;
    Ok(worker)
}

/// Carry one Gateway-admitted HTTP Responses request over the retained native Codex WebSocket.
async fn dispatch_codex(
    stream: &mut TcpStream,
    head: &Head,
    pool: Arc<Mutex<Pool>>,
    registry: Arc<HostedRegistry>,
    args: Arc<Args>,
    response_started: &mut bool,
) -> Result<()> {
    ensure!(
        head.method == "POST" && head.path == "/dispatch/v1/responses",
        "unsupported hosted route"
    );
    ensure!(
        !head
            .headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding"),
        "unsupported hosted framing"
    );
    let length: usize = head.header("content-length")?.parse()?;
    ensure!(
        length <= 48 * 1024 * 1024,
        "hosted Responses body too large"
    );
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let mut request: Value = serde_json::from_slice(&body)?;
    ensure!(request.is_object(), "invalid Responses request");
    if request["background"] == true {
        return answer(stream, 400, serde_json::json!({"error":{
            "type":"unsupported_transport", "message":"background Responses are unavailable over the retained provider WebSocket"
        }})).await;
    }
    let streaming = request["stream"] == true;
    request
        .as_object_mut()
        .expect("Responses request is an object")
        .remove("stream");
    request
        .as_object_mut()
        .expect("Responses request is an object")
        .remove("background");
    request["type"] = Value::String("response.create".into());
    let binding: Dispatch = serde_json::from_str(head.header("x-concurro-binding")?)?;
    ensure!(
        binding.route == "chatgpt-subscription",
        "hosted route differs from binding"
    );
    let endpoint = lease(pool, registry, args, &binding).await?;
    let mut upgrade = format!("ws://{endpoint}/v1/responses").into_client_request()?;
    upgrade.headers_mut().insert(
        "Authorization",
        HeaderValue::from_static("Bearer local-relay-placeholder"),
    );
    let (mut socket, _) =
        tokio_tungstenite::client_async(upgrade, TcpStream::connect(endpoint).await?).await?;
    socket
        .send(Message::Text(request.to_string().into()))
        .await?;
    if streaming {
        *response_started = true;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").await?;
    }
    while let Some(message) = socket.next().await {
        let Message::Text(raw) = message? else {
            continue;
        };
        let event: Value = serde_json::from_str(&raw)?;
        let kind = event["type"].as_str().context("Codex event type missing")?;
        if streaming {
            stream
                .write_all(format!("event: {kind}\ndata: {raw}\n\n").as_bytes())
                .await?;
        }
        if FINAL_EVENTS.contains(&kind) {
            if !streaming {
                answer(stream, 200, event.get("response").cloned().unwrap_or(event)).await?;
            }
            return Ok(());
        }
    }
    bail!("native Codex response ended before a terminal event")
}

/// Serve one authenticated private control or inference connection.
async fn private(
    mut stream: TcpStream,
    token: Arc<String>,
    registry: Arc<HostedRegistry>,
    pool: Arc<Mutex<Pool>>,
    args: Arc<Args>,
) -> Result<()> {
    let head = read_head(&mut stream).await?;
    if !authorized(&head, &token) {
        return answer(&mut stream, 403, serde_json::json!({"error":"forbidden"})).await;
    }
    match (head.method.as_str(), head.path.as_str()) {
        ("POST", "/approve") => {
            let approval: Approval = json_body(&mut stream, &head).await?;
            let result = match approval {
                Approval::One { code, binding } => registry.approve(&code, binding),
                Approval::Routes { code, bindings } => registry.approve_routes(&code, bindings),
            };
            match result {
                Ok(relay) => answer(&mut stream, 200, serde_json::json!({"relay":relay})).await,
                Err(_) => {
                    answer(
                        &mut stream,
                        409,
                        serde_json::json!({"error":"approval unavailable"}),
                    )
                    .await
                }
            }
        }
        ("POST", "/status") => {
            let query: StatusQuery = json_body(&mut stream, &head).await?;
            let now = clock();
            let pool = pool.lock().await;
            let relays: Vec<_> = query
                .relays
                .iter()
                .filter(|relay| query.user_id > 0 && registry.owner(relay) == Some(query.user_id))
                .map(|relay| pool.status(relay, now))
                .collect();
            drop(pool);
            answer(
                &mut stream,
                200,
                serde_json::json!({"started": args.started, "now": now, "relays": relays}),
            )
            .await
        }
        ("POST", "/pending") => {
            let query: PendingQuery = json_body(&mut stream, &head).await?;
            match registry.pending(&query.code) {
                Some(pending) => answer(&mut stream, 200, serde_json::json!(pending)).await,
                None => {
                    answer(
                        &mut stream,
                        404,
                        serde_json::json!({"error":"unknown or expired relay code"}),
                    )
                    .await
                }
            }
        }
        ("POST", "/release") => {
            let release: Release = json_body(&mut stream, &head).await?;
            ensure!(release.deadline.is_finite(), "invalid release deadline");
            pool.lock().await.release(
                (release.session, release.turn),
                release.deadline,
                now_seconds()?,
            );
            answer(&mut stream, 200, serde_json::json!({})).await
        }
        ("POST", "/dispatch/v1/responses") => {
            let mut response_started = false;
            if let Err(error) = dispatch_codex(
                &mut stream,
                &head,
                pool,
                registry,
                args,
                &mut response_started,
            )
            .await
            {
                eprintln!("hosted Codex inference refused: {error:#}");
                if !response_started {
                    let _ = answer(&mut stream, 503, serde_json::json!({"error":{"type":"unavailable","message":"relay link unavailable"}})).await;
                }
            }
            Ok(())
        }
        ("POST", "/dispatch/v1/messages") => {
            match dispatch(&head, pool, registry, args).await {
                Ok(mut worker) => {
                    if let Err(error) = io::copy_bidirectional(&mut stream, &mut worker).await {
                        eprintln!("hosted inference stream ended: {error:#}");
                    }
                }
                Err(error) => {
                    eprintln!("hosted inference refused: {error:#}");
                    let remaining = head
                        .header("content-length")
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok());
                    let _ = answer(
                        &mut stream,
                        503,
                        serde_json::json!({"error":{"type":"unavailable","message":"relay link unavailable"}}),
                    )
                    .await;
                    if let Some(remaining) = remaining {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            io::copy(&mut stream.take(remaining), &mut io::sink()),
                        )
                        .await;
                    }
                }
            }
            Ok(())
        }
        _ => {
            answer(
                &mut stream,
                404,
                serde_json::json!({"error":"unknown private operation"}),
            )
            .await
        }
    }
}

/// Start both listeners and retain only authenticated, owner-bound live links.
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    args.started = clock();
    let args = Arc::new(args);
    let token = Arc::new(fs::read_to_string(&args.service_token)?.trim().to_owned());
    ensure!(!token.is_empty(), "private service token is empty");
    let (withdrawals, mut withdrawn) = mpsc::unbounded_channel();
    let registry = Arc::new(
        HostedRegistry::open(args.registry.clone(), Some(withdrawals))?
            .with_verification_uri(args.verification_url.clone())
            .with_limits(registry::Limits {
                pending: args.pending_registrations.get(),
                name_bytes: args.relay_name_max_bytes.get(),
            }),
    );
    let pool = Pool::shared(clock);
    let (ready, mut accepted) = mpsc::unbounded_channel();
    let relay = TcpListener::bind(args.relay_listen).await?;
    let private_listener = TcpListener::bind(args.private_listen).await?;
    tokio::spawn(accept::serve(
        relay,
        tls(&args.certificate, &args.private_key)?,
        Arc::new(Acceptor::new(registry.clone(), ready).with_limits(Limits {
            handshake: Duration::from_secs(args.handshake_timeout_secs.get()),
            half_link: Duration::from_secs(args.half_link_timeout_secs.get()),
            pending_connections: args.max_pending_connections.get(),
        })),
    ));
    let accepted_pool = pool.clone();
    tokio::spawn(async move {
        while let Some(link) = accepted.recv().await {
            accepted_pool.lock().await.park(link, clock());
        }
    });
    let withdrawn_pool = pool.clone();
    tokio::spawn(async move {
        while let Some(relay) = withdrawn.recv().await {
            withdrawn_pool.lock().await.withdraw(&relay, clock());
        }
    });
    eprintln!("hosted relay verifier listening on {}", args.relay_listen);
    loop {
        let stream = accept::next_connection(&private_listener).await;
        let (token, registry, pool, args) =
            (token.clone(), registry.clone(), pool.clone(), args.clone());
        tokio::spawn(async move {
            if let Err(error) = private(stream, token, registry, pool, args).await {
                eprintln!("private verifier request failed: {error:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A limit of 0, which would stop the verifier serving, is refused.
    #[test]
    fn zero_limits_are_refused() {
        let required = [
            "concurro-relay-hosted",
            "--certificate=c",
            "--private-key=k",
            "--registry=r",
            "--service-token=t",
            "--verification-url=u",
        ];
        assert!(Args::try_parse_from(required).is_ok());
        for limit in [
            "--handshake-timeout-secs=0",
            "--half-link-timeout-secs=0",
            "--max-pending-connections=0",
            "--pending-registrations=0",
            "--relay-name-max-bytes=0",
        ] {
            let mut arguments = required.to_vec();
            arguments.push(limit);
            assert!(Args::try_parse_from(arguments).is_err(), "{limit}");
        }
    }

    /// Arguments for in-process private-listener tests.
    fn fixture_args(started: f64) -> Arc<Args> {
        Arc::new(Args {
            relay_listen: "127.0.0.1:0".parse().unwrap(),
            private_listen: "127.0.0.1:0".parse().unwrap(),
            certificate: PathBuf::new(),
            private_key: PathBuf::new(),
            registry: PathBuf::new(),
            service_token: PathBuf::new(),
            verification_url: "http://localhost/credentials/relay".into(),
            provider_host: String::new(),
            provider_port: 0,
            codex_provider_host: String::new(),
            codex_provider_port: 0,
            provider_ca: PathBuf::new(),
            handshake_timeout_secs: NonZeroU64::new(10).unwrap(),
            half_link_timeout_secs: NonZeroU64::new(30).unwrap(),
            max_pending_connections: NonZeroUsize::new(1024).unwrap(),
            pending_registrations: NonZeroUsize::new(1000).unwrap(),
            relay_name_max_bytes: NonZeroUsize::new(256).unwrap(),
            started,
        })
    }

    /// Send one private request and return its status and JSON body.
    async fn private_call(
        registry: Arc<HostedRegistry>,
        pool: Arc<Mutex<Pool>>,
        token: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            private(
                stream,
                Arc::new("service".into()),
                registry,
                pool,
                fixture_args(5.0),
            )
            .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        // A refused request is answered without reading its body.
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        client
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nX-Concurro-Verifier-Auth: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        server.await.unwrap().unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (
            head[9..12].parse().unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    }

    /// Status reports only the requesting owner's relays; pending lookup shows
    /// a code's device and exact routes; both require the service bearer.
    #[tokio::test]
    async fn private_status_and_pending_are_owner_scoped() {
        use concurro_relay_protocol::link::Registration;
        use concurro_relay_verifier::accept::Registry;

        let path = std::env::temp_dir().join(format!(
            "hosted-status-{}.json",
            hex::encode(concurro_relay_protocol::identity::random::<8>())
        ));
        let registry = Arc::new(HostedRegistry::open(path.clone(), None).unwrap());
        let code = registry
            .register(Registration {
                version: 4,
                name: "studio".into(),
                public_key: vec![3; 32],
                routes: vec![Route::ChatgptSubscription, Route::ClaudeSubscription],
            })
            .unwrap();
        let pool = Pool::shared(clock);
        let pending = |code: &str| serde_json::json!({ "code": code });
        assert_eq!(
            private_call(
                registry.clone(),
                pool.clone(),
                "wrong",
                "/status",
                serde_json::Value::Null
            )
            .await
            .0,
            403
        );
        let (status, found) = private_call(
            registry.clone(),
            pool.clone(),
            "service",
            "/pending",
            pending(&code.user_code),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(found["name"], "studio");
        assert_eq!(
            found["routes"],
            serde_json::json!(["chatgpt-subscription", "claude-subscription"])
        );
        assert_eq!(
            private_call(
                registry.clone(),
                pool.clone(),
                "service",
                "/pending",
                pending("BCDF-GHJK")
            )
            .await
            .0,
            404
        );
        let binding = |route: &str, entry: char| Binding {
            user_id: 7,
            login: "owner".into(),
            route: route.into(),
            entry_id: entry.to_string().repeat(32),
            record_id: "b".repeat(64),
            version: 1,
        };
        let relay = registry
            .approve_routes(
                &code.user_code,
                vec![
                    binding("claude-subscription", 'a'),
                    binding("chatgpt-subscription", 'c'),
                ],
            )
            .unwrap();
        let query =
            |user: u64| serde_json::json!({ "user_id": user, "relays": [relay, "relay-other"] });
        let (status, mine) = private_call(
            registry.clone(),
            pool.clone(),
            "service",
            "/status",
            query(7),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(mine["started"], 5.0);
        assert_eq!(mine["relays"].as_array().unwrap().len(), 1);
        assert_eq!(mine["relays"][0]["relay"], relay.as_str());
        assert_eq!(mine["relays"][0]["idle"], 0);
        assert!(mine["relays"][0]["last_seen"].is_null());
        let (_, other) = private_call(
            registry.clone(),
            pool.clone(),
            "service",
            "/status",
            query(8),
        )
        .await;
        assert_eq!(other["relays"], serde_json::json!([]));
        fs::remove_file(path).unwrap();
    }

    /// The task identity is optional, so an Exchange without it still dispatches.
    #[test]
    fn dispatch_binding_task_is_optional() {
        let base = serde_json::json!({
            "session": "s", "turn": "t", "user_id": 7, "route": "claude-subscription",
            "entry_id": "a", "record_id": "b", "relay_id": "relay-x", "version": 1, "deadline": 1.0,
        });
        let older: Dispatch = serde_json::from_value(base.clone()).unwrap();
        assert_eq!((older.repository, older.issue), (None, None));
        let mut current = base;
        current["repository"] = "acme/demo".into();
        current["issue"] = 4.into();
        let current: Dispatch = serde_json::from_value(current).unwrap();
        assert_eq!(
            (current.repository.as_deref(), current.issue),
            (Some("acme/demo"), Some(4))
        );
    }

    /// A stalled bootstrap cannot outlive the admitted turn.
    #[tokio::test]
    async fn admitted_deadline_covers_stalled_startup() {
        let started = std::time::Instant::now();
        let result = admitted(
            now_seconds().unwrap() + 0.05,
            std::future::pending::<Result<()>>(),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("deadline ended"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// An earlier release prevents a delayed dispatch from taking a ready link.
    #[tokio::test]
    async fn released_turn_cannot_create_a_late_lease() {
        let now = now_seconds().unwrap();
        let turn = ("session".into(), "turn".into());
        let pool = Pool::shared(clock);
        pool.lock().await.release(turn, now + 60.0, now);
        let registry = Arc::new(
            HostedRegistry::open(
                std::env::temp_dir().join(format!("hosted-empty-{}", now.to_bits())),
                None,
            )
            .unwrap(),
        );
        let args = fixture_args(now);
        let dispatch = Dispatch {
            session: "session".into(),
            turn: "turn".into(),
            user_id: 7,
            route: "claude-subscription".into(),
            entry_id: "a".repeat(32),
            record_id: "b".repeat(64),
            relay_id: "relay-fixture".into(),
            version: 1,
            deadline: now + 60.0,
            repository: None,
            issue: None,
        };
        let error = lease(pool, registry, args, &dispatch).await.unwrap_err();
        assert!(error.to_string().contains("released"));
    }

    /// Releasing an in-progress bootstrap aborts its worker before ingress exists.
    #[tokio::test]
    async fn release_aborts_bootstrap_worker() {
        let worker = tokio::spawn(std::future::pending::<()>());
        let (sender, receiver) = watch::channel(None);
        let _sender = sender;
        let now = now_seconds().unwrap();
        let turn = ("session".into(), "turn".into());
        let pool = Pool::shared(clock);
        let mut pool = pool.lock().await;
        pool.leases.insert(
            turn.clone(),
            Lease {
                relay: "relay-fixture".into(),
                slot: ("relay-fixture".into(), 1),
                number: 1,
                deadline: now + 60.0,
                started: now,
                task: None,
                binding: Binding {
                    user_id: 7,
                    login: "owner".into(),
                    route: "claude-subscription".into(),
                    entry_id: "a".repeat(32),
                    record_id: "b".repeat(64),
                    version: 1,
                },
                address: receiver,
                abort: worker.abort_handle(),
            },
        );
        pool.release(turn.clone(), now + 60.0, now);
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(!pool.leases.contains_key(&turn));
        assert!(pool.cancelled.contains_key(&turn));
    }
}
