//! Stands in for Concurro while a relay is developed: registers relays,
//! approving each registration by itself, accepts their links, and serves a
//! real harness through them.
//!
//! The harness's base URL points at `--listen`. Relays are pointed at
//! `--relay-listen` and trust the certificate written to `--certificate`.

use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use concurro_relay_dev::{gateway::Gateway, registry::DevRegistry, tls};
use concurro_relay_native::{self as native, NativeOptions, NativeRole};
use concurro_relay_protocol::{
    Roots,
    link::{Notice, Order},
    route::Route,
    wire,
};
use concurro_relay_verifier::{
    accept::{self, Acceptor},
    exchange::Expect,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{self, TcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc},
    task::{JoinHandle, JoinSet},
    time,
};

/// A bound native worker endpoint for the legacy shared ingress.
struct NativeEndpoint {
    /// Unique worker instance for cleanup and tracing.
    id: usize,
    /// Registered relay which owns this worker.
    relay: String,
    /// Stable link slot within the registered relay.
    slot: u32,
    /// Provider route served by this worker.
    route: Route,
    /// Bound local CLI adapter address.
    address: SocketAddr,
}

/// Keep the legacy shared ingress pinned to its first authenticated link.
#[derive(Default)]
struct NativeRouter {
    /// Ready workers reachable through their own dedicated leases.
    endpoints: Mutex<Vec<NativeEndpoint>>,
    /// Relay and slot permanently assigned to the legacy ingress.
    owner: Mutex<Option<(String, u32)>>,
    /// Wakes CLI connections when the pinned worker becomes available.
    available: Notify,
}

impl NativeRouter {
    /// Publish a ready worker without changing the shared ingress's owner.
    async fn add(&self, id: usize, relay: String, slot: u32, route: Route, address: SocketAddr) {
        let mut owner = self.owner.lock().await;
        if owner.is_none() {
            *owner = Some((relay.clone(), slot));
        }
        drop(owner);
        self.endpoints.lock().await.push(NativeEndpoint {
            id,
            relay,
            slot,
            route,
            address,
        });
        self.available.notify_waiters();
    }

    /// Remove a worker when its authenticated link has ended.
    async fn remove(&self, id: usize) {
        self.endpoints
            .lock()
            .await
            .retain(|endpoint| endpoint.id != id);
    }

    /// Select only the worker owned by the shared ingress's original link.
    async fn acquire(&self, route: Route) -> (usize, SocketAddr) {
        loop {
            let available = self.available.notified();
            let owner = self.owner.lock().await.clone();
            let endpoints = self.endpoints.lock().await;
            if let Some(endpoint) = endpoints.iter().find(|entry| {
                owner.as_ref().is_some_and(|(relay, slot)| {
                    entry.relay == *relay && entry.slot == *slot && entry.route == route
                })
            }) {
                return (endpoint.id, endpoint.address);
            }
            drop(endpoints);
            let _ = time::timeout(Duration::from_millis(50), available).await;
        }
    }

    /// Inspect one HTTP request line, then proxy the untouched local byte stream.
    async fn forward(self: Arc<Self>, mut client: TcpStream) -> Result<()> {
        let mut first_line = Vec::new();
        loop {
            let byte = client.read_u8().await?;
            first_line.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        let route = if first_line.starts_with(b"POST /v1/messages") {
            Route::ClaudeSubscription
        } else if first_line.starts_with(b"GET /v1/responses") {
            Route::ChatgptSubscription
        } else {
            anyhow::bail!("unknown native CLI route");
        };
        let (id, address) = self.acquire(route).await;
        let mut worker = TcpStream::connect(address).await?;
        eprintln!("NATIVE_ROUTE {route:?} worker={id}");
        worker.write_all(&first_line).await?;
        io::copy_bidirectional(&mut client, &mut worker).await?;
        Ok(())
    }

    /// Accept legacy CLI connections for the pinned link.
    async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (client, _) = listener.accept().await?;
            let router = self.clone();
            tokio::spawn(async move {
                if let Err(error) = router.forward(client).await {
                    eprintln!("native CLI connection ended: {error:#}");
                }
            });
        }
    }
}

/// Keep one local ingress leased to one native worker for the life of its link.
async fn serve_lease(listener: TcpListener, address: SocketAddr, number: u32) -> Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut client, _) = accepted?;
                eprintln!("NATIVE_SESSION_CLI link={number}");
                clients.spawn(async move {
                    let mut worker = TcpStream::connect(address).await?;
                    io::copy_bidirectional(&mut client, &mut worker).await?;
                    Ok::<(), anyhow::Error>(())
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => {
                if let Err(error) = result? {
                    eprintln!("native leased CLI connection ended: {error:#}");
                }
            }
        }
    }
}

/// Returns freed proof buffers to the system instead of retaining them.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Request header naming the ChatGPT account, which a relay adds.
const CHATGPT_ACCOUNT_HEADER: &str = "chatgpt-account-id";

#[derive(Parser)]
struct Args {
    /// Routes to serve on independent links; repeat to allocate more links.
    #[arg(long = "route", required = true)]
    routes: Vec<Route>,
    /// Address the harness sends requests to.
    #[arg(long, default_value = "127.0.0.1:7050")]
    listen: SocketAddr,
    /// Address relays connect to.
    #[arg(long, default_value = "127.0.0.1:7443")]
    relay_listen: SocketAddr,
    /// Where to write the certificate relays must trust.
    #[arg(long, default_value = "dev-verifier.pem")]
    certificate: PathBuf,
    /// Where registered relays are kept, so that they stay registered when
    /// this is started again.
    #[arg(long, default_value = "dev-verifier.json")]
    registry: PathBuf,
    /// The account every relay is registered to.
    #[arg(long, default_value = "dev")]
    login: String,
    /// Seconds a registration waits before it is approved.
    #[arg(long, default_value_t = 3)]
    approve_after: u64,
    /// Compress request bodies with zstd before they are sent and proven.
    #[arg(long)]
    zstd: bool,
    /// Transport backend for accepted relay links.
    #[arg(long, value_enum, default_value_t = Backend::Tls13)]
    backend: Backend,
    /// Provider socket host for the native backend.
    #[arg(long)]
    provider_host: Option<String>,
    /// Provider socket port for the native backend.
    #[arg(long, default_value_t = 443)]
    provider_port: u16,
    /// Claude provider socket host for mixed-route native runs.
    #[arg(long)]
    provider_claude_host: Option<String>,
    /// Claude provider socket port for mixed-route native runs.
    #[arg(long)]
    provider_claude_port: Option<u16>,
    /// Codex provider socket host for mixed-route native runs.
    #[arg(long)]
    provider_codex_host: Option<String>,
    /// Codex provider socket port for mixed-route native runs.
    #[arg(long)]
    provider_codex_port: Option<u16>,
    /// Provider CA bundle for the native backend.
    #[arg(long, default_value = "/etc/ssl/cert.pem")]
    provider_ca: PathBuf,
}

/// The proof protocol used on a registered relay link.
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Tlsnotary,
    Tls13,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let operation = async {
        let route = args.routes[0];
        let host = route.host();
        let provider = if matches!(args.backend, Backend::Tlsnotary) {
            let mut resolved: Vec<_> = net::lookup_host((host, 443)).await?.collect();
            resolved.sort_by_key(|addr| !addr.is_ipv4());
            Some(
                *resolved
                    .first()
                    .with_context(|| format!("{host} did not resolve"))?,
            )
        } else {
            None
        };

        let (tls, certificate) =
            tls::self_signed(vec!["localhost".into(), args.relay_listen.ip().to_string()])?;
        fs::write(&args.certificate, certificate)?;
        let registry = Arc::new(DevRegistry::new(
            args.login,
            Duration::from_secs(args.approve_after),
            Some(args.registry),
        )?);
        let (ready, accepted) = mpsc::unbounded_channel();
        let relay_listener = TcpListener::bind(args.relay_listen).await?;
        tokio::spawn(accept::serve(
            relay_listener,
            tls,
            Arc::new(Acceptor::new(registry, ready)),
        ));

        if matches!(args.backend, Backend::Tls13) {
            let router = if args.routes.len() > 1 {
                None
            } else {
                let ingress = TcpListener::bind(args.listen).await?;
                let router = Arc::new(NativeRouter::default());
                tokio::spawn(router.clone().serve(ingress));
                Some(router)
            };
            eprintln!(
                "native TLS 1.3 relay on {} (certificate in {}); {}",
                args.relay_listen,
                args.certificate.display(),
                if router.is_some() {
                    format!(
                        "legacy CLI ingress on {} plus dedicated leases",
                        args.listen
                    )
                } else {
                    "dedicated CLI ingresses".to_owned()
                }
            );
            let mut accepted = accepted;
            let mut next_id = 0;
            let mut slots: HashMap<(String, u32), (usize, JoinHandle<()>)> = HashMap::new();
            while let Some(mut link) = accepted.recv().await {
                let id = next_id;
                let number = link.slot;
                let identity = (link.relay.clone(), number);
                if let Some((previous_id, previous)) = slots.remove(&identity) {
                    previous.abort();
                    let _ = previous.await;
                    if let Some(router) = &router {
                        router.remove(previous_id).await;
                    }
                }
                let route = args.routes[(number.saturating_sub(1) as usize) % args.routes.len()];
                next_id += 1;
                let (host_override, port_override) = match route {
                    Route::ClaudeSubscription => {
                        (&args.provider_claude_host, args.provider_claude_port)
                    }
                    Route::ChatgptSubscription => {
                        (&args.provider_codex_host, args.provider_codex_port)
                    }
                };
                let provider_host = host_override
                    .clone()
                    .or_else(|| args.provider_host.clone())
                    .unwrap_or_else(|| route.host().to_owned());
                let provider_port = port_override.unwrap_or(args.provider_port);
                let provider_ca = args.provider_ca.clone();
                let router = router.clone();
                let relay = identity.0.clone();
                let worker = tokio::spawn(async move {
                    let result: Result<()> = async {
                        wire::send(&mut link.control, &Order::NativeStart {
                            route, provider_host: provider_host.clone(), provider_port,
                        }).await?;
                        match wire::recv::<_, Notice>(&mut link.control).await? {
                            Notice::NativeReady => {}
                            Notice::Refused(reason) => anyhow::bail!("Sponsor refused native session: {reason}"),
                            answer => anyhow::bail!("Sponsor answered native session with {answer:?}"),
                        }
                        let (ready, mut bound) = mpsc::unbounded_channel();
                        let bridge = native::bridge(link.control, link.proofs, NativeOptions {
                            role: NativeRole::Concurro, route, provider_host, provider_port,
                            provider_ca, listen: Some("127.0.0.1:0".to_owned()),
                            token: None, account: None, audit: None, ready: Some(ready),
                        });
                        tokio::pin!(bridge);
                        tokio::select! {
                            address = bound.recv() => {
                                if let Some(address) = address {
                                    let address = address.parse()?;
                                    let lease = TcpListener::bind("127.0.0.1:0").await?;
                                    eprintln!("NATIVE_SESSION_READY link={number} route={route:?} ingress={} relay={relay}", lease.local_addr()?);
                                    if let Some(router) = &router {
                                        router.add(id, relay, number, route, address).await;
                                    }
                                    tokio::select! {
                                        result = &mut bridge => result,
                                        result = serve_lease(lease, address, number) => result,
                                    }
                                } else {
                                    bridge.await
                                }
                            }
                            result = &mut bridge => result,
                        }
                    }.await;
                    if let Some(router) = router {
                        router.remove(id).await;
                    }
                    if let Err(error) = result {
                        eprintln!("native session ended: {error:#}");
                    }
                });
                slots.insert(identity, (id, worker));
            }
            anyhow::bail!("native relay acceptor closed")
        } else {
            let expect = Expect {
                provider: provider.expect("TLSNotary provider resolved"),
                roots: Roots::Mozilla,
                relay_headers: match route {
                    Route::ChatgptSubscription => vec![CHATGPT_ACCOUNT_HEADER.to_owned()],
                    Route::ClaudeSubscription => Vec::new(),
                },
            };
            let gateway = Gateway::new(route, expect, args.zstd, accepted);
            let listener = TcpListener::bind(args.listen).await?;
            eprintln!(
                "serving the harness on http://{}, relays on {} (certificate in {}), provider {host} at {}",
                args.listen,
                args.relay_listen,
                args.certificate.display(),
                provider.unwrap()
            );
            gateway.serve(listener).await
        }
    };
    tokio::select! {
        result = operation => result,
        signal = native::shutdown_signal() => {
            signal?;
            native::stop_workers();
            Ok(())
        }
    }
}
