//! Hosted Rust verifier for owner-approved, claim-authorized subscription relay sessions.

mod dispatch;
mod http;
mod journal;
mod lease;
mod pool;
mod private;
mod registry;
mod storage;

use std::{
    fs,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use concurro_relay_hosted_api::claim::VerificationKeys;
use concurro_relay_native::NativeLimits;
use concurro_relay_verifier::accept::{self, Acceptor, Limits};
use journal::Journal;
use private::Credentials;
use registry::HostedRegistry;
use rustls::{ServerConfig, crypto::ring as rustls_ring, pki_types::CertificateDer};
use time::OffsetDateTime;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, mpsc},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

type Pool = pool::Pool<TlsStream<TcpStream>>;

/// Hosted verifier listeners, durable registry, and native provider settings.
#[derive(Parser)]
struct Args {
    /// TLS listener to which Sponsor relays connect.
    #[arg(long, default_value = "0.0.0.0:7443")]
    relay_listen: SocketAddr,
    /// Private listener for Accounts, Gateway and Exchange.
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
    /// Private bearer file for owner registration and relay status.
    #[arg(long)]
    owner_token: PathBuf,
    /// Private bearer file for signed inference dispatch.
    #[arg(long)]
    inference_token: PathBuf,
    /// Private bearer file for claim release.
    #[arg(long)]
    release_token: PathBuf,
    /// Exchange Ed25519 public keys (JSON Web Key Set).
    #[arg(long)]
    exchange_public_keys: PathBuf,
    /// Durable claim journal (defaults to the registry path plus .claims).
    #[arg(long)]
    claim_journal: Option<PathBuf>,
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
    /// Bytes a Sponsor's credential may have; its length sets the size of
    /// the prefix circuit generated for it.
    #[arg(long, default_value_t = NativeLimits::DEFAULT.credential_bytes)]
    max_credential_bytes: NonZeroUsize,
    /// Generated prefix circuits kept in the cache; the least recently used
    /// beyond it are removed.
    #[arg(long, default_value_t = NativeLimits::DEFAULT.cached_circuits)]
    cached_circuits: NonZeroUsize,
    /// Unix start time; live telemetry before it is unknown.
    #[arg(skip)]
    started: f64,
}

/// Shared state for the private listener and the authenticated Sponsor links.
struct App {
    args: Arc<Args>,
    credentials: Credentials,
    keys: VerificationKeys,
    registry: Arc<HostedRegistry>,
    pool: Arc<AsyncMutex<Pool>>,
    journal: Mutex<Journal>,
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

/// Current Unix time for relay liveness.
fn clock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Convert relay liveness to the owner API's UTC timestamp.
fn timestamp(seconds: f64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos((seconds * 1e9) as i128)
        .expect("relay liveness is in the RFC 3339 range")
}

/// Start both listeners and retain only authenticated, owner-bound live links.
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    args.started = clock();
    let args = Arc::new(args);
    let credentials = Credentials::read(
        &args.owner_token,
        &args.inference_token,
        &args.release_token,
    )?;
    let keys = VerificationKeys::from_jwks(&fs::read(&args.exchange_public_keys)?)
        .context("invalid exchange public key set")?;
    let claim_path = args
        .claim_journal
        .clone()
        .unwrap_or_else(|| storage::with_suffix(&args.registry, ".claims"));
    ensure!(
        claim_path != args.registry
            && claim_path != args.registry.with_extension("withdrawn")
            && claim_path != storage::with_suffix(&args.registry, ".tmp")
            && storage::with_suffix(&claim_path, ".tmp") != args.registry,
        "claim journal path collides with the relay registry"
    );

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
    let journal = Journal::open(claim_path, OffsetDateTime::now_utc().unix_timestamp())
        .context("could not open claim journal")?;
    let app = Arc::new(App {
        args: args.clone(),
        credentials,
        keys,
        registry: registry.clone(),
        pool: pool.clone(),
        journal: Mutex::new(journal),
    });
    let (ready, mut accepted) = mpsc::unbounded_channel();
    let relay = TcpListener::bind(args.relay_listen).await?;
    let private_listener = TcpListener::bind(args.private_listen).await?;
    tokio::spawn(accept::serve(
        relay,
        tls(&args.certificate, &args.private_key)?,
        Arc::new(Acceptor::new(registry, ready).with_limits(Limits {
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
    tokio::spawn(async move {
        while let Some(relay) = withdrawn.recv().await {
            pool.lock().await.withdraw(&relay, clock());
        }
    });
    let pruned = app.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if let Err(error) = pruned
                .journal
                .lock()
                .expect("claim journal lock")
                .prune(now)
            {
                eprintln!("claim journal compaction failed: {error:#}");
            }
        }
    });
    eprintln!("hosted relay verifier listening on {}", args.relay_listen);
    loop {
        let stream = accept::next_connection(&private_listener).await;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(error) = private::serve(stream, app).await {
                eprintln!("private verifier connection failed: {error:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests;
