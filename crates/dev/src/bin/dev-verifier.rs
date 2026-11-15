//! Stands in for Concurro while a relay is developed: registers relays,
//! approving each registration by itself, accepts their links, and serves a
//! real harness through them.
//!
//! The harness's base URL points at `--listen`. Relays are pointed at
//! `--relay-listen` and trust the certificate written to `--certificate`.

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use concurro_relay_dev::{gateway::Gateway, registry::DevRegistry, tls};
use concurro_relay_protocol::{Roots, route::Route};
use concurro_relay_verifier::{
    accept::{self, Acceptor},
    exchange::Expect,
};
use tokio::{
    net::{self, TcpListener},
    sync::mpsc,
};

/// Returns freed proof buffers to the system instead of retaining them.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Request header naming the ChatGPT account, which a relay adds.
const CHATGPT_ACCOUNT_HEADER: &str = "chatgpt-account-id";

#[derive(Parser)]
struct Args {
    /// The route harness requests are sent on.
    #[arg(long)]
    route: Route,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let host = args.route.host();
    let mut resolved: Vec<_> = net::lookup_host((host, 443)).await?.collect();
    resolved.sort_by_key(|addr| !addr.is_ipv4());
    let provider = *resolved.first().with_context(|| format!("{host} did not resolve"))?;

    let (tls, certificate) = tls::self_signed(vec!["localhost".into(), args.relay_listen.ip().to_string()])?;
    fs::write(&args.certificate, certificate)?;
    let registry = Arc::new(DevRegistry::new(args.login, Duration::from_secs(args.approve_after), Some(args.registry))?);
    let (ready, accepted) = mpsc::unbounded_channel();
    let relay_listener = TcpListener::bind(args.relay_listen).await?;
    tokio::spawn(accept::serve(relay_listener, tls, Arc::new(Acceptor::new(registry, ready))));

    let relay_headers = match args.route {
        Route::ChatgptSubscription => vec![CHATGPT_ACCOUNT_HEADER.to_owned()],
        Route::ClaudeSubscription => Vec::new(),
    };
    let expect = Expect { provider, roots: Roots::Mozilla, relay_headers };
    let gateway = Gateway::new(args.route, expect, args.zstd, accepted);
    let listener = TcpListener::bind(args.listen).await?;
    eprintln!(
        "serving the harness on http://{}, relays on {} (certificate in {}), provider {host} at {provider}",
        args.listen,
        args.relay_listen,
        args.certificate.display()
    );
    gateway.serve(listener).await
}
