//! `concurro-relay`: keeps a sponsor's provider login on their machine and
//! performs the requests Concurro orders with it.

use std::{
    io::{self, IsTerminal},
    num::NonZeroUsize,
    path::PathBuf,
    process::Command as Process,
    sync::Arc,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use concurro_relay::{login, plain, review::Reviewer, state::Store, transport::Server, tui};
use concurro_relay_native::{self as native, NativeLimits};
use concurro_relay_protocol::route::Route;

/// Returns freed proof buffers to the system instead of retaining them.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Keeps your provider login on this machine and performs the requests
/// Concurro orders with it. Without a command it opens a full-screen view
/// which signs in if needed and then serves.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Directory the relay keeps its registration and key in.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(flatten)]
    server: ServerArgs,
    #[command(flatten)]
    serving: ServingArgs,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args)]
struct ServerArgs {
    /// Concurro's address for relays, as host:port.
    #[arg(long, env = "CONCURRO_RELAY_SERVER")]
    server: Option<String>,
    /// A certificate file to trust for that address, for a server under
    /// development.
    #[arg(long)]
    server_ca: Option<PathBuf>,
}

#[derive(Args)]
struct ServingArgs {
    /// How many requests the relay can serve at once.
    #[arg(long, default_value_t = 1)]
    links: usize,
    /// A shell command which reviews each request before it is sent. It
    /// gets the request as JSON on standard input; exiting with 0 accepts
    /// it, with 1 rejects it, and otherwise leaves it to you, or accepts it
    /// in `run`. The first line it prints is shown as the reason.
    #[arg(long, env = "CONCURRO_RELAY_REVIEW_COMMAND")]
    review_command: Option<String>,
    /// How many proof-helper connections Concurro may hold open to this
    /// machine at once in one session; more are closed as they are opened.
    #[arg(long, default_value_t = NativeLimits::DEFAULT.tunnel_channels)]
    max_tunnel_channels: NonZeroUsize,
}

impl ServingArgs {
    fn reviewer(&self) -> Arc<Reviewer> {
        Arc::new(Reviewer::new(self.review_command.clone()))
    }

    /// Native session bounds; only the tunnel's applies to a Sponsor.
    fn native(&self) -> NativeLimits {
        NativeLimits {
            tunnel_channels: self.max_tunnel_channels,
            ..NativeLimits::DEFAULT
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Register this relay to your Concurro account.
    Login {
        #[command(flatten)]
        server: ServerArgs,
        /// A route to serve; may be repeated. Without it, every route the
        /// relay has a credential for.
        #[arg(long)]
        route: Vec<Route>,
        /// What to call this relay. Defaults to this machine's name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Serve requests, printing what happens line by line.
    Run {
        #[command(flatten)]
        serving: ServingArgs,
    },
    /// Sign in to a route's provider again, keeping the registration.
    Connect { route: Route },
    /// Show the registration and whether each route is ready.
    Status,
    /// Withdraw the registration and remove the relay's key.
    Logout,
}

impl ServerArgs {
    fn server(self) -> Option<Server> {
        self.server.map(|address| Server {
            address,
            ca_file: self.server_ca,
        })
    }
}

/// This machine's name, by which a person will recognize the relay.
fn machine_name() -> String {
    let name = Process::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok());
    name.map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "relay".into())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let operation = async {
        let store = Store::open(cli.state_dir)?;
        match cli.command {
            None if io::stdout().is_terminal() => {
                tui::run(
                    store,
                    cli.server.server(),
                    machine_name(),
                    cli.serving.links,
                    cli.serving.reviewer(),
                    cli.serving.native(),
                )
                .await
            }
            None => {
                plain::run(
                    plain::relay(&store, cli.serving.reviewer(), cli.serving.native())?,
                    cli.serving.links,
                )
                .await
            }
            Some(Command::Login {
                server,
                route,
                name,
            }) => {
                let server = server
                    .server()
                    .context("name Concurro's address with --server")?;
                plain::login(&store, server, name.unwrap_or_else(machine_name), route)
                    .await
                    .map(|_| ())
            }
            Some(Command::Run { serving }) => {
                let relay = plain::relay(&store, serving.reviewer(), serving.native())?;
                plain::run(relay, serving.links).await
            }
            Some(Command::Connect { route }) => plain::connect(&store, route).await,
            Some(Command::Status) => plain::status(&store),
            Some(Command::Logout) => {
                match login::logout(&store).await {
                    Ok(true) => println!("Signed out."),
                    Ok(false) => println!("Not registered."),
                    Err(error) => {
                        println!("Removed this relay's key, but could not tell Concurro: {error:#}")
                    }
                }
                Ok(())
            }
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
