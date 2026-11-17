//! Launch the existing TLSNotary mock provider for packaged relay checks.

use std::env;

use concurro_relay_dev::provider::{self, ProviderConfig};
use tokio::net::TcpListener;

/// Serve the fixture with the token supplied by the local test runner.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    println!("{}", listener.local_addr()?);
    provider::serve(
        listener,
        ProviderConfig {
            token: env::var("CONCURRO_FIXTURE_TOKEN")?,
            lenient: false,
        },
    )
    .await
}
