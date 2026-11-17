//! What the test files share: a mock provider's credential and jobs for it.

#![allow(dead_code)]

use std::{net::SocketAddr, time::Duration};

use concurro_relay_dev::provider::{self, ProviderConfig, RESPONSE_BYTES_HEADER};
use concurro_relay_protocol::wire::Job;
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tokio::net::{TcpListener, TcpStream};

/// The credential the mock provider accepts.
pub const TOKEN: &str = "sk-test-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// The mock provider's inference path.
pub const PATH: &str = "/v1/responses";

/// Longest any step of a test may take before it counts as stuck.
pub const STEP_LIMIT: Duration = Duration::from_secs(30);

/// Starts a mock provider, which authenticates on a prefix of the token
/// alone if `lenient`, and returns its address.
pub async fn provider(lenient: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(provider::serve(
        listener,
        ProviderConfig {
            token: TOKEN.into(),
            lenient,
        },
    ));
    address
}

/// A connected pair of loopback sockets.
pub async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let near = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (far, _) = listener.accept().await.unwrap();
    near.set_nodelay(true).unwrap();
    far.set_nodelay(true).unwrap();
    (near, far)
}

/// An inference job for the mock provider whose body is about
/// `request_bytes` long, asking for a response of about `response_bytes`.
pub fn job(request_bytes: usize, response_bytes: usize) -> Job {
    let body = serde_json::json!({
        "model": "test-model",
        "stream": true,
        "tools": [{"type": "function", "name": "shell"}],
        "input": "p".repeat(request_bytes),
    });
    Job {
        host: SERVER_DOMAIN.into(),
        path: PATH.into(),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            (RESPONSE_BYTES_HEADER.into(), response_bytes.to_string()),
        ],
        body: body.to_string().into_bytes(),
    }
}
