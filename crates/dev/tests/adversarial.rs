//! What a verifier accepts and rejects on a provider connection which
//! stays open: from an honest relay, from a relay which departs from the
//! protocol, and from a provider which does.

mod common;

use std::{assert_matches, future::IntoFuture, net::SocketAddr, ops::Range, pin::pin, time::Duration};

use anyhow::Result;
use common::{STEP_LIMIT, TOKEN};
use concurro_relay::{
    live::{LiveRelay, Misproof},
    policy::{Policy, UNKNOWN_RESPONSE},
    ws::WsRelay,
};
use concurro_relay_dev::{
    provider::{
        CLOSE, CLOSE_HELD, DELAY_HEADER, DUPLICATE_END, FORGED_ID, FORGED_RESPONSE, MISBEHAVE_HEADER, MIXED_ID, PING,
        PING_GATED, RESPONSE_BYTES_HEADER, STALE_EVENT, WRONG_PARENT,
    },
    slow::{self, Shape},
};
use concurro_relay_protocol::{
    Roots,
    link::{self, Notice, Order},
    meter::{Counters, Metered},
    wire::{self, CredentialHeader, Job, Offer},
    ws::{self, Asked, HEAD_END, Inbox, Progress},
};
use concurro_relay_verifier::{
    exchange::{Expect, Verdict},
    link::Link,
    live::LiveVerifier,
    ws::WsVerifier,
};
use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt};
use serde_json::{Value, json};
use tlsn::{
    Session, SessionHandle,
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::proxy::ProxyTlsConfig},
    connection::{DnsName, ServerName},
    transcript::Direction,
};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tokio::{io, net::TcpStream, time};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::compat::TokioAsyncReadCompatExt;

fn offer() -> Offer {
    Offer { credential: CredentialHeader::bearer(), hidden_len: TOKEN.len(), headers: Vec::new() }
}

/// The bytes the relay sends for `job`, and where the credential sits.
fn request(job: &Job) -> (Vec<u8>, Range<usize>) {
    wire::encode_request_on(job, &offer(), TOKEN.as_bytes(), "keep-alive")
}

/// What the verifier expects the relay to have sent for `job`.
fn expected(job: &Job) -> (Vec<u8>, Range<usize>) {
    wire::encode_request_on(job, &offer(), &vec![0; TOKEN.len()], "keep-alive")
}

fn shifted(range: &Range<usize>, by: usize) -> Range<usize> {
    by + range.start..by + range.end
}

/// A relay and a verifier sharing one session, with the traffic the
/// verifier receives from the relay.
struct Sides {
    relay_handle: SessionHandle,
    verifier_handle: SessionHandle,
    provider: SocketAddr,
    traffic: Counters,
    /// Pongs sent while turns were in flight.
    pongs: usize,
}

impl Sides {
    async fn new() -> Self {
        Self::over(None).await
    }

    /// Relay and verifier joined directly, or by a link which delays each
    /// direction by `delay`, as a real one would.
    async fn over(delay: Option<Duration>) -> Self {
        let provider_addr = common::provider(false).await;

        let (relay_stream, verifier_stream) = match delay {
            None => common::pair().await,
            Some(delay) => {
                let (relay_stream, relay_far) = common::pair().await;
                let (verifier_far, verifier_stream) = common::pair().await;
                let shape = Some(Shape { bits_per_second: 1e9, delay });
                tokio::spawn(slow::join(relay_far, verifier_far, shape, shape));
                (relay_stream, verifier_stream)
            }
        };
        let (driver, relay_handle) = Session::new(relay_stream.compat()).split();
        tokio::spawn(driver);
        let traffic = Counters::default();
        let (driver, verifier_handle) =
            Session::new(Metered::new(verifier_stream, traffic.clone()).compat()).split();
        tokio::spawn(driver);
        Self { relay_handle, verifier_handle, provider: provider_addr, traffic, pongs: 0 }
    }

    /// Opens a provider connection on both sides.
    async fn open(&mut self) -> (LiveRelay, LiveVerifier) {
        let (relay, verifier) = time::timeout(STEP_LIMIT, async {
            tokio::join!(
                LiveRelay::open(&mut self.relay_handle, SERVER_DOMAIN, Roots::Fixture),
                LiveVerifier::open(&mut self.verifier_handle, SERVER_DOMAIN, self.provider, Roots::Fixture),
            )
        })
        .await
        .unwrap();
        (relay.unwrap(), verifier.unwrap())
    }

    /// Runs the relay's part of a turn alongside the verifier checking that
    /// the relay sent `job`, returning what the verifier concluded.
    async fn turn(
        &mut self,
        verifier: &mut LiveVerifier,
        job: &Job,
        relay: impl Future<Output = Result<()>>,
    ) -> Verified {
        let (expected, hidden) = expected(job);
        let verifier_handle = &mut self.verifier_handle;
        let hidden = [hidden];
        let both = async { tokio::join!(relay, verifier.verify(verifier_handle, &expected, &hidden)) };
        let verified = match time::timeout(STEP_LIMIT, both).await {
            Ok((_, Ok(Ok(received)))) => Verified::Accepted(received),
            Ok((_, Ok(Err(reason)))) => Verified::Rejected(reason),
            Ok((_, Err(error))) => Verified::Rejected(format!("{error:#}")),
            Err(_) => Verified::Stuck,
        };
        if let Verified::Rejected(reason) = &verified {
            println!("rejected: {reason}");
        }
        verified
    }
}

#[derive(Debug)]
enum Verified {
    Accepted(Vec<u8>),
    Rejected(String),
    /// Neither accepted nor rejected within the time limit.
    Stuck,
}

/// The relay's honest part of a turn.
async fn honest(relay: &mut LiveRelay, handle: &mut SessionHandle, job: &Job) -> Result<()> {
    let start = relay.sent();
    let (bytes, hidden) = request(job);
    relay.send(&bytes).await?;
    relay.read_http_response().await?;
    relay.prove(handle, &[shifted(&hidden, start)]).await
}

/// Opens a connection and completes one honest turn on it.
async fn after_one_turn(sides: &mut Sides) -> (LiveRelay, LiveVerifier) {
    let (mut relay, mut verifier) = sides.open().await;
    let job = common::job(900, 256);
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);
    let verified = sides.turn(&mut verifier, &job, honest(&mut relay, &mut relay_handle, &job)).await;
    sides.relay_handle = relay_handle;
    assert_matches!(verified, Verified::Accepted(_));
    (relay, verifier)
}

/// A handle to stand in while the real one is lent to a relay future.
async fn placeholder_handle() -> SessionHandle {
    let (stream, _) = common::pair().await;
    Session::new(stream.compat()).split().1
}

/// Two requests on one provider connection are each proven while it stays
/// open, and the second proof costs what the second request costs.
#[tokio::test(flavor = "multi_thread")]
async fn each_turn_on_an_open_connection_is_proven() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open().await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let mut uploads = Vec::new();
    for job in [common::job(20_000, 512), common::job(300, 512)] {
        let before = sides.traffic.read();
        let verified = sides.turn(&mut verifier, &job, honest(&mut relay, &mut relay_handle, &job)).await;
        let Verified::Accepted(received) = verified else { panic!("{verified:?}") };
        let response = wire::parse_response(&received).unwrap();
        assert_eq!(response.status, 200);
        let body = String::from_utf8_lossy(&response.body).into_owned();
        assert!(body.contains(&format!("\"input_bytes\":{}", job.body.len())), "{body}");
        uploads.push(sides.traffic.read() - before);
    }
    assert!(uploads[1] < uploads[0] / 4, "{uploads:?}");

    let (closed, _) = tokio::join!(relay.close(), verifier.close());
    closed.unwrap();
}

/// A request the verifier did not ask for, sent before the expected one, is
/// rejected at that turn, whether the relay reveals it or tries to leave it
/// out of the proof.
#[tokio::test(flavor = "multi_thread")]
async fn inserted_request_is_rejected_at_that_turn() {
    for reveal_inserted in [true, false] {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

        let (inserted, job) = (common::job(700, 256), common::job(700, 256));
        let cheat = async {
            let first = relay.sent();
            let (bytes, first_hidden) = request(&inserted);
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            let second = relay.sent();
            let (bytes, second_hidden) = request(&job);
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            let snapshot = relay.snapshot().await?;
            let (hidden, misproof) = if reveal_inserted {
                (vec![shifted(&first_hidden, first), shifted(&second_hidden, second)], Misproof::default())
            } else {
                (vec![shifted(&second_hidden, second)], Misproof { reveal_from: Some(second), ..Misproof::default() })
            };
            relay.prove_snapshot(&mut relay_handle, snapshot, &hidden, &misproof).await
        };
        let verified = sides.turn(&mut verifier, &job, cheat).await;
        assert_matches!(verified, Verified::Rejected(_), "reveal_inserted={reveal_inserted}");
    }
}

/// A proof which adds no request is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn omitted_request_is_rejected() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let job = common::job(700, 256);
    let cheat = async { relay.prove(&mut relay_handle, &[]).await };
    assert_matches!(sides.turn(&mut verifier, &job, cheat).await, Verified::Rejected(_));
}

/// A request sent after the proof's snapshot was taken is caught by that
/// proof, before its response could be acted on.
#[tokio::test(flavor = "multi_thread")]
async fn request_sent_after_the_cut_is_rejected_at_that_turn() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let (job, extra) = (common::job(700, 256), common::job(500, 256));
    let cheat = async {
        let start = relay.sent();
        let (bytes, hidden) = request(&job);
        relay.send(&bytes).await?;
        relay.read_http_response().await?;
        let snapshot = relay.snapshot().await?;
        // The extra request has reached the provider and been answered by
        // the time the proof is offered.
        relay.send(&request(&extra).0).await?;
        relay.read_http_response().await?;
        relay.prove_snapshot(&mut relay_handle, snapshot, &[shifted(&hidden, start)], &Misproof::default()).await
    };
    let verified = sides.turn(&mut verifier, &job, cheat).await;
    assert_matches!(verified, Verified::Rejected(reason) if reason.contains("beyond what it proved"));
}

/// A snapshot from an earlier turn can not stand in for the current one.
#[tokio::test(flavor = "multi_thread")]
async fn replayed_snapshot_is_rejected() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open().await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let first = common::job(900, 256);
    let mut kept = None;
    let turn_one = async {
        let start = relay.sent();
        let (bytes, hidden) = request(&first);
        relay.send(&bytes).await?;
        relay.read_http_response().await?;
        let snapshot = relay.snapshot().await?;
        kept = Some(snapshot.clone());
        relay.prove_snapshot(&mut relay_handle, snapshot, &[shifted(&hidden, start)], &Misproof::default()).await
    };
    assert_matches!(sides.turn(&mut verifier, &first, turn_one).await, Verified::Accepted(_));

    let second = common::job(700, 256);
    let cheat = async {
        relay.send(&request(&second).0).await?;
        relay.read_http_response().await?;
        relay.prove_snapshot(&mut relay_handle, kept.take().unwrap(), &[], &Misproof::default()).await
    };
    assert_matches!(sides.turn(&mut verifier, &second, cheat).await, Verified::Rejected(_));
}

/// A proof must reveal the sent data from exactly where the last one ended.
#[tokio::test(flavor = "multi_thread")]
async fn overlapping_or_skipped_prefix_is_rejected() {
    for offset in [-10isize, 10] {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

        let job = common::job(700, 256);
        let cheat = async {
            let start = relay.sent();
            let (bytes, hidden) = request(&job);
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            let snapshot = relay.snapshot().await?;
            let misproof = Misproof { reveal_from: Some(start.checked_add_signed(offset).unwrap()), ..Misproof::default() };
            relay.prove_snapshot(&mut relay_handle, snapshot, &[shifted(&hidden, start)], &misproof).await
        };
        assert_matches!(sides.turn(&mut verifier, &job, cheat).await, Verified::Rejected(_), "offset={offset}");
    }
}

/// The verifier counts the records earlier proofs covered itself; a relay
/// which claims a different count does not get its proof accepted.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_record_count_is_not_accepted() {
    for claimed in [0, 1_000] {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

        let job = common::job(700, 256);
        let cheat = async {
            let start = relay.sent();
            let (bytes, hidden) = request(&job);
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            let snapshot = relay.snapshot().await?;
            let misproof = Misproof { tags_from: Some(claimed), ..Misproof::default() };
            relay.prove_snapshot(&mut relay_handle, snapshot, &[shifted(&hidden, start)], &misproof).await
        };
        let verified = sides.turn(&mut verifier, &job, cheat).await;
        assert!(!matches!(verified, Verified::Accepted(_)), "claimed={claimed}");
    }
}

/// A snapshot of one provider connection is not accepted as a proof about
/// another, even on the same session and with the same request.
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_from_another_connection_is_rejected() {
    let mut sides = Sides::new().await;
    let (mut relay_a, mut verifier_a) = sides.open().await;
    let (mut relay_b, _verifier_b) = sides.open().await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let job = common::job(900, 256);
    let cheat = async {
        let (bytes, hidden) = request(&job);
        for relay in [&mut relay_a, &mut relay_b] {
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
        }
        let other = relay_b.snapshot().await?;
        relay_a.prove_snapshot(&mut relay_handle, other, &[hidden], &Misproof::default()).await
    };
    let verified = sides.turn(&mut verifier_a, &job, cheat).await;
    assert_matches!(verified, Verified::Rejected(_));
}

/// A proof cut before any of the response arrived is a valid proof of the
/// request, and yields no response to act on.
#[tokio::test(flavor = "multi_thread")]
async fn proof_cut_before_the_response_yields_no_response() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let mut job = common::job(700, 256);
    job.headers.push((DELAY_HEADER.into(), "400".into()));
    let early = async {
        let start = relay.sent();
        let (bytes, hidden) = request(&job);
        relay.send(&bytes).await?;
        let snapshot = relay.snapshot_after_sending().await?;
        relay.prove_snapshot(&mut relay_handle, snapshot, &[shifted(&hidden, start)], &Misproof::default()).await
    };
    let verified = sides.turn(&mut verifier, &job, early).await;
    assert_matches!(verified, Verified::Accepted(received) if received.is_empty());
}

/// A first proof which hides nothing still proves the request in zero
/// knowledge. Authenticating it with the client's key would be cheaper,
/// and would hand the verifier the sending side of a connection still in
/// use.
#[tokio::test(flavor = "multi_thread")]
async fn first_proof_hiding_nothing_does_not_disclose_the_client_key() {
    let mut uploads = Vec::new();
    for credential in ["", "x"] {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = sides.open().await;
        let offer = Offer { hidden_len: credential.len(), ..offer() };
        let job = common::job(20_000, 256);
        let (bytes, hidden) = wire::encode_request_on(&job, &offer, credential.as_bytes(), "keep-alive");
        let (expected, _) = wire::encode_request_on(&job, &offer, &vec![0; credential.len()], "keep-alive");
        let hidden: Vec<_> = Some(hidden).into_iter().filter(|range| !range.is_empty()).collect();

        let relayed = async {
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            relay.prove(&mut sides.relay_handle, &hidden).await
        };
        let (relayed, verified) = tokio::join!(relayed, verifier.verify(&mut sides.verifier_handle, &expected, &hidden));
        relayed.unwrap();
        verified.unwrap().unwrap();
        uploads.push(sides.traffic.read());
    }
    assert!(uploads[0].abs_diff(uploads[1]) < uploads[1] / 20, "{uploads:?}");
}

/// A provider connection which closes while a turn of another connection on
/// the same session is being proven does not disturb that proof.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_connection_does_not_disturb_a_proof_on_another() {
    for _ in 0..6 {
        let mut sides = Sides::new().await;
        let (mut relay_a, mut verifier_a) = sides.open().await;
        let (mut relay_b, mut verifier_b) = sides.open().await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);
        let job = common::job(4_000, 256);
        for (relay, verifier) in [(&mut relay_a, &mut verifier_a), (&mut relay_b, &mut verifier_b)] {
            let verified = sides.turn(verifier, &job, honest(relay, &mut relay_handle, &job)).await;
            assert_matches!(verified, Verified::Accepted(_));
        }

        let closing = async {
            let (closed, _) = tokio::join!(relay_a.close(), verifier_a.close());
            closed
        };
        let proving = sides.turn(&mut verifier_b, &job, honest(&mut relay_b, &mut relay_handle, &job));
        let (closed, verified) = tokio::join!(closing, proving);
        closed.unwrap();
        assert_matches!(verified, Verified::Accepted(_));
    }
}

/// How long the link of the slow-link tests delays each direction.
const LINK_DELAY: Duration = Duration::from_millis(30);

/// Over a link with delay, a session goes on proving after one of its
/// connections has closed: turns on another connection, and on a new one.
#[tokio::test(flavor = "multi_thread")]
async fn session_survives_a_connection_closing_over_a_slow_link() {
    for _ in 0..3 {
        let mut sides = Sides::over(Some(LINK_DELAY)).await;
        let (mut relay_a, mut verifier_a) = sides.open().await;
        let (mut relay_b, mut verifier_b) = sides.open().await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);
        let job = common::job(2_000, 2_000);
        for (relay, verifier) in [(&mut relay_a, &mut verifier_a), (&mut relay_b, &mut verifier_b)] {
            let verified = sides.turn(verifier, &job, honest(relay, &mut relay_handle, &job)).await;
            assert_matches!(verified, Verified::Accepted(_));
        }
        let (closed, _) = tokio::join!(relay_a.close(), verifier_a.close());
        closed.unwrap();

        let verified = sides.turn(&mut verifier_b, &job, honest(&mut relay_b, &mut relay_handle, &job)).await;
        assert_matches!(verified, Verified::Accepted(_));

        sides.relay_handle = relay_handle;
        let (mut relay_c, mut verifier_c) = sides.open().await;
        let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);
        let verified = sides.turn(&mut verifier_c, &job, honest(&mut relay_c, &mut relay_handle, &job)).await;
        assert_matches!(verified, Verified::Accepted(_));
    }
}

/// A provider which closes the connection after answering, while the turn
/// is being proven, does not get an honest relay rejected: the relay's TLS
/// client answering the close is not a request.
#[tokio::test(flavor = "multi_thread")]
async fn provider_closing_during_a_proof_does_not_reject_an_honest_relay() {
    for _ in 0..3 {
        let mut sides = Sides::over(Some(LINK_DELAY)).await;
        let (mut relay, mut verifier) = sides.open().await;
        let job = common::job(2_000, 256);
        let closing = |credential: &[u8]| wire::encode_request_on(&job, &offer(), credential, "close");
        let (bytes, hidden) = closing(TOKEN.as_bytes());
        let (expected, _) = closing(&vec![0; TOKEN.len()]);
        let hidden = [hidden];

        let relayed = async {
            relay.send(&bytes).await?;
            relay.read_http_response().await?;
            relay.prove(&mut sides.relay_handle, &hidden).await
        };
        let (relayed, verified) = tokio::join!(relayed, verifier.verify(&mut sides.verifier_handle, &expected, &hidden));
        relayed.unwrap();
        let response = wire::parse_response(&verified.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, 200);
    }
}

/// After a rejected proof the verifier's session is closed, so nothing more
/// is proven with its OT state.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_proof_closes_the_session() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = after_one_turn(&mut sides).await;
    let mut relay_handle = std::mem::replace(&mut sides.relay_handle, placeholder_handle().await);

    let job = common::job(700, 256);
    let cheat = async { relay.prove(&mut relay_handle, &[]).await };
    assert_matches!(sides.turn(&mut verifier, &job, cheat).await, Verified::Rejected(_));

    let (expected, hidden) = expected(&job);
    let hidden = [hidden];
    let again = verifier.verify(&mut sides.verifier_handle, &expected, &hidden);
    assert_matches!(time::timeout(Duration::from_secs(5), again).await, Ok(Ok(Err(_))));
}

const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const PONG_MASK: [u8; 4] = [7, 7, 7, 7];

fn ws_policy() -> Policy {
    Policy {
        host: SERVER_DOMAIN.into(),
        paths: vec![common::PATH.into()],
        headers: vec![RESPONSE_BYTES_HEADER.into(), MISBEHAVE_HEADER.into()],
        body_fields: ["type", "model", "store", "input", "previous_response_id"].map(Into::into).to_vec(),
    }
}

/// The upgrade request for a WebSocket connection to the mock provider.
fn ws_job(misbehaviour: Option<&str>) -> Job {
    let mut headers = vec![(RESPONSE_BYTES_HEADER.to_owned(), "2048".to_owned())];
    headers.extend(misbehaviour.map(|kind| (MISBEHAVE_HEADER.to_owned(), kind.to_owned())));
    Job { host: SERVER_DOMAIN.into(), path: common::PATH.into(), headers, body: Vec::new() }
}

/// The message asking for a response, with `fields` laid over an allowed
/// request.
fn ws_message(fields: Value) -> String {
    let mut request = json!({"type": "response.create", "model": "test-model", "store": false, "input": "list"});
    request.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
    request.to_string()
}

/// The client frame carrying [`ws_message`].
fn ws_request(fields: Value) -> Vec<u8> {
    ws::text_frame(&ws_message(fields), [0x5a, 0x17, 0xc3, 0x09])
}

impl Sides {
    /// Opens and upgrades a WebSocket connection on both sides.
    async fn open_ws(&mut self, misbehaviour: Option<&str>) -> (WsRelay, WsVerifier) {
        let (job, offer) = (ws_job(misbehaviour), offer());
        let (relay, verifier) = time::timeout(STEP_LIMIT, async {
            tokio::join!(
                WsRelay::open(&mut self.relay_handle, &job, &offer, TOKEN.as_bytes(), WS_KEY, ws_policy(), Roots::Fixture),
                WsVerifier::open(&mut self.verifier_handle, &job, &offer, &[], WS_KEY, self.provider, Roots::Fixture),
            )
        })
        .await
        .unwrap();
        (relay.unwrap(), verifier.unwrap().unwrap())
    }

    /// Runs one turn on both sides, answering the pings which interrupt it,
    /// and returns the provider's messages as the verifier accepted them.
    /// Ends as soon as either side fails.
    async fn ws_turn(&mut self, relay: &mut WsRelay, verifier: &mut WsVerifier, frame: &[u8]) -> Result<Vec<Message>, String> {
        let relayed = async {
            relay.turn(&mut self.relay_handle, frame).await.map_err(|error| format!("{error:#}"))?
        };
        let verified = async {
            verifier.turn(&mut self.verifier_handle, frame).await.map_err(|error| format!("{error:#}"))?
        };
        let both = async { tokio::try_join!(relayed, verified) };
        let (_, mut progress) = time::timeout(STEP_LIMIT, both).await.map_err(|_| "turn did not finish in time")??;
        loop {
            match progress {
                Progress::Response(messages) => return Ok(messages),
                Progress::Ping(payload) => {
                    let pong = ws::pong_frame(&payload, PONG_MASK);
                    progress = self.ws_pong(relay, verifier, &pong).await?.ok_or("no response in flight")?;
                    self.pongs += 1;
                }
            }
        }
    }

    /// Opens and upgrades a WebSocket connection held by a relay which
    /// checks nothing.
    async fn open_credulous(&mut self, misbehaviour: &str) -> (Credulous, WsVerifier) {
        let (job, offer) = (ws_job(Some(misbehaviour)), offer());
        let (relay, verifier) = time::timeout(STEP_LIMIT, async {
            tokio::join!(
                Credulous::open(&mut self.relay_handle, &job, &offer),
                WsVerifier::open(&mut self.verifier_handle, &job, &offer, &[], WS_KEY, self.provider, Roots::Fixture),
            )
        })
        .await
        .unwrap();
        (relay.unwrap(), verifier.unwrap().unwrap())
    }

    /// Runs one turn with a relay which checks nothing, returning what the
    /// verifier alone concluded.
    async fn ws_turn_unchecked(&mut self, relay: &mut Credulous, verifier: &mut WsVerifier, frame: &[u8]) -> Result<Vec<Message>, String> {
        let both = async {
            tokio::join!(relay.turn(&mut self.relay_handle, frame), verifier.turn(&mut self.verifier_handle, frame))
        };
        let (relayed, verified) = time::timeout(STEP_LIMIT, both).await.map_err(|_| "turn did not finish in time")?;
        relayed.unwrap();
        match verified.map_err(|error| format!("{error:#}"))?? {
            Progress::Response(messages) => Ok(messages),
            Progress::Ping(_) => Err("a ping is waiting".into()),
        }
    }

    /// Has the relay send `frame` as a pong, and the verifier check it did.
    /// Returns what the verifier says comes next.
    async fn ws_pong(&mut self, relay: &mut WsRelay, verifier: &mut WsVerifier, frame: &[u8]) -> Result<Option<Progress>, String> {
        let relayed = async {
            relay.pong(&mut self.relay_handle, frame).await.map_err(|error| format!("{error:#}"))?
        };
        let verified = async {
            verifier.pong(&mut self.verifier_handle, frame).await.map_err(|error| format!("{error:#}"))?
        };
        let both = async { tokio::try_join!(relayed, verified) };
        let (relayed, verified) = time::timeout(STEP_LIMIT, both).await.map_err(|_| "pong did not finish in time")??;
        assert_eq!(relayed, verified, "the sides disagree on what comes next");
        Ok(verified)
    }
}

/// A modified relay which holds a WebSocket connection and checks nothing
/// of what the provider sends: it proves a turn as soon as its reading of
/// the response comes to any conclusion, good or bad.
struct Credulous {
    live: LiveRelay,
    inbox: Inbox,
}

impl Credulous {
    async fn open(handle: &mut SessionHandle, job: &Job, offer: &Offer) -> Result<Self> {
        let (request, hidden) = ws::upgrade(job, offer, TOKEN.as_bytes(), WS_KEY)?;
        let mut live = LiveRelay::open(handle, &job.host, Roots::Fixture).await?;
        live.send(&request).await?;
        let mut response = Vec::new();
        let head_end = loop {
            response.extend(live.read().await?);
            if let Some(at) = response.windows(HEAD_END.len()).position(|window| window == HEAD_END) {
                break at + HEAD_END.len();
            }
        };
        let mut inbox = Inbox::default();
        inbox.push(&response[head_end..])?;
        live.prove(handle, &[hidden]).await?;
        Ok(Self { live, inbox })
    }

    /// Sends `frame` and proves everything up to the point at which the
    /// response looked complete or looked wrong.
    async fn turn(&mut self, handle: &mut SessionHandle, frame: &[u8]) -> Result<()> {
        let asked = Asked::default();
        self.live.send(frame).await?;
        while let Ok(false) = self.inbox.can_progress(&asked) {
            let received = self.live.read().await?;
            self.inbox.push(&received)?;
        }
        let snapshot = self.live.snapshot().await?;
        self.inbox.push(&self.live.take_arrived())?;
        let _ = self.inbox.take_turn(&asked);
        self.live.prove_snapshot(handle, snapshot, &[], &Misproof::default()).await
    }
}

/// The last event of a turn, as JSON.
fn last_event(messages: &[Message]) -> Value {
    serde_json::from_str(messages.last().unwrap().to_text().unwrap()).unwrap()
}

/// Turns on one WebSocket connection are each proven, the second continues
/// the first's response, and its proof costs what its own frame costs.
#[tokio::test(flavor = "multi_thread")]
async fn websocket_turns_are_proven_and_continue_a_response() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(None).await;

    let before = sides.traffic.read();
    let first = sides.ws_turn(&mut relay, &mut verifier, &ws_request(json!({"input": "p".repeat(20_000)}))).await.unwrap();
    let first_upload = sides.traffic.read() - before;
    let id = ws::completed_response(&first).unwrap();

    let before = sides.traffic.read();
    let second = sides.ws_turn(&mut relay, &mut verifier, &ws_request(json!({"previous_response_id": id}))).await.unwrap();
    let second_upload = sides.traffic.read() - before;

    let completed = last_event(&second);
    assert_eq!(completed["type"], "response.completed");
    assert_eq!(completed["response"]["previous_response_id"], id);
    assert_eq!(completed["response"]["store"], false);
    assert!(second_upload < first_upload / 4, "{first_upload} then {second_upload}");
}

/// The relay sends nothing for a message its policy does not allow.
#[tokio::test(flavor = "multi_thread")]
async fn relay_refuses_websocket_messages_outside_policy() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(None).await;
    let (mut other_relay, mut other_verifier) = sides.open_ws(None).await;
    let elsewhere = sides.ws_turn(&mut other_relay, &mut other_verifier, &ws_request(json!({}))).await.unwrap();
    let elsewhere = ws::completed_response(&elsewhere).unwrap();

    let unstated = json!({"type": "response.create", "model": "test-model", "input": "list"});
    let unmasked = {
        let mut frame = ws_request(json!({}));
        frame[1] &= 0x7f;
        frame
    };
    let refused = [
        (ws_request(json!({"store": true})), "does not disable storage"),
        (ws::text_frame(&unstated.to_string(), [1, 2, 3, 4]), "does not disable storage"),
        (ws_request(json!({"type": "response.cancel"})), "not a request for a response"),
        (ws_request(json!({"metadata": {}})), "field not allowed"),
        (ws_request(json!({"previous_response_id": elsewhere})), UNKNOWN_RESPONSE),
        (unmasked, "not exactly one masked frame"),
    ];
    let sent = relay.sent();
    for (frame, reason) in refused {
        let refusal = relay.turn(&mut sides.relay_handle, &frame).await.unwrap().unwrap_err();
        assert!(refusal.contains(reason), "{refusal}");
    }
    assert_eq!(relay.sent(), sent);

    sides.ws_turn(&mut relay, &mut verifier, &ws_request(json!({}))).await.unwrap();
}

/// The relay answers a ping only with the pong the gateway orders, once,
/// and proves it: everything it sent is the request and that pong.
#[tokio::test(flavor = "multi_thread")]
async fn pings_are_answered_only_as_the_gateway_orders() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(Some(PING)).await;

    for turn in 1..=2 {
        let sent = relay.sent();
        let frame = ws_request(json!({}));
        let messages = sides.ws_turn(&mut relay, &mut verifier, &frame).await.unwrap();
        assert_eq!(last_event(&messages)["type"], "response.completed");

        let unasked = ws::pong_frame(b"never pinged", PONG_MASK);
        assert!(relay.pong(&mut sides.relay_handle, &unasked).await.unwrap().is_err());

        // The ping may have arrived with the response it preceded.
        let pong = ws::pong_frame(b"spike", PONG_MASK);
        if sides.pongs < turn {
            assert_eq!(sides.ws_pong(&mut relay, &mut verifier, &pong).await, Ok(None));
            sides.pongs += 1;
        }
        assert_eq!(relay.sent(), sent + frame.len() + pong.len());
        assert!(relay.pong(&mut sides.relay_handle, &pong).await.unwrap().is_err());
        assert_eq!(relay.sent(), sent + frame.len() + pong.len());
    }
}

/// A provider which sends nothing more of a response until its ping is
/// answered gets the pong the gateway orders while the response is in
/// flight, and the turn then completes.
#[tokio::test(flavor = "multi_thread")]
async fn ping_during_a_response_is_answered_before_it_ends() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(Some(PING_GATED)).await;

    for turn in 1..=2 {
        let sent = relay.sent();
        let frame = ws_request(json!({}));
        let messages = sides.ws_turn(&mut relay, &mut verifier, &frame).await.unwrap();
        assert_eq!(last_event(&messages)["type"], "response.completed");
        assert_eq!(sides.pongs, turn);
        assert_eq!(relay.sent(), sent + frame.len() + ws::pong_frame(b"gate", PONG_MASK).len());
    }
}

/// A response id which the provider can not continue passes the relay,
/// whose record of ids is not authentication, and gets an error from the
/// provider.
#[tokio::test(flavor = "multi_thread")]
async fn relay_record_of_response_ids_authenticates_nothing() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(Some(FORGED_ID)).await;

    let first = sides.ws_turn(&mut relay, &mut verifier, &ws_request(json!({}))).await.unwrap();
    assert_eq!(ws::completed_response(&first).as_deref(), Some(FORGED_RESPONSE));

    let frame = ws_request(json!({"previous_response_id": FORGED_RESPONSE}));
    let second = sides.ws_turn(&mut relay, &mut verifier, &frame).await.unwrap();
    assert_eq!(last_event(&second)["type"], "error");
}

/// A provider which drops the connection mid-response ends the turn
/// without a response, and the relay does not answer the close.
#[tokio::test(flavor = "multi_thread")]
async fn provider_drop_mid_response_yields_no_response() {
    let mut sides = Sides::new().await;
    let (mut relay, mut verifier) = sides.open_ws(Some(CLOSE)).await;

    let sent = relay.sent();
    let frame = ws_request(json!({}));
    sides.ws_turn(&mut relay, &mut verifier, &frame).await.unwrap_err();
    assert_eq!(relay.sent(), sent + frame.len());
}

/// The verifier, given a valid proof by a relay which checks nothing,
/// refuses a response which does not belong to the turn or did not end.
#[tokio::test(flavor = "multi_thread")]
async fn verifier_refuses_responses_which_are_not_the_turns() {
    let at_once = [
        (CLOSE_HELD, "closed before the response ended"),
        (MIXED_ID, "belongs to another response"),
        (WRONG_PARENT, "does not continue the one asked for"),
    ];
    for (misbehaviour, reason) in at_once {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = sides.open_credulous(misbehaviour).await;
        let refusal = sides.ws_turn_unchecked(&mut relay, &mut verifier, &ws_request(json!({}))).await.unwrap_err();
        assert!(refusal.contains(reason), "{misbehaviour}: {refusal}");
    }

    // What arrives after one response ended is refused with the next turn.
    for misbehaviour in [DUPLICATE_END, STALE_EVENT] {
        let mut sides = Sides::new().await;
        let (mut relay, mut verifier) = sides.open_credulous(misbehaviour).await;
        sides.ws_turn_unchecked(&mut relay, &mut verifier, &ws_request(json!({}))).await.unwrap();
        time::sleep(Duration::from_millis(100)).await;
        let refusal = sides.ws_turn_unchecked(&mut relay, &mut verifier, &ws_request(json!({}))).await.unwrap_err();
        assert!(refusal.contains("before the request"), "{misbehaviour}: {refusal}");
    }
}

/// The relay itself abandons a connection whose provider misbehaves.
#[tokio::test(flavor = "multi_thread")]
async fn relay_abandons_responses_which_are_not_the_turns() {
    for misbehaviour in [CLOSE_HELD, MIXED_ID, WRONG_PARENT] {
        let mut sides = Sides::new().await;
        let (mut relay, _verifier) = sides.open_ws(Some(misbehaviour)).await;
        let abandoned = time::timeout(STEP_LIMIT, relay.turn(&mut sides.relay_handle, &ws_request(json!({})))).await.unwrap();
        assert!(abandoned.is_err(), "{misbehaviour}");
    }
}

/// The verifier refuses a relay's offer which would add lines of its own to
/// the upgrade request, before anything is sent.
#[tokio::test(flavor = "multi_thread")]
async fn websocket_offer_is_checked_before_the_upgrade() {
    let mut sides = Sides::new().await;
    let injected = vec![("x-account".to_owned(), "a\r\nx-evil: 1".to_owned())];
    let offers = [
        Offer { headers: injected, ..offer() },
        Offer { headers: vec![("x-other".into(), "a".into())], ..offer() },
        Offer { credential: CredentialHeader { name: "cookie".into(), prefix: String::new() }, ..offer() },
    ];
    for offer in offers {
        let opened = WsVerifier::open(
            &mut sides.verifier_handle,
            &ws_job(None),
            &offer,
            &["x-account".to_owned()],
            WS_KEY,
            sides.provider,
            Roots::Fixture,
        )
        .await
        .unwrap();
        assert!(opened.is_err());
    }
}

/// Ways a modified relay departs from an honest one on a single request.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Cheat {
    #[default]
    None,
    /// Send a different body than the one requested.
    AlterBody,
    /// Smuggle an extra header inside the hidden credential bytes, keeping
    /// their length.
    SmuggleHeader,
    /// Complete a different request inside the hidden credential bytes, so
    /// the provider processes [`SUBSTITUTE_BODY`] and discards the rest.
    SubstituteBody,
    /// Hide more of the request than the credential.
    OverRedact,
    /// Run the exchange against a different server name.
    WrongServer,
}

/// How a modified relay handles the proof that every hidden byte is at
/// least `0x20`.
#[derive(Clone, Copy, Debug, Default)]
enum Predicate {
    /// Prove it over all hidden bytes.
    #[default]
    Full,
    /// Do not prove it.
    Omit,
    /// Prove it only over the first `usize` hidden bytes.
    Shrink(usize),
    /// Prove it over revealed bytes of the same length elsewhere.
    Move,
}

/// The header a [`Cheat::SmuggleHeader`] relay injects.
const SMUGGLED: &str = "\r\nx-evil: 1";

/// The body a [`Cheat::SubstituteBody`] relay has the provider process.
const SUBSTITUTE_BODY: &str = r#"{"model":"attacker-model","stream":true,"input":"attacker prompt"}"#;

/// Rejection because the proof found a hidden byte below `0x20`.
const CONTROL_CHARACTER: &str = "contains a byte below 0x20";

/// Rejection because the relay did not offer the proof over the hidden
/// bytes.
const NOT_PROVEN: &str = "not proven to be at least 0x20";

/// The bytes a [`Cheat::SubstituteBody`] relay puts where the credential
/// belongs: the credential, then the rest of a complete request.
fn substitution() -> Vec<u8> {
    format!(
        "{TOKEN}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{SUBSTITUTE_BODY}",
        SUBSTITUTE_BODY.len()
    )
    .into_bytes()
}

/// Performs the jobs ordered on a link as a relay modified by `cheat` and
/// `predicate` would.
async fn modified_relay(control: TcpStream, proofs: TcpStream, cheat: Cheat, predicate: Predicate) -> Result<()> {
    let (driver, mut handle) = Session::new(proofs.compat()).split();
    tokio::spawn(driver);
    let (orders, mut notices) = io::split(control);
    let mut orders = pin!(link::incoming::<_, Order>(orders));
    while let Some(Ok(Order::Job(mut job))) = orders.next().await {
        let mut credential = TOKEN.as_bytes().to_vec();
        match cheat {
            Cheat::AlterBody => job.body.push(b' '),
            Cheat::SmuggleHeader => {
                credential.truncate(credential.len() - SMUGGLED.len());
                credential.extend_from_slice(SMUGGLED.as_bytes());
            }
            Cheat::SubstituteBody => credential = substitution(),
            _ => {}
        }
        let offer = Offer { credential: CredentialHeader::bearer(), hidden_len: credential.len(), headers: Vec::new() };
        wire::send(&mut notices, &Notice::Offer(offer.clone())).await?;
        let (request, mut hidden) = wire::encode_request(&job, &offer, &credential);
        if cheat == Cheat::OverRedact {
            hidden.end += 16;
        }
        let server = if cheat == Cheat::WrongServer { "evil.example" } else { job.host.as_str() };

        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(ProxyTlsConfig::builder().server_name(DnsName::try_from(server)?).build()?)
            .await?;
        let (mut tls, prover) = prover.connect(
            TlsClientConfig::builder().server_name(ServerName::Dns(server.try_into()?)).root_store(Roots::Fixture.store()).build()?,
        )?;
        let prover = tokio::spawn(prover.into_future());
        tls.write_all(&request).await?;
        tls.flush().await?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;
        drop(tls);
        let mut prover = prover.await??;

        let sent = prover.transcript().sent().len();
        let mut proof = ProveConfig::builder(prover.transcript());
        proof.server_identity();
        proof.reveal_sent(&(0..hidden.start))?;
        proof.reveal_sent(&(hidden.end..sent))?;
        let checked = match predicate {
            Predicate::Full => Some(hidden.clone()),
            Predicate::Omit => None,
            Predicate::Shrink(len) => Some(hidden.start..hidden.start + len),
            Predicate::Move => Some(hidden.end + 2..hidden.end + 2 + hidden.len()),
        };
        if let Some(checked) = checked {
            proof.prove_no_control(Direction::Sent, checked)?;
        }
        proof.reveal_recv_all()?;
        prover.prove(&proof.build()?).await?;
        prover.close().await?;
    }
    Ok(())
}

/// Has a relay modified by `cheat` and `predicate` perform `job` against a
/// provider which is `lenient` about the credential's length or not.
/// Returns the verifier's verdict, and the link if it may be used again.
async fn cheated(job: &Job, cheat: Cheat, predicate: Predicate, lenient: bool) -> (Result<Verdict>, Option<Link<TcpStream>>) {
    let expect = Expect { provider: common::provider(lenient).await, roots: Roots::Fixture, relay_headers: Vec::new() };
    let (relay_control, control) = common::pair().await;
    let (relay_proofs, proofs) = common::pair().await;
    tokio::spawn(modified_relay(relay_control, relay_proofs, cheat, predicate));
    time::timeout(STEP_LIMIT, Link::new(control, proofs).exchange(job, &expect)).await.expect("exchange ends in time")
}

/// The relay the tests below modify is verified when it departs in
/// nothing, so what they reject is rejected for its departure.
#[tokio::test(flavor = "multi_thread")]
async fn unmodified_relay_is_verified() {
    let (verdict, link) = cheated(&common::job(1024, 1024), Cheat::None, Predicate::Full, false).await;
    assert_matches!(verdict, Ok(Verdict::Verified(response)) if response.status == 200);
    assert!(link.is_some());
}

/// A request other than the one ordered, a request hidden beyond its
/// credential, and an exchange with another server are each rejected, and
/// the link is not used again.
#[tokio::test(flavor = "multi_thread")]
async fn altered_over_redacted_and_misdirected_requests_are_rejected() {
    for cheat in [Cheat::AlterBody, Cheat::OverRedact, Cheat::WrongServer] {
        let (verdict, link) = cheated(&common::job(1024, 1024), cheat, Predicate::Full, false).await;
        assert_matches!(verdict, Ok(Verdict::Rejected(_)), "{cheat:?}");
        assert!(link.is_none(), "{cheat:?}");
    }
}

/// A header smuggled into the hidden bytes needs a line break, which the
/// proof that every hidden byte is at least `0x20` rules out whatever the
/// provider would accept.
#[tokio::test(flavor = "multi_thread")]
async fn smuggled_header_is_rejected() {
    for lenient in [false, true] {
        let (verdict, _) = cheated(&common::job(1024, 1024), Cheat::SmuggleHeader, Predicate::Full, lenient).await;
        assert_matches!(verdict, Ok(Verdict::Rejected(reason)) if reason.contains(CONTROL_CHARACTER), "lenient={lenient}");
    }
}

/// A relay which completes a different request inside the hidden bytes,
/// so that the provider would process another body, is rejected by the
/// proof over them.
#[tokio::test(flavor = "multi_thread")]
async fn body_substituted_in_hidden_bytes_is_rejected() {
    let (verdict, link) = cheated(&common::job(1024, 1024), Cheat::SubstituteBody, Predicate::Full, false).await;
    assert_matches!(verdict, Ok(Verdict::Rejected(reason)) if reason.contains(CONTROL_CHARACTER));
    assert!(link.is_none());
}

/// The proof must cover exactly the hidden bytes: a relay can not leave it
/// out, limit it to the credential, or point it at other bytes. An honest
/// relay which leaves it out is rejected too.
#[tokio::test(flavor = "multi_thread")]
async fn missing_or_misplaced_proof_over_the_hidden_bytes_is_rejected() {
    for predicate in [Predicate::Omit, Predicate::Shrink(TOKEN.len()), Predicate::Move] {
        let (verdict, _) = cheated(&common::job(1024, 1024), Cheat::SubstituteBody, predicate, false).await;
        assert_matches!(verdict, Ok(Verdict::Rejected(reason)) if reason.contains(NOT_PROVEN), "{predicate:?}");
    }
    let (verdict, _) = cheated(&common::job(1024, 1024), Cheat::None, Predicate::Omit, false).await;
    assert_matches!(verdict, Ok(Verdict::Rejected(reason)) if reason.contains(NOT_PROVEN));
}
