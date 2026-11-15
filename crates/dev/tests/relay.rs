//! A relay registers with a verifier, opens links to it and performs
//! proven exchanges with a mock provider.

use std::{assert_matches, env, fs, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;

use concurro_relay::{
    credentials::{Credential, Source},
    events::{Event, LinkState},
    link::{self, Relay},
    login,
    policy::Policy,
    routes::Served,
    serve::RelayConfig,
    state::Store,
    transport::Server,
};
use concurro_relay_dev::{
    gateway::Gateway,
    provider::{self, MISBEHAVE_HEADER, PING_GATED, PING_IDLE, ProviderConfig, RESPONSE_BYTES_HEADER},
    registry::DevRegistry,
    tls,
};
use concurro_relay_protocol::{
    Roots,
    identity::Identity,
    link::{Hello, PROTOCOL_VERSION, Role, present},
    route::Route,
    wire::{CredentialHeader, Job},
    ws::FINAL_EVENTS,
};
use futures::{SinkExt, StreamExt};
use concurro_relay_verifier::{
    accept::{self, Acceptor},
    exchange::{Expect, Verdict},
};
use serde_json::{Value, json};
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, UnboundedReceiver},
    task::JoinHandle,
    time,
};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const TOKEN: &str = "sk-test-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PATH: &str = "/v1/responses";

/// Longest any step of a test may take before it counts as stuck.
const STEP_LIMIT: Duration = Duration::from_secs(30);

/// A verifier with a gateway, a mock provider behind it, and where a relay
/// reaches it.
struct Verifier {
    gateway: Arc<Gateway>,
    registry: Arc<DevRegistry>,
    server: Server,
    store: Store,
}

impl Verifier {
    async fn new(name: &str) -> Self {
        let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let expect = Expect { provider: provider.local_addr().unwrap(), roots: Roots::Fixture, relay_headers: Vec::new() };
        tokio::spawn(provider::serve(provider, ProviderConfig { token: TOKEN.into(), lenient: false }));

        let directory: PathBuf = env::temp_dir().join(format!("concurro-relay-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let (tls, certificate) = tls::self_signed(vec!["localhost".into()]).unwrap();
        let ca_file = directory.join("verifier.pem");
        fs::write(&ca_file, certificate).unwrap();

        let registry = Arc::new(DevRegistry::new("octocat".into(), Duration::ZERO, Some(directory.join("relays.json"))).unwrap());
        let (ready, accepted) = mpsc::unbounded_channel();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("localhost:{}", listener.local_addr().unwrap().port());
        tokio::spawn(accept::serve(listener, tls, Arc::new(Acceptor::new(registry.clone(), ready))));

        Self {
            gateway: Gateway::new(Route::ChatgptSubscription, expect, false, accepted),
            registry,
            server: Server { address, ca_file: Some(ca_file) },
            store: Store::open(Some(directory.join("relay"))).unwrap(),
        }
    }

    /// Registers a relay and starts it with one link, returning what it
    /// reports.
    async fn relay(&self) -> UnboundedReceiver<Event> {
        let pending = login::begin(self.server.clone(), "test relay".into(), vec![Route::ChatgptSubscription]).await.unwrap();
        let registration = time::timeout(STEP_LIMIT, pending.approved(&self.store)).await.unwrap().unwrap();
        assert_eq!(registration.login, "octocat");
        let (registration, identity) = self.store.load().unwrap().unwrap();
        let (events, reported) = mpsc::unbounded_channel();
        tokio::spawn(link::run(Arc::new(Relay { registration, identity, config: config() }), 1, events));
        reported
    }
}

/// A relay's configuration for the mock provider.
fn config() -> RelayConfig {
    let policy = Policy {
        host: SERVER_DOMAIN.into(),
        paths: vec![PATH.into()],
        headers: vec![RESPONSE_BYTES_HEADER.into()],
        body_fields: ["model", "stream", "input"].map(Into::into).to_vec(),
    };
    let websocket = Policy {
        host: SERVER_DOMAIN.into(),
        paths: vec![PATH.into()],
        headers: vec![RESPONSE_BYTES_HEADER.into(), MISBEHAVE_HEADER.into()],
        body_fields: ["type", "model", "store", "input", "previous_response_id"].map(Into::into).to_vec(),
    };
    let served = Served { route: Route::ChatgptSubscription, policy, websocket: Some(websocket), credential_header: CredentialHeader::bearer() };
    RelayConfig {
        served: vec![served],
        credentials: Source::Fixed(Credential::token(TOKEN)),
        roots: Roots::Fixture,
        parents: Default::default(),
    }
}

/// A harness's WebSocket connection which a relay is carrying, and how
/// carrying it ends.
struct Carried {
    harness: WebSocketStream<TcpStream>,
    carrying: JoinHandle<Result<()>>,
}

impl Verifier {
    /// Has the gateway's relay carry a new connection of a harness to a
    /// provider which misbehaves as named.
    async fn carry(&self, misbehaviour: Option<&str>) -> Carried {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (far, _) = listener.accept().await.unwrap();
        let (harness, accepted) =
            tokio::join!(tokio_tungstenite::client_async("ws://gateway/v1/responses", near), tokio_tungstenite::accept_async(far));
        let mut accepted = accepted.unwrap();
        let mut headers = vec![(RESPONSE_BYTES_HEADER.to_owned(), "2048".to_owned())];
        headers.extend(misbehaviour.map(|kind| (MISBEHAVE_HEADER.to_owned(), kind.to_owned())));
        let job = Job { host: SERVER_DOMAIN.into(), path: PATH.into(), headers, body: Vec::new() };
        let gateway = self.gateway.clone();
        let carrying = tokio::spawn(async move { gateway.carry(&mut accepted, &job, "test").await });
        Carried { harness: harness.unwrap().0, carrying }
    }
}

impl Carried {
    /// Sends a request as the harness and returns the event which ends
    /// its response.
    async fn ask(&mut self, fields: Value) -> Value {
        let mut request = json!({"type": "response.create", "model": "test-model", "store": false, "input": "list"});
        request.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
        self.harness.send(Message::text(request.to_string())).await.unwrap();
        loop {
            let message = time::timeout(STEP_LIMIT, self.harness.next()).await.expect("turn finishes in time");
            let event: Value = serde_json::from_str(message.unwrap().unwrap().to_text().unwrap()).unwrap();
            if FINAL_EVENTS.contains(&event["type"].as_str().unwrap()) {
                return event;
            }
        }
    }

    /// Closes the harness's connection and returns how carrying it ended.
    async fn close(mut self) -> Result<()> {
        self.harness.close(None).await.unwrap();
        time::timeout(STEP_LIMIT, self.carrying).await.expect("connection closes in time").unwrap()
    }
}

fn job(fields: serde_json::Value) -> Job {
    let mut body = json!({"model": "test-model", "stream": true, "input": "list"});
    body.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
    Job {
        host: SERVER_DOMAIN.into(),
        path: PATH.into(),
        headers: vec![(RESPONSE_BYTES_HEADER.into(), "2048".into())],
        body: body.to_string().into_bytes(),
    }
}

async fn next(reported: &mut UnboundedReceiver<Event>) -> Event {
    time::timeout(STEP_LIMIT, reported.recv()).await.expect("the relay reports in time").expect("the relay is running")
}

/// A registered relay performs the jobs a gateway orders on one link,
/// refusing what its policy does not allow, and reports each.
#[tokio::test(flavor = "multi_thread")]
async fn registered_relay_performs_and_proves_exchanges() {
    let verifier = Verifier::new("exchanges").await;
    let mut reported = verifier.relay().await;
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Up });

    for _ in 0..2 {
        let performed = time::timeout(STEP_LIMIT, verifier.gateway.perform(&job(json!({})))).await.unwrap().unwrap();
        let Verdict::Verified(response) = performed.verdict else { panic!("exchange was not verified") };
        assert_eq!(response.status, 200);
        assert!(performed.upload > 0);
        let Event::Proved { link: 1, exchange } = next(&mut reported).await else { panic!("exchange was not reported") };
        assert_eq!((exchange.route, exchange.model.as_deref()), (Route::ChatgptSubscription, Some("test-model")));
        assert!(exchange.received > 2048 && exchange.upload > 0);
    }

    let performed = verifier.gateway.perform(&job(json!({"tools": []}))).await.unwrap();
    let Verdict::Refused(reason) = performed.verdict else { panic!("job was not refused") };
    assert_eq!(next(&mut reported).await, Event::Refused { link: 1, reason });

    // The refusal left the link usable.
    let performed = time::timeout(STEP_LIMIT, verifier.gateway.perform(&job(json!({})))).await.unwrap().unwrap();
    assert_matches!(performed.verdict, Verdict::Verified(_));
}

/// A verifier refuses a relay it does not know, a key which is not the
/// registered one, and another protocol version, and a relay stops trying.
#[tokio::test(flavor = "multi_thread")]
async fn verifier_refuses_relays_it_should_not_serve() {
    let verifier = Verifier::new("refusals").await;
    let mut reported = verifier.relay().await;
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Up });
    let (registration, _) = verifier.store.load().unwrap().unwrap();

    // The registered relay's name with another key.
    let (impostor, _) = Identity::generate().unwrap();
    let (events, mut impostor_reported) = mpsc::unbounded_channel();
    let relay = Relay { registration: registration.clone(), identity: impostor, config: config() };
    tokio::spawn(link::run(Arc::new(relay), 1, events));
    assert_eq!(next(&mut impostor_reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_matches!(next(&mut impostor_reported).await, Event::Link { state: LinkState::Refused(_), .. });
    assert!(time::timeout(STEP_LIMIT, impostor_reported.recv()).await.unwrap().is_none(), "a refused relay stops");

    let (_, identity) = verifier.store.load().unwrap().unwrap();
    let hello = |version, relay: &str| Hello::Link { version, relay: relay.into(), link: 9, role: Role::Control };
    let mut connection = verifier.server.connect().await.unwrap();
    let outdated = present(&mut connection, &hello(PROTOCOL_VERSION + 1, &registration.relay), &identity).await.unwrap_err();
    assert!(outdated.to_string().contains("update concurro-relay"), "{outdated}");
    let mut connection = verifier.server.connect().await.unwrap();
    assert!(present(&mut connection, &hello(PROTOCOL_VERSION, "relay-unknown"), &identity).await.is_err());
}

/// Signing out withdraws the registration and removes the relay's state.
#[tokio::test(flavor = "multi_thread")]
async fn logout_withdraws_the_registration() {
    let verifier = Verifier::new("logout").await;
    let mut reported = verifier.relay().await;
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_eq!(verifier.registry.registered(), 1);

    // A verifier which is started again still knows the relay.
    let kept = env::temp_dir().join(format!("concurro-relay-test-{}-logout/relays.json", std::process::id()));
    assert_eq!(DevRegistry::new("octocat".into(), Duration::ZERO, Some(kept.clone())).unwrap().registered(), 1);

    assert!(login::logout(&verifier.store).await.unwrap());
    assert_eq!(verifier.registry.registered(), 0);
    assert_eq!(DevRegistry::new("octocat".into(), Duration::ZERO, Some(kept)).unwrap().registered(), 0);
    assert!(verifier.store.load().unwrap().is_none());
    assert!(!login::logout(&verifier.store).await.unwrap());
}

/// A relay carries a harness's WebSocket turns on a link, reports each,
/// tells the harness at once of a request it refuses, and serves a second
/// connection and a single request on the same link afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn relay_carries_websocket_turns_and_reports_refusals() {
    let verifier = Verifier::new("websocket").await;
    let mut reported = verifier.relay().await;
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Up });

    let mut carried = verifier.carry(None).await;
    let first = carried.ask(json!({"input": "first question"})).await;
    assert_eq!(first["type"], "response.completed");
    let Event::Proved { exchange, .. } = next(&mut reported).await else { panic!("turn was not reported") };
    assert_eq!((exchange.route, exchange.model.as_deref()), (Route::ChatgptSubscription, Some("test-model")));
    assert!(exchange.request.contains("first question") && exchange.response.contains("response.completed"));
    assert!(exchange.received > 2048 && exchange.upload > 0);

    let refused = carried.ask(json!({"store": true})).await;
    assert_eq!(refused["type"], "error");
    assert!(refused["error"]["code"].is_null());
    assert_matches!(next(&mut reported).await, Event::Refused { .. });
    let unknown = carried.ask(json!({"previous_response_id": "resp_elsewhere"})).await;
    assert_eq!(unknown["error"]["code"], "previous_response_not_found");
    assert_matches!(next(&mut reported).await, Event::Refused { .. });

    let second = carried.ask(json!({"previous_response_id": first["response"]["id"]})).await;
    assert_eq!(second["response"]["previous_response_id"], first["response"]["id"]);
    assert_matches!(next(&mut reported).await, Event::Proved { .. });
    carried.close().await.unwrap();

    // A response of the first connection is unknown on the second.
    let mut carried = verifier.carry(None).await;
    assert_eq!(carried.ask(json!({})).await["type"], "response.completed");
    let crossed = carried.ask(json!({"previous_response_id": first["response"]["id"]})).await;
    assert_eq!(crossed["error"]["code"], "previous_response_not_found");
    carried.close().await.unwrap();

    let performed = time::timeout(STEP_LIMIT, verifier.gateway.perform(&job(json!({})))).await.unwrap().unwrap();
    assert_matches!(performed.verdict, Verdict::Verified(_));
}

/// Pings from the provider are answered as the gateway orders: one which
/// arrives between turns without waiting for the next turn, and one which
/// interrupts a response before it ends.
#[tokio::test(flavor = "multi_thread")]
async fn relay_answers_pings_between_turns_and_during_a_response() {
    let verifier = Verifier::new("pings").await;
    let _reported = verifier.relay().await;

    let mut carried = verifier.carry(Some(PING_IDLE)).await;
    for _ in 0..3 {
        assert_eq!(carried.ask(json!({})).await["type"], "response.completed");
        // The provider drops the connection if the next request arrives
        // before the pong.
        time::sleep(Duration::from_secs(1)).await;
    }
    carried.close().await.unwrap();

    let mut carried = verifier.carry(Some(PING_GATED)).await;
    for _ in 0..2 {
        assert_eq!(carried.ask(json!({})).await["type"], "response.completed");
    }
    carried.close().await.unwrap();
}

/// A provider which refuses the upgrade ends the connection at once, with
/// the status it gave.
#[tokio::test(flavor = "multi_thread")]
async fn refused_upgrade_is_reported_with_its_status() {
    let verifier = Verifier::new("upgrade").await;
    let pending = login::begin(verifier.server.clone(), "test relay".into(), vec![Route::ChatgptSubscription]).await.unwrap();
    pending.approved(&verifier.store).await.unwrap();
    let (registration, identity) = verifier.store.load().unwrap().unwrap();
    let wrong = RelayConfig { credentials: Source::Fixed(Credential::token(&TOKEN.replace('s', "x"))), ..config() };
    let (events, _reported) = mpsc::unbounded_channel();
    tokio::spawn(link::run(Arc::new(Relay { registration, identity, config: wrong }), 1, events));

    let carried = verifier.carry(None).await;
    let ended = time::timeout(STEP_LIMIT, carried.carrying).await.expect("refusal is reported in time").unwrap();
    assert!(format!("{:#}", ended.unwrap_err()).contains("401"));
}

/// A harness's WebSocket upgrade on the gateway's listener reaches a relay.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_listener_accepts_a_websocket_upgrade() {
    let verifier = Verifier::new("listener").await;
    let mut reported = verifier.relay().await;
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Connecting });
    assert_eq!(next(&mut reported).await, Event::Link { link: 1, state: LinkState::Up });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(verifier.gateway.clone().serve(listener));
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut harness, accepted) = tokio_tungstenite::client_async(format!("ws://{address}/v1/responses"), stream).await.unwrap();
    assert_eq!(accepted.status(), 101);

    // The gateway asks for its route's own host, which this relay, set up
    // for the mock provider, does not serve.
    let Event::Refused { reason, .. } = next(&mut reported).await else { panic!("connection was not refused") };
    assert!(reason.contains("host not served"), "{reason}");
    let closed = time::timeout(STEP_LIMIT, harness.next()).await.expect("the gateway closes the connection");
    assert_matches!(closed, Some(Ok(Message::Close(_))));
}
