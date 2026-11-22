//! Private listener acceptance tests with disposable registries and native ingress fixtures.

use std::{path::Path, time::Duration};

use concurro_relay_hosted_api::{
    claim::{self, SessionClaim},
    dispatch::{
        ALLOWANCE_SPENT_CODE, CHATGPT_SUBSCRIPTION, CLAIM_HEADER, CLAIM_REFUSED_CODE,
        CLAUDE_SUBSCRIPTION, MESSAGES_PATH, REQUEST_HEADER, REQUEST_REUSED_CODE, RESPONSES_PATH,
    },
    owner::{self, APPROVALS_PATH, REGISTRATIONS_PREFIX, RELAYS_PATH},
    release::{CLAIMS_PREFIX, ReleaseClaim},
};
use concurro_relay_protocol::{
    identity::{self, Identity},
    link::{self, Answer, DeviceCode, Hello, PROTOCOL_VERSION, Registration, Role},
    route::Route,
};
use concurro_relay_verifier::accept::Registry;
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Frame, Incoming},
    client::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    io,
    sync::{oneshot, watch},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::Message;

use super::*;

const OWNER: &str = "owner-token";
const INFERENCE: &str = "inference-token";
const RELEASE: &str = "release-token";
const KID: &str = "exchange-key";
const MODEL: &str = "fixture-model";

const REQUIRED_ARGS: &[&str] = &[
    "hosted",
    "--certificate=unused",
    "--private-key=unused",
    "--registry=unused",
    "--owner-token=unused",
    "--inference-token=unused",
    "--release-token=unused",
    "--exchange-public-keys=unused",
    "--verification-url=https://example.test/credentials/relay",
];

/// An isolated verifier with real HTTP endpoints and a replaceable process state.
struct Fixture {
    dir: PathBuf,
    app: Arc<App>,
    key: Vec<u8>,
}

impl Fixture {
    /// Create the verifier with three distinct temporary bearer files.
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "hosted-claims-{}",
            hex::encode(identity::random::<8>())
        ));
        fs::create_dir(&dir).unwrap();
        let (identity, key) = Identity::generate().unwrap();
        let keys = VerificationKeys::new([(KID.into(), identity.public_key().try_into().unwrap())])
            .unwrap();
        for token in [OWNER, INFERENCE, RELEASE] {
            fs::write(dir.join(token), token).unwrap();
        }
        let app = Self::open(&dir, keys);
        Self { dir, app, key }
    }

    /// Reopen registry and journal without retaining any live links or prior memory.
    fn open(dir: &Path, keys: VerificationKeys) -> Arc<App> {
        let mut args = Args::parse_from(REQUIRED_ARGS);
        args.started = clock();
        Arc::new(App {
            args: Arc::new(args),
            credentials: Credentials::read(
                &dir.join(OWNER),
                &dir.join(INFERENCE),
                &dir.join(RELEASE),
            )
            .unwrap(),
            keys,
            registry: Arc::new(HostedRegistry::open(dir.join("relays.json"), None).unwrap()),
            pool: Pool::shared(clock),
            journal: Mutex::new(Journal::open(dir.join("claims.jsonl"), now()).unwrap()),
        })
    }

    /// Use a fresh verifier instance over the same files.
    fn restart(&mut self) {
        let identity = Identity::from_pkcs8(&self.key).unwrap();
        let keys = VerificationKeys::new([(KID.into(), identity.public_key().try_into().unwrap())])
            .unwrap();
        self.app = Self::open(&self.dir, keys);
    }

    /// Persist one approved binding for a native ingress fixture.
    fn approved_claim(&self, route: Route) -> SessionClaim {
        let code = self
            .app
            .registry
            .register(Registration {
                version: PROTOCOL_VERSION,
                name: "fixture Sponsor".into(),
                public_key: vec![1; 32],
                routes: vec![route],
            })
            .unwrap();
        let route = match route {
            Route::ClaudeSubscription => CLAUDE_SUBSCRIPTION,
            Route::ChatgptSubscription => CHATGPT_SUBSCRIPTION,
        };
        let approval = approval(&code, route);
        let relay_id = self.app.registry.approve(approval).unwrap();
        SessionClaim {
            jti: format!("claim-{}", route),
            iss: claim::ISSUER.into(),
            sub: format!("session-{}", route),
            iat: now(),
            exp: now() + 120,
            relay_id,
            user_id: 7,
            entry_id: "1".repeat(32),
            record_id: "2".repeat(64),
            version: 1,
            route: route.into(),
            models: vec![MODEL.into()],
            calls: 3,
            tokens: 10,
            repository: "fixture/example".into(),
            issue: 20,
        }
    }

    /// Send one signed dispatch while holding the lifetime of the HTTP client.
    async fn dispatch(&self, claim: &SessionClaim, request: &str) -> Response<Incoming> {
        let path = if claim.route == CLAUDE_SUBSCRIPTION {
            MESSAGES_PATH
        } else {
            RESPONSES_PATH
        };
        let signed = claim::sign(claim, KID, &self.key).unwrap();
        self.call(dispatch_request(path, &signed, request, MODEL))
            .await
    }

    /// Connect through Hyper's client to the real private listener implementation.
    async fn call(&self, request: Request<Full<Bytes>>) -> Response<Incoming> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = self.app.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Err(error) = private::serve(stream, app).await {
                assert!(
                    error
                        .downcast_ref::<hyper::Error>()
                        .is_some_and(hyper::Error::is_incomplete_message),
                    "{error}"
                );
            }
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut client, connection) = http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(connection);
        tokio::time::timeout(Duration::from_secs(5), client.send_request(request))
            .await
            .unwrap()
            .unwrap()
    }

    /// Supply the native ingress endpoint previously leased by this session.
    async fn retained(
        &self,
        claim: &SessionClaim,
        endpoint: SocketAddr,
    ) -> (watch::Sender<Option<SocketAddr>>, JoinHandle<()>) {
        let (published, address) = watch::channel(Some(endpoint));
        let worker = tokio::spawn(std::future::pending());
        let lease = pool::Lease {
            claim_id: claim.jti.clone(),
            relay: claim.relay_id.clone(),
            slot: (claim.relay_id.clone(), 1),
            number: 17,
            started: clock(),
            task: Some(owner::Task {
                repository: claim.repository.clone(),
                issue: claim.issue,
            }),
            binding: lease::binding(&self.app, claim).unwrap(),
            address,
            abort: worker.abort_handle(),
        };
        self.app
            .pool
            .lock()
            .await
            .leases
            .insert(claim.sub.clone(), lease);
        (published, worker)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

/// Current NumericDate for fixture claims and expiry checks.
fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Pair one owner with a fixture credential binding.
fn approval(code: &DeviceCode, route: &str) -> owner::Approval {
    owner::Approval {
        code: code.user_code.clone(),
        user: owner::User {
            id: 7,
            login: "sponsor".into(),
        },
        bindings: vec![owner::Binding {
            route: route.into(),
            entry_id: "1".repeat(32),
            record_id: "2".repeat(64),
            version: 1,
        }],
    }
}

/// Build a control request with the given caller bearer.
fn request(method: &str, path: &str, token: &str, body: Bytes) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(body))
        .unwrap()
}

/// Build a provider-native request with the two mandatory dispatch headers.
fn dispatch_request(
    path: &str,
    signed: &str,
    request_id: &str,
    model: &str,
) -> Request<Full<Bytes>> {
    let mut request = request(
        "POST",
        path,
        INFERENCE,
        Bytes::from(json!({"model":model,"stream":true}).to_string()),
    );
    request
        .headers_mut()
        .insert(CLAIM_HEADER, signed.parse().unwrap());
    request
        .headers_mut()
        .insert(REQUEST_HEADER, request_id.parse().unwrap());
    request
}

/// Collect a private response's JSON representation.
async fn json_response(response: Response<Incoming>) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

/// Check both the status and the code that clients use for classification.
async fn refused(response: Response<Incoming>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let body = json_response(response).await;
    assert_eq!(body["error"]["code"], code, "{body}");
    assert!(body["error"]["message"].is_string());
}

/// Existing connection and registration limits must remain positive.
#[test]
fn zero_limits_are_refused() {
    assert!(Args::try_parse_from(REQUIRED_ARGS).is_ok());
    for limit in [
        "--handshake-timeout-secs=0",
        "--half-link-timeout-secs=0",
        "--max-pending-connections=0",
        "--pending-registrations=0",
        "--relay-name-max-bytes=0",
    ] {
        assert!(Args::try_parse_from(REQUIRED_ARGS.iter().copied().chain([limit])).is_err());
    }
}

/// Each private path requires its own Authorization bearer and legacy paths are gone.
#[tokio::test]
async fn caller_credentials_do_not_cross_routes() {
    let fixture = Fixture::new();
    for (method, path, expected) in [
        ("GET", "/owner/v1/registrations/unknown", OWNER),
        ("POST", APPROVALS_PATH, OWNER),
        ("GET", "/owner/v1/relays?user_id=7", OWNER),
        ("POST", MESSAGES_PATH, INFERENCE),
        ("POST", RESPONSES_PATH, INFERENCE),
        ("POST", "/release/v1/claims/unseen", RELEASE),
    ] {
        for token in [OWNER, INFERENCE, RELEASE]
            .into_iter()
            .filter(|token| *token != expected)
        {
            refused(
                fixture
                    .call(request(method, path, token, Bytes::new()))
                    .await,
                StatusCode::FORBIDDEN,
                "forbidden",
            )
            .await;
        }
        let mut alias = request(method, path, expected, Bytes::new());
        let bearer = alias.headers_mut().remove("authorization").unwrap();
        alias
            .headers_mut()
            .insert("x-concurro-verifier-auth", bearer);
        refused(
            fixture.call(alias).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        )
        .await;
    }
    for path in [
        "/approve",
        "/pending",
        "/status",
        "/release",
        "/dispatch/v1/messages",
        "/dispatch/v1/responses",
    ] {
        refused(
            fixture
                .call(request("POST", path, INFERENCE, Bytes::new()))
                .await,
            StatusCode::NOT_FOUND,
            "unknown_operation",
        )
        .await;
    }
    for path in [MESSAGES_PATH, RESPONSES_PATH] {
        refused(
            fixture
                .call(request("POST", path, INFERENCE, Bytes::new()))
                .await,
            StatusCode::FORBIDDEN,
            CLAIM_REFUSED_CODE,
        )
        .await;
    }
}

/// Sponsor protocol 5 registration and link proof work through the versioned owner API.
#[tokio::test]
async fn sponsor_registers_and_links_via_owner_api() {
    let mut fixture = Fixture::new();
    let (identity, _) = Identity::generate().unwrap();
    let (accepted, mut links) = mpsc::unbounded_channel();
    let acceptor = Arc::new(Acceptor::new(fixture.app.registry.clone(), accepted));
    let open = || {
        let (client, server) = io::duplex(4096);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            acceptor.accept(server).await.unwrap();
        });
        client
    };
    let mut registration = Registration {
        version: 4,
        name: "test Sponsor".into(),
        public_key: identity.public_key(),
        routes: vec![Route::ClaudeSubscription],
    };
    let outdated = link::greet(&mut open(), &Hello::Register(registration.clone()))
        .await
        .unwrap();
    std::assert_matches!(outdated, Answer::Refused(reason) if reason.contains("update concurro-relay"));
    registration.version = PROTOCOL_VERSION;
    let accepted = link::greet(&mut open(), &Hello::Register(registration))
        .await
        .unwrap();
    let Answer::DeviceCode(code) = accepted else {
        panic!("expected a registration code")
    };
    let path = format!("{REGISTRATIONS_PREFIX}{}", code.user_code);
    let pending = fixture
        .call(request("GET", &path, OWNER, Bytes::new()))
        .await;
    assert_eq!(pending.status(), StatusCode::OK);
    let pending: owner::Registration =
        serde_json::from_value(json_response(pending).await).unwrap();
    assert_eq!(pending.name, "test Sponsor");
    assert_eq!(pending.routes, [CLAUDE_SUBSCRIPTION]);
    assert!(pending.expires_at.unix_timestamp() > now());

    let mut approval = approval(&code, CLAUDE_SUBSCRIPTION);
    let post = |approval: &owner::Approval| {
        request(
            "POST",
            APPROVALS_PATH,
            OWNER,
            serde_json::to_vec(approval).unwrap().into(),
        )
    };
    let first = fixture.call(post(&approval)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first: owner::Approved = serde_json::from_value(json_response(first).await).unwrap();
    let repeat = fixture.call(post(&approval)).await;
    assert_eq!(repeat.status(), StatusCode::OK);
    assert_eq!(json_response(repeat).await["relay_id"], first.relay_id);
    approval.bindings[0].version += 1;
    refused(
        fixture.call(post(&approval)).await,
        StatusCode::CONFLICT,
        "approval_conflict",
    )
    .await;
    refused(
        fixture
            .call(request("GET", &path, OWNER, Bytes::new()))
            .await,
        StatusCode::NOT_FOUND,
        "unknown_registration",
    )
    .await;
    let polled = link::greet(
        &mut open(),
        &Hello::Poll {
            device_code: code.device_code,
        },
    )
    .await
    .unwrap();
    std::assert_matches!(polled, Answer::Registered(registered) if registered.relay == first.relay_id);
    for role in [Role::Control, Role::Proofs] {
        let mut stream = open();
        link::present(
            &mut stream,
            &Hello::Link {
                version: PROTOCOL_VERSION,
                relay: first.relay_id.clone(),
                link: 5,
                slot: 1,
                role,
            },
            &identity,
        )
        .await
        .unwrap();
    }
    assert_eq!(links.recv().await.unwrap().relay, first.relay_id);
    fixture.restart();
    for (user, len) in [(7, 1), (8, 0)] {
        let listed = fixture
            .call(request(
                "GET",
                &format!("{RELAYS_PATH}?user_id={user}"),
                OWNER,
                Bytes::new(),
            ))
            .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: owner::Relays = serde_json::from_value(json_response(listed).await).unwrap();
        assert_eq!(listed.relays.len(), len);
        if let Some(relay) = listed.relays.first() {
            assert_eq!(relay.relay_id, first.relay_id);
            assert_eq!(relay.idle, 0);
            assert!(relay.last_seen.is_none());
        }
        assert!(listed.checked >= listed.started);
    }
}

/// Bad keys, time, binding and model never create a native lease or durable request.
#[tokio::test]
async fn invalid_claims_never_admit_a_call() {
    let fixture = Fixture::new();
    let valid = fixture.approved_claim(Route::ClaudeSubscription);
    let cases: &[fn(&mut SessionClaim)] = &[
        |claim| {
            claim.iat = now() - 20;
            claim.exp = now() - 10;
        },
        |claim| {
            claim.iat = now() + 60;
        },
        |claim| {
            claim.iss = "other".into();
        },
        |claim| {
            claim.relay_id = "different".into();
        },
        |claim| {
            claim.user_id = 999;
        },
        |claim| {
            claim.entry_id = "different".into();
        },
        |claim| {
            claim.record_id = "different".into();
        },
        |claim| {
            claim.version += 1;
        },
        |claim| {
            claim.route = CHATGPT_SUBSCRIPTION.into();
        },
        |claim| {
            claim.models = vec!["different".into()];
        },
    ];
    for amend in cases {
        let mut invalid = valid.clone();
        amend(&mut invalid);
        let signed = claim::sign(&invalid, KID, &fixture.key).unwrap();
        refused(
            fixture
                .call(dispatch_request(MESSAGES_PATH, &signed, "request", MODEL))
                .await,
            StatusCode::FORBIDDEN,
            CLAIM_REFUSED_CODE,
        )
        .await;
    }
    for (kid, key) in [
        ("unknown", fixture.key.clone()),
        (KID, Identity::generate().unwrap().1),
    ] {
        let signed = claim::sign(&valid, kid, &key).unwrap();
        refused(
            fixture
                .call(dispatch_request(MESSAGES_PATH, &signed, "request", MODEL))
                .await,
            StatusCode::FORBIDDEN,
            CLAIM_REFUSED_CODE,
        )
        .await;
    }
    assert!(fixture.app.pool.lock().await.leases.is_empty());
    assert!(!fixture.dir.join("claims.jsonl").exists());
}

/// A completed Claude SSE stream charges its merged usage before another call enters.
#[tokio::test]
async fn claude_usage_serializes_and_survives_restart() {
    let mut fixture = Fixture::new();
    let claim = fixture.approved_claim(Route::ClaudeSubscription);
    let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_published, worker) = fixture.retained(&claim, native.local_addr().unwrap()).await;
    let (finish, delayed) = oneshot::channel();
    let native_task = claude_ingress(native, delayed);

    let first = fixture.dispatch(&claim, "first").await;
    assert_eq!(first.status(), StatusCode::OK);
    let mut stream = first.into_body();
    let initial = stream.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(
        initial
            .windows(b"message_start".len())
            .any(|window| window == b"message_start")
    );
    {
        let queued = fixture.dispatch(&claim, "next");
        tokio::pin!(queued);
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut queued)
                .await
                .is_err()
        );
        finish.send(()).unwrap();
        let rest = stream.collect().await.unwrap().to_bytes();
        assert!(rest.ends_with(b"data: {\"type\":\"message_stop\"}\n\n"));
        refused(
            (&mut queued).await,
            StatusCode::TOO_MANY_REQUESTS,
            ALLOWANCE_SPENT_CODE,
        )
        .await;
    }

    let active: owner::Relays = serde_json::from_value(
        json_response(
            fixture
                .call(request(
                    "GET",
                    "/owner/v1/relays?user_id=7",
                    OWNER,
                    Bytes::new(),
                ))
                .await,
        )
        .await,
    )
    .unwrap();
    assert_eq!(active.relays[0].active[0].task.as_ref().unwrap().issue, 20);
    let release = format!("{CLAIMS_PREFIX}{}", claim.jti);
    assert_eq!(
        fixture
            .call(request("POST", &release, RELEASE, Bytes::new()))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(worker.await.unwrap_err().is_cancelled());
    assert!(fixture.app.pool.lock().await.leases.is_empty());
    native_task.abort();

    let log = fixture.dir.join("claims.jsonl");
    let settled = fs::read_to_string(&log).unwrap();
    assert_eq!(settled.lines().count(), 3);
    let accounted: Value = serde_json::from_str(settled.lines().nth(1).unwrap()).unwrap();
    assert_eq!(accounted["tokens"], 13);
    assert_eq!(accounted["complete"], true);
    fixture.restart();
    refused(
        fixture.dispatch(&claim, "after-release").await,
        StatusCode::FORBIDDEN,
        CLAIM_REFUSED_CODE,
    )
    .await;
    assert_eq!(fs::read_to_string(log).unwrap(), settled);
}

/// Native ingress fixture that reports input usage before the caller lets it finish.
fn claude_ingress(
    native: TcpListener,
    delayed: oneshot::Receiver<()>,
) -> JoinHandle<Result<(), hyper::Error>> {
    tokio::spawn(async move {
        let (connection, _) = native.accept().await.unwrap();
        let delayed = Mutex::new(Some(delayed));
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(connection), service_fn(|request: Request<Incoming>| {
                let delayed = delayed.lock().unwrap().take().unwrap();
                async move {
                assert_eq!(request.uri().path(), "/v1/messages");
                assert_eq!(request.headers()["authorization"], "Bearer local-relay-placeholder");
                assert!(!request.headers().contains_key(CLAIM_HEADER));
                assert!(!request.headers().contains_key(REQUEST_HEADER));
                let body = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["model"], MODEL);
                let (send, body) = http::streaming();
                let mut response = Response::new(body);
                response.headers_mut().insert("content-type", "text/event-stream".parse().unwrap());
                let frame = |value: &'static str| Ok(Frame::data(Bytes::from_static(value.as_bytes())));
                send.send(frame("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg\",\"usage\":{\"input_tokens\":6}}}\n\n"))
                    .await.unwrap();
                tokio::spawn(async move {
                    let finished = tokio::select! {
                        result = delayed => result.is_ok(),
                        () = send.closed() => false,
                    };
                    if !finished {
                        return;
                    }
                    send.send(frame("data: {\"type\":\"message_delta\",\"us")).await.unwrap();
                    send.send(frame("age\":{\"output_tokens\":7}}\n\ndata: {\"type\":\"message_stop\"}\n\n"))
                        .await.unwrap();
                });
                Ok::<_, std::convert::Infallible>(response)
                }
            }))
            .await
    })
}

/// A disconnected Claude caller stops native work and keeps observed input usage.
#[tokio::test]
async fn claude_cancellation_records_partial_usage() {
    let mut fixture = Fixture::new();
    let mut claim = fixture.approved_claim(Route::ClaudeSubscription);
    claim.tokens = 6;
    let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_published, worker) = fixture.retained(&claim, native.local_addr().unwrap()).await;
    let (_finish, delayed) = oneshot::channel();
    let native_task = claude_ingress(native, delayed);
    let mut stream = fixture.dispatch(&claim, "partial").await.into_body();
    let seen = stream.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(
        seen.windows(b"input_tokens".len())
            .any(|word| word == b"input_tokens")
    );
    drop(stream);
    refused(
        fixture.dispatch(&claim, "next").await,
        StatusCode::TOO_MANY_REQUESTS,
        ALLOWANCE_SPENT_CODE,
    )
    .await;
    let disconnected = tokio::time::timeout(Duration::from_secs(5), native_task)
        .await
        .unwrap()
        .unwrap();
    assert!(disconnected.is_ok() || disconnected.is_err_and(|error| error.is_incomplete_message()));
    let log = fs::read_to_string(fixture.dir.join("claims.jsonl")).unwrap();
    let usage: Value = serde_json::from_str(log.lines().nth(1).unwrap()).unwrap();
    assert_eq!(usage["tokens"], 6);
    assert_eq!(usage["complete"], false);
    worker.abort();
    fixture.restart();
    refused(
        fixture.dispatch(&claim, "after-restart").await,
        StatusCode::TOO_MANY_REQUESTS,
        ALLOWANCE_SPENT_CODE,
    )
    .await;
}

/// Native startup can fail without spending a call or consuming its request ID.
#[tokio::test]
async fn failed_native_startup_does_not_admit() {
    let fixture = Fixture::new();
    let claim = fixture.approved_claim(Route::ClaudeSubscription);
    let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (published, worker) = fixture.retained(&claim, native.local_addr().unwrap()).await;
    published.send(None).unwrap();
    drop(published);
    refused(
        fixture.dispatch(&claim, "retryable").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
    )
    .await;
    assert!(!fixture.dir.join("claims.jsonl").exists());
    worker.abort();
}

/// Two Codex calls use one retained lease, with a literal replay spending no new calls.
#[tokio::test]
async fn codex_accounts_calls_and_terminal_tokens() {
    let mut fixture = Fixture::new();
    let mut claim = fixture.approved_claim(Route::ChatgptSubscription);
    claim.calls = 2;
    claim.tokens = 100;
    let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_published, worker) = fixture.retained(&claim, native.local_addr().unwrap()).await;
    let native_task = tokio::spawn(async move {
        for _ in 0..2 {
            codex_turn(&native, "response.completed").await;
        }
    });
    let first = fixture.dispatch(&claim, "one").await;
    assert_eq!(first.status(), StatusCode::OK);
    let events = first.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&events)
            .unwrap()
            .contains("event: response.completed")
    );
    refused(
        fixture.dispatch(&claim, "one").await,
        StatusCode::CONFLICT,
        REQUEST_REUSED_CODE,
    )
    .await;
    let second = fixture.dispatch(&claim, "two").await;
    assert_eq!(second.status(), StatusCode::OK);
    second.into_body().collect().await.unwrap();
    native_task.await.unwrap();
    assert_eq!(fixture.app.pool.lock().await.leases.len(), 1);
    refused(
        fixture.dispatch(&claim, "extra").await,
        StatusCode::TOO_MANY_REQUESTS,
        ALLOWANCE_SPENT_CODE,
    )
    .await;
    worker.abort();
    fixture.restart();
    refused(
        fixture.dispatch(&claim, "extra").await,
        StatusCode::TOO_MANY_REQUESTS,
        ALLOWANCE_SPENT_CODE,
    )
    .await;

    // Every response terminal status may report usage independently of its call cap.
    for terminal in [
        "response.completed",
        "response.incomplete",
        "response.failed",
    ] {
        let mut metered = fixture.approved_claim(Route::ChatgptSubscription);
        metered.jti = format!("metered-{terminal}");
        metered.sub = format!("session-{terminal}");
        metered.tokens = 4;
        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_published, worker) = fixture
            .retained(&metered, native.local_addr().unwrap())
            .await;
        let native_task = tokio::spawn(async move { codex_turn(&native, terminal).await });
        let allowed = fixture.dispatch(&metered, "one").await;
        assert_eq!(allowed.status(), StatusCode::OK);
        allowed.into_body().collect().await.unwrap();
        native_task.await.unwrap();
        worker.abort();
        fixture.restart();
        refused(
            fixture.dispatch(&metered, "extra").await,
            StatusCode::TOO_MANY_REQUESTS,
            ALLOWANCE_SPENT_CODE,
        )
        .await;
    }
}

/// Recorded native Codex event sequence with terminal response usage.
async fn codex_turn(native: &TcpListener, terminal: &str) {
    let (connection, _) = native.accept().await.unwrap();
    let mut websocket = tokio_tungstenite::accept_async(connection).await.unwrap();
    let Message::Text(event) = websocket.next().await.unwrap().unwrap() else {
        panic!("expected response.create")
    };
    let event: Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["type"], "response.create");
    assert_eq!(event["model"], MODEL);
    assert!(event.get("stream").is_none());
    for event in [
        json!({"type":"response.created","response":{"id":"resp_1"}}),
        json!({"type":terminal,"response":{"id":"resp_1","usage":{"input_tokens":2,"output_tokens":3}}}),
    ] {
        websocket
            .send(Message::Text(event.to_string().into()))
            .await
            .unwrap();
    }
}

/// A pre-dispatch release survives restart and obtains its expiry only from the signed claim.
#[tokio::test]
async fn release_before_dispatch_is_durable_and_expires() {
    let mut fixture = Fixture::new();
    let mut claim = fixture.approved_claim(Route::ClaudeSubscription);
    claim.jti = "release/id with %".into();
    let path = ReleaseClaim {
        claim_id: claim.jti.clone().into(),
    }
    .path();
    for _ in 0..2 {
        let released = fixture
            .call(request("POST", &path, RELEASE, Bytes::new()))
            .await;
        assert_eq!(released.status(), StatusCode::NO_CONTENT);
        assert!(
            released
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    let journal = fixture.dir.join("claims.jsonl");
    assert_eq!(fs::read_to_string(&journal).unwrap().lines().count(), 1);
    fixture.restart();
    refused(
        fixture.dispatch(&claim, "late").await,
        StatusCode::FORBIDDEN,
        CLAIM_REFUSED_CODE,
    )
    .await;
    let records = fs::read_to_string(&journal).unwrap();
    assert_eq!(records.lines().count(), 2);
    let known: Value = serde_json::from_str(records.lines().nth(1).unwrap()).unwrap();
    assert_eq!(known["expires"], claim.exp);
    Journal::open(journal.clone(), claim.exp).unwrap();
    assert!(fs::read(journal).unwrap().is_empty());
}

/// A crash before the last append completes leaves earlier call accounting intact.
#[tokio::test]
async fn journal_reopens_after_a_torn_append() {
    let fixture = Fixture::new();
    let mut claim = fixture.approved_claim(Route::ClaudeSubscription);
    claim.calls = 1;
    let file = fixture.dir.join("torn.jsonl");
    let mut journal = Journal::open(file.clone(), now()).unwrap();
    journal.check(&claim, "escaped \"request\"", now()).unwrap();
    journal.admit(&claim, "escaped \"request\"").unwrap();
    let durable = fs::read(&file).unwrap();
    drop(journal);
    storage::append(&file, b"{\"kind\":\"charged\",").unwrap();
    let mut restored = Journal::open(file.clone(), now()).unwrap();
    std::assert_matches!(
        restored.check(&claim, "escaped \"request\"", now()),
        Err(journal::Refusal::Duplicate)
    );
    std::assert_matches!(
        restored.check(&claim, "two", now()),
        Err(journal::Refusal::Spent)
    );
    assert_eq!(fs::read(file).unwrap(), durable);
}
