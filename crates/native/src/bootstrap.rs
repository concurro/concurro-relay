//! Explicit test and development bootstrap through the accepted helper boundary.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_provider_protocol::claude;
use concurro_relay_tls13::handshake::{self, Profile, ServerFlight};
use concurro_relay_tls13::record::ApplicationRecords;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    NativeRole,
    helpers::{self, CircuitSpec, KeyShare, Peer, Runtime, metadata},
};

mod prefix;

/// Inputs for an explicitly selected fixture bootstrap session.
pub struct BootstrapOptions {
    /// Local role; Sponsor alone owns the provider connection and credential.
    pub role: NativeRole,
    /// TLS ALPN and provider protocol profile.
    pub profile: Profile,
    /// Accepted native helper runtime and private output paths.
    pub runtime: Runtime,
    /// Provider TCP destination, distinct from the certificate hostname.
    pub provider_host: String,
    /// Provider TCP destination port.
    pub provider_port: u16,
    /// Provider CA PEM, verified on both roles.
    pub provider_ca: PathBuf,
    /// Sponsor credential; fixture sessions use a fixed dummy value when omitted.
    pub credential: Option<Vec<u8>>,
    /// Public account identifier, if supplied by the Sponsor.
    pub account: Option<String>,
    /// Public headers admitted from the local Codex upgrade.
    pub codex_headers: Vec<(String, String)>,
    /// First Claude path and public headers captured before bootstrap.
    pub claude_template: Option<claude::Template>,
}

impl BootstrapOptions {
    /// Return the fixed certificate identity for this provider profile.
    pub fn hostname(&self) -> &'static str {
        match self.profile {
            Profile::Codex => "chatgpt.com",
            Profile::ClaudeH2 => "api.anthropic.com",
        }
    }

    /// Return the route label used by native control messages.
    pub fn route(&self) -> &'static str {
        match self.profile {
            Profile::Codex => "codex",
            Profile::ClaudeH2 => "claude_h2",
        }
    }
}

/// Public, authenticated bootstrap facts without either role's private shares.
#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapResult {
    /// Route whose certificate and ALPN were authenticated.
    pub route: String,
    /// Hash of the two public TLS hello messages.
    pub h2: String,
    /// Hash of the authenticated server Finished transcript.
    pub h3: String,
    /// Joint key-share session identifier.
    pub session_id: String,
    /// True only after verifying the provider's server Finished.
    pub server_finished_verified: bool,
    /// True only after both roles agree on the client Finished record.
    pub client_finished_sent: bool,
    /// Ordered control message kinds for mixed-role fixture comparison.
    pub events: Vec<String>,
    /// Public bytes emitted by the handshake MPC.
    pub handshake_public: String,
    /// Public output of the protected credential-prefix circuit.
    pub prefix_public: String,
    /// Commitment to Concurro's application traffic secrets.
    pub prefix_key_commitment: String,
    /// True only after Sponsor writes the prefix to the provider.
    pub prefix_forwarded: bool,
    /// True on Concurro after both application traffic epochs are constructed.
    pub application_epoch_ready: bool,
}

/// Role-owned application state retained after one completed bootstrap.
pub enum Application {
    /// Sponsor owns provider TCP bytes and the public request tail.
    Sponsor {
        /// Provider socket retained after bootstrap.
        provider: TcpStream,
        /// Public Codex request continuation.
        tail: Vec<u8>,
        /// First public Claude request template.
        claude_template: Option<claude::Template>,
        /// Sponsor's credential length for the shadow HPACK table.
        credential_length: usize,
    },
    /// Concurro owns client and server traffic epochs and public request tail.
    Concurro {
        records: Box<ApplicationRecords>,
        tail: Vec<u8>,
        /// Credential length for Concurro's public HPACK table state.
        credential_length: usize,
    },
}

/// Resumable session with one authenticated control peer and one bootstrap.
pub struct Session<C> {
    /// Authenticated control stream and ordered events.
    pub peer: Peer<C>,
    /// Public bootstrap facts.
    pub result: BootstrapResult,
    /// Provider socket or application epochs, according to role.
    pub application: Application,
    /// Exact public hello hash.
    pub h2: [u8; 32],
    /// Authenticated server transcript hash.
    pub h3: [u8; 32],
    /// Joint key-share session binding.
    pub session_id: [u8; 32],
    /// Protected application-key commitment.
    pub key_commitment: [u8; 32],
}

/// Run one fresh fixture bootstrap over authenticated control and auxiliary links.
pub async fn run<C: AsyncRead + AsyncWrite + Unpin>(
    control: C,
    tunnel: Option<Arc<Tunnel>>,
    options: BootstrapOptions,
) -> Result<BootstrapResult> {
    let output = options.runtime.output.clone();
    let role = options.role;
    let session = start(control, tunnel, options).await?;
    let result = session.result;
    let name = if role == NativeRole::Sponsor {
        "sponsor"
    } else {
        "concurro"
    };
    tokio::fs::write(
        output.join(format!("{name}-result.json")),
        serde_json::to_vec_pretty(&result)?,
    )
    .await?;
    Ok(result)
}

/// Start one bootstrap and retain the socket or epochs for proved continuations.
pub async fn start<C: AsyncRead + AsyncWrite + Unpin>(
    control: C,
    tunnel: Option<Arc<Tunnel>>,
    options: BootstrapOptions,
) -> Result<Session<C>> {
    options.runtime.prepare().await?;
    let mut peer = Peer {
        stream: control,
        events: Vec::new(),
    };
    helpers::exchange_mascot_identity(&mut peer, options.role, &options.runtime).await?;
    continue_start(peer, tunnel, options).await
}

/// Continue bootstrap after the worker's native prelude exchanged MASCOT identities.
pub async fn start_after_identity<C: AsyncRead + AsyncWrite + Unpin>(
    control: C,
    tunnel: Option<Arc<Tunnel>>,
    options: BootstrapOptions,
) -> Result<Session<C>> {
    options.runtime.prepare().await?;
    continue_start(
        Peer {
            stream: control,
            events: Vec::new(),
        },
        tunnel,
        options,
    )
    .await
}

/// Share the exact handshake and prefix path between fixture and worker entry points.
async fn continue_start<C: AsyncRead + AsyncWrite + Unpin>(
    mut peer: Peer<C>,
    tunnel: Option<Arc<Tunnel>>,
    options: BootstrapOptions,
) -> Result<Session<C>> {
    let (result, application, h2, h3, session_id) = match options.role {
        NativeRole::Sponsor => sponsor(&mut peer, tunnel.as_ref(), &options).await,
        NativeRole::Concurro => concurro(&mut peer, tunnel.as_ref(), &options).await,
    }?;
    let result = BootstrapResult {
        events: peer.events.clone(),
        ..result
    };
    let key_commitment = hex::decode(&result.prefix_key_commitment)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid prefix commitment"))?;
    Ok(Session {
        peer,
        result,
        application,
        h2,
        h3,
        session_id,
        key_commitment,
    })
}

/// Own provider bytes and release the client Finished only after both flight checks.
async fn sponsor<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    tunnel: Option<&Arc<Tunnel>>,
    options: &BootstrapOptions,
) -> Result<(BootstrapResult, Application, [u8; 32], [u8; 32], [u8; 32])> {
    let credential = options.credential.as_deref().unwrap_or(b"fixturetoken");
    ensure!(
        !credential.is_empty() && !credential.contains(&b'\r') && !credential.contains(&b'\n'),
        "invalid Sponsor credential"
    );
    peer.send(
        "credential_shape",
        &[],
        serde_json::from_value(json!({"length": credential.len(), "account": options.account}))?,
    )
    .await?;
    let (mut keyshare, offer) = KeyShare::start(&options.runtime).await?;
    let (joint, session) = keyshare.joint(peer, options.role, offer).await?;
    let prepared = prefix::prepare(peer, tunnel, options, credential.len(), session).await?;
    let mut provider = TcpStream::connect((options.provider_host.as_str(), options.provider_port))
        .await
        .context("connect fixture provider")?;
    let hello = handshake::client_hello(options.profile, options.hostname(), &joint)?;
    handshake::validate_client_hello(options.profile, &hello.wire, options.hostname(), &joint)?;
    let wire = handshake::plaintext_record(22, &hello.wire)?;
    provider.write_all(&wire).await?;
    peer.send("client_hello", &hello.wire, Map::new()).await?;
    let server_wire = read_tls_record(&mut provider).await?;
    let (kind, server) = handshake::parse_plaintext_record(&server_wire)?;
    ensure!(kind == 22, "provider did not send ServerHello");
    let server = server.to_vec();
    let server_point = handshake::server_hello(&server, &hello.session)?;
    peer.send("server_hello", &server, Map::new()).await?;
    let h2 = helpers::sha256(&[hello.wire.as_slice(), &server].concat());
    let contribution = keyshare.contribution(server_point).await?;
    let share = helpers::arithmetic_share(
        peer,
        options.role,
        &options.runtime,
        tunnel,
        contribution,
        session,
        h2,
    )
    .await?;
    let mut master_mask = [0; 32];
    let mut random_tail = [0; 64];
    SystemRandom::new()
        .fill(&mut master_mask)
        .map_err(|_| anyhow::anyhow!("master mask random failed"))?;
    SystemRandom::new()
        .fill(&mut random_tail)
        .map_err(|_| anyhow::anyhow!("handshake random failed"))?;
    let input = [&share[..], &h2, &master_mask, &random_tail].concat();
    let circuit = options.runtime.handshake_circuit();
    let public = helpers::circuit_pair(
        peer,
        options.role,
        &options.runtime,
        tunnel,
        CircuitSpec {
            circuit: &circuit,
            private: &input,
            phase: "handshake",
            session,
        },
    )
    .await?;
    ensure!(public.len() == 193, "handshake output shape mismatch");
    let ca = tokio::fs::read(&options.provider_ca).await?;
    let mut records = Vec::new();
    let h3 = loop {
        let wire = read_tls_record(&mut provider).await?;
        peer.send("server_flight_record", &wire, Map::new()).await?;
        records.push(wire);
        let answer = peer.receive_any().await?;
        if answer.kind == "flight_more" {
            continue;
        }
        ensure!(
            answer.kind == "flight_keys" && answer.data.len() == 64,
            "Concurro did not validate provider flight"
        );
        let (client_secret, server_secret) = answer.data.split_at(32);
        let commitment = helpers::sha256(
            &[
                b"Concurro/Handoff/v2/handshake-keys".as_slice(),
                &h2,
                client_secret,
                server_secret,
            ]
            .concat(),
        );
        ensure!(
            public[161..193] == commitment,
            "released handshake keys differ from MPC commitment"
        );
        let mut flight = ServerFlight::new(
            options.profile,
            &hello.wire,
            &server,
            &joint,
            server_secret.try_into().unwrap(),
            &ca,
            options.hostname(),
        )?;
        for observed in &records {
            flight.feed(observed)?;
        }
        let (finished, h3) = flight.client_finished(client_secret.try_into().unwrap())?;
        ensure!(
            answer.metadata.get("h3") == Some(&json!(hex::encode(h3))),
            "parties computed different server Finished transcript"
        );
        peer.send("flight_approved", &h3, Map::new()).await?;
        ensure!(
            peer.receive("client_finished").await?.data == finished,
            "client Finished differs"
        );
        provider.write_all(&finished).await?;
        break h3;
    };
    let context = prefix::PrefixContext {
        options,
        h2,
        h3,
        session,
        handshake_public: &public,
        master_mask,
    };
    let prefix =
        prefix::sponsor(peer, tunnel, &mut provider, credential, &context, prepared).await?;
    Ok((
        result(options, h2, h3, session, &public, &prefix.public, false),
        Application::Sponsor {
            provider,
            tail: prefix.tail,
            claude_template: prefix.claude_template,
            credential_length: credential.len(),
        },
        h2,
        h3,
        session,
    ))
}

/// Authenticate provider records independently and withhold keys until Finished verifies.
async fn concurro<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    tunnel: Option<&Arc<Tunnel>>,
    options: &BootstrapOptions,
) -> Result<(BootstrapResult, Application, [u8; 32], [u8; 32], [u8; 32])> {
    let shape = peer.receive("credential_shape").await?;
    ensure!(
        shape
            .metadata
            .get("length")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "invalid public credential length"
    );
    let (mut keyshare, offer) = KeyShare::start(&options.runtime).await?;
    let (joint, session) = keyshare.joint(peer, options.role, offer).await?;
    let prepared = prefix::prepare(
        peer,
        tunnel,
        options,
        shape.metadata["length"].as_u64().unwrap() as usize,
        session,
    )
    .await?;
    let client = peer.receive("client_hello").await?.data;
    let hello_session =
        handshake::validate_client_hello(options.profile, &client, options.hostname(), &joint)?;
    let server = peer.receive("server_hello").await?.data;
    let server_point = handshake::server_hello(&server, &hello_session)?;
    let h2 = helpers::sha256(&[client.as_slice(), &server].concat());
    let contribution = keyshare.contribution(server_point).await?;
    let share = helpers::arithmetic_share(
        peer,
        options.role,
        &options.runtime,
        tunnel,
        contribution,
        session,
        h2,
    )
    .await?;
    let mut master_mask = [0; 32];
    let mut handshake_masks = [0; 64];
    SystemRandom::new()
        .fill(&mut master_mask)
        .map_err(|_| anyhow::anyhow!("master mask random failed"))?;
    SystemRandom::new()
        .fill(&mut handshake_masks)
        .map_err(|_| anyhow::anyhow!("handshake masks random failed"))?;
    let input = [&share[..], &h2, &master_mask, &handshake_masks].concat();
    let circuit = options.runtime.handshake_circuit();
    let public = helpers::circuit_pair(
        peer,
        options.role,
        &options.runtime,
        tunnel,
        CircuitSpec {
            circuit: &circuit,
            private: &input,
            phase: "handshake",
            session,
        },
    )
    .await?;
    ensure!(public.len() == 193, "handshake output shape mismatch");
    let mut client_secret = [0; 32];
    let mut server_secret = [0; 32];
    for i in 0..32 {
        client_secret[i] = public[1 + i] ^ handshake_masks[i];
        server_secret[i] = public[33 + i] ^ handshake_masks[32 + i];
    }
    let ca = tokio::fs::read(&options.provider_ca).await?;
    let mut flight = ServerFlight::new(
        options.profile,
        &client,
        &server,
        &joint,
        server_secret,
        &ca,
        options.hostname(),
    )?;
    loop {
        let wire = peer.receive("server_flight_record").await?.data;
        if flight.feed(&wire)? {
            break;
        }
        peer.send("flight_more", &[], Map::new()).await?;
    }
    let (finished, h3) = flight.client_finished(client_secret)?;
    peer.send(
        "flight_keys",
        &[&client_secret[..], &server_secret].concat(),
        metadata("h3", json!(hex::encode(h3))),
    )
    .await?;
    ensure!(
        peer.receive("flight_approved").await?.data == h3,
        "Sponsor computed different server transcript"
    );
    peer.send("client_finished", &finished, Map::new()).await?;
    let context = prefix::PrefixContext {
        options,
        h2,
        h3,
        session,
        handshake_public: &public,
        master_mask,
    };
    let prefix = prefix::concurro(
        peer,
        tunnel,
        shape.metadata["length"].as_u64().unwrap() as usize,
        &context,
        prepared,
    )
    .await?;
    Ok((
        result(options, h2, h3, session, &public, &prefix.public, true),
        Application::Concurro {
            records: Box::new(prefix.records),
            tail: prefix.tail,
            credential_length: shape.metadata["length"].as_u64().unwrap() as usize,
        },
        h2,
        h3,
        session,
    ))
}

/// Read exactly one bounded TLS record from the fixture provider.
pub async fn read_tls_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    ensure!(len <= 16_640, "provider TLS record too large");
    let mut wire = header.to_vec();
    wire.resize(5 + len, 0);
    stream.read_exact(&mut wire[5..]).await?;
    Ok(wire)
}

/// Assemble public bootstrap evidence with role-independent field names.
fn result(
    options: &BootstrapOptions,
    h2: [u8; 32],
    h3: [u8; 32],
    session: [u8; 32],
    public: &[u8],
    prefix: &[u8],
    application_epoch_ready: bool,
) -> BootstrapResult {
    BootstrapResult {
        route: options.route().into(),
        h2: hex::encode(h2),
        h3: hex::encode(h3),
        session_id: hex::encode(session),
        server_finished_verified: true,
        client_finished_sent: true,
        events: Vec::new(),
        handshake_public: hex::encode(public),
        prefix_public: hex::encode(prefix),
        prefix_key_commitment: hex::encode(&prefix[1..33]),
        prefix_forwarded: true,
        application_epoch_ready,
    }
}
