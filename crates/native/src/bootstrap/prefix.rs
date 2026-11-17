//! Protected credential-prefix handoff before application request proofs.

use std::sync::Arc;

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_native_transport::tunnel::Tunnel;
use concurro_relay_provider_protocol::{claude, codex};
use concurro_relay_tls13::{handshake::Profile, record::ApplicationRecords};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Map;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::BootstrapOptions;
use crate::{
    NativeRole,
    helpers::{self, CircuitSpec, Peer},
};

/// Public transcript binding and one role's mask for the prefix circuit.
pub struct PrefixContext<'a> {
    /// Fixture or development session configuration.
    pub options: &'a BootstrapOptions,
    /// Hash of exact public TLS hellos.
    pub h2: [u8; 32],
    /// Hash of the authenticated server transcript.
    pub h3: [u8; 32],
    /// Joint key-share session identifier.
    pub session: [u8; 32],
    /// Exact public handshake circuit output.
    pub handshake_public: &'a [u8],
    /// This role's private handshake master mask.
    pub master_mask: [u8; 32],
}

/// Protected prefix plus the public continuation required for Codex requests.
pub struct SponsorPrefix {
    /// Exact public prefix circuit output.
    pub public: Vec<u8>,
    /// HTTP headers after the protected credential prefix.
    pub tail: Vec<u8>,
    /// First public Claude request template, when this is an H2 session.
    pub claude_template: Option<claude::Template>,
}

/// Protected prefix and Concurro's application record epochs.
pub struct ConcurroPrefix {
    /// Exact public prefix circuit output.
    pub public: Vec<u8>,
    /// HTTP headers after the protected credential prefix.
    pub tail: Vec<u8>,
    /// Independently authenticated application records.
    pub records: ApplicationRecords,
}

/// Sponsor writes only the circuit-produced prefix bytes after peer comparison.
pub async fn sponsor<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    tunnel: Option<&Arc<Tunnel>>,
    provider: &mut TcpStream,
    credential: &[u8],
    context: &PrefixContext<'_>,
) -> Result<SponsorPrefix> {
    let mut websocket_key = Vec::new();
    let mut claude_template = None;
    let (head, slot) = if context.options.profile == Profile::Codex {
        websocket_key = peer.receive("websocket_key").await?.data;
        codex::request_head(credential, &websocket_key)
    } else {
        let template = peer.receive("h2_template").await?;
        let template = claude::Template::from_metadata(&template.metadata)?;
        let result = claude::bootstrap(credential, &template)?;
        claude_template = Some(template);
        result
    };
    let partial = if context.options.profile == Profile::Codex {
        &head[..slot + credential.len() + 2]
    } else {
        &head
    };
    let tail = if context.options.profile == Profile::Codex && context.options.account.is_some() {
        peer.receive("request_tail").await?.data
    } else {
        head[partial.len()..].to_vec()
    };
    if context.options.profile == Profile::Codex {
        codex::validate_request_tail(&tail, &websocket_key)?;
    }
    let circuit = helpers::prefix_circuit(
        &context.options.runtime,
        context.options.route(),
        partial.len(),
        slot,
        credential.len(),
    )
    .await?;
    let binding = binding(context);
    let input = [&context.master_mask[..], &[0; 64], &binding, partial].concat();
    let public = helpers::circuit_pair(
        peer,
        NativeRole::Sponsor,
        &context.options.runtime,
        tunnel,
        CircuitSpec {
            circuit: &circuit,
            private: &input,
            phase: "prefix",
            session: context.session,
        },
    )
    .await?;
    ensure!(public.len() > 97, "protected prefix shape mismatch");
    ensure!(
        context.options.profile == Profile::ClaudeH2 || [75, 84, 85].contains(&slot),
        "protected prefix shape mismatch"
    );
    provider.write_all(&public[97..]).await?;
    peer.send("prefix_forwarded", &[], Map::new()).await?;
    Ok(SponsorPrefix {
        public,
        tail,
        claude_template,
    })
}

/// Concurro derives both application epochs after the protected prefix is forwarded.
pub async fn concurro<C: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C>,
    tunnel: Option<&Arc<Tunnel>>,
    credential_len: usize,
    context: &PrefixContext<'_>,
) -> Result<ConcurroPrefix> {
    let zero_credential = vec![0; credential_len];
    let (head, slot) = if context.options.profile == Profile::Codex {
        let mut key = [0; 16];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("WebSocket key random failed"))?;
        let encoded = STANDARD.encode(key);
        peer.send("websocket_key", encoded.as_bytes(), Map::new())
            .await?;
        codex::request_head(&zero_credential, encoded.as_bytes())
    } else {
        let template = context
            .options
            .claude_template
            .clone()
            .unwrap_or_else(claude::Template::fixture_default);
        peer.send("h2_template", &[], template.metadata()?).await?;
        claude::bootstrap(&zero_credential, &template)?
    };
    let partial = if context.options.profile == Profile::Codex {
        &head[..slot + credential_len + 2]
    } else {
        &head
    };
    let mut tail = head[partial.len()..].to_vec();
    if context.options.profile == Profile::Codex {
        for (name, value) in &context.options.codex_headers {
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || b"!#$%&'*+-.^_`|~".contains(&byte))
                    && !value.contains(['\r', '\n'])
                    && ![
                        "authorization",
                        "host",
                        "connection",
                        "upgrade",
                        "sec-websocket-key",
                        "sec-websocket-version",
                        "sec-websocket-extensions",
                        "proxy-authorization",
                        "x-api-key",
                        "cookie",
                        "chatgpt-account-id",
                        "content-length"
                    ]
                    .contains(&name.to_ascii_lowercase().as_str()),
                "invalid public CLI upgrade header"
            );
            tail.splice(
                tail.len() - 2..tail.len() - 2,
                format!("{name}: {value}\r\n").bytes(),
            );
        }
        if let Some(account) = &context.options.account {
            ensure!(
                !account.is_empty() && !account.contains(['\r', '\n']),
                "invalid provider account identity"
            );
            tail.splice(
                tail.len() - 2..tail.len() - 2,
                format!("ChatGPT-Account-Id: {account}\r\n").bytes(),
            );
            peer.send("request_tail", &tail, Map::new()).await?;
        }
    }
    let circuit = helpers::prefix_circuit(
        &context.options.runtime,
        context.options.route(),
        partial.len(),
        slot,
        credential_len,
    )
    .await?;
    let mut master_share = [0; 32];
    for (index, byte) in master_share.iter_mut().enumerate() {
        *byte = context.handshake_public[65 + index] ^ context.master_mask[index];
    }
    let mut masks = [0; 64];
    SystemRandom::new()
        .fill(&mut masks)
        .map_err(|_| anyhow::anyhow!("prefix masks random failed"))?;
    let binding = binding(context);
    let input = [&master_share[..], &masks, &binding, partial].concat();
    let public = helpers::circuit_pair(
        peer,
        NativeRole::Concurro,
        &context.options.runtime,
        tunnel,
        CircuitSpec {
            circuit: &circuit,
            private: &input,
            phase: "prefix",
            session: context.session,
        },
    )
    .await?;
    ensure!(public.len() > 97, "protected prefix shape mismatch");
    let mut client_secret = [0; 32];
    let mut server_secret = [0; 32];
    for index in 0..32 {
        client_secret[index] = public[33 + index] ^ masks[index];
        server_secret[index] = public[65 + index] ^ masks[32 + index];
    }
    peer.receive("prefix_forwarded").await?;
    let records = ApplicationRecords::new(server_secret, client_secret)?;
    Ok(ConcurroPrefix {
        public,
        tail,
        records,
    })
}

/// Bind the prefix circuit to both public transcripts and the handshake output.
fn binding(context: &PrefixContext<'_>) -> Vec<u8> {
    [
        &context.h2[..],
        &context.h3,
        &context.handshake_public[97..161],
    ]
    .concat()
}
