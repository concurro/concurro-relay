//! The verifier's end of a provider connection whose turns are proven
//! while it stays open.
//!
//! One verifier carries the connection, forwarding traffic it cannot read.
//! Each turn is verified by a further, short-lived one which checks the
//! relay's commitment to the traffic so far and what it reveals of the new
//! part.

use std::{net::SocketAddr, ops::Range, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use concurro_relay_protocol::Roots;
use tlsn::{
    SessionHandle, TrafficTap,
    config::verifier::VerifierConfig,
    connection::ServerName,
    rangeset::set::RangeSet,
    verifier::{VerifierCommitStart, VerifierOutput},
};
use tokio::{net::TcpStream, task::JoinHandle, time};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// How long the verifier waits for the relay's proof of a turn.
const PROOF_LIMIT: Duration = Duration::from_secs(120);

/// What the provider sent between two proofs.
#[derive(Clone, Debug)]
pub struct Received {
    pub bytes: Vec<u8>,
    /// Marks the moment the last of the proven request was forwarded to the
    /// provider, for [`LiveVerifier::received_before`].
    pub request_mark: usize,
}

/// The verifier's end of a provider connection which stays open.
pub struct LiveVerifier {
    tap: TrafficTap,
    forwarding: JoinHandle<()>,
    host: String,
    roots: Roots,
    /// The sent data verified so far, with hidden bytes as zeros.
    sent: Vec<u8>,
    received: usize,
    /// Received records whose tags earlier proofs covered.
    records: usize,
    /// Whether a proof failed, after which none is accepted.
    abandoned: bool,
}

impl LiveVerifier {
    /// Starts forwarding the relay's connection to `provider`, which must be
    /// `host`.
    ///
    /// Opening uses the session's OT state, so a failure closes the
    /// session, as a failed proof does.
    pub async fn open(
        handle: &mut SessionHandle,
        host: &str,
        provider: SocketAddr,
        roots: Roots,
    ) -> Result<Self> {
        let opened = time::timeout(
            PROOF_LIMIT,
            Self::open_unguarded(handle, host, provider, roots),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow!("relay did not open the connection in time")));
        if opened.is_err() {
            handle.close();
        }
        opened
    }

    async fn open_unguarded(
        handle: &mut SessionHandle,
        host: &str,
        provider: SocketAddr,
        roots: Roots,
    ) -> Result<Self> {
        let verifier = handle.new_verifier(
            VerifierConfig::builder()
                .root_store(roots.store())
                .build()?,
        )?;
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
            bail!("relay did not request proxy mode");
        };
        ensure!(
            verifier.config().server_name().as_str() == host,
            "relay targeted another server"
        );
        let provider = TcpStream::connect(provider).await?;
        provider.set_nodelay(true)?;
        let verifier = verifier.accept().await?;
        let tap = verifier.tap();
        let forwarding = tokio::spawn(async move {
            let _ = verifier.forward(provider.compat()).await;
        });
        Ok(Self {
            tap,
            forwarding,
            host: host.to_owned(),
            roots,
            sent: Vec::new(),
            received: 0,
            records: 0,
            abandoned: false,
        })
    }

    /// Verifies the relay's proof of everything since the last one.
    ///
    /// `expected` is what the relay must have sent since then, with the
    /// `hidden` ranges (relative to `expected`) as zeros. Returns what the
    /// provider sent in that time, or why the proof was rejected. After a
    /// rejection the connection must not be used again.
    pub async fn verify(
        &mut self,
        handle: &mut SessionHandle,
        expected: &[u8],
        hidden: &[Range<usize>],
    ) -> Result<Result<Vec<u8>, String>> {
        Ok(self
            .verify_received(handle, expected, hidden)
            .await?
            .map(|received| received.bytes))
    }

    /// How many of the bytes received on the connection, from its start,
    /// the provider had begun to send before the moment `request_mark`
    /// names, and so without having seen that request. It counts what has
    /// been forwarded to the relay, proven yet or not.
    pub fn received_before(&self, request_mark: usize) -> usize {
        self.tap.application_data_started_before(request_mark)
    }

    /// Like [`Self::verify`], also marking the moment the request was
    /// forwarded.
    pub async fn verify_received(
        &mut self,
        handle: &mut SessionHandle,
        expected: &[u8],
        hidden: &[Range<usize>],
    ) -> Result<Result<Received, String>> {
        if self.abandoned {
            return Ok(Err("connection was abandoned after a failed proof".into()));
        }
        // Abandoned until verified, so that a verification which is
        // cancelled part-way counts as failed.
        self.abandoned = true;
        // A relay could stall any step, or name a prefix longer than the
        // traffic will ever be.
        let verified = time::timeout(PROOF_LIMIT, self.verify_unguarded(handle, expected, hidden))
            .await
            .unwrap_or_else(|_| Ok(Err("relay's proof did not finish in time".into())));
        match verified {
            Ok(Ok(_)) => self.abandoned = false,
            _ => handle.close(),
        }
        verified
    }

    async fn verify_unguarded(
        &mut self,
        handle: &mut SessionHandle,
        expected: &[u8],
        hidden: &[Range<usize>],
    ) -> Result<Result<Received, String>> {
        let verifier = handle.new_verifier(
            VerifierConfig::builder()
                .root_store(self.roots.store())
                .build()?,
        )?;
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
            return Ok(Err("relay did not request proxy mode".into()));
        };
        if verifier.config().server_name().as_str() != self.host {
            verifier.reject(Some("wrong server")).await?;
            return Ok(Err("relay targeted another server".into()));
        }
        let verifier = verifier.accept().await?;
        let (verifier, prefix) = verifier.attach(&self.tap, self.records).await?;
        let records = verifier.tls_transcript().recv().len();
        let verifier = verifier.verify().await?;

        let start = self.sent.len();
        let end = start + expected.len();
        let hidden = RangeSet::from(
            hidden
                .iter()
                .map(|range| start + range.start..start + range.end)
                .collect::<Vec<_>>(),
        );
        let mut revealed = RangeSet::from(start..end);
        revealed.difference_mut(&hidden);

        // The proof must cover exactly the new bytes: hidden ones proven
        // unable to reframe the request, the rest revealed.
        let request = verifier.request();
        let reveals_new = request.reveal().is_some_and(|(sent, received)| {
            *sent == revealed && received.min().is_none_or(|from| from == self.received)
        });
        if !reveals_new || !request.reveal_recv_key() || request.no_control().0 != hidden {
            let reason = "proof does not cover exactly the new request bytes";
            verifier.reject(Some(reason)).await?;
            return Ok(Err(reason.into()));
        }
        let (
            VerifierOutput {
                server_name,
                transcript,
                ..
            },
            verifier,
        ) = match verifier.accept().await {
            Ok(accepted) => accepted,
            Err(error) => return Ok(Err(format!("proof failed: {error}"))),
        };
        verifier.close().await?;

        let Some(ServerName::Dns(name)) = server_name else {
            return Ok(Err("server identity not proven".into()));
        };
        if name.as_str() != self.host {
            return Ok(Err(format!("proof is for {}", name.as_str())));
        }
        let transcript = transcript.context("no transcript revealed")?;
        if transcript.len_sent() != end {
            return Ok(Err(format!(
                "relay sent {} bytes, expected {end}",
                transcript.len_sent()
            )));
        }
        let sent = transcript
            .sent_unsafe(end)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if sent[start..] != *expected {
            return Ok(Err("request differs from the one asked for".into()));
        }
        if *transcript.received_authed() != RangeSet::from(self.received..transcript.len_received())
        {
            return Ok(Err("response is partly hidden".into()));
        }
        // The relay may have sent no application data beyond what this proof
        // covers, up to now. Its TLS client answering the provider's close is
        // not application data.
        if self.tap.sent_application_data_beyond(prefix.sent) {
            return Ok(Err("relay sent data beyond what it proved".into()));
        }
        let received = transcript
            .received_unsafe(transcript.len_received())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let bytes = received[self.received..].to_vec();

        self.sent.extend_from_slice(expected);
        self.received = received.len();
        self.records = records;
        Ok(Ok(Received {
            bytes,
            request_mark: prefix.received_at_last_send,
        }))
    }

    /// Waits for the relay to close the provider connection.
    pub async fn close(self) -> Result<()> {
        self.forwarding.await?;
        Ok(())
    }
}
