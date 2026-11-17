//! Proving the turns of a provider connection which stays open.
//!
//! One prover and verifier pair carries the connection. Each turn is proven
//! by a further, short-lived pair which commits to the traffic so far and
//! reveals only what is new, so a turn costs what its own bytes cost and
//! leaves no proof state behind.

use std::{mem, ops::Range, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_protocol::Roots;
use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use tlsn::{
    ProxySnapshot, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    prover::{ProverControl, TlsConnection},
    rangeset::set::RangeSet,
    transcript::Direction,
};
use tokio::{task::JoinHandle, time};

/// How long the relay waits for the connection to go quiet before a proof.
const QUIET_LIMIT: Duration = Duration::from_secs(5);

/// Departures from an honest proof, for testing what a verifier rejects.
#[derive(Clone, Debug, Default)]
pub struct Misproof {
    /// Reveal sent data from this offset, not from where the last proof
    /// ended.
    pub reveal_from: Option<usize>,
    /// Claim this many received records were covered by earlier proofs.
    pub tags_from: Option<usize>,
}

/// The relay's end of a provider connection which stays open.
pub struct LiveRelay {
    tls: TlsConnection,
    control: ProverControl,
    connection: JoinHandle<()>,
    server: String,
    /// Application bytes written and read so far.
    sent: usize,
    received: usize,
    /// Application bytes sent and received which earlier proofs covered.
    proven: usize,
    proven_received: usize,
    /// Received records whose tags earlier proofs covered.
    proven_records: usize,
    /// Received bytes which no caller has taken yet.
    unread: Vec<u8>,
    /// Whether a proof failed, after which none is attempted.
    abandoned: bool,
}

impl LiveRelay {
    /// Connects to `server` through the verifier on `handle`'s session.
    ///
    /// Opening uses the session's OT state, so a failure closes the
    /// session, as a failed proof does.
    pub async fn open(handle: &mut SessionHandle, server: &str, roots: Roots) -> Result<Self> {
        let opened = Self::open_unguarded(handle, server, roots).await;
        if opened.is_err() {
            handle.close();
        }
        opened
    }

    async fn open_unguarded(
        handle: &mut SessionHandle,
        server: &str,
        roots: Roots,
    ) -> Result<Self> {
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(
                ProxyTlsConfig::builder()
                    .server_name(DnsName::try_from(server)?)
                    .build()?,
            )
            .await?;
        let (tls, prover) = prover.connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(server.try_into()?))
                .root_store(roots.store())
                .build()?,
        )?;
        let control = prover.control();
        // Nothing is proven when a carried connection ends, so its end,
        // whenever that comes, does not draw on the session's OT state.
        let connection = tokio::spawn(async move {
            let _ = prover.carry().await;
        });
        Ok(Self {
            tls,
            control,
            connection,
            server: server.to_owned(),
            sent: 0,
            received: 0,
            proven: 0,
            proven_received: 0,
            proven_records: 0,
            unread: Vec::new(),
            abandoned: false,
        })
    }

    /// Offset the next sent byte will have in the connection's sent data.
    pub fn sent(&self) -> usize {
        self.sent
    }

    /// Whether anything was sent or read which no proof covers yet.
    pub fn has_unproven(&self) -> bool {
        self.sent > self.proven || self.received > self.proven_received
    }

    /// Writes `bytes` to the provider.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tls.write_all(bytes).await?;
        self.tls.flush().await?;
        self.sent += bytes.len();
        Ok(())
    }

    /// Reads more of what the provider sent into the unread bytes.
    async fn fill(&mut self) -> Result<()> {
        let mut chunk = [0; 16384];
        let n = self.tls.read(&mut chunk).await?;
        ensure!(n > 0, "provider closed the connection");
        self.unread.extend_from_slice(&chunk[..n]);
        self.received += n;
        Ok(())
    }

    /// Takes the received bytes not taken yet, waiting for some to arrive
    /// if there are none.
    pub async fn read(&mut self) -> Result<Vec<u8>> {
        if self.unread.is_empty() {
            self.fill().await?;
        }
        Ok(mem::take(&mut self.unread))
    }

    /// Takes the received bytes not taken yet, without waiting for any.
    pub fn take_arrived(&mut self) -> Vec<u8> {
        mem::take(&mut self.unread)
    }

    /// Reads one HTTP response which declares its content length.
    pub async fn read_http_response(&mut self) -> Result<Vec<u8>> {
        let mut response = Vec::new();
        let head_end = loop {
            if let Some(at) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            response.extend(self.read().await?);
        };
        let head = String::from_utf8_lossy(&response[..head_end]).to_ascii_lowercase();
        let length: usize = head
            .split("\r\n")
            .find_map(|line| line.strip_prefix("content-length:"))
            .context("response does not declare its length")?
            .trim()
            .parse()?;
        while response.len() < head_end + length {
            response.extend(self.read().await?);
        }
        self.unread = response.split_off(head_end + length);
        Ok(response)
    }

    /// Proves everything sent and received since the last proof, keeping the
    /// `hidden` ranges of the sent data private and proving that each of
    /// their bytes is at least `0x20`.
    pub async fn prove(
        &mut self,
        handle: &mut SessionHandle,
        hidden: &[Range<usize>],
    ) -> Result<()> {
        let snapshot = self.snapshot().await?;
        self.prove_snapshot(handle, snapshot, hidden, &Misproof::default())
            .await
    }

    /// Takes a snapshot holding exactly what this side has written and
    /// received, reading anything which arrived unasked.
    pub async fn snapshot(&mut self) -> Result<ProxySnapshot> {
        let deadline = time::Instant::now() + QUIET_LIMIT;
        loop {
            match self.control.snapshot() {
                Ok(snapshot)
                    if snapshot.len_sent() == self.sent
                        && snapshot.len_received() == self.received =>
                {
                    return Ok(snapshot);
                }
                _ if time::Instant::now() >= deadline => bail!("connection did not go quiet"),
                Ok(snapshot) if snapshot.len_received() > self.received => {
                    if let Ok(filled) = time::timeout(Duration::from_millis(1), self.fill()).await {
                        filled?;
                    }
                }
                _ => time::sleep(Duration::from_millis(1)).await,
            }
        }
    }

    /// Takes a snapshot once everything written has been sent, whether or
    /// not the response has arrived.
    pub async fn snapshot_after_sending(&self) -> Result<ProxySnapshot> {
        let deadline = time::Instant::now() + QUIET_LIMIT;
        loop {
            match self.control.snapshot() {
                Ok(snapshot) if snapshot.len_sent() == self.sent => return Ok(snapshot),
                _ if time::Instant::now() >= deadline => bail!("request was not sent in time"),
                _ => time::sleep(Duration::from_millis(1)).await,
            }
        }
    }

    /// Proves the part of `snapshot` which earlier proofs did not cover.
    ///
    /// A proof which fails closes `handle`'s session: the proofs of a
    /// session share OT state, which is not to be used again once one of
    /// them has gone wrong.
    pub async fn prove_snapshot(
        &mut self,
        handle: &mut SessionHandle,
        snapshot: ProxySnapshot,
        hidden: &[Range<usize>],
        misproof: &Misproof,
    ) -> Result<()> {
        ensure!(
            !self.abandoned,
            "connection was abandoned after a failed proof"
        );
        // Abandoned until proven otherwise, so that a proof which is
        // cancelled part-way counts as failed.
        self.abandoned = true;
        let proven = self
            .prove_unguarded(handle, snapshot, hidden, misproof)
            .await;
        match proven {
            Ok(()) => self.abandoned = false,
            Err(_) => handle.close(),
        }
        proven
    }

    async fn prove_unguarded(
        &mut self,
        handle: &mut SessionHandle,
        snapshot: ProxySnapshot,
        hidden: &[Range<usize>],
        misproof: &Misproof,
    ) -> Result<()> {
        let (sent, received) = (snapshot.len_sent(), snapshot.len_received());
        let mut prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(
                ProxyTlsConfig::builder()
                    .server_name(DnsName::try_from(self.server.as_str())?)
                    .build()?,
            )
            .await?
            .attach(snapshot, misproof.tags_from.unwrap_or(self.proven_records))
            .await?;
        let records = prover.tls_transcript().recv().len();

        let mut revealed = RangeSet::from(misproof.reveal_from.unwrap_or(self.proven)..sent);
        let mut proof = ProveConfig::builder(prover.transcript());
        proof.server_identity();
        for range in hidden {
            revealed.difference_mut(range.clone());
            proof.prove_no_control(Direction::Sent, range.clone())?;
        }
        proof.reveal_sent(&revealed)?;
        // The server's key authenticates the response, so only the new part
        // of it needs to travel with this proof.
        if received > self.proven_received {
            proof.reveal_recv(&(self.proven_received..received))?;
        }
        proof.reveal_recv_key();
        let proof = proof.build()?;
        prover.prove(&proof).await?;
        prover.close().await?;

        self.proven = sent;
        self.proven_received = received;
        self.proven_records = records;
        Ok(())
    }

    /// Closes the provider connection.
    pub async fn close(mut self) -> Result<()> {
        self.tls.close().await?;
        self.connection.await?;
        Ok(())
    }
}
