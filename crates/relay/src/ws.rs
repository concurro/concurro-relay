//! The relay's end of a WebSocket connection to a provider, whose turns it
//! proves while the connection stays open.

use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use concurro_relay_protocol::{
    Roots,
    wire::{Job, Offer},
    ws::{self, Asked, HEAD_END, Inbox, Progress},
};
use tlsn::SessionHandle;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Control, OpCode};

use crate::{
    live::{LiveRelay, Misproof},
    policy::Policy,
};

/// The relay's end of a proven WebSocket connection.
pub struct WsRelay {
    live: LiveRelay,
    inbox: Inbox,
    policy: Policy,
    /// Ids of the responses the provider reported as completed on this
    /// connection. They keep the gateway from continuing a response it was
    /// not given here by mistake. They authenticate nothing: whoever holds
    /// the connection's server key can make the relay record any id.
    responses: HashSet<String>,
    /// The request in flight, while one is.
    in_flight: Option<Asked>,
}

impl WsRelay {
    /// Connects to the provider, upgrades the connection with `credential`
    /// and proves the upgrade.
    pub async fn open(
        handle: &mut SessionHandle,
        job: &Job,
        offer: &Offer,
        credential: &[u8],
        key: &str,
        policy: Policy,
        roots: Roots,
    ) -> Result<Self> {
        policy.check_target(job).map_err(anyhow::Error::msg)?;
        let (request, hidden) = ws::upgrade(job, offer, credential, key)?;
        let mut live = LiveRelay::open(handle, &job.host, roots).await?;
        live.send(&request).await?;
        let mut response = Vec::new();
        let head_end = loop {
            response.extend(live.read().await?);
            if let Some(at) = response
                .windows(HEAD_END.len())
                .position(|window| window == HEAD_END)
            {
                break at + HEAD_END.len();
            }
        };
        // A refusal is proven too, so that the verifier learns of it.
        let status = ws::status(&response[..head_end]);
        let mut inbox = Inbox::default();
        if status == Some("101") {
            inbox.push(&response[head_end..])?;
        }
        live.prove(handle, &[hidden]).await?;
        ensure!(
            status == Some("101"),
            "provider refused the upgrade with status {}",
            status.unwrap_or("unreadable")
        );
        Ok(Self {
            live,
            inbox,
            policy,
            responses: HashSet::new(),
            in_flight: None,
        })
    }

    /// Bytes sent to the provider so far.
    pub fn sent(&self) -> usize {
        self.live.sent()
    }

    /// Sends the client frame `frame` if the policy allows its message,
    /// then waits and proves as [`Self::pong`] does. A refusal sends
    /// nothing.
    pub async fn turn(
        &mut self,
        handle: &mut SessionHandle,
        frame: &[u8],
    ) -> Result<Result<Progress, String>> {
        if let Err(reason) = self.send_request(frame).await? {
            return Ok(Err(reason));
        }
        self.advance(handle)
            .await?
            .context("nothing to prove after the request")
            .map(Ok)
    }

    /// Sends the pong `frame` if it answers a ping this connection received
    /// and has not answered. If a response is in flight, waits for it to
    /// end or for another ping. Proves everything sent and received up to
    /// then.
    pub async fn pong(
        &mut self,
        handle: &mut SessionHandle,
        frame: &[u8],
    ) -> Result<Result<Option<Progress>, String>> {
        if let Err(reason) = self.send_pong(frame).await? {
            return Ok(Err(reason));
        }
        Ok(Ok(self.advance(handle).await?))
    }

    /// Sends the client frame `frame` if the policy allows its message. A
    /// refusal sends nothing.
    pub async fn send_request(&mut self, frame: &[u8]) -> Result<Result<(), String>> {
        let text = match ws::client_text(frame) {
            Ok(text) => text,
            Err(reason) => return Ok(Err(reason)),
        };
        if self.in_flight.is_some() {
            return Ok(Err("a response is still in flight".into()));
        }
        if let Err(reason) = self.policy.check_message(&text, &self.responses) {
            return Ok(Err(reason));
        }
        // What has been read so far can not answer a request not yet sent.
        let asked = self.inbox.asking(ws::continued_response(&text));
        self.live.send(frame).await?;
        self.in_flight = Some(asked);
        Ok(Ok(()))
    }

    /// Sends the pong `frame` if it answers a ping this connection received
    /// and has not answered. A refusal sends nothing.
    pub async fn send_pong(&mut self, frame: &[u8]) -> Result<Result<(), String>> {
        let answered =
            ws::client_payload(frame, OpCode::Control(Control::Pong)).and_then(|payload| {
                self.inbox
                    .answer(&payload)
                    .then_some(())
                    .ok_or("no such ping to answer".into())
            });
        if let Err(reason) = answered {
            return Ok(Err(reason));
        }
        self.live.send(frame).await?;
        Ok(Ok(()))
    }

    /// Waits for a ping to answer while no request is in flight. Dropping
    /// the wait loses nothing which was received.
    pub async fn idle_ping(&mut self) -> Result<()> {
        while self.inbox.waiting_ping().is_none() {
            let received = self.live.read().await?;
            self.inbox.push(&received)?;
        }
        Ok(())
    }

    /// Whether anything was sent or received which no proof covers yet.
    pub fn has_unproven(&self) -> bool {
        self.live.has_unproven()
    }

    /// Waits for the response in flight, if any, to end or for a ping.
    pub async fn settle(&mut self) -> Result<()> {
        let Some(asked) = &self.in_flight else {
            return Ok(());
        };
        loop {
            if self.inbox.can_progress(asked).map_err(anyhow::Error::msg)? {
                return Ok(());
            }
            let received = self.live.read().await?;
            self.inbox.push(&received)?;
        }
    }

    /// [`Self::settle`], then [`Self::prove`].
    async fn advance(&mut self, handle: &mut SessionHandle) -> Result<Option<Progress>> {
        self.settle().await?;
        self.prove(handle).await
    }

    /// Proves everything sent and received so far.
    ///
    /// What happens next is decided on exactly the bytes the proof covers,
    /// so the verifier reaches the same decision.
    pub async fn prove(&mut self, handle: &mut SessionHandle) -> Result<Option<Progress>> {
        let snapshot = self.live.snapshot().await?;
        self.inbox.push(&self.live.take_arrived())?;
        let progress = match &self.in_flight {
            None => self.inbox.waiting_ping(),
            Some(asked) => self.inbox.progress(asked).map_err(anyhow::Error::msg)?,
        };
        if let Some(Progress::Response(messages)) = &progress {
            self.in_flight = None;
            self.responses.extend(ws::completed_response(messages));
        }
        self.live
            .prove_snapshot(handle, snapshot, &[], &Misproof::default())
            .await?;
        Ok(progress)
    }

    /// Closes the provider connection.
    pub async fn close(self) -> Result<()> {
        self.live.close().await
    }
}
