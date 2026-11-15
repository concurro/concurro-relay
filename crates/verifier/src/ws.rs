//! The verifier's end of a WebSocket connection a relay holds to a
//! provider: it checks each proof against the exact frame it ordered and
//! accepts a response only if it is whole and answers that frame.

use std::net::SocketAddr;

use anyhow::{Result, bail, ensure};
use concurro_relay_protocol::{
    Roots,
    wire::{self, Job, Offer},
    ws::{self, Asked, HEAD_END, Inbox, Progress},
};
use tlsn::SessionHandle;
use tokio_tungstenite::tungstenite::{
    handshake::derive_accept_key,
    protocol::frame::coding::{Control, OpCode},
};

use crate::{exchange, live::LiveVerifier};

/// The verifier's end of a proven WebSocket connection.
pub struct WsVerifier {
    live: LiveVerifier,
    inbox: Inbox,
    /// Length of the provider's answer to the upgrade, which precedes its
    /// messages.
    head: usize,
    /// Marks the moment the request in flight was forwarded to the
    /// provider.
    request_mark: usize,
    /// The request in flight, while one is.
    in_flight: Option<Asked>,
}

impl WsVerifier {
    /// Forwards a connection to `provider` and verifies the relay's proof
    /// that it sent the upgrade for `job` and that the provider accepted
    /// it. The relay's `offer` may add only a known credential header and
    /// the headers named in `relay_headers`.
    pub async fn open(
        handle: &mut SessionHandle,
        job: &Job,
        offer: &Offer,
        relay_headers: &[String],
        key: &str,
        provider: SocketAddr,
        roots: Roots,
    ) -> Result<Result<Self, String>> {
        if let Err(reason) = exchange::admit(offer, relay_headers) {
            return Ok(Err(reason));
        }
        let (expected, hidden) = ws::upgrade(job, offer, &vec![0; offer.hidden_len], key)?;
        let mut live = LiveVerifier::open(handle, &job.host, provider, roots).await?;
        let received = match live.verify(handle, &expected, &[hidden]).await? {
            Ok(received) => received,
            Err(reason) => return Ok(Err(reason)),
        };
        let Some(head_end) = received.windows(HEAD_END.len()).position(|window| window == HEAD_END) else {
            return Ok(Err("upgrade response is incomplete".into()));
        };
        let head_end = head_end + HEAD_END.len();
        let accepted = wire::parse_response(&received[..head_end]).is_ok_and(|response| {
            let accept = derive_accept_key(key.as_bytes());
            response.status == 101
                && response.headers.iter().any(|(name, value)| name == "sec-websocket-accept" && *value == accept)
        });
        if !accepted {
            let status = ws::status(&received[..head_end]).unwrap_or("unreadable");
            return Ok(Err(format!("provider did not accept the upgrade: status {status}")));
        }
        let mut inbox = Inbox::default();
        if let Err(error) = inbox.push(&received[head_end..]) {
            return Ok(Err(format!("{error:#}")));
        }
        Ok(Ok(Self { live, inbox, head: head_end, request_mark: 0, in_flight: None }))
    }

    /// Verifies the relay's proof that it sent exactly the request `frame`.
    /// Returns the response if it has ended, or the ping to answer first.
    pub async fn turn(&mut self, handle: &mut SessionHandle, frame: &[u8]) -> Result<Result<Progress, String>> {
        let Ok(text) = ws::client_text(frame) else {
            bail!("frame to verify is not a text message");
        };
        ensure!(self.in_flight.is_none(), "a response is still in flight");
        let received = self.receive(handle, frame, Some(ws::continued_response(&text))).await?;
        Ok(received.and_then(|next| next.ok_or_else(|| "response is incomplete".into())))
    }

    /// Verifies the relay's proof that it sent exactly the pong `frame`,
    /// which answers a ping the provider sent. Returns as [`Self::turn`]
    /// does if a response is in flight, and otherwise any further ping to
    /// answer.
    pub async fn pong(&mut self, handle: &mut SessionHandle, frame: &[u8]) -> Result<Result<Option<Progress>, String>> {
        let answers = ws::client_payload(frame, OpCode::Control(Control::Pong)).is_ok_and(|payload| self.inbox.answer(&payload));
        ensure!(answers, "frame to verify does not answer a ping");
        let awaited = self.in_flight.is_some();
        Ok(self.receive(handle, frame, None).await?.and_then(|next| match next {
            None if awaited => Err("response is incomplete".into()),
            next => Ok(next),
        }))
    }

    /// Verifies the relay's proof of what the provider sent while no
    /// request was in flight, the relay having sent nothing. Returns any
    /// ping to answer.
    pub async fn report(&mut self, handle: &mut SessionHandle) -> Result<Result<Option<Progress>, String>> {
        ensure!(self.in_flight.is_none(), "a response is still in flight");
        self.receive(handle, &[], None).await
    }

    /// The oldest ping which has been verified and not answered.
    pub fn waiting_ping(&self) -> Option<Progress> {
        self.inbox.waiting_ping()
    }

    /// Waits for the relay to close the provider connection.
    pub async fn close(self) -> Result<()> {
        self.live.close().await
    }

    /// Verifies the relay's proof that it sent exactly `frame`, and decides
    /// what happens next from what the provider had sent by then. If the
    /// frame is a request, `asks` is the response it continues.
    async fn receive(
        &mut self,
        handle: &mut SessionHandle,
        frame: &[u8],
        asks: Option<Option<String>>,
    ) -> Result<Result<Option<Progress>, String>> {
        let received = match self.live.verify_received(handle, frame, &[]).await? {
            Ok(received) => received,
            Err(reason) => return Ok(Err(reason)),
        };
        if let Err(error) = self.inbox.push(&received.bytes) {
            return Ok(Err(format!("{error:#}")));
        }
        if let Some(previous) = asks {
            self.request_mark = received.request_mark;
            self.in_flight = Some(Asked { previous, before: 0 });
        }
        // What the provider sent before the request reached it may only be
        // proven now, with a later frame of the same turn.
        if let Some(asked) = &mut self.in_flight {
            asked.before = self.live.received_before(self.request_mark).saturating_sub(self.head);
        }
        let Some(asked) = &self.in_flight else {
            return Ok(Ok(self.inbox.waiting_ping()));
        };
        let progress = self.inbox.progress(asked);
        if let Ok(Some(Progress::Response(_))) = &progress {
            self.in_flight = None;
        }
        Ok(progress)
    }
}
