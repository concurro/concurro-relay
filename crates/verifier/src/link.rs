//! The verifier's end of a relay link: orders the relay to perform single
//! requests and to carry a harness's WebSocket connections, and verifies
//! the proof of each.

use std::{pin::Pin, time::Duration};

use anyhow::{Context, Error, Result, anyhow, bail};
use concurro_relay_protocol::{
    identity,
    link::{self, Notice, Order},
    meter::Counters,
    wire::{self, Job},
    ws::{self, Progress},
};
use futures::{SinkExt, Stream, StreamExt};
use serde_json::{Value, json};
use tlsn::{Session, SessionHandle};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, WriteHalf},
    task::JoinHandle,
    time::{self, Instant},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::client},
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    exchange::{self, Expect, Pending, Verdict},
    ws::WsVerifier,
};

/// Longest the relay may take to answer an order, which includes the
/// provider's time to respond.
const ANSWER_LIMIT: Duration = Duration::from_secs(600);

/// Longest the relay may take to close a provider connection.
const CLOSE_LIMIT: Duration = Duration::from_secs(30);

/// Start of a relay's refusal of a message continuing a response which it
/// did not receive on the same connection.
const UNKNOWN_RESPONSE: &str = "response was not received on this connection";

/// A relay link, whose proofs share one session so that only the first
/// pays the OT bootstrap.
pub struct Link<C> {
    orders: WriteHalf<C>,
    notices: Pin<Box<dyn Stream<Item = Result<Notice>> + Send>>,
    handle: SessionHandle,
    driver: JoinHandle<()>,
}

impl<C> Link<C>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Creates a link from the relay's two connections: `control` carries
    /// orders and notices, and `proofs` carries the proof session.
    pub fn new<P>(control: C, proofs: P) -> Self
    where
        P: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (driver, handle) = Session::new(proofs.compat()).split();
        let driver = tokio::spawn(async move {
            let _ = driver.await;
        });
        let (notices, orders) = io::split(control);
        Self { orders, notices: Box::pin(link::incoming(notices)), handle, driver }
    }

    /// Gives the relay `order` and returns its answer.
    async fn order(&mut self, order: &Order) -> Result<Notice> {
        wire::send(&mut self.orders, order).await?;
        let answer = async {
            loop {
                match self.notices.next().await.context("relay ended the link")?? {
                    // Sent before the relay read the order. The ping is
                    // part of what the order's proof covers.
                    Notice::PingWaiting => {}
                    answer => return Ok(answer),
                }
            }
        };
        time::timeout(ANSWER_LIMIT, answer).await.context("relay did not answer in time")?
    }

    /// Gives the relay `order`, which leads to a proof unless the relay
    /// refuses it.
    async fn order_proof(&mut self, order: &Order) -> Result<Result<(), String>> {
        match self.order(order).await? {
            Notice::Proving => Ok(Ok(())),
            Notice::Refused(reason) => Ok(Err(reason)),
            other => bail!("relay answered an order with {other:?}"),
        }
    }

    /// Asks the relay to perform `job` and verifies the outcome.
    ///
    /// The link is handed back only when it is safe to use again. After a
    /// rejection or an error it is dropped, because its exchanges share
    /// proof state which a failed check must not be allowed to probe twice.
    pub async fn exchange(mut self, job: &Job, expect: &Expect) -> (Result<Verdict>, Option<Self>) {
        let offer = match self.order(&Order::Job(job.clone())).await {
            Ok(Notice::Offer(offer)) => offer,
            Ok(Notice::Refused(reason)) => return (Ok(Verdict::Refused(reason)), Some(self)),
            Ok(other) => return (Err(anyhow!("relay answered a job with {other:?}")), None),
            Err(error) => return (Err(error), None),
        };
        let pending = match Pending::new(job, &offer, expect) {
            Ok(pending) => pending,
            Err(reason) => return (Ok(Verdict::Rejected(reason)), None),
        };
        match exchange::verify(&mut self.handle, job, pending, expect).await {
            Ok(verdict @ Verdict::Verified(_)) => (Ok(verdict), Some(self)),
            outcome => (outcome, None),
        }
    }

    /// Has the relay answer pings until `progress` is the end of a
    /// response, which is returned, or no ping waits.
    async fn follow(&mut self, verifier: &mut WsVerifier, mut progress: Option<Progress>) -> Result<Option<Vec<Message>>> {
        loop {
            let payload = match progress {
                Some(Progress::Response(messages)) => return Ok(Some(messages)),
                Some(Progress::Ping(payload)) => payload,
                None => return Ok(None),
            };
            let mask = identity::random();
            let pong = Order::Pong { payload: payload.clone(), mask };
            self.order_proof(&pong).await?.map_err(|reason| anyhow!("relay refused a pong: {reason}"))?;
            progress = verifier.pong(&mut self.handle, &ws::pong_frame(&payload, mask)).await?.map_err(rejected)?;
        }
    }

    /// Carries the WebSocket connection `harness` to the provider with the
    /// upgrade request for `job`, until the harness is done with it. The
    /// link's traffic, which `traffic` counts, is logged for each turn
    /// under `label`.
    ///
    /// Each message of the harness is one turn, whose response the harness
    /// receives once it is verified. An error means the link must not be
    /// used again.
    pub async fn carry<H>(
        &mut self,
        harness: &mut WebSocketStream<H>,
        job: &Job,
        expect: &Expect,
        label: &str,
        traffic: &Counters,
    ) -> Result<()>
    where
        H: AsyncRead + AsyncWrite + Unpin,
    {
        let key = client::generate_key();
        let offer = match self.order(&Order::Open { job: job.clone(), key: key.clone() }).await? {
            Notice::Offer(offer) => offer,
            Notice::Refused(reason) => {
                eprintln!("{label} relay refused the connection: {reason}");
                return Ok(());
            }
            other => bail!("relay answered an order with {other:?}"),
        };
        let opened = Instant::now();
        let mut verifier =
            WsVerifier::open(&mut self.handle, job, &offer, &expect.relay_headers, &key, expect.provider, expect.roots)
                .await?
                .map_err(rejected)?;
        eprintln!("{label} provider accepted the upgrade, verified in {:.2}s", opened.elapsed().as_secs_f64());

        let mut turn = 0;
        loop {
            // Pings verified along with a response they did not interrupt.
            let waiting = verifier.waiting_ping();
            self.follow(&mut verifier, waiting).await?;
            let text = tokio::select! {
                message = harness.next() => match message {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    // The harness is done, however its connection ended.
                    _ => break,
                },
                notice = self.notices.next() => {
                    let Notice::PingWaiting = notice.context("relay ended the link")?? else {
                        bail!("relay sent a notice which answers no order");
                    };
                    if self.order_proof(&Order::Report).await?.is_ok() {
                        let progress = verifier.report(&mut self.handle).await?.map_err(rejected)?;
                        self.follow(&mut verifier, progress).await?;
                        eprintln!("{label} answered a ping between turns");
                    }
                    continue;
                }
            };

            turn += 1;
            let (started, up, down) = (Instant::now(), traffic.read(), traffic.written());
            let mask = identity::random();
            if let Err(reason) = self.order_proof(&Order::Request { text: text.to_string(), mask }).await? {
                eprintln!("{label} turn {turn} refused by the relay: {reason}");
                if harness.send(Message::text(refusal(&reason).to_string())).await.is_err() {
                    break;
                }
                continue;
            }
            let waited = started.elapsed();
            let progress = verifier.turn(&mut self.handle, &ws::text_frame(text.as_str(), mask)).await?.map_err(rejected)?;
            let messages = self.follow(&mut verifier, Some(progress)).await?.context("turn ended without a response")?;
            let events: Vec<Message> = messages.into_iter().filter(Message::is_text).collect();
            eprintln!(
                "{label} turn {turn} verified: sent {} bytes, received {} bytes in {} events, total {:.2}s of which {:.2}s after the response, relay→gateway {:.2} MB, gateway→relay {:.2} MB",
                text.len(),
                events.iter().map(Message::len).sum::<usize>(),
                events.len(),
                started.elapsed().as_secs_f64(),
                (started.elapsed() - waited).as_secs_f64(),
                (traffic.read() - up) as f64 / 1e6,
                (traffic.written() - down) as f64 / 1e6,
            );
            let mut delivered = true;
            for event in events {
                delivered = delivered && harness.send(event).await.is_ok();
            }
            if !delivered {
                break;
            }
        }

        wire::send(&mut self.orders, &Order::Close).await?;
        time::timeout(CLOSE_LIMIT, verifier.close()).await.context("relay did not close the connection in time")?
    }
}

impl<C> Drop for Link<C> {
    fn drop(&mut self) {
        self.handle.close();
        self.driver.abort();
    }
}

fn rejected(reason: String) -> Error {
    anyhow!("proof rejected: {reason}")
}

/// The event which tells the harness that its request was refused, in the
/// form the provider uses. A request continuing a response which is unknown
/// on this connection gets the provider's own code for that.
fn refusal(reason: &str) -> Value {
    let code = reason.starts_with(UNKNOWN_RESPONSE).then_some("previous_response_not_found");
    json!({
        "type": "error",
        "status": 400,
        "error": {
            "type": "invalid_request_error",
            "code": code,
            "message": format!("relay refused the request: {reason}"),
        },
    })
}
