//! Keeps the relay's links to Concurro open.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use concurro_relay_protocol::{
    identity::{self, Identity},
    link::{self, Hello, PROTOCOL_VERSION, Refusal, Role},
    meter::{Counters, Metered},
};
use tokio::{sync::mpsc::UnboundedSender, time};

use crate::{
    events::{Event, LinkState},
    serve::{self, RelayConfig},
    state::Registration,
    transport::Connection,
};

/// Pause before a link is opened again after it ended, and the longest
/// that pause grows to while the link keeps failing.
const RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Who the relay is to Concurro.
pub struct Relay {
    pub registration: Registration,
    pub identity: Identity,
    pub config: RelayConfig,
}

impl Relay {
    /// Opens one connection of link `number` and proves the relay's
    /// identity on it.
    async fn connect(&self, number: u64, role: Role) -> Result<Connection> {
        let mut connection = self.registration.server.connect().await?;
        let hello = Hello::Link { version: PROTOCOL_VERSION, relay: self.registration.relay.clone(), link: number, role };
        link::present(&mut connection, &hello, &self.identity).await?;
        Ok(connection)
    }

    /// Opens a link and serves it until it ends.
    async fn serve(&self, link: usize, events: &UnboundedSender<Event>) -> Result<usize> {
        let number = u64::from_be_bytes(identity::random());
        let control = self.connect(number, Role::Control).await?;
        let proofs = self.connect(number, Role::Proofs).await?;
        let _ = events.send(Event::Link { link, state: LinkState::Up });
        let traffic = Counters::default();
        serve::serve_link(control, Metered::new(proofs, traffic.clone()), &self.config, link, &traffic, events).await
    }

    /// Keeps link `link` open, opening it again whenever it ends, until
    /// Concurro refuses the relay.
    async fn keep(&self, link: usize, events: UnboundedSender<Event>) {
        let mut delay = RETRY_DELAY;
        loop {
            let _ = events.send(Event::Link { link, state: LinkState::Connecting });
            let state = match self.serve(link, &events).await {
                // A link which did work ends for reasons of its own.
                Ok(served) => {
                    delay = if served > 0 { RETRY_DELAY } else { delay };
                    LinkState::Down("Concurro closed the link".into())
                }
                Err(error) => match error.downcast_ref::<Refusal>() {
                    Some(Refusal(reason)) => LinkState::Refused(reason.clone()),
                    None => LinkState::Down(format!("{error:#}")),
                },
            };
            let refused = matches!(state, LinkState::Refused(_));
            if events.send(Event::Link { link, state }).is_err() || refused {
                return;
            }
            time::sleep(delay).await;
            delay = (delay * 2).min(MAX_RETRY_DELAY);
        }
    }
}

/// Keeps `links` links open for `relay`, reporting to `events`, until every
/// one of them has been refused.
pub async fn run(relay: Arc<Relay>, links: usize, events: UnboundedSender<Event>) {
    let workers: Vec<_> = (1..=links)
        .map(|link| {
            let (relay, events) = (relay.clone(), events.clone());
            tokio::spawn(async move { relay.keep(link, events).await })
        })
        .collect();
    for worker in workers {
        let _ = worker.await;
    }
}
