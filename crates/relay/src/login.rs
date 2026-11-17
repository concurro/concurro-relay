//! Registering the relay to a person's Concurro account, and withdrawing
//! the registration.

use std::time::Duration;

use anyhow::{Result, bail};
use concurro_relay_protocol::{
    identity::Identity,
    link::{self, Answer, DeviceCode, Hello, PROTOCOL_VERSION, Refusal},
    route::Route,
};
use tokio::time::{self, Instant};

use crate::{
    state::{Registration, Store},
    transport::Server,
};

/// A registration waiting for the person's approval.
pub struct Pending {
    server: Server,
    name: String,
    routes: Vec<Route>,
    private_key: Vec<u8>,
    /// What the person needs in order to approve.
    pub device: DeviceCode,
}

/// Asks `server` to register a relay called `name` for `routes`, under a
/// new key.
pub async fn begin(server: Server, name: String, routes: Vec<Route>) -> Result<Pending> {
    let (identity, private_key) = Identity::generate()?;
    let registration = link::Registration {
        version: PROTOCOL_VERSION,
        name: name.clone(),
        public_key: identity.public_key(),
        routes: routes.clone(),
    };
    let mut connection = server.connect().await?;
    match link::greet(&mut connection, &Hello::Register(registration)).await? {
        Answer::DeviceCode(device) => Ok(Pending {
            server,
            name,
            routes,
            private_key,
            device,
        }),
        Answer::Refused(reason) => bail!(Refusal(reason)),
        other => bail!("Concurro answered a registration with {other:?}"),
    }
}

impl Pending {
    /// Waits for the person to approve the registration, then saves it and
    /// its key in `store`.
    pub async fn approved(self, store: &Store) -> Result<Registration> {
        let expires = Instant::now() + Duration::from_secs(self.device.expires_secs);
        let interval = Duration::from_secs(self.device.interval_secs.max(1));
        loop {
            time::sleep(interval).await;
            if Instant::now() >= expires {
                bail!("the code expired before it was approved");
            }
            let mut connection = self.server.connect().await?;
            let poll = Hello::Poll {
                device_code: self.device.device_code.clone(),
            };
            let registered = match link::greet(&mut connection, &poll).await? {
                Answer::Pending => continue,
                Answer::Registered(registered) => registered,
                Answer::Refused(reason) => bail!(Refusal(reason)),
                other => bail!("Concurro answered a poll with {other:?}"),
            };
            let registration = Registration {
                server: self.server,
                relay: registered.relay,
                login: registered.login,
                name: self.name,
                routes: self.routes,
            };
            store.save(&registration, &self.private_key)?;
            return Ok(registration);
        }
    }
}

/// Withdraws the registration in `store` from Concurro and removes it and
/// its key. Returns whether there was one.
///
/// The local state is removed even if Concurro cannot be told, so that a
/// relay can always be signed out.
pub async fn logout(store: &Store) -> Result<bool> {
    let Some((registration, identity)) = store.load()? else {
        return Ok(false);
    };
    let withdrawn = async {
        let mut connection = registration.server.connect().await?;
        link::present(
            &mut connection,
            &Hello::Deregister {
                relay: registration.relay.clone(),
            },
            &identity,
        )
        .await
    };
    let withdrawn = withdrawn.await;
    store.clear()?;
    withdrawn.map(|()| true)
}
