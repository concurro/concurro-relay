//! How a relay registers with a verifier and opens its links.
//!
//! Every connection a relay opens begins with a [`Hello`]. A link is two
//! such connections sharing a link number: one carries the verifier's
//! orders and the relay's notices, the other the proof session.

use anyhow::{Result, bail};
use futures::{Stream, stream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    identity::{self, Identity},
    route::Route,
    wire::{self, Job, Offer},
};

/// Version of these messages and of the proof stack beneath them. A relay
/// and a verifier work together only at the same version.
pub const PROTOCOL_VERSION: u32 = 6;

/// What the verifier tells the relay to do on a link.
///
/// The verifier orders everything the relay sends to a provider. The relay
/// answers each order with a [`Notice`]: it refuses, or says when it is
/// ready to prove what the order led to, so the verifier never waits on a
/// proof which is not coming.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Order {
    /// Start one native TLS 1.3 session on the authenticated link pair.
    NativeStart {
        route: Route,
        provider_host: String,
        provider_port: u16,
    },
    /// Perform one request on a provider connection of its own, and prove
    /// the exchange.
    Job(Job),
    /// Open a WebSocket connection to the provider with the upgrade
    /// request for `job`, and prove the upgrade.
    Open { job: Job, key: String },
    /// On the open connection, send `text` as one text frame masked with
    /// `mask`.
    Request { text: String, mask: [u8; 4] },
    /// On the open connection, answer the ping which carried `payload`.
    Pong { payload: Vec<u8>, mask: [u8; 4] },
    /// Prove what the provider sent on the open connection while no
    /// request was in flight.
    Report,
    /// Close the open connection.
    Close,
}

/// What the relay tells the verifier on a link.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Notice {
    /// The Sponsor has admitted a native TLS 1.3 session.
    NativeReady,
    /// The job or connection ordered will be performed with these
    /// additions to its request.
    Offer(Offer),
    /// The order was not carried out, and nothing was sent for it.
    Refused(String),
    /// The order was carried out and its proof begins.
    Proving,
    /// The provider sent a ping while no order was being carried out.
    PingWaiting,
}

/// The messages arriving on `stream`. Dropping a wait for the next one
/// loses nothing.
pub fn incoming<S, T>(stream: S) -> impl Stream<Item = Result<T>>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    stream::try_unfold(stream, |mut stream| async move {
        let message = wire::recv(&mut stream).await?;
        Ok(Some((message, stream)))
    })
}

/// Which of a link's two connections this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Carries jobs and the relay's answers.
    Control,
    /// Carries the proof session.
    Proofs,
}

/// A relay asking to be registered to a person's account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub version: u32,
    /// What the person will recognize the relay by, such as its host name.
    pub name: String,
    pub public_key: Vec<u8>,
    pub routes: Vec<Route>,
}

/// How a person approves a registration, and how the relay asks whether
/// they have.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceCode {
    /// Identifies the registration to the verifier; not shown.
    pub device_code: String,
    /// What the person enters at `verification_uri`.
    pub user_code: String,
    pub verification_uri: String,
    pub interval_secs: u64,
    pub expires_secs: u64,
}

/// An approved registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// The verifier's name for the relay.
    pub relay: String,
    /// The account the relay was registered to.
    pub login: String,
}

/// The first message on every connection a relay opens.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Hello {
    /// Answered with [`Answer::DeviceCode`].
    Register(Registration),
    /// Asks whether a registration was approved. Answered with
    /// [`Answer::Pending`] or [`Answer::Registered`].
    Poll { device_code: String },
    /// Opens one connection of a link. The relay must then prove it holds
    /// its key.
    Link {
        version: u32,
        relay: String,
        /// Random number pairing this link's control and proof streams.
        link: u64,
        /// Stable Sponsor link slot across reconnects.
        slot: u32,
        role: Role,
    },
    /// Withdraws a registration. The relay must then prove it holds its key.
    Deregister { relay: String },
}

/// What a verifier says to a relay before a connection is put to use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Answer {
    DeviceCode(DeviceCode),
    Pending,
    Registered(Registered),
    /// To be signed along with the [`Hello`] it answers.
    Challenge([u8; 32]),
    Welcome,
    Refused(String),
}

/// A relay's signature answering an [`Answer::Challenge`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub signature: Vec<u8>,
}

/// What a relay signs to answer `challenge` for `hello`.
fn signed(challenge: &[u8; 32], hello: &Hello) -> Vec<u8> {
    let mut message = b"concurro-relay hello\0".to_vec();
    message.extend_from_slice(challenge);
    message.extend(serde_json::to_vec(hello).expect("a hello serializes"));
    message
}

/// Sends `hello` on a new connection and returns the verifier's answer.
pub async fn greet<S>(stream: &mut S, hello: &Hello) -> Result<Answer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    wire::send(stream, hello).await?;
    wire::recv(stream).await
}

/// Sends `hello` on a new connection and proves to the verifier that the
/// relay holds `identity`. Returns once the verifier has welcomed it.
pub async fn present<S>(stream: &mut S, hello: &Hello, identity: &Identity) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge = match greet(stream, hello).await? {
        Answer::Challenge(challenge) => challenge,
        Answer::Refused(reason) => bail!(Refusal(reason)),
        other => bail!("verifier answered a hello with {other:?}"),
    };
    wire::send(
        stream,
        &Proof {
            signature: identity.sign(&signed(&challenge, hello)),
        },
    )
    .await?;
    match wire::recv(stream).await? {
        Answer::Welcome => Ok(()),
        Answer::Refused(reason) => bail!(Refusal(reason)),
        other => bail!("verifier answered a proof with {other:?}"),
    }
}

/// Challenges the relay which sent `hello` to prove it holds the private
/// key for `public_key`, and returns whether it did.
pub async fn challenge<S>(stream: &mut S, hello: &Hello, public_key: &[u8]) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge = identity::random();
    wire::send(stream, &Answer::Challenge(challenge)).await?;
    let proof: Proof = wire::recv(stream).await?;
    Ok(identity::verify(
        public_key,
        &signed(&challenge, hello),
        &proof.signature,
    ))
}

/// A verifier's refusal of a relay, which trying again will not change.
#[derive(Debug)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused by Concurro: {}", self.0)
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use tokio::io;

    use super::*;

    fn link(relay: &str) -> Hello {
        Hello::Link {
            version: PROTOCOL_VERSION,
            relay: relay.into(),
            link: 1,
            slot: 1,
            role: Role::Control,
        }
    }

    /// Runs both ends of a challenge, the verifier judging `judged` while
    /// the relay presents `presented`.
    async fn challenged(
        presented: Hello,
        judged: Hello,
        identity: &Identity,
        public_key: &[u8],
    ) -> bool {
        let (mut relay, mut verifier) = io::duplex(4096);
        let verify = async {
            let _: Hello = wire::recv(&mut verifier).await.unwrap();
            let proven = challenge(&mut verifier, &judged, public_key).await.unwrap();
            let answer = if proven {
                Answer::Welcome
            } else {
                Answer::Refused("unknown relay".into())
            };
            wire::send(&mut verifier, &answer).await.unwrap();
            proven
        };
        let (presented, proven) = tokio::join!(present(&mut relay, &presented, identity), verify);
        assert_eq!(presented.is_ok(), proven);
        proven
    }

    #[tokio::test]
    async fn challenge_accepts_only_the_registered_key_for_the_same_hello() {
        let (identity, _) = Identity::generate().unwrap();
        let (other, _) = Identity::generate().unwrap();
        assert!(challenged(link("a"), link("a"), &identity, &identity.public_key()).await);
        assert!(!challenged(link("a"), link("a"), &other, &identity.public_key()).await);
        // A signature for one hello does not serve for another.
        assert!(!challenged(link("a"), link("b"), &identity, &identity.public_key()).await);
        let mut other_slot = link("a");
        if let Hello::Link { slot, .. } = &mut other_slot {
            *slot = 2;
        }
        assert!(!challenged(link("a"), other_slot, &identity, &identity.public_key()).await);
    }
}
