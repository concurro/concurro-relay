//! Receives the connections relays open: registers relays, and pairs the
//! two connections of a link once the relay has proven its identity on
//! each.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use concurro_relay_protocol::{
    link::{self, Answer, DeviceCode, Hello, PROTOCOL_VERSION, Registered, Registration, Role},
    wire,
};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc::UnboundedSender,
    time,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// How long a relay has to say what a new connection is for and, where it
/// must, prove its identity.
const HELLO_LIMIT: Duration = Duration::from_secs(10);

/// How long accepting connections pauses after an accept error, such as
/// running out of file descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// How long connections may take to get going. Each may be set; the
/// defaults suit relays on ordinary networks.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// For a connection to finish its TLS handshake.
    pub handshake: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
        }
    }
}

/// TCP keepalive on relay connections: a vanished relay's idle link ends
/// within about a minute instead of looking connected indefinitely.
const KEEPALIVE: TcpKeepalive = TcpKeepalive::new()
    .with_time(Duration::from_secs(30))
    .with_interval(Duration::from_secs(10))
    .with_retries(3);

/// What a verifier knows of the relays registered with it.
pub trait Registry: Send + Sync + 'static {
    /// Starts a registration, returning how the person approves it.
    fn register(&self, registration: Registration) -> Result<DeviceCode, String>;

    /// The registration `device_code` names, once the person has approved
    /// it.
    fn poll(&self, device_code: &str) -> Result<Option<Registered>, String>;

    /// The public key of the registered relay `relay`.
    fn public_key(&self, relay: &str) -> Option<Vec<u8>>;

    /// Durably forgets the relay `relay`, or reports why it could not.
    fn deregister(&self, relay: &str) -> Result<(), String>;
}

/// A link whose relay has proven its identity on both connections.
pub struct Accepted<S> {
    pub relay: String,
    /// Random number pairing the link's two authenticated streams.
    pub number: u64,
    /// Stable Sponsor link slot across reconnects.
    pub slot: u32,
    /// Carries jobs and the relay's answers.
    pub control: S,
    /// Carries the proof session.
    pub proofs: S,
}

/// Receives relays' connections.
pub struct Acceptor<R, S> {
    registry: Arc<R>,
    /// The first connection of each link whose second has not arrived, by
    /// relay, random link number, and stable slot.
    halves: Mutex<HashMap<(String, u64, u32), (Role, S)>>,
    ready: UnboundedSender<Accepted<S>>,
    limits: Limits,
}

fn outdated(version: u32) -> Option<String> {
    (version != PROTOCOL_VERSION).then(|| {
        format!("this relay speaks protocol version {version} and Concurro version {PROTOCOL_VERSION}; update concurro-relay")
    })
}

impl<R, S> Acceptor<R, S>
where
    R: Registry,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// An acceptor which sends each link it has paired on `ready`.
    pub fn new(registry: Arc<R>, ready: UnboundedSender<Accepted<S>>) -> Self {
        Self {
            registry,
            halves: Mutex::default(),
            ready,
            limits: Limits::default(),
        }
    }

    /// This acceptor with `limits` instead of the defaults.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Handles one connection from its first message.
    pub async fn accept(&self, stream: S) -> Result<()> {
        time::timeout(HELLO_LIMIT, self.greet(stream))
            .await
            .context("relay did not identify itself in time")?
    }

    async fn greet(&self, mut stream: S) -> Result<()> {
        let hello: Hello = wire::recv(&mut stream).await?;
        let answer = match &hello {
            Hello::Register(registration) => match outdated(registration.version) {
                Some(reason) => Answer::Refused(reason),
                None => self
                    .registry
                    .register(registration.clone())
                    .map_or_else(Answer::Refused, Answer::DeviceCode),
            },
            Hello::Poll { device_code } => match self.registry.poll(device_code) {
                Ok(Some(registered)) => Answer::Registered(registered),
                Ok(None) => Answer::Pending,
                Err(reason) => Answer::Refused(reason),
            },
            Hello::Deregister { relay } => match self.proven(&mut stream, &hello, relay).await? {
                Ok(()) => {
                    let registry = self.registry.clone();
                    let relay = relay.clone();
                    match tokio::task::spawn_blocking(move || registry.deregister(&relay)).await {
                        Ok(Ok(())) => Answer::Welcome,
                        Ok(Err(reason)) => Answer::Refused(reason),
                        Err(error) => {
                            Answer::Refused(format!("registry withdrawal failed: {error}"))
                        }
                    }
                }
                Err(reason) => Answer::Refused(reason),
            },
            Hello::Link {
                version,
                relay,
                link,
                slot,
                role,
            } => {
                let proven = match outdated(*version) {
                    Some(reason) => Err(reason),
                    None => self.proven(&mut stream, &hello, relay).await?,
                };
                if let Err(reason) = proven {
                    return wire::send(&mut stream, &Answer::Refused(reason)).await;
                }
                wire::send(&mut stream, &Answer::Welcome).await?;
                self.pair(relay.clone(), *link, *slot, *role, stream);
                return Ok(());
            }
        };
        wire::send(&mut stream, &answer).await
    }

    /// Has the relay which sent `hello` prove that it is the registered
    /// relay `relay`.
    async fn proven(
        &self,
        stream: &mut S,
        hello: &Hello,
        relay: &str,
    ) -> Result<Result<(), String>> {
        let Some(public_key) = self.registry.public_key(relay) else {
            return Ok(Err(
                "this relay is not registered; run `concurro-relay login`".into(),
            ));
        };
        let proven = link::challenge(stream, hello, &public_key).await?;
        Ok(if proven {
            Ok(())
        } else {
            Err("the relay's key is not the one it registered".into())
        })
    }

    /// Keeps `stream` until its link's other connection arrives, or pairs
    /// it with the one already waiting.
    fn pair(&self, relay: String, link: u64, slot: u32, role: Role, stream: S) {
        let mut halves = self.halves.lock().expect("lock is not poisoned");
        let key = (relay, link, slot);
        let (control, proofs) = match halves.remove(&key) {
            Some((other_role, other)) if other_role != role => match role {
                Role::Control => (stream, other),
                Role::Proofs => (other, stream),
            },
            // A repeated role replaces the connection which was waiting.
            _ => {
                halves.insert(key, (role, stream));
                return;
            }
        };
        let _ = self.ready.send(Accepted {
            relay: key.0,
            number: key.1,
            slot: key.2,
            control,
            proofs,
        });
    }
}

/// The next connection on `listener`. An accept error, such as running out
/// of file descriptors, is reported and retried after a pause, so that the
/// listener keeps serving once the cause passes.
pub async fn next_connection(listener: &TcpListener) -> TcpStream {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => return stream,
            Err(error) => {
                eprintln!("accepting a connection failed: {error}");
                time::sleep(ACCEPT_PAUSE).await;
            }
        }
    }
}

/// Accepts relays' connections on `listener`, secured by `tls`, for as long
/// as it runs.
pub async fn serve<R: Registry>(
    listener: TcpListener,
    tls: TlsAcceptor,
    acceptor: Arc<Acceptor<R, TlsStream<TcpStream>>>,
) {
    loop {
        let stream = next_connection(&listener).await;
        let (tls, acceptor) = (tls.clone(), acceptor.clone());
        tokio::spawn(async move {
            if stream.set_nodelay(true).is_err()
                || SockRef::from(&stream)
                    .set_tcp_keepalive(&KEEPALIVE)
                    .is_err()
            {
                return;
            }
            let handshake = time::timeout(acceptor.limits.handshake, tls.accept(stream));
            if let Ok(Ok(stream)) = handshake.await {
                let _ = acceptor.accept(stream).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use concurro_relay_protocol::link::{DeviceCode, Registered, Registration};
    use rustls::{
        ServerConfig,
        crypto::ring,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, TcpStream},
        sync::mpsc,
        time,
    };
    use tokio_rustls::TlsAcceptor;

    use super::{Acceptor, Limits, Registry, serve};

    /// Knows no relays.
    struct Empty;

    impl Registry for Empty {
        fn register(&self, _: Registration) -> Result<DeviceCode, String> {
            Err("closed".into())
        }
        fn poll(&self, _: &str) -> Result<Option<Registered>, String> {
            Err("closed".into())
        }
        fn public_key(&self, _: &str) -> Option<Vec<u8>> {
            None
        }
        fn deregister(&self, _: &str) -> Result<(), String> {
            Err("closed".into())
        }
    }

    fn tls() -> TlsAcceptor {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    /// A connection which never starts its TLS handshake is closed once the
    /// handshake limit passes.
    #[tokio::test]
    async fn a_silent_connection_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, _accepted) = mpsc::unbounded_channel();
        let acceptor = Acceptor::new(Arc::new(Empty), ready).with_limits(Limits {
            handshake: Duration::from_millis(200),
        });
        tokio::spawn(serve(listener, tls(), Arc::new(acceptor)));
        let mut silent = TcpStream::connect(address).await.unwrap();
        let mut byte = [0];
        let closed = time::timeout(Duration::from_secs(5), silent.read(&mut byte)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
    }
}
