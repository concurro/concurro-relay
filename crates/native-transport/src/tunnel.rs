//! Multiplex native helper TCP streams over one authenticated auxiliary link.

use std::{
    collections::HashMap,
    future::Future,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{self, Duration, Instant},
};

/// Maximum auxiliary frame payload accepted by the Python reference.
pub const MAX_PAYLOAD: usize = 65_536;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(90);

/// Auxiliary frame operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Register a Sponsor target port.
    Register = b'R',
    /// Acknowledge the Concurro listener port.
    Acknowledge = b'A',
    /// Open one logical TCP channel.
    Open = b'O',
    /// Forward bytes on a channel.
    Data = b'D',
    /// End one direction of a channel.
    End = b'E',
}

impl TryFrom<u8> for Kind {
    type Error = anyhow::Error;

    /// Reject unknown auxiliary operations.
    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            b'R' => Self::Register,
            b'A' => Self::Acknowledge,
            b'O' => Self::Open,
            b'D' => Self::Data,
            b'E' => Self::End,
            _ => bail!("unexpected native tunnel frame"),
        })
    }
}

/// One auxiliary link frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Frame operation.
    pub kind: Kind,
    /// Registration or channel number.
    pub channel: u32,
    /// Operation-specific bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Write one bounded frame in the Python wire format.
    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        self.validate()?;
        writer.write_all(&[self.kind as u8]).await?;
        writer.write_all(&self.channel.to_be_bytes()).await?;
        writer
            .write_all(&(self.payload.len() as u32).to_be_bytes())
            .await?;
        writer.write_all(&self.payload).await?;
        Ok(())
    }

    /// Read one complete frame across arbitrary input fragmentation.
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut header = [0; 9];
        reader
            .read_exact(&mut header)
            .await
            .context("native tunnel header")?;
        let kind = Kind::try_from(header[0])?;
        let channel = u32::from_be_bytes(header[1..5].try_into().unwrap());
        let length = u32::from_be_bytes(header[5..9].try_into().unwrap()) as usize;
        ensure!(length <= MAX_PAYLOAD, "native tunnel frame too large");
        let mut payload = vec![0; length];
        reader
            .read_exact(&mut payload)
            .await
            .context("native tunnel payload")?;
        let frame = Self {
            kind,
            channel,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }

    /// Enforce the existing operation payload shapes.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.payload.len() <= MAX_PAYLOAD,
            "native tunnel frame too large"
        );
        match self.kind {
            Kind::Register | Kind::Acknowledge => {
                ensure!(self.payload.len() == 2, "invalid native tunnel port")
            }
            Kind::Open => ensure!(
                self.payload.len() == 4,
                "invalid native tunnel registration"
            ),
            Kind::End => ensure!(self.payload.is_empty(), "invalid native tunnel EOF"),
            Kind::Data => {}
        }
        Ok(())
    }
}

/// Side of the authenticated helper tunnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Registers Sponsor-local helper listeners.
    Sponsor,
    /// Creates mapped listeners for Concurro-local helper connections.
    Concurro,
}

/// Ordered inbound channel data, with `None` indicating remote EOF.
type Inbound = mpsc::UnboundedSender<Option<Vec<u8>>>;
/// Registration acknowledgement or tunnel failure.
type Reply = oneshot::Sender<std::result::Result<u16, String>>;

/// Mutable registration and channel maps shared by tunnel tasks.
#[derive(Default)]
struct Shared {
    /// Sponsor target port by registration number.
    registrations: HashMap<u32, u16>,
    /// Pending Sponsor registration replies.
    acknowledgements: HashMap<u32, Reply>,
    /// Mapped Concurro listener port by Sponsor target port.
    targets: HashMap<u16, u16>,
    /// Inbound queue by channel number.
    channels: HashMap<u32, Inbound>,
    /// Concurro listener tasks.
    listeners: Vec<JoinHandle<()>>,
    /// Terminal link error shared with pending callers.
    error: Option<String>,
}

/// Link writer and session state shared across channel tasks.
struct Inner {
    /// Which side handles registration and open frames.
    role: Role,
    /// Serialized auxiliary link writer.
    writer: Mutex<Box<dyn AsyncWrite + Unpin + Send>>,
    /// Mutable channel and listener state.
    shared: StdMutex<Shared>,
    /// Next registration or channel number.
    next_id: AtomicU32,
    /// Wake Concurro target waiters.
    targets_changed: Notify,
    /// Wake channel and listener tasks during cancellation.
    closed: Notify,
    /// Whether terminal cleanup already ran.
    stopped: AtomicBool,
}

/// Fail the link if a frame write is dropped before it completes.
struct FrameWriteGuard<'a> {
    /// Tunnel whose framing may have been interrupted.
    inner: &'a Inner,
    /// Whether the frame write is still in progress.
    armed: bool,
}

impl Drop for FrameWriteGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.inner
                .fail("native tunnel frame write interrupted".to_owned());
        }
    }
}

impl Inner {
    /// Complete an I/O operation only while the tunnel remains active.
    async fn until_closed<T>(&self, operation: impl Future<Output = Result<T>>) -> Result<T> {
        let closed = self.closed.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        ensure!(!self.stopped.load(Ordering::SeqCst), "native tunnel closed");
        tokio::select! {
            biased;
            _ = &mut closed => bail!("native tunnel closed"),
            result = operation => {
                let value = result?;
                ensure!(!self.stopped.load(Ordering::SeqCst), "native tunnel closed");
                Ok(value)
            }
        }
    }

    /// Send one frame without interleaving another channel's bytes.
    async fn send(&self, kind: Kind, channel: u32, payload: Vec<u8>) -> Result<()> {
        let result = self
            .until_closed(async {
                let mut writer = self.writer.lock().await;
                ensure!(!self.stopped.load(Ordering::SeqCst), "native tunnel closed");
                let mut guard = FrameWriteGuard {
                    inner: self,
                    armed: true,
                };
                let result = Frame {
                    kind,
                    channel,
                    payload,
                }
                .write(&mut *writer)
                .await;
                if let Err(error) = &result {
                    self.fail(error.to_string());
                }
                guard.armed = false;
                result
            })
            .await;
        if let Err(error) = &result {
            self.fail(error.to_string());
        }
        result
    }

    /// Stop listeners and wake every pending registration or channel.
    fn fail(&self, error: String) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut shared = self.shared.lock().unwrap();
        shared.error = Some(error.clone());
        for (_, reply) in shared.acknowledgements.drain() {
            let _ = reply.send(Err(error.clone()));
        }
        shared.registrations.clear();
        shared.targets.clear();
        for listener in shared.listeners.drain(..) {
            listener.abort();
        }
        for channel in shared.channels.values() {
            let _ = channel.send(None);
        }
        self.targets_changed.notify_waiters();
        self.closed.notify_waiters();
    }

    /// Allocate a registration or channel identifier.
    fn number(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Queue inbound bytes before a delayed local target connects.
    fn prepare_channel(&self, number: u32) -> mpsc::UnboundedReceiver<Option<Vec<u8>>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.shared.lock().unwrap().channels.insert(number, sender);
        receiver
    }
}

/// Active auxiliary tunnel with independent channel pumps.
pub struct Tunnel {
    /// Shared tunnel state.
    inner: Arc<Inner>,
    /// Auxiliary link reader task.
    reader: JoinHandle<()>,
}

impl Tunnel {
    /// Start receiving frames without blocking helper calls.
    pub fn start<T>(link: T, role: Role) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read, write) = tokio::io::split(link);
        let inner = Arc::new(Inner {
            role,
            writer: Mutex::new(Box::new(write)),
            shared: StdMutex::new(Shared::default()),
            next_id: AtomicU32::new(1),
            targets_changed: Notify::new(),
            closed: Notify::new(),
            stopped: AtomicBool::new(false),
        });
        let receiving = inner.clone();
        let reader = tokio::spawn(async move {
            let outcome = read_loop(read, receiving.clone()).await;
            receiving.fail(outcome.err().map_or_else(
                || "authenticated tunnel link closed".to_owned(),
                |error| error.to_string(),
            ));
        });
        Self { inner, reader }
    }

    /// Expose a Sponsor-local service on a Concurro-local port.
    pub async fn register(&self, target_port: u16) -> Result<u16> {
        ensure!(
            self.inner.role == Role::Sponsor,
            "only Sponsor registers native listeners"
        );
        let number = self.inner.number();
        let (sender, receiver) = oneshot::channel();
        {
            let mut shared = self.inner.shared.lock().unwrap();
            if let Some(error) = &shared.error {
                bail!("{error}");
            }
            shared.registrations.insert(number, target_port);
            shared.acknowledgements.insert(number, sender);
        }
        match time::timeout(REGISTRATION_TIMEOUT, async {
            self.inner
                .send(Kind::Register, number, target_port.to_be_bytes().to_vec())
                .await?;
            receiver.await?.map_err(anyhow::Error::msg)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.inner
                    .fail("native tunnel registration timed out".to_owned());
                bail!("native tunnel registration timed out")
            }
        }
    }

    /// Wait for a mapped listener corresponding to a Sponsor target.
    pub async fn wait_target(&self, target_port: u16) -> Result<u16> {
        ensure!(
            self.inner.role == Role::Concurro,
            "only Concurro waits for registered targets"
        );
        time::timeout(REGISTRATION_TIMEOUT, async {
            loop {
                let notified = self.inner.targets_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let shared = self.inner.shared.lock().unwrap();
                    if let Some(error) = &shared.error {
                        bail!("{error}");
                    }
                    if let Some(port) = shared.targets.get(&target_port) {
                        return Ok(*port);
                    }
                }
                notified.await;
            }
        })
        .await
        .context("native tunnel target registration timed out")?
    }

    /// Cancel active listeners and wake pending helper calls.
    pub fn cancel(&self) {
        self.inner.fail("native tunnel closed".to_owned());
        self.reader.abort();
    }

    /// End the tunnel and its helper listeners.
    pub fn close(self) {
        self.cancel();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.inner.fail("native tunnel closed".to_owned());
        self.reader.abort();
    }
}

/// Dispatch link frames while individual local connects run independently.
async fn read_loop<R: AsyncRead + Unpin>(mut read: R, inner: Arc<Inner>) -> Result<()> {
    loop {
        let frame = inner.until_closed(Frame::read(&mut read)).await?;
        match (inner.role, frame.kind) {
            (Role::Concurro, Kind::Register) => {
                let target = u16::from_be_bytes(frame.payload.try_into().unwrap());
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let port = listener.local_addr()?.port();
                let registration = frame.channel;
                {
                    inner.shared.lock().unwrap().targets.insert(target, port);
                }
                inner.targets_changed.notify_waiters();
                let serving = inner.clone();
                let task = tokio::spawn(async move {
                    if let Err(error) = accept_loop(listener, registration, serving.clone()).await {
                        serving.fail(error.to_string());
                    }
                });
                inner.shared.lock().unwrap().listeners.push(task);
                inner
                    .send(Kind::Acknowledge, registration, port.to_be_bytes().to_vec())
                    .await?;
            }
            (Role::Sponsor, Kind::Acknowledge) => {
                let port = u16::from_be_bytes(frame.payload.try_into().unwrap());
                let reply = inner
                    .shared
                    .lock()
                    .unwrap()
                    .acknowledgements
                    .remove(&frame.channel)
                    .context("unknown native tunnel acknowledgement")?;
                let _ = reply.send(Ok(port));
            }
            (Role::Sponsor, Kind::Open) => {
                let registration = u32::from_be_bytes(frame.payload.try_into().unwrap());
                let target = *inner
                    .shared
                    .lock()
                    .unwrap()
                    .registrations
                    .get(&registration)
                    .context("unknown native tunnel registration")?;
                let receiver = inner.prepare_channel(frame.channel);
                let connecting = inner.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        connect_target(connecting.clone(), frame.channel, target, receiver).await
                    {
                        connecting.fail(error.to_string());
                    }
                });
            }
            (_, Kind::Data | Kind::End) => {
                let sender = inner
                    .shared
                    .lock()
                    .unwrap()
                    .channels
                    .get(&frame.channel)
                    .cloned()
                    .context("unknown native tunnel channel")?;
                sender
                    .send((frame.kind == Kind::Data).then_some(frame.payload))
                    .map_err(|_| anyhow::anyhow!("native tunnel channel closed"))?;
            }
            _ => bail!("unexpected native tunnel frame for role"),
        }
    }
}

/// Accept Concurro-local helper connections without blocking link reads.
async fn accept_loop(listener: TcpListener, registration: u32, inner: Arc<Inner>) -> Result<()> {
    loop {
        let (socket, _) = inner
            .until_closed(async { Ok(listener.accept().await?) })
            .await?;
        let number = inner.number();
        let receiver = inner.prepare_channel(number);
        let (ready, started) = oneshot::channel();
        pump_channel(inner.clone(), number, socket, receiver, Some(started));
        inner
            .send(Kind::Open, number, registration.to_be_bytes().to_vec())
            .await?;
        let _ = ready.send(());
    }
}

/// Retry a Sponsor target independently of all other channels.
async fn connect_target(
    inner: Arc<Inner>,
    number: u32,
    target: u16,
    receiver: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
) -> Result<()> {
    let deadline = Instant::now() + REGISTRATION_TIMEOUT;
    loop {
        match inner
            .until_closed(async { Ok(TcpStream::connect((Ipv4Addr::LOCALHOST, target)).await?) })
            .await
        {
            Ok(socket) => {
                pump_channel(inner, number, socket, receiver, None);
                return Ok(());
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
                    && Instant::now() < deadline =>
            {
                inner
                    .until_closed(async {
                        time::sleep(Duration::from_millis(20)).await;
                        Ok(())
                    })
                    .await?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Pump both TCP directions and preserve a remote half-close.
fn pump_channel(
    inner: Arc<Inner>,
    number: u32,
    socket: TcpStream,
    mut inbound: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    ready: Option<oneshot::Receiver<()>>,
) {
    tokio::spawn(async move {
        let (mut read, mut write) = socket.into_split();
        {
            let outbound = async {
                if let Some(ready) = ready {
                    inner.until_closed(async { Ok(ready.await?) }).await?;
                }
                let mut buffer = vec![0; MAX_PAYLOAD];
                loop {
                    let count = inner
                        .until_closed(async { Ok(read.read(&mut buffer).await?) })
                        .await?;
                    if count == 0 {
                        inner.send(Kind::End, number, Vec::new()).await?;
                        return Ok::<(), anyhow::Error>(());
                    }
                    inner
                        .send(Kind::Data, number, buffer[..count].to_vec())
                        .await?;
                }
            };
            let incoming = async {
                loop {
                    let payload = inner
                        .until_closed(async { Ok(inbound.recv().await) })
                        .await?;
                    match payload {
                        Some(Some(bytes)) => {
                            inner
                                .until_closed(async { Ok(write.write_all(&bytes).await?) })
                                .await?
                        }
                        Some(None) => {
                            inner
                                .until_closed(async { Ok(write.shutdown().await?) })
                                .await?;
                            return Ok::<(), anyhow::Error>(());
                        }
                        None => return Ok(()),
                    }
                }
            };
            tokio::pin!(outbound, incoming);
            let mut sent_done = false;
            let mut received_done = false;
            while !sent_done || !received_done {
                tokio::select! {
                    sent = &mut outbound, if !sent_done => match sent {
                        Ok(()) => sent_done = true,
                        Err(error) => {
                            if !inner.stopped.load(Ordering::SeqCst) {
                                eprintln!("NATIVE_TUNNEL outbound {number}: {error:#}");
                            }
                            break;
                        }
                    },
                    received = &mut incoming, if !received_done => match received {
                        Ok(()) => received_done = true,
                        Err(error) => {
                            if !inner.stopped.load(Ordering::SeqCst) {
                                eprintln!("NATIVE_TUNNEL inbound {number}: {error:#}");
                            }
                            break;
                        }
                    },
                }
            }
        }
        inner.shared.lock().unwrap().channels.remove(&number);
    });
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    use super::{Role, Tunnel, pump_channel};

    /// Cancellation drops a channel blocked on link and TCP backpressure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_backpressured_pump_releases_socket() {
        let (link, _nonreading_peer) = tokio::io::duplex(1);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let inbound = tunnel.inner.prepare_channel(7);
        let sender = tunnel.inner.shared.lock().unwrap().channels[&7].clone();
        pump_channel(tunnel.inner.clone(), 7, socket, inbound, None);
        sender.send(Some(vec![b'z'; 8 * 1024 * 1024])).unwrap();
        client.write_all(b"outbound").await.unwrap();
        time::timeout(Duration::from_secs(1), async {
            while tunnel.inner.writer.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tunnel.cancel();
        time::timeout(Duration::from_secs(1), async {
            while tunnel
                .inner
                .shared
                .lock()
                .unwrap()
                .channels
                .contains_key(&7)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut received = Vec::new();
        time::timeout(Duration::from_secs(2), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
    }

    /// A local error after a partial frame fails the link and releases its channel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_write_error_releases_both_halves() {
        let (link, mut peer) = tokio::io::duplex(1);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let inbound = tunnel.inner.prepare_channel(8);
        let sender = tunnel.inner.shared.lock().unwrap().channels[&8].clone();
        pump_channel(tunnel.inner.clone(), 8, socket, inbound, None);
        client.write_all(b"outbound").await.unwrap();
        let mut first_byte = [0];
        time::timeout(Duration::from_secs(1), peer.read_exact(&mut first_byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_byte, [b'D']);
        drop(client);
        sender.send(Some(vec![b'z'; 8 * 1024 * 1024])).unwrap();
        time::timeout(Duration::from_secs(2), async {
            while tunnel
                .inner
                .shared
                .lock()
                .unwrap()
                .channels
                .contains_key(&8)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            tunnel
                .inner
                .stopped
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(tunnel.register(12345).await.is_err());
        time::timeout(Duration::from_secs(1), async {
            while !tunnel.reader.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tunnel.close();
    }

    /// Aborting a registration mid-frame fails the link before another registration.
    #[tokio::test]
    async fn aborted_registration_fails_partial_link() {
        let (link, mut peer) = tokio::io::duplex(1);
        let tunnel = std::sync::Arc::new(Tunnel::start(link, Role::Sponsor));
        let pending = tunnel.clone();
        let registration = tokio::spawn(async move { pending.register(12345).await });
        let mut first_byte = [0];
        time::timeout(Duration::from_secs(1), peer.read_exact(&mut first_byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_byte, [b'R']);
        registration.abort();
        assert!(registration.await.unwrap_err().is_cancelled());
        assert!(
            tunnel
                .inner
                .stopped
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        {
            let shared = tunnel.inner.shared.lock().unwrap();
            assert!(shared.acknowledgements.is_empty());
            assert!(shared.registrations.is_empty());
        }
        assert!(tunnel.register(12346).await.is_err());
        time::timeout(Duration::from_secs(1), async {
            while !tunnel.reader.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
