//! Multiplex native helper TCP streams over one authenticated auxiliary link.

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    net::Ipv4Addr,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{self, Duration, Instant},
};

/// Maximum auxiliary frame payload accepted by the Python reference.
pub const MAX_PAYLOAD: usize = 65_536;
/// Bytes either side may send on one channel before the receiver grants more.
pub const WINDOW: usize = 4 << 20;
/// Consumed bytes a receiver gathers before granting them back.
const GRANT: usize = WINDOW / 4;
/// Concurro listeners a Sponsor may register before Concurro claims them; an
/// honest Sponsor has at most one waiting.
pub const UNCLAIMED: usize = 4;
/// Channels Concurro may hold open to the Sponsor at once, unless configured.
pub const CHANNELS: NonZeroUsize = NonZeroUsize::new(64).unwrap();
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
    /// Allow the peer to send more bytes on a channel.
    Credit = b'W',
    /// Abandon both directions of a channel.
    Close = b'C',
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
            b'W' => Self::Credit,
            b'C' => Self::Close,
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
            Kind::Credit => ensure!(self.payload.len() == 4, "invalid native tunnel credit"),
            Kind::End | Kind::Close => {
                ensure!(self.payload.is_empty(), "invalid native tunnel EOF")
            }
            Kind::Data => {}
        }
        Ok(())
    }

    /// The 4-byte number an Open or Credit frame carries.
    fn number(&self) -> u32 {
        u32::from_be_bytes(self.payload[..4].try_into().unwrap())
    }

    /// The port a Register or Acknowledge frame carries.
    fn port(&self) -> u16 {
        u16::from_be_bytes(self.payload[..2].try_into().unwrap())
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
type Inbound = mpsc::UnboundedReceiver<Option<Vec<u8>>>;
/// Registration acknowledgement or tunnel failure.
type Reply = oneshot::Sender<std::result::Result<u16, String>>;

/// Bytes this side may still send on one channel.
struct Credit {
    /// Unspent bytes the peer has allowed.
    available: StdMutex<usize>,
    /// Whether the peer abandoned the channel.
    closed: AtomicBool,
    /// Wakes a sender waiting for credit.
    changed: Notify,
}

impl Credit {
    /// Start with the window every channel begins with.
    fn new() -> Self {
        Self {
            available: StdMutex::new(WINDOW),
            closed: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }

    /// Wait for credit and take up to `most` bytes of it.
    async fn take(&self, most: usize) -> Result<usize> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            ensure!(
                !self.closed.load(Ordering::SeqCst),
                "native tunnel channel closed by peer"
            );
            {
                let mut available = self.available.lock().unwrap();
                if *available > 0 {
                    let taken = most.min(*available);
                    *available -= taken;
                    return Ok(taken);
                }
            }
            changed.await;
        }
    }

    /// Add bytes the peer allowed.
    fn grant(&self, bytes: usize) {
        let mut available = self.available.lock().unwrap();
        *available = available.saturating_add(bytes);
        self.changed.notify_waiters();
    }

    /// Wait until the peer abandons the channel.
    async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }

    /// Wake the sender of a channel the peer abandoned.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

/// One open channel.
struct Channel {
    /// Inbound queue; dropped when the peer abandons the channel.
    inbound: mpsc::UnboundedSender<Option<Vec<u8>>>,
    /// Received bytes not yet granted back to the peer, at most [`WINDOW`].
    held: usize,
    /// This side's own sending credit.
    credit: Arc<Credit>,
}

/// A Concurro listener for one Sponsor registration.
struct Listening {
    /// Accept loop forwarding connections to the registration.
    task: JoinHandle<()>,
    /// Ends the accept loop between connections when dropped.
    _stop: oneshot::Sender<()>,
    /// Whether a local helper was given this port.
    claimed: bool,
}

/// Mutable registration and channel maps shared by tunnel tasks.
#[derive(Default)]
struct Shared {
    /// Sponsor target port by registration number, while registered.
    registrations: HashMap<u32, u16>,
    /// Pending Sponsor registration replies.
    acknowledgements: HashMap<u32, Reply>,
    /// Concurro listeners by local port, until their claim ends.
    listeners: HashMap<u16, Listening>,
    /// Open channels by number.
    channels: HashMap<u32, Channel>,
    /// Highest channel number opened; lower ones absent from `channels` are
    /// closed, and late frames for them are dropped.
    highest: u32,
    /// Terminal link error shared with pending callers.
    error: Option<String>,
}

impl Shared {
    /// Track channel `number`, which must exceed every earlier one.
    fn open(&mut self, number: u32) -> Result<(Inbound, Arc<Credit>)> {
        ensure!(number > self.highest, "native tunnel channel reused");
        self.highest = number;
        let (inbound, receiver) = mpsc::unbounded_channel();
        let credit = Arc::new(Credit::new());
        self.channels.insert(
            number,
            Channel {
                inbound,
                held: 0,
                credit: credit.clone(),
            },
        );
        Ok((receiver, credit))
    }

    /// Fail on a frame for a channel that never existed; a closed one's are
    /// dropped.
    fn closed(&self, number: u32) -> Result<()> {
        ensure!(number <= self.highest, "unknown native tunnel channel");
        Ok(())
    }
}

/// Link writer and session state shared across channel tasks.
struct Inner {
    /// Which side handles registration and open frames.
    role: Role,
    /// Serialized auxiliary link writer.
    writer: Mutex<Box<dyn AsyncWrite + Unpin + Send>>,
    /// Mutable channel and listener state.
    shared: StdMutex<Shared>,
    /// Next registration number.
    next_id: AtomicU32,
    /// Wake channel and listener tasks during cancellation.
    closed: Notify,
    /// Whether terminal cleanup already ran.
    stopped: AtomicBool,
    /// Channels the peer may hold open at once; more are closed as opened.
    channels: usize,
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
        self.write(|| {
            Ok((
                Frame {
                    kind,
                    channel,
                    payload,
                },
                (),
            ))
        })
        .await
    }

    /// Write the frame `frame` makes while holding the writer, so frames are
    /// sent in the order `frame` runs.
    async fn write<T>(&self, frame: impl FnOnce() -> Result<(Frame, T)>) -> Result<T> {
        let result = self
            .until_closed(async {
                let mut writer = self.writer.lock().await;
                ensure!(!self.stopped.load(Ordering::SeqCst), "native tunnel closed");
                let (frame, value) = frame()?;
                let mut guard = FrameWriteGuard {
                    inner: self,
                    armed: true,
                };
                let result = frame.write(&mut *writer).await;
                if let Err(error) = &result {
                    self.fail(error.to_string());
                }
                guard.armed = false;
                result.map(|()| value)
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
        for (_, listening) in shared.listeners.drain() {
            listening.task.abort();
        }
        for channel in shared.channels.values() {
            let _ = channel.inbound.send(None);
            channel.credit.close();
        }
        self.closed.notify_waiters();
    }

    /// Allocate a registration number.
    fn number(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Open the next local channel to `registration`; numbers reach the peer
    /// in increasing order.
    async fn open_local(&self, registration: u32) -> Result<(u32, Inbound, Arc<Credit>)> {
        self.write(|| {
            let mut shared = self.shared.lock().unwrap();
            let number = shared
                .highest
                .checked_add(1)
                .context("native tunnel channels exhausted")?;
            let (inbound, credit) = shared.open(number)?;
            Ok((
                Frame {
                    kind: Kind::Open,
                    channel: number,
                    payload: registration.to_be_bytes().to_vec(),
                },
                (number, inbound, credit),
            ))
        })
        .await
    }

    /// Stop tracking channel `number`, telling the peer when it was still open.
    async fn close_channel(&self, number: u32) {
        let open = self
            .shared
            .lock()
            .unwrap()
            .channels
            .remove(&number)
            .is_some();
        if open && !self.stopped.load(Ordering::SeqCst) {
            let _ = self.send(Kind::Close, number, Vec::new()).await;
        }
    }

    /// Grant `bytes` the local side consumed back to the peer.
    async fn grant(&self, number: u32, bytes: usize) -> Result<()> {
        {
            let mut shared = self.shared.lock().unwrap();
            let Some(channel) = shared.channels.get_mut(&number) else {
                return Ok(());
            };
            channel.held -= bytes;
        }
        self.send(Kind::Credit, number, (bytes as u32).to_be_bytes().to_vec())
            .await
    }
}

/// Active auxiliary tunnel with independent channel pumps.
pub struct Tunnel {
    /// Shared tunnel state.
    inner: Arc<Inner>,
    /// Auxiliary link reader task.
    reader: JoinHandle<()>,
}

/// A Sponsor target exposed on a Concurro port until dropped.
#[must_use = "dropping it releases the registration"]
pub struct Registration {
    /// Shared tunnel state.
    inner: Arc<Inner>,
    /// Registration number Concurro opens channels with.
    number: u32,
    /// Concurro's listener port, once acknowledged.
    port: u16,
}

impl fmt::Debug for Registration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Registration")
            .field("number", &self.number)
            .field("port", &self.port)
            .finish()
    }
}

impl Registration {
    /// Concurro's listener port for this target.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut shared = self.inner.shared.lock().unwrap();
        shared.registrations.remove(&self.number);
        shared.acknowledgements.remove(&self.number);
    }
}

/// One Concurro listener given to a local helper; dropping it closes the
/// listener, while channels already open carry on.
#[must_use = "dropping it closes the listener"]
pub struct Claim {
    /// Shared tunnel state.
    inner: Arc<Inner>,
    /// The claimed listener port.
    port: u16,
}

impl fmt::Debug for Claim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Claim")
            .field("port", &self.port)
            .finish()
    }
}

impl Claim {
    /// The claimed listener port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.inner
            .shared
            .lock()
            .unwrap()
            .listeners
            .remove(&self.port);
    }
}

impl Tunnel {
    /// Start receiving frames without blocking helper calls.
    pub fn start<T>(link: T, role: Role) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::with_channels(link, role, CHANNELS)
    }

    /// Start a tunnel whose peer may hold at most `channels` channels open.
    pub fn with_channels<T>(link: T, role: Role, channels: NonZeroUsize) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read, write) = tokio::io::split(link);
        let inner = Arc::new(Inner {
            role,
            writer: Mutex::new(Box::new(write)),
            shared: StdMutex::new(Shared::default()),
            next_id: AtomicU32::new(1),
            closed: Notify::new(),
            stopped: AtomicBool::new(false),
            channels: channels.get(),
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

    /// Expose a Sponsor-local service on a Concurro-local port while the
    /// returned registration lives.
    pub async fn register(&self, target_port: u16) -> Result<Registration> {
        ensure!(
            self.inner.role == Role::Sponsor,
            "only Sponsor registers native listeners"
        );
        let number = self.inner.number();
        let (sender, receiver) = oneshot::channel();
        let mut registration = Registration {
            inner: self.inner.clone(),
            number,
            port: 0,
        };
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
            Ok(port) => {
                registration.port = port?;
                Ok(registration)
            }
            Err(_) => {
                self.inner
                    .fail("native tunnel registration timed out".to_owned());
                bail!("native tunnel registration timed out")
            }
        }
    }

    /// Take the Concurro listener on `port` for one local helper; it must be
    /// one the Sponsor registered and no helper has taken yet.
    pub fn claim(&self, port: u16) -> Result<Claim> {
        ensure!(
            self.inner.role == Role::Concurro,
            "only Concurro claims registered listeners"
        );
        let mut shared = self.inner.shared.lock().unwrap();
        if let Some(error) = &shared.error {
            bail!("{error}");
        }
        let listening = shared
            .listeners
            .get_mut(&port)
            .context("Sponsor named a port the native tunnel did not open")?;
        ensure!(!listening.claimed, "native tunnel port already claimed");
        listening.claimed = true;
        Ok(Claim {
            inner: self.inner.clone(),
            port,
        })
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
                let unclaimed = inner
                    .shared
                    .lock()
                    .unwrap()
                    .listeners
                    .values()
                    .filter(|listening| !listening.claimed)
                    .count();
                ensure!(
                    unclaimed < UNCLAIMED,
                    "Sponsor registered more native tunnel listeners than it used"
                );
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let port = listener.local_addr()?.port();
                let registration = frame.channel;
                let serving = inner.clone();
                let (stop, stopped) = oneshot::channel();
                let task = tokio::spawn(async move {
                    if let Err(error) =
                        accept_loop(listener, registration, serving.clone(), stopped).await
                    {
                        serving.fail(error.to_string());
                    }
                });
                inner.shared.lock().unwrap().listeners.insert(
                    port,
                    Listening {
                        task,
                        _stop: stop,
                        claimed: false,
                    },
                );
                inner
                    .send(Kind::Acknowledge, registration, port.to_be_bytes().to_vec())
                    .await?;
            }
            (Role::Sponsor, Kind::Acknowledge) => {
                let reply = inner
                    .shared
                    .lock()
                    .unwrap()
                    .acknowledgements
                    .remove(&frame.channel);
                match reply {
                    Some(reply) => {
                        let _ = reply.send(Ok(frame.port()));
                    }
                    // Released before Concurro answered.
                    None => ensure!(
                        frame.channel < inner.next_id.load(Ordering::Relaxed),
                        "unknown native tunnel acknowledgement"
                    ),
                }
            }
            (Role::Sponsor, Kind::Open) => {
                let registration = frame.number();
                let (target, full, receiver, credit) = {
                    let mut shared = inner.shared.lock().unwrap();
                    let target = shared.registrations.get(&registration).copied();
                    let full = shared.channels.len() >= inner.channels;
                    let (receiver, credit) = shared.open(frame.channel)?;
                    (target, full, receiver, credit)
                };
                match (target, full) {
                    (Some(target), false) => {
                        let connecting = inner.clone();
                        tokio::spawn(async move {
                            connect_target(connecting, frame.channel, target, receiver, credit)
                                .await;
                        });
                    }
                    (None, _) if registration >= inner.next_id.load(Ordering::Relaxed) => {
                        bail!("unknown native tunnel registration")
                    }
                    // Released, or too many open: the opener gets a closed
                    // channel.
                    (target, _) => {
                        if target.is_some() {
                            eprintln!(
                                "NATIVE_TUNNEL refused channel {}: {} channels are open",
                                frame.channel, inner.channels
                            );
                        }
                        inner.close_channel(frame.channel).await;
                    }
                }
            }
            (_, Kind::Data | Kind::End) => {
                let mut shared = inner.shared.lock().unwrap();
                match shared.channels.get_mut(&frame.channel) {
                    Some(channel) => {
                        channel.held += frame.payload.len();
                        ensure!(
                            channel.held <= WINDOW,
                            "native tunnel peer overran its channel window"
                        );
                        let _ = channel
                            .inbound
                            .send((frame.kind == Kind::Data).then_some(frame.payload));
                    }
                    None => shared.closed(frame.channel)?,
                }
            }
            (_, Kind::Credit) => {
                let shared = inner.shared.lock().unwrap();
                match shared.channels.get(&frame.channel) {
                    Some(channel) => channel.credit.grant(frame.number() as usize),
                    None => shared.closed(frame.channel)?,
                }
            }
            (_, Kind::Close) => {
                let mut shared = inner.shared.lock().unwrap();
                match shared.channels.remove(&frame.channel) {
                    Some(channel) => channel.credit.close(),
                    None => shared.closed(frame.channel)?,
                }
            }
            _ => bail!("unexpected native tunnel frame for role"),
        }
    }
}

/// Accept Concurro-local helper connections without blocking link reads,
/// until `stop` resolves.
async fn accept_loop(
    listener: TcpListener,
    registration: u32,
    inner: Arc<Inner>,
    mut stop: oneshot::Receiver<()>,
) -> Result<()> {
    loop {
        let accepted = inner
            .until_closed(async {
                tokio::select! {
                    _ = &mut stop => Ok(None),
                    accepted = listener.accept() => Ok(Some(accepted?)),
                }
            })
            .await?;
        let Some((socket, _)) = accepted else {
            return Ok(());
        };
        let (number, receiver, credit) = inner.open_local(registration).await?;
        pump_channel(inner.clone(), number, socket, receiver, credit);
    }
}

/// Connect a Sponsor target, retrying while it starts, then pump the channel;
/// a target that never accepts closes only this channel.
async fn connect_target(
    inner: Arc<Inner>,
    number: u32,
    target: u16,
    receiver: Inbound,
    credit: Arc<Credit>,
) {
    let deadline = Instant::now() + REGISTRATION_TIMEOUT;
    loop {
        // A channel the peer closes stops connecting, releasing what it queued.
        let attempt = inner
            .until_closed(async {
                tokio::select! {
                    socket = TcpStream::connect((Ipv4Addr::LOCALHOST, target)) => Ok(Some(socket?)),
                    () = credit.closed() => Ok(None),
                }
            })
            .await;
        match attempt {
            Ok(Some(socket)) => {
                pump_channel(inner, number, socket, receiver, credit);
                return;
            }
            Ok(None) => return,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
                    && Instant::now() < deadline =>
            {
                let waited = inner
                    .until_closed(async {
                        tokio::select! {
                            () = time::sleep(Duration::from_millis(20)) => Ok(true),
                            () = credit.closed() => Ok(false),
                        }
                    })
                    .await;
                if !matches!(waited, Ok(true)) {
                    return;
                }
            }
            Err(error) => {
                if !inner.stopped.load(Ordering::SeqCst) {
                    eprintln!("NATIVE_TUNNEL connect {number}: {error:#}");
                }
                inner.close_channel(number).await;
                return;
            }
        }
    }
}

/// Pump both TCP directions within the channel's credit and preserve a remote
/// half-close; a failure closes this channel alone.
fn pump_channel(
    inner: Arc<Inner>,
    number: u32,
    socket: TcpStream,
    mut inbound: Inbound,
    credit: Arc<Credit>,
) {
    tokio::spawn(async move {
        let (mut read, mut write) = socket.into_split();
        let failed = {
            let outbound = async {
                let mut buffer = vec![0; MAX_PAYLOAD];
                loop {
                    let count = inner
                        .until_closed(async {
                            tokio::select! {
                                count = read.read(&mut buffer) => Ok(count?),
                                () = credit.closed() => bail!("native tunnel channel closed by peer"),
                            }
                        })
                        .await?;
                    if count == 0 {
                        inner.send(Kind::End, number, Vec::new()).await?;
                        return Ok::<(), anyhow::Error>(());
                    }
                    let mut sent = 0;
                    while sent < count {
                        let allowed = inner.until_closed(credit.take(count - sent)).await?;
                        inner
                            .send(Kind::Data, number, buffer[sent..sent + allowed].to_vec())
                            .await?;
                        sent += allowed;
                    }
                }
            };
            let incoming = async {
                let mut consumed = 0;
                loop {
                    let payload = inner
                        .until_closed(async { Ok(inbound.recv().await) })
                        .await?;
                    match payload {
                        Some(Some(bytes)) => {
                            inner
                                .until_closed(async { Ok(write.write_all(&bytes).await?) })
                                .await?;
                            consumed += bytes.len();
                            if consumed >= GRANT {
                                inner.grant(number, consumed).await?;
                                consumed = 0;
                            }
                        }
                        Some(None) => {
                            inner
                                .until_closed(async { Ok(write.shutdown().await?) })
                                .await?;
                            return Ok::<(), anyhow::Error>(());
                        }
                        None => return Err(anyhow!("native tunnel channel closed by peer")),
                    }
                }
            };
            tokio::pin!(outbound, incoming);
            let mut sent_done = false;
            let mut received_done = false;
            let mut failed = false;
            while !sent_done || !received_done {
                tokio::select! {
                    sent = &mut outbound, if !sent_done => match sent {
                        Ok(()) => sent_done = true,
                        Err(error) => {
                            if !inner.stopped.load(Ordering::SeqCst) {
                                eprintln!("NATIVE_TUNNEL outbound {number}: {error:#}");
                            }
                            failed = true;
                            break;
                        }
                    },
                    received = &mut incoming, if !received_done => match received {
                        Ok(()) => received_done = true,
                        Err(error) => {
                            if !inner.stopped.load(Ordering::SeqCst) {
                                eprintln!("NATIVE_TUNNEL inbound {number}: {error:#}");
                            }
                            failed = true;
                            break;
                        }
                    },
                }
            }
            failed
        };
        drop((read, write));
        if failed {
            inner.close_channel(number).await;
        } else {
            inner.shared.lock().unwrap().channels.remove(&number);
        }
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

    use super::{Frame, Kind, Role, Tunnel, UNCLAIMED, WINDOW, pump_channel};

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
        let (inbound, credit) = tunnel.inner.shared.lock().unwrap().open(7).unwrap();
        let sender = tunnel.inner.shared.lock().unwrap().channels[&7]
            .inbound
            .clone();
        pump_channel(tunnel.inner.clone(), 7, socket, inbound, credit);
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
        let (inbound, credit) = tunnel.inner.shared.lock().unwrap().open(8).unwrap();
        let sender = tunnel.inner.shared.lock().unwrap().channels[&8]
            .inbound
            .clone();
        pump_channel(tunnel.inner.clone(), 8, socket, inbound, credit);
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

    /// Send one raw frame as the tunnel's peer.
    async fn send(peer: &mut tokio::io::DuplexStream, kind: Kind, channel: u32, payload: &[u8]) {
        Frame {
            kind,
            channel,
            payload: payload.to_vec(),
        }
        .write(peer)
        .await
        .unwrap();
    }

    /// Wait until the tunnel has stopped, reporting why.
    async fn stopped(tunnel: &Tunnel) -> String {
        time::timeout(Duration::from_secs(2), async {
            while !tunnel.reader.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tunnel.inner.shared.lock().unwrap().error.clone().unwrap()
    }

    /// Acknowledge the next registration as Concurro would.
    async fn acknowledge(peer: &mut tokio::io::DuplexStream) -> u32 {
        let frame = Frame::read(peer).await.unwrap();
        assert_eq!(frame.kind, Kind::Register);
        send(peer, Kind::Acknowledge, frame.channel, &9u16.to_be_bytes()).await;
        frame.channel
    }

    /// A peer sending past the window it was given fails the link, before the
    /// excess is queued.
    #[tokio::test]
    async fn overrunning_the_window_fails_the_link() {
        let (link, mut peer) = tokio::io::duplex(1 << 20);
        let tunnel = Tunnel::start(link, Role::Concurro);
        let (_inbound, _credit) = tunnel.inner.shared.lock().unwrap().open(1).unwrap();
        let chunk = vec![b'x'; super::MAX_PAYLOAD];
        for _ in 0..WINDOW / chunk.len() {
            send(&mut peer, Kind::Data, 1, &chunk).await;
        }
        send(&mut peer, Kind::Data, 1, b"!").await;
        assert!(
            stopped(&tunnel)
                .await
                .contains("overran its channel window")
        );
    }

    /// A sender waits for credit, and the receiver grants what its helper
    /// consumed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sending_waits_for_credit() {
        let (link, mut peer) = tokio::io::duplex(1 << 20);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let (inbound, credit) = tunnel.inner.shared.lock().unwrap().open(3).unwrap();
        pump_channel(tunnel.inner.clone(), 3, socket, inbound, credit);
        let writing = tokio::spawn(async move {
            client.write_all(&vec![b'y'; 2 * WINDOW]).await.unwrap();
            client
        });
        let mut received = 0;
        while received < WINDOW {
            let frame = time::timeout(Duration::from_secs(2), Frame::read(&mut peer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!((frame.kind, frame.channel), (Kind::Data, 3));
            received += frame.payload.len();
        }
        assert_eq!(received, WINDOW);
        assert!(
            time::timeout(Duration::from_millis(200), Frame::read(&mut peer))
                .await
                .is_err(),
            "sent past the window"
        );
        send(&mut peer, Kind::Credit, 3, &1000u32.to_be_bytes()).await;
        let frame = Frame::read(&mut peer).await.unwrap();
        assert_eq!((frame.kind, frame.payload.len()), (Kind::Data, 1000));
        writing.abort();

        // Bytes written to the local helper are granted back.
        let (link, mut peer) = tokio::io::duplex(1 << 20);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let (inbound, credit) = tunnel.inner.shared.lock().unwrap().open(5).unwrap();
        pump_channel(tunnel.inner.clone(), 5, socket, inbound, credit);
        let chunk = vec![b'z'; super::MAX_PAYLOAD];
        for _ in 0..WINDOW / chunk.len() {
            send(&mut peer, Kind::Data, 5, &chunk).await;
        }
        let mut body = vec![0; WINDOW];
        client.read_exact(&mut body).await.unwrap();
        let mut granted = 0;
        while granted < WINDOW {
            let frame = time::timeout(Duration::from_secs(2), Frame::read(&mut peer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!((frame.kind, frame.channel), (Kind::Credit, 5));
            granted += u32::from_be_bytes(frame.payload.try_into().unwrap()) as usize;
        }
        assert_eq!(granted, WINDOW);
        assert_eq!(tunnel.inner.shared.lock().unwrap().channels[&5].held, 0);
    }

    /// Frames for a closed channel are dropped; for one never opened, or an
    /// Open reusing a number, they fail the link.
    #[tokio::test]
    async fn closed_unknown_and_reused_channels() {
        let (link, mut peer) = tokio::io::duplex(4096);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        let (registration, number) = tokio::join!(tunnel.register(1), acknowledge(&mut peer));
        assert_eq!(registration.unwrap().port(), 9);
        // A released registration answers with Close.
        send(&mut peer, Kind::Open, 6, &number.to_be_bytes()).await;
        let frame = time::timeout(Duration::from_secs(2), Frame::read(&mut peer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((frame.kind, frame.channel), (Kind::Close, 6));
        send(&mut peer, Kind::Data, 6, b"late").await;
        send(&mut peer, Kind::Credit, 6, &1u32.to_be_bytes()).await;
        send(&mut peer, Kind::Close, 6, &[]).await;
        tokio::task::yield_now().await;
        assert!(!tunnel.reader.is_finished());
        send(&mut peer, Kind::Open, 6, &number.to_be_bytes()).await;
        assert!(stopped(&tunnel).await.contains("reused"));

        let (link, mut peer) = tokio::io::duplex(4096);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        send(&mut peer, Kind::Data, 1, b"never opened").await;
        assert!(
            stopped(&tunnel)
                .await
                .contains("unknown native tunnel channel")
        );

        let (link, mut peer) = tokio::io::duplex(4096);
        let tunnel = Tunnel::start(link, Role::Sponsor);
        send(&mut peer, Kind::Open, 1, &7u32.to_be_bytes()).await;
        assert!(
            stopped(&tunnel)
                .await
                .contains("unknown native tunnel registration")
        );
    }

    /// Concurro hands each registered port to one helper, closes it when the
    /// claim ends, and refuses ports it never opened or a pile of unclaimed ones.
    #[tokio::test]
    async fn claims_and_unclaimed_listeners() {
        let (link, mut peer) = tokio::io::duplex(4096);
        let tunnel = Tunnel::start(link, Role::Concurro);
        let mut ports = Vec::new();
        for number in 1..=UNCLAIMED as u32 {
            send(&mut peer, Kind::Register, number, &1u16.to_be_bytes()).await;
            let frame = Frame::read(&mut peer).await.unwrap();
            assert_eq!((frame.kind, frame.channel), (Kind::Acknowledge, number));
            ports.push(u16::from_be_bytes(frame.payload.try_into().unwrap()));
        }
        assert!(tunnel.claim(1).is_err());
        let claim = tunnel.claim(ports[0]).unwrap();
        assert!(tunnel.claim(ports[0]).is_err());
        drop(claim);
        time::timeout(Duration::from_secs(2), async {
            while TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0]))
                .await
                .is_ok()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // One slot is free again after the claim; the next past it fails.
        send(&mut peer, Kind::Register, 10, &1u16.to_be_bytes()).await;
        assert_eq!(
            Frame::read(&mut peer).await.unwrap().kind,
            Kind::Acknowledge
        );
        send(&mut peer, Kind::Register, 11, &1u16.to_be_bytes()).await;
        assert!(
            stopped(&tunnel)
                .await
                .contains("more native tunnel listeners")
        );
        assert!(tunnel.claim(ports[1]).is_err());
    }

    /// Channels opened past the limit are closed at once; the tunnel lives on
    /// and opens again once one ends.
    #[tokio::test]
    async fn channels_past_the_limit_are_closed() {
        let (link, mut peer) = tokio::io::duplex(4096);
        let tunnel = Tunnel::with_channels(link, Role::Sponsor, 2.try_into().unwrap());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let (registration, number) = tokio::join!(tunnel.register(target), acknowledge(&mut peer));
        let _registration = registration.unwrap();
        for channel in 1..=3 {
            send(&mut peer, Kind::Open, channel, &number.to_be_bytes()).await;
        }
        let frame = time::timeout(Duration::from_secs(2), Frame::read(&mut peer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((frame.kind, frame.channel), (Kind::Close, 3));
        send(&mut peer, Kind::Close, 1, &[]).await;
        time::timeout(Duration::from_secs(2), async {
            while tunnel.inner.shared.lock().unwrap().channels.len() > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        send(&mut peer, Kind::Open, 4, &number.to_be_bytes()).await;
        assert!(
            time::timeout(Duration::from_millis(200), Frame::read(&mut peer))
                .await
                .is_err(),
            "a channel within the limit was closed"
        );
        assert!(!tunnel.reader.is_finished());
    }

    /// A channel closed while its target still refuses stops connecting and
    /// drops what it queued, so closing channels cannot get past the limit.
    #[tokio::test]
    async fn closed_channel_stops_connecting() {
        let (link, mut peer) = tokio::io::duplex(1 << 20);
        let tunnel = Tunnel::with_channels(link, Role::Sponsor, 2.try_into().unwrap());
        let refusing = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = refusing.local_addr().unwrap().port();
        drop(refusing);
        let (registration, number) = tokio::join!(tunnel.register(target), acknowledge(&mut peer));
        let _registration = registration.unwrap();
        send(&mut peer, Kind::Open, 1, &number.to_be_bytes()).await;
        send(&mut peer, Kind::Data, 1, b"queued").await;
        let inbound = time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(channel) = tunnel.inner.shared.lock().unwrap().channels.get(&1) {
                    break channel.inbound.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        send(&mut peer, Kind::Close, 1, &[]).await;
        time::timeout(Duration::from_secs(2), inbound.closed())
            .await
            .expect("the closed channel kept connecting");
    }
}
