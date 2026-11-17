//! A stream wrapper that counts, and optionally records, what crosses it.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug, Default)]
pub struct Counters {
    read: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
    recorded: Option<Arc<Mutex<Vec<u8>>>>,
}

impl Counters {
    /// Counters that also keep every byte read.
    pub fn recording() -> Self {
        Self {
            recorded: Some(Arc::default()),
            ..Self::default()
        }
    }

    pub fn read(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    pub fn recorded(&self) -> Vec<u8> {
        self.recorded
            .as_ref()
            .map(|bytes| bytes.lock().unwrap().clone())
            .unwrap_or_default()
    }
}

pub struct Metered<S> {
    inner: S,
    counters: Counters,
}

impl<S> Metered<S> {
    pub fn new(inner: S, counters: Counters) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let fresh = &buf.filled()[before..];
        self.counters
            .read
            .fetch_add(fresh.len() as u64, Ordering::Relaxed);
        if let Some(recorded) = &self.counters.recorded {
            recorded.lock().unwrap().extend_from_slice(fresh);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.counters
                .written
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
