//! A userspace network link between relay and verifier with optional
//! bandwidth and latency shaping, counting bytes in each direction.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::mpsc,
    time::{self, Instant},
};

/// One direction's capacity and one-way delay.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub bits_per_second: f64,
    pub delay: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct Traffic {
    pub relay_to_verifier: Arc<AtomicU64>,
    pub verifier_to_relay: Arc<AtomicU64>,
}

/// Joins the two sockets until either side closes. `up` shapes
/// relay→verifier traffic and `down` the reverse.
pub async fn join(relay: TcpStream, verifier: TcpStream, up: Option<Shape>, down: Option<Shape>) -> Traffic {
    let traffic = Traffic::default();
    let (relay_rx, relay_tx) = relay.into_split();
    let (verifier_rx, verifier_tx) = verifier.into_split();
    tokio::join!(
        pump(relay_rx, verifier_tx, up, traffic.relay_to_verifier.clone()),
        pump(verifier_rx, relay_tx, down, traffic.verifier_to_relay.clone()),
    );
    traffic
}

async fn pump(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, shape: Option<Shape>, count: Arc<AtomicU64>) {
    let (queue, mut queued) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let deliver = tokio::spawn(async move {
        while let Some((at, bytes)) = queued.recv().await {
            time::sleep_until(at).await;
            if to.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = to.shutdown().await;
    });
    // When the sender's link is next free; models serialization at the
    // shaped rate and backpressures the reader behind it.
    let mut free = Instant::now();
    let mut buf = vec![0; 64 << 10];
    while let Ok(n @ 1..) = from.read(&mut buf).await {
        count.fetch_add(n as u64, Ordering::Relaxed);
        let at = match shape {
            Some(shape) => {
                free = free.max(Instant::now()) + Duration::from_secs_f64(n as f64 * 8.0 / shape.bits_per_second);
                time::sleep_until(free).await;
                free + shape.delay
            }
            None => Instant::now(),
        };
        if queue.send((at, buf[..n].to_vec())).is_err() {
            break;
        }
    }
    drop(queue);
    let _ = deliver.await;
}
