//! Authenticated relay links: idle links parked under a liveness watch, links
//! leased to one signed session, and the owner telemetry derived from both.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use concurro_relay_hosted_api::owner::{ActiveSlot, Relay, Task};
use concurro_relay_verifier::accept::Accepted;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{Mutex, mpsc, oneshot, watch},
    task::AbortHandle,
};

use crate::{registry::Binding, timestamp};

/// A relay's stable link slot across reconnects.
pub type Slot = (String, u32);
/// One task's exclusive relay link and retained native provider session.
#[derive(Clone)]
pub struct Lease {
    /// Signed claim authorizing the lease.
    pub claim_id: String,
    /// Relay whose link is leased.
    pub relay: String,
    /// Relay and slot of the leased link; at most one lease holds a slot.
    pub slot: Slot,
    /// Random number of the leased link, distinguishing it from later links on the slot.
    pub number: u64,
    /// When the lease took its link.
    pub started: f64,
    /// Task the turn belongs to, when Exchange supplied it.
    pub task: Option<Task>,
    /// Exact approval the lease serves.
    pub binding: Binding,
    /// Native ingress address once the worker is ready.
    pub address: watch::Receiver<Option<SocketAddr>>,
    /// Stops the lease's native worker.
    pub abort: AbortHandle,
}

/// An idle link held by its watcher, which hands it over on request.
struct Parked<S> {
    number: u64,
    take: oneshot::Sender<oneshot::Sender<Accepted<S>>>,
}

/// Unassigned authenticated links, task-bound leases and per-relay liveness.
pub struct Pool<S> {
    ready: HashMap<Slot, Parked<S>>,
    /// Leases by the signed session that holds them.
    pub leases: HashMap<String, Lease>,
    /// When each relay last had a live link, updated as links come and go.
    seen: HashMap<String, f64>,
    /// Watchers report links that ended while idle.
    gone: mpsc::UnboundedSender<(Slot, u64)>,
}

impl<S: AsyncRead + Unpin + Send + 'static> Pool<S> {
    /// A shared pool whose idle links are removed as soon as their relay disconnects.
    pub fn shared(clock: fn() -> f64) -> Arc<Mutex<Self>> {
        let (gone, mut ended) = mpsc::unbounded_channel();
        let pool = Arc::new(Mutex::new(Self {
            ready: HashMap::new(),
            leases: HashMap::new(),
            seen: HashMap::new(),
            gone,
        }));
        let sweeper = Arc::downgrade(&pool);
        tokio::spawn(async move {
            while let Some((slot, number)) = ended.recv().await {
                let Some(pool) = sweeper.upgrade() else {
                    return;
                };
                pool.lock().await.ended(&slot, number, clock());
            }
        });
        pool
    }

    /// Park a newly authenticated link, replacing whatever its slot held before.
    pub fn park(&mut self, mut link: Accepted<S>, now: f64) {
        let slot = (link.relay.clone(), link.slot);
        // A reconnected slot means its previous link, idle or leased, is gone.
        if let Some(turn) = self
            .leases
            .iter()
            .find(|(_, lease)| lease.slot == slot)
            .map(|(turn, _)| turn.clone())
        {
            self.leases
                .remove(&turn)
                .expect("lease was just found")
                .abort
                .abort();
        }
        let (take, taken) = oneshot::channel::<oneshot::Sender<Accepted<S>>>();
        let gone = self.gone.clone();
        let number = link.number;
        let watched = slot.clone();
        tokio::spawn(async move {
            let (mut control, mut proofs) = ([0; 1], [0; 1]);
            // An idle relay sends nothing: end of stream, an error or stray bytes all end the link.
            let request = tokio::select! {
                request = taken => request.ok(),
                _ = link.control.read(&mut control) => None,
                _ = link.proofs.read(&mut proofs) => None,
            };
            match request {
                Some(reply) => {
                    let _ = reply.send(link);
                }
                None => {
                    drop(link);
                    let _ = gone.send((watched, number));
                }
            }
        });
        self.seen.insert(slot.0.clone(), now);
        self.ready.insert(slot, Parked { number, take });
    }

    /// Idle slots, for exact-binding selection.
    pub fn ready_slots(&self) -> impl Iterator<Item = &Slot> {
        self.ready.keys()
    }

    /// Take a parked link from its watcher; `None` when it ended meanwhile.
    pub async fn take(&mut self, slot: &Slot, now: f64) -> Option<Accepted<S>> {
        let parked = self.ready.remove(slot)?;
        let (reply, link) = oneshot::channel();
        parked.take.send(reply).ok()?;
        let link = link.await.ok();
        self.seen.insert(slot.0.clone(), now);
        link
    }

    /// Forget an idle link its watcher saw end, unless the slot already holds a newer one.
    fn ended(&mut self, slot: &Slot, number: u64, now: f64) {
        if self
            .ready
            .get(slot)
            .is_some_and(|parked| parked.number == number)
        {
            self.ready.remove(slot);
        }
        self.seen.insert(slot.0.clone(), now);
    }

    /// Remove a finished lease if it is still the one on record.
    pub fn finish(&mut self, session: &str, number: u64, now: f64) {
        if let Some(lease) = self
            .leases
            .get(session)
            .filter(|lease| lease.number == number)
        {
            self.seen.insert(lease.relay.clone(), now);
            self.leases.remove(session);
        }
    }

    /// Stop the native worker for each active lease of a durably revoked claim.
    pub fn release(&mut self, claim_id: &str, now: f64) {
        self.leases.retain(|_, lease| {
            if lease.claim_id != claim_id {
                return true;
            }
            lease.abort.abort();
            self.seen.insert(lease.relay.clone(), now);
            false
        });
    }

    /// Drop every idle link and lease of a withdrawn relay.
    pub fn withdraw(&mut self, relay: &str, now: f64) {
        let before = self.ready.len();
        self.ready.retain(|slot, _| slot.0 != relay);
        let mut ended = before != self.ready.len();
        self.leases.retain(|_, lease| {
            let keep = lease.relay != relay;
            if !keep {
                lease.abort.abort();
                ended = true;
            }
            keep
        });
        if ended {
            self.seen.insert(relay.to_owned(), now);
        }
    }

    /// Live capacity and activity of `relay`, as of `now`.
    pub fn status(&self, relay: &str, now: f64) -> Relay {
        let idle = self.ready.keys().filter(|slot| slot.0 == relay).count();
        let mut active: Vec<_> = self
            .leases
            .values()
            .filter(|lease| lease.relay == relay)
            .map(|lease| ActiveSlot {
                slot: lease.slot.1,
                route: lease.binding.route.clone(),
                entry_id: lease.binding.entry_id.clone(),
                version: lease.binding.version,
                since: timestamp(lease.started),
                task: lease.task.clone(),
            })
            .collect();
        active.sort_by(|left, right| {
            left.since
                .cmp(&right.since)
                .then(left.slot.cmp(&right.slot))
        });
        let live = idle > 0 || !active.is_empty();
        Relay {
            relay_id: relay.to_owned(),
            idle,
            active,
            last_seen: if live {
                Some(timestamp(now))
            } else {
                self.seen.get(relay).copied().map(timestamp)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const NOW: f64 = 1_000.0;

    fn clock() -> f64 {
        NOW
    }

    /// An authenticated link and the relay's ends of its two streams.
    fn link(relay: &str, slot: u32, number: u64) -> (Accepted<DuplexStream>, [DuplexStream; 2]) {
        let (control, relay_control) = duplex(64);
        let (proofs, relay_proofs) = duplex(64);
        let accepted = Accepted {
            relay: relay.into(),
            number,
            slot,
            control,
            proofs,
        };
        (accepted, [relay_control, relay_proofs])
    }

    fn lease(relay: &str, slot: u32, route: &str, task: Option<Task>) -> Lease {
        Lease {
            claim_id: format!("claim-{slot}"),
            relay: relay.into(),
            slot: (relay.into(), slot),
            number: u64::from(slot),
            started: NOW - f64::from(slot),
            task,
            binding: Binding {
                user_id: 7,
                login: "owner".into(),
                route: route.into(),
                entry_id: "a".repeat(32),
                record_id: "b".repeat(64),
                version: 2,
            },
            address: watch::channel(None).1,
            abort: tokio::spawn(std::future::pending::<()>()).abort_handle(),
        }
    }

    /// Wait until the sweeper has applied what the watchers reported.
    async fn settled(pool: &Arc<Mutex<Pool<DuplexStream>>>, relay: &str, idle: usize) -> Relay {
        for _ in 0..100 {
            let status = pool.lock().await.status(relay, NOW + 5.0);
            if status.idle == idle {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("idle links of {relay} never became {idle}");
    }

    /// A relay never seen since start is unknown; a disconnected idle link is
    /// swept rather than reported as live capacity.
    #[tokio::test]
    async fn disconnected_idle_link_is_not_reported_live() {
        let pool = Pool::shared(clock);
        assert_eq!(pool.lock().await.status("relay-a", NOW).last_seen, None);
        let (first, relay_first) = link("relay-a", 1, 11);
        let (second, _relay_second) = link("relay-a", 2, 12);
        pool.lock().await.park(first, NOW - 30.0);
        pool.lock().await.park(second, NOW - 30.0);
        let live = pool.lock().await.status("relay-a", NOW + 5.0);
        assert_eq!((live.idle, live.last_seen), (2, Some(timestamp(NOW + 5.0))));
        drop(relay_first);
        let status = settled(&pool, "relay-a", 1).await;
        assert_eq!(status.last_seen, Some(timestamp(NOW + 5.0)));
        let mut pool = pool.lock().await;
        assert!(pool.take(&("relay-a".into(), 1), NOW).await.is_none());
        pool.withdraw("relay-a", NOW);
        let withdrawn = pool.status("relay-a", NOW + 5.0);
        assert_eq!(
            (withdrawn.idle, withdrawn.last_seen),
            (0, Some(timestamp(NOW)))
        );
    }

    /// A reconnected slot replaces its old link, whose late end does not
    /// remove the new one, and a taken link still carries its streams.
    #[tokio::test]
    async fn reconnect_replaces_slot_and_take_hands_over_link() {
        let pool = Pool::shared(clock);
        let (old, relay_old) = link("relay-a", 1, 1);
        let (new, mut relay_new) = link("relay-a", 1, 2);
        pool.lock().await.park(old, NOW);
        pool.lock().await.park(new, NOW);
        drop(relay_old);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let status = settled(&pool, "relay-a", 1).await;
        assert_eq!(status.idle, 1);
        let mut taken = pool
            .lock()
            .await
            .take(&("relay-a".into(), 1), NOW)
            .await
            .expect("live link is handed over");
        assert_eq!(taken.number, 2);
        relay_new[0].write_all(b"x").await.unwrap();
        let mut byte = [0; 1];
        taken.control.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        assert_eq!(pool.lock().await.status("relay-a", NOW).idle, 0);
    }

    /// Leases of every route share the relay's capacity, report their task
    /// without other owners' relays, and a finished lease updates last seen.
    #[tokio::test]
    async fn leases_share_capacity_and_finish_updates_last_seen() {
        let pool = Pool::<DuplexStream>::shared(clock);
        let mut pool = pool.lock().await;
        let task = Task {
            repository: "example/repo".into(),
            issue: 4,
        };
        pool.leases.insert(
            "s1".into(),
            lease("relay-a", 1, "claude-subscription", Some(task.clone())),
        );
        pool.leases.insert(
            "s2".into(),
            lease("relay-a", 2, "chatgpt-subscription", None),
        );
        pool.leases.insert(
            "s3".into(),
            lease("relay-b", 3, "claude-subscription", None),
        );
        let status = pool.status("relay-a", NOW);
        assert_eq!(status.idle, 0);
        assert_eq!(status.last_seen, Some(timestamp(NOW)));
        assert_eq!(
            status
                .active
                .iter()
                .map(|active| (active.route.as_str(), active.task.as_ref()))
                .collect::<Vec<_>>(),
            [
                ("chatgpt-subscription", None),
                ("claude-subscription", Some(&task))
            ]
        );
        // Two sessions of one approval starting in the same second stay distinct.
        let mut same = lease("relay-a", 4, "claude-subscription", None);
        same.started = NOW - 1.0;
        pool.leases.insert("s4".into(), same);
        let concurrent = pool.status("relay-a", NOW);
        let slots: Vec<_> = concurrent
            .active
            .iter()
            .map(|active| (active.entry_id.clone(), active.since, active.slot))
            .collect();
        assert_eq!(slots.len(), 3);
        assert_eq!(
            slots
                .iter()
                .filter(
                    |(entry, since, _)| *entry == "a".repeat(32) && *since == timestamp(NOW - 1.0)
                )
                .count(),
            2
        );
        assert_eq!(
            slots
                .iter()
                .map(|(_, _, slot)| *slot)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        pool.leases.remove("s4");
        pool.finish("s1", 99, NOW);
        assert_eq!(pool.status("relay-a", NOW).active.len(), 2);
        pool.finish("s1", 1, NOW - 1.0);
        let finished = pool.status("relay-a", NOW);
        assert_eq!(finished.active.len(), 1);
        pool.release("claim-2", NOW + 2.0);
        let ended = pool.status("relay-a", NOW + 9.0);
        assert_eq!(
            (ended.active.len(), ended.last_seen),
            (0, Some(timestamp(NOW + 2.0)))
        );
        assert_eq!(pool.status("relay-b", NOW).active.len(), 1);
    }
}
