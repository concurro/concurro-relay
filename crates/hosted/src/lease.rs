//! Bind signed claims to retained native provider sessions.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use concurro_relay_hosted_api::{
    claim::SessionClaim,
    dispatch::{
        ALLOWANCE_SPENT_CODE, CHATGPT_SUBSCRIPTION, CLAIM_REFUSED_CODE, CLAUDE_SUBSCRIPTION,
        REQUEST_REUSED_CODE,
    },
    owner::Task,
};
use concurro_relay_native::{self as native, NativeOptions, NativeRole};
use concurro_relay_protocol::{
    link::{Notice, Order},
    route::Route,
    wire,
};
use concurro_relay_verifier::accept::Accepted;
use hyper::StatusCode;
use time::OffsetDateTime;
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch},
};
use tokio_rustls::server::TlsStream;

use crate::{App, Args, clock, http::Failure, journal::Refusal, pool::Lease, registry::Binding};

type RelayLink = Accepted<TlsStream<TcpStream>>;

/// Run the existing native Concurro worker on one leased authenticated link.
async fn run_lease(
    mut link: RelayLink,
    binding: Binding,
    args: Arc<Args>,
    address: watch::Sender<Option<SocketAddr>>,
) -> Result<()> {
    let (route, provider_host, provider_port) = match binding.route.as_str() {
        CLAUDE_SUBSCRIPTION => (
            Route::ClaudeSubscription,
            &args.provider_host,
            args.provider_port,
        ),
        CHATGPT_SUBSCRIPTION => (
            Route::ChatgptSubscription,
            &args.codex_provider_host,
            args.codex_provider_port,
        ),
        _ => bail!("unsupported hosted route"),
    };
    wire::send(
        &mut link.control,
        &Order::NativeStart {
            route,
            provider_host: provider_host.clone(),
            provider_port,
        },
    )
    .await?;
    match wire::recv::<_, Notice>(&mut link.control).await? {
        Notice::NativeReady => {}
        Notice::Refused(reason) => bail!("Sponsor refused native session: {reason}"),
        answer => bail!("unexpected Sponsor answer: {answer:?}"),
    }
    let (ready, mut bound) = mpsc::unbounded_channel();
    let bridge = native::bridge(
        link.control,
        link.proofs,
        NativeOptions {
            role: NativeRole::Concurro,
            route,
            provider_host: provider_host.clone(),
            provider_port,
            provider_ca: args.provider_ca.clone(),
            listen: Some("127.0.0.1:0".into()),
            token: None,
            account: None,
            audit: None,
            review: None,
            ready: Some(ready),
        },
    );
    tokio::pin!(bridge);
    tokio::select! {
        endpoint = bound.recv() => {
            let endpoint: SocketAddr = endpoint.context("native worker did not bind")?.parse()?;
            eprintln!("hosted native session ready for owner={} record={}", binding.user_id, binding.record_id);
            let _ = address.send(Some(endpoint));
            bridge.await
        }
        result = &mut bridge => result,
    }
}

/// Obtain the registry's exact approved binding for the claim.
pub fn binding(app: &App, claim: &SessionClaim) -> Option<Binding> {
    app.registry
        .binding_for(&claim.relay_id, &claim.route)
        .filter(|binding| {
            binding.user_id == claim.user_id
                && binding.entry_id == claim.entry_id
                && binding.record_id == claim.record_id
                && binding.version == claim.version
        })
}

/// Admission and release both take the pool lock before modifying the journal.
pub async fn admit(
    app: &Arc<App>,
    claim: &SessionClaim,
    request_id: &str,
) -> Result<SocketAddr, Failure> {
    let mut pool = app.pool.lock().await;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let now_subsec = clock();
    let approved = binding(app, claim).ok_or_else(claim_refused)?;
    app.journal
        .lock()
        .expect("claim journal lock")
        .check(claim, request_id, now)
        .map_err(refused)?;
    let (mut address, number) = if let Some(existing) = pool.leases.get(&claim.sub) {
        if existing.claim_id != claim.jti
            || existing.relay != claim.relay_id
            || existing.binding != approved
        {
            return Err(claim_refused());
        }
        (existing.address.clone(), existing.number)
    } else {
        let (slot, link) = loop {
            let slot = pool
                .ready_slots()
                .find(|slot| slot.0 == claim.relay_id)
                .cloned()
                .ok_or_else(|| {
                    Failure::unavailable(anyhow::anyhow!("no live link for approved relay"))
                })?;
            if let Some(link) = pool.take(&slot, now_subsec).await {
                break (slot, link);
            }
        };
        let (sender, receiver) = watch::channel(None);
        let number = link.number;
        let task_key = claim.sub.clone();
        let worker_pool = app.pool.clone();
        let worker_args = app.args.clone();
        let lease_binding = approved.clone();
        let deadline = claim.exp;
        let worker = tokio::spawn(async move {
            if let Err(error) =
                before_expiry(deadline, run_lease(link, approved, worker_args, sender)).await
            {
                eprintln!("hosted native session ended: {error:#}");
            }
            worker_pool.lock().await.finish(&task_key, number, clock());
        });
        pool.leases.insert(
            claim.sub.clone(),
            Lease {
                claim_id: claim.jti.clone(),
                relay: slot.0.clone(),
                slot,
                number,
                started: now_subsec,
                task: Some(Task {
                    repository: claim.repository.clone(),
                    issue: claim.issue,
                }),
                binding: lease_binding,
                address: receiver.clone(),
                abort: worker.abort_handle(),
            },
        );
        (receiver, number)
    };
    drop(pool);
    let endpoint = before_expiry(claim.exp, async {
        loop {
            if let Some(endpoint) = *address.borrow_and_update() {
                return Ok(endpoint);
            }
            address
                .changed()
                .await
                .context("native session did not start")?;
        }
    })
    .await
    .map_err(Failure::unavailable)?;

    // Readiness can race release, expiry, withdrawal or a reconnect.
    let pool = app.pool.lock().await;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut journal = app.journal.lock().expect("claim journal lock");
    journal.check(claim, request_id, now).map_err(refused)?;
    let approved = binding(app, claim).ok_or_else(claim_refused)?;
    if !pool.leases.get(&claim.sub).is_some_and(|lease| {
        lease.number == number && lease.claim_id == claim.jti && lease.binding == approved
    }) {
        return Err(Failure::unavailable(anyhow::anyhow!(
            "native lease ended during startup"
        )));
    }
    journal
        .admit(claim, request_id)
        .map_err(Failure::unavailable)?;
    Ok(endpoint)
}

/// Refusal independent of the caller's asserted identity or model.
pub fn claim_refused() -> Failure {
    Failure::new(
        StatusCode::FORBIDDEN,
        CLAIM_REFUSED_CODE,
        "session claim does not authorize this dispatch",
    )
}

/// Map durable admission outcomes to stable wire errors.
fn refused(error: Refusal) -> Failure {
    match error {
        Refusal::Invalid | Refusal::Revoked => claim_refused(),
        Refusal::Duplicate => Failure::new(
            StatusCode::CONFLICT,
            REQUEST_REUSED_CODE,
            "request already spent an admitted call",
        ),
        Refusal::Spent => Failure::new(
            StatusCode::TOO_MANY_REQUESTS,
            ALLOWANCE_SPENT_CODE,
            "session claim allowance spent",
        ),
        Refusal::Storage(error) => Failure::unavailable(error),
    }
}

/// Bound native startup and lifetime by the signed claim's expiry.
async fn before_expiry<T>(deadline: i64, work: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(remaining(deadline), work)
        .await
        .context("claim deadline ended")?
}

/// Time left for a lease or a request waiting to enter it.
pub fn remaining(deadline: i64) -> Duration {
    Duration::from_secs_f64((deadline as f64 - clock()).max(0.0))
}
