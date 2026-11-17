//! Carries out the orders Concurro gives on a link: single requests, each
//! on a provider connection of its own, and WebSocket connections whose
//! turns are proven while they stay open. Every exchange is proven with
//! the credential hidden.

use std::{env, future::IntoFuture, ops::Range, path::PathBuf, pin::pin, time::Instant};

use anyhow::{Context, Result, bail};
use concurro_relay_native::{self as native, NativeOptions, NativeRole};
use concurro_relay_protocol::{
    Roots,
    link::{self, Notice, Order},
    meter::Counters,
    route::Route,
    wire::{self, Job, Offer},
    ws::{self, Progress},
};
use futures::{AsyncReadExt as _, AsyncWriteExt as _, Stream, StreamExt};
use serde_json::Value;
use tlsn::{
    Session, SessionHandle,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    transcript::Direction,
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    sync::mpsc::{self, UnboundedSender},
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    credentials::{Credential, Source},
    events::{Event, Exchange},
    policy::{Policy, ThreadParents},
    routes::Served,
    ws::WsRelay,
};

/// What a relay serves, and with what.
#[derive(Clone)]
pub struct RelayConfig {
    /// The routes the relay is registered for.
    pub served: Vec<Served>,
    pub credentials: Source,
    pub roots: Roots,
    /// Shared by every exchange this relay serves.
    pub parents: ThreadParents,
}

impl RelayConfig {
    /// The route whose provider is `host`, with the relay's credential for
    /// it as it is now.
    fn route(&self, host: &str) -> Result<(&Served, Credential), String> {
        let served = self.served.iter().find(|served| served.policy.host == host);
        let served = served.ok_or_else(|| format!("host not served: {host}"))?;
        let credential = self
            .credentials
            .load(served.route)
            .map_err(|error| format!("{error:#}"))?;
        Ok((served, credential))
    }
}

/// What the relay adds to a request on `served` to carry `credential`.
fn offer(served: &Served, credential: Credential) -> Offer {
    Offer {
        credential: served.credential_header.clone(),
        hidden_len: credential.token.len(),
        headers: credential.headers,
    }
}

/// The model a request body asks for.
fn model(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok()?["model"]
        .as_str()
        .map(str::to_owned)
}

/// A link's traffic counters and where it reports, for timing an exchange
/// and reporting it.
struct Reporter<'a> {
    link: usize,
    traffic: &'a Counters,
    events: &'a UnboundedSender<Event>,
}

/// An exchange under way, as a [`Reporter`] measures it.
struct Timed {
    started: Instant,
    upload: u64,
    download: u64,
}

impl Reporter<'_> {
    fn start(&self) -> Timed {
        Timed {
            started: Instant::now(),
            upload: self.traffic.written(),
            download: self.traffic.read(),
        }
    }

    /// Reports that the exchange `timed` was proved.
    fn proved(
        &self,
        timed: &Timed,
        route: Route,
        sent: usize,
        received: usize,
        request: String,
        response: String,
    ) {
        let exchange = Exchange {
            route,
            model: model(&request),
            sent,
            received,
            upload: self.traffic.written() - timed.upload,
            download: self.traffic.read() - timed.download,
            seconds: timed.started.elapsed().as_secs_f64(),
            request,
            response,
        };
        let _ = self.events.send(Event::Proved {
            link: self.link,
            exchange,
        });
    }

    fn refused(&self, reason: String) {
        let _ = self.events.send(Event::Refused {
            link: self.link,
            reason,
        });
    }
}

/// A job the relay has agreed to perform.
struct Admitted {
    route: Route,
    /// The request's body, for showing.
    body: String,
    request: Vec<u8>,
    hidden: Range<usize>,
    server: String,
}

/// Decides whether to perform `job`, returning what to send to the provider
/// and what the relay adds to it, or the reason the job is refused.
fn admit(job: &Job, config: &RelayConfig) -> Result<(Admitted, Offer), String> {
    let (served, credential) = config.route(&job.host)?;
    served.policy.check(job, &config.parents)?;
    let token = credential.token.clone();
    let offer = offer(served, credential);
    let (request, hidden) = wire::encode_request(job, &offer, token.as_bytes());
    let body = String::from_utf8_lossy(&job.decoded_body().unwrap_or_default()).into_owned();
    Ok((
        Admitted {
            route: served.route,
            body,
            request,
            hidden,
            server: job.host.clone(),
        },
        offer,
    ))
}

/// Performs an admitted job and proves the exchange over `handle`'s
/// session. Returns what the provider sent.
async fn prove(
    handle: &mut SessionHandle,
    admitted: &Admitted,
    config: &RelayConfig,
) -> Result<Vec<u8>> {
    let server = admitted.server.as_str();
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server)?)
                .build()?,
        )
        .await?;
    let (mut tls, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server.try_into()?))
            .root_store(config.roots.store())
            .build()?,
    )?;
    let prover = tokio::spawn(prover.into_future());

    tls.write_all(&admitted.request).await?;
    tls.flush().await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    config.parents.record(&response);
    drop(tls);
    let mut prover = prover.await??;

    let hidden = &admitted.hidden;
    let sent = prover.transcript().sent().len();
    let mut proof = ProveConfig::builder(prover.transcript());
    proof.server_identity();
    proof.reveal_sent(&(0..hidden.start))?;
    proof.reveal_sent(&(hidden.end..sent))?;
    proof.prove_no_control(Direction::Sent, hidden.clone())?;
    proof.reveal_recv_all()?;
    let proof = proof.build()?;
    prover.prove(&proof).await?;
    prover.close().await?;
    Ok(response)
}

/// Performs `job` if the relay's policy allows it, and proves the
/// exchange. Returns whether it was performed.
async fn perform(
    job: &Job,
    handle: &mut SessionHandle,
    notices: &mut (impl AsyncWrite + Unpin),
    config: &RelayConfig,
    reporter: &Reporter<'_>,
) -> Result<bool> {
    let admitted = match admit(job, config) {
        Ok((admitted, offer)) => {
            wire::send(notices, &Notice::Offer(offer)).await?;
            admitted
        }
        Err(reason) => {
            wire::send(notices, &Notice::Refused(reason.clone())).await?;
            reporter.refused(reason);
            return Ok(false);
        }
    };
    let timed = reporter.start();
    let received = prove(handle, &admitted, config).await?;
    let response =
        wire::parse_response(&received).map_or_else(|_| received.clone(), |response| response.body);
    let response = String::from_utf8_lossy(&response).into_owned();
    reporter.proved(
        &timed,
        admitted.route,
        admitted.request.len(),
        received.len(),
        admitted.body,
        response,
    );
    Ok(true)
}

/// The WebSocket connection `job` asks for, as the relay would open it, or
/// the reason it will not.
fn admit_connection<'a>(
    job: &Job,
    config: &'a RelayConfig,
) -> Result<(&'a Served, &'a Policy, Credential), String> {
    let (served, credential) = config.route(&job.host)?;
    let policy = served
        .websocket
        .as_ref()
        .ok_or_else(|| format!("{} has no WebSocket connections", served.route.label()))?;
    policy.check_target(job)?;
    Ok((served, policy, credential))
}

/// A response's events as a stream of them, which is how a response to a
/// single request arrives and how it is shown.
fn as_stream(messages: &[Message]) -> String {
    messages
        .iter()
        .filter_map(|message| message.to_text().ok().filter(|_| message.is_text()))
        .map(|event| format!("data: {event}\n"))
        .collect()
}

/// Opens the WebSocket connection Concurro ordered for `job`, if the
/// relay's policy allows it, and carries out Concurro's orders on it until
/// it orders the connection closed. Returns the turns proved.
async fn carry(
    job: &Job,
    key: &str,
    handle: &mut SessionHandle,
    orders: &mut (impl Stream<Item = Result<Order>> + Unpin),
    notices: &mut (impl AsyncWrite + Unpin),
    config: &RelayConfig,
    reporter: &Reporter<'_>,
) -> Result<usize> {
    let (served, policy, credential) = match admit_connection(job, config) {
        Ok(admitted) => admitted,
        Err(reason) => {
            wire::send(notices, &Notice::Refused(reason.clone())).await?;
            reporter.refused(reason);
            return Ok(0);
        }
    };
    let token = credential.token.clone();
    let offer = offer(served, credential);
    wire::send(notices, &Notice::Offer(offer.clone())).await?;
    let mut relay = WsRelay::open(
        handle,
        job,
        &offer,
        token.as_bytes(),
        key,
        policy.clone(),
        config.roots,
    )
    .await?;

    let mut turns = 0;
    // The request in flight, with when it was sent.
    let mut asked: Option<(Timed, String, usize)> = None;
    // Whether Concurro was told of a ping since its last order.
    let mut noticed = false;
    loop {
        let order = tokio::select! {
            order = orders.next() => order.context("Concurro ended the link")??,
            waiting = relay.idle_ping(), if !noticed => {
                waiting?;
                noticed = true;
                wire::send(notices, &Notice::PingWaiting).await?;
                continue;
            }
        };
        noticed = false;
        let admitted = match order {
            Order::Request { text, mask } => {
                let frame = ws::text_frame(&text, mask);
                let sent = relay.send_request(&frame).await?;
                if sent.is_ok() {
                    asked = Some((reporter.start(), text, frame.len()));
                }
                sent
            }
            Order::Pong { payload, mask } => {
                relay.send_pong(&ws::pong_frame(&payload, mask)).await?
            }
            Order::Report if relay.has_unproven() => Ok(()),
            Order::Report => Err("nothing to report".into()),
            Order::Close => return relay.close().await.map(|()| turns),
            Order::Job(_) | Order::Open { .. } | Order::NativeStart { .. } => {
                bail!("Concurro gave an order which needs the connection closed")
            }
        };
        if let Err(reason) = admitted {
            wire::send(notices, &Notice::Refused(reason.clone())).await?;
            reporter.refused(reason);
            continue;
        }
        relay.settle().await?;
        wire::send(notices, &Notice::Proving).await?;
        if let Some(Progress::Response(messages)) = relay.prove(handle).await?
            && let Some((timed, text, sent)) = asked.take()
        {
            turns += 1;
            let received = messages.iter().map(Message::len).sum();
            reporter.proved(
                &timed,
                served.route,
                sent,
                received,
                text,
                as_stream(&messages),
            );
        }
    }
}

/// Carries out the orders arriving on `control` one after another, proving
/// each over a single session on `proofs`, whose traffic `traffic` counts,
/// and reporting each to `events` as link number `link`.
///
/// Returns the number of exchanges proved once `control` closes. Any
/// failure ends the link, and with it the proof state its proofs share.
pub async fn serve_link<C, P>(
    mut control: C,
    proofs: P,
    config: &RelayConfig,
    link: usize,
    traffic: &Counters,
    events: &UnboundedSender<Event>,
) -> Result<usize>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let first: Order = match wire::recv(&mut control).await {
        Ok(order) => order,
        Err(_) => return Ok(0),
    };
    if let Order::NativeStart {
        route,
        provider_host,
        provider_port,
    } = &first
    {
        let credential = config.credentials.load(*route)?;
        let account = credential
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("chatgpt-account-id"))
            .map(|(_, value)| value.clone());
        wire::send(&mut control, &Notice::NativeReady).await?;
        let (audit, mut reported) = mpsc::unbounded_channel();
        let events = events.clone();
        let route = *route;
        let forward = tokio::spawn(async move {
            while let Some(audit) = reported.recv().await {
                let _ = events.send(Event::NativeAudit { link, route, audit });
            }
        });
        let result = native::bridge(
            control,
            proofs,
            NativeOptions {
                role: NativeRole::Sponsor,
                route,
                provider_host: provider_host.clone(),
                provider_port: *provider_port,
                provider_ca: env::var_os("CONCURRO_NATIVE_PROVIDER_CA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/etc/ssl/cert.pem")),
                listen: None,
                token: Some(credential.token),
                account,
                audit: Some(audit),
                ready: None,
            },
        )
        .await;
        forward.await?;
        result?;
        return Ok(1);
    }
    let (driver, mut handle) = Session::new(proofs.compat()).split();
    let driver = tokio::spawn(driver);
    let (orders, mut notices) = io::split(control);
    let mut orders = pin!(link::incoming::<_, Order>(orders));
    let reporter = Reporter {
        link,
        traffic,
        events,
    };
    let mut served = 0;
    let mut first = Some(first);
    // A failure to read the next order means Concurro ended the link.
    while let Some(Ok(order)) = match first.take() {
        Some(order) => Some(Ok(order)),
        None => orders.next().await,
    } {
        served += match order {
            Order::Job(job) => {
                usize::from(perform(&job, &mut handle, &mut notices, config, &reporter).await?)
            }
            Order::Open { job, key } => {
                carry(
                    &job,
                    &key,
                    &mut handle,
                    &mut orders,
                    &mut notices,
                    config,
                    &reporter,
                )
                .await?
            }
            other => bail!("Concurro gave an order which needs an open connection: {other:?}"),
        };
    }
    handle.close();
    let _ = driver.await;
    Ok(served)
}
