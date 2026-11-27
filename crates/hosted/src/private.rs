//! Owner, inference and release operations on the private listener.

use std::{convert::Infallible, fs, path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use concurro_relay_hosted_api::{dispatch as api_dispatch, owner, release};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::net::TcpStream;

use crate::{
    App, clock, dispatch,
    http::{self, Body, Failure, Outcome},
    registry::ApprovalError,
    timestamp,
};

/// The three noninterchangeable caller bearers.
pub struct Credentials {
    owner: String,
    inference: String,
    release: String,
}

impl Credentials {
    /// Load separate nonempty tokens without putting their values in startup errors.
    pub fn read(owner: &Path, inference: &Path, release: &Path) -> Result<Self> {
        let credentials = Self {
            owner: read_bearer(owner).context("owner token")?,
            inference: read_bearer(inference).context("inference token")?,
            release: read_bearer(release).context("release token")?,
        };
        ensure!(
            credentials.owner != credentials.inference
                && credentials.owner != credentials.release
                && credentials.inference != credentials.release,
            "private caller tokens must be distinct"
        );
        Ok(credentials)
    }
}

/// Read one bearer from a token file.
fn read_bearer(file: &Path) -> Result<String> {
    let value = fs::read_to_string(file)?;
    let token = value.trim();
    ensure!(!token.is_empty(), "private token is empty");
    Ok(format!("Bearer {token}"))
}

/// The versioned operations and their isolated credentials.
enum Operation<'a> {
    Registration(&'a str),
    Approve,
    Relays,
    Dispatch(dispatch::Provider),
    Release(&'a str),
}

impl Operation<'_> {
    /// Bearer required by this operation.
    fn bearer<'a>(&self, credentials: &'a Credentials) -> &'a str {
        match self {
            Self::Registration(_) | Self::Approve | Self::Relays => &credentials.owner,
            Self::Dispatch(_) => &credentials.inference,
            Self::Release(_) => &credentials.release,
        }
    }
}

/// Serve authenticated HTTP operations on one private connection.
pub async fn serve(stream: TcpStream, app: Arc<App>) -> Result<()> {
    http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| {
                let app = app.clone();
                async move {
                    Ok::<Response<Body>, Infallible>(
                        handle(app, request).await.unwrap_or_else(Failure::response),
                    )
                }
            }),
        )
        .await?;
    Ok(())
}

/// Require the route's bearer before reading its request body.
async fn handle(app: Arc<App>, request: Request<Incoming>) -> Outcome {
    let path = request.uri().path();
    let operation = match (request.method(), path) {
        (&Method::POST, owner::APPROVALS_PATH) => Operation::Approve,
        (&Method::GET, owner::RELAYS_PATH) => Operation::Relays,
        (&Method::POST, api_dispatch::MESSAGES_PATH) => {
            Operation::Dispatch(dispatch::Provider::Claude)
        }
        (&Method::POST, api_dispatch::ANTIGRAVITY_PATH) => {
            Operation::Dispatch(dispatch::Provider::Antigravity)
        }
        (&Method::POST, api_dispatch::RESPONSES_PATH) => {
            Operation::Dispatch(dispatch::Provider::Codex)
        }
        (&Method::GET, path) if path.starts_with(owner::REGISTRATIONS_PREFIX) => {
            Operation::Registration(
                path.strip_prefix(owner::REGISTRATIONS_PREFIX)
                    .expect("registration prefix matched"),
            )
        }
        (&Method::POST, path) if path.starts_with(release::CLAIMS_PREFIX) => Operation::Release(
            path.strip_prefix(release::CLAIMS_PREFIX)
                .expect("release prefix matched"),
        ),
        _ => {
            return Err(Failure::new(
                StatusCode::NOT_FOUND,
                "unknown_operation",
                "unknown private operation",
            ));
        }
    };
    let authorized = http::unique_header(request.headers(), "authorization").is_some_and(|value| {
        bool::from(
            value
                .as_bytes()
                .ct_eq(operation.bearer(&app.credentials).as_bytes()),
        )
    });
    if !authorized {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "private caller is not authorized",
        ));
    }
    match operation {
        Operation::Registration(code) => {
            let pending = app.registry.pending(code).ok_or_else(unknown_code)?;
            let expires_at = OffsetDateTime::from_unix_timestamp(pending.expires as i64)
                .map_err(|error| Failure::unavailable(error.into()))?;
            Ok(http::json(&owner::Registration {
                name: pending.name,
                routes: pending.routes.into_iter().map(str::to_owned).collect(),
                expires_at,
            }))
        }
        Operation::Approve => {
            let approval = http::read_json(request.into_body()).await?;
            let relay_id = app
                .registry
                .approve(approval)
                .map_err(|error| match error {
                    ApprovalError::Invalid => Failure::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_approval",
                        "invalid owner or route binding",
                    ),
                    ApprovalError::Unknown => unknown_code(),
                    ApprovalError::Conflict => Failure::new(
                        StatusCode::CONFLICT,
                        "approval_conflict",
                        "approval conflicts with the relay registration",
                    ),
                    ApprovalError::Storage(error) => Failure::unavailable(error),
                })?;
            Ok(http::json(&owner::Approved { relay_id }))
        }
        Operation::Relays => {
            let query: owner::RelaysQuery = request
                .uri()
                .query()
                .and_then(|query| query.strip_prefix("user_id="))
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
                .map(|user_id| owner::RelaysQuery { user_id })
                .ok_or_else(|| {
                    Failure::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_user_id",
                        "positive user_id required",
                    )
                })?;
            let pool = app.pool.lock().await;
            let now = clock();
            let relays = app
                .registry
                .relays(query.user_id)
                .iter()
                .map(|relay| pool.status(relay, now))
                .collect();
            Ok(http::json(&owner::Relays {
                started: timestamp(app.args.started),
                checked: timestamp(now),
                relays,
            }))
        }
        Operation::Dispatch(provider) => dispatch::handle(app, provider, request).await,
        Operation::Release(segment) => {
            let key = release::ReleaseClaim::from_segment(segment).map_err(|_| {
                Failure::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_claim_id",
                    "a claim ID is required",
                )
            })?;
            let mut pool = app.pool.lock().await;
            let now = OffsetDateTime::now_utc().unix_timestamp();
            app.journal
                .lock()
                .expect("claim journal lock")
                .revoke(&key.claim_id, now)
                .map_err(Failure::unavailable)?;
            pool.release(&key.claim_id, clock());
            Ok(http::empty(StatusCode::NO_CONTENT))
        }
    }
}

/// Unapproved registration lookup and approval use the same missing-code error.
fn unknown_code() -> Failure {
    Failure::new(
        StatusCode::NOT_FOUND,
        "unknown_registration",
        "unknown or expired relay code",
    )
}
