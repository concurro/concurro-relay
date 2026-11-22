//! HTTP/1 private API transport and structured failures.

use std::convert::Infallible;

use anyhow::Error;
use concurro_relay_hosted_api::{ErrorDetail, ErrorResponse};
use futures::stream;
use http_body_util::{
    BodyExt, Full, LengthLimitError, Limited, StreamBody, combinators::UnsyncBoxBody,
};
use hyper::{
    HeaderMap, Response, StatusCode,
    body::{Bytes, Frame, Incoming},
    header,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;

/// A fixed JSON body or a streamed provider result.
pub type Body = UnsyncBoxBody<Bytes, Error>;
/// A provider stream's send side; dropping it after success completes the HTTP response.
pub type ResponseStream = mpsc::Sender<anyhow::Result<Frame<Bytes>>>;
/// Result of a private HTTP operation.
pub type Outcome = Result<Response<Body>, Failure>;

/// A safe public error paired with its HTTP status.
#[derive(Debug)]
pub struct Failure(StatusCode, &'static str, &'static str);

impl Failure {
    /// Build an error without embedding submitted or provider data.
    pub fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self(status, code, message)
    }

    /// Report a local failure and return a service unavailable response.
    pub fn unavailable(error: Error) -> Self {
        eprintln!("private verifier operation unavailable: {error:#}");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "verifier operation unavailable",
        )
    }

    /// Respond using the versioned private API error shape.
    pub fn response(self) -> Response<Body> {
        let mut response = json(&ErrorResponse {
            error: ErrorDetail {
                code: self.1.into(),
                message: self.2.into(),
            },
        });
        *response.status_mut() = self.0;
        response
    }
}

/// Return a JSON value with a non-cacheable OK response.
pub fn json(value: &impl Serialize) -> Response<Body> {
    let Ok(bytes) = serde_json::to_vec(value) else {
        let mut failed = Response::new(full(Bytes::new()));
        *failed.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return failed;
    };
    let mut response = Response::new(full(Bytes::from(bytes)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// A response with no body, including the durable release acknowledgement.
pub fn empty(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(full(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// Wrap response bytes as one body.
fn full(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

/// Stream provider frames and let the forwarding task detect a disconnected client.
pub fn streaming() -> (ResponseStream, Body) {
    let (send, receive) = mpsc::channel(1);
    let body = StreamBody::new(stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|frame| (frame, receive))
    }));
    (send, body.boxed_unsync())
}

/// Read a bounded request body so the model can be verified before leasing a link.
pub async fn bytes(body: Incoming, limit: usize) -> Result<Bytes, Failure> {
    let collected = Limited::new(body, limit).collect().await.map_err(|error| {
        if error.is::<LengthLimitError>() {
            Failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body too large",
            )
        } else {
            Failure(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "could not read request body",
            )
        }
    })?;
    Ok(collected.to_bytes())
}

/// Read and deserialize a private control request.
pub async fn read_json<T: DeserializeOwned>(body: Incoming) -> Result<T, Failure> {
    let body = bytes(body, 64 * 1024).await?;
    serde_json::from_slice(&body).map_err(|_| {
        Failure(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "invalid JSON request body",
        )
    })
}

/// Return a single, unambiguous ASCII field value.
pub fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
