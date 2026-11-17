//! Has a relay perform a job and accepts the exchange only if the proven
//! transcript is the requested one with exactly the credential bytes hidden.
//! The verifier forwards the relay's TLS traffic to the provider and cannot
//! read it.

use std::{net::SocketAddr, ops::Range};

use anyhow::{Context, Result};
use concurro_relay_protocol::{
    Roots,
    timing::Laps,
    wire::{self, Job, Offer},
};
use tlsn::{
    SessionHandle,
    config::verifier::VerifierConfig,
    connection::ServerName,
    rangeset::set::RangeSet,
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Credential headers a relay may use, as name and prefix.
const CREDENTIAL_HEADERS: [(&str, &str); 2] = [("authorization", "Bearer "), ("x-api-key", "")];

#[derive(Clone, Debug)]
pub struct Expect {
    pub provider: SocketAddr,
    pub roots: Roots,
    /// Names of headers the relay may add to the request.
    pub relay_headers: Vec<String>,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// The body with any chunked transfer encoding removed.
    pub body: Vec<u8>,
    pub laps: Laps,
}

#[derive(Debug)]
pub enum Verdict {
    /// The provider's response to exactly the requested job.
    Verified(Response),
    /// The relay's policy refused the job.
    Refused(String),
    /// The relay's proof does not match the requested job.
    Rejected(String),
}

/// The request an accepted job must produce.
pub struct Pending {
    expected: Vec<u8>,
    hidden: Range<usize>,
}

impl Pending {
    /// What `job` must produce with what the relay offers to add to it, or
    /// why the offer is not acceptable.
    pub fn new(job: &Job, offer: &Offer, expect: &Expect) -> Result<Self, String> {
        admit(offer, &expect.relay_headers)?;
        let (expected, hidden) = wire::encode_request(job, offer, &vec![0; offer.hidden_len]);
        Ok(Self { expected, hidden })
    }
}

/// Forwards the relay's exchange with the provider and verifies its proof
/// over `handle`'s session.
pub async fn verify(
    handle: &mut SessionHandle,
    job: &Job,
    pending: Pending,
    expect: &Expect,
) -> Result<Verdict> {
    let Pending { expected, hidden } = pending;

    let mut laps = Laps::start();
    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(expect.roots.store())
            .build()?,
    )?;

    let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
        return Ok(Verdict::Rejected("relay did not request proxy mode".into()));
    };
    if verifier.config().server_name().as_str() != job.host {
        let reason = format!(
            "relay targeted {}",
            verifier.config().server_name().as_str()
        );
        verifier.reject(Some(&reason)).await?;
        return Ok(Verdict::Rejected(reason));
    }
    let provider = TcpStream::connect(expect.provider).await?;
    provider.set_nodelay(true)?;
    let verifier = verifier.accept().await?;
    laps.lap("setup");
    let verifier = verifier.run(provider.compat()).await?;
    laps.lap("exchange");

    let verifier = verifier.verify().await?;
    // The hidden bytes sit before the body, so they must be proven unable to
    // end the header block or reframe the request.
    if verifier.request().no_control().0 != RangeSet::from(hidden.clone()) {
        let reason = "hidden bytes are not proven to be at least 0x20";
        verifier.reject(Some(reason)).await?;
        return Ok(Verdict::Rejected(reason.into()));
    }
    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = match verifier.accept().await {
        Ok(accepted) => accepted,
        Err(error) => return Ok(Verdict::Rejected(format!("proof failed: {error}"))),
    };
    verifier.close().await?;
    laps.lap("verify");

    let Some(ServerName::Dns(name)) = server_name else {
        return Ok(Verdict::Rejected("server identity not proven".into()));
    };
    if name.as_str() != job.host {
        return Ok(Verdict::Rejected(format!("proof is for {}", name.as_str())));
    }
    let transcript = transcript.context("no transcript revealed")?;
    Ok(match check(&transcript, &expected, hidden) {
        Ok(response) => Verdict::Verified(Response { laps, ..response }),
        Err(reason) => Verdict::Rejected(reason),
    })
}

/// Checks what the relay offers to add to the request.
pub fn admit(offer: &Offer, relay_headers: &[String]) -> Result<(), String> {
    let credential = (
        offer.credential.name.as_str(),
        offer.credential.prefix.as_str(),
    );
    if !CREDENTIAL_HEADERS.contains(&credential) {
        return Err(format!(
            "credential header not allowed: {}",
            offer.credential.name
        ));
    }
    for (name, value) in &offer.headers {
        if !relay_headers.contains(name) {
            return Err(format!("relay header not allowed: {name}"));
        }
        if !value.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
            return Err(format!("relay header value breaks framing: {name}"));
        }
    }
    Ok(())
}

/// Checks the proven transcript against the `expected` request, in which
/// only `hidden` may be undisclosed, and parses the response.
fn check(
    transcript: &PartialTranscript,
    expected: &[u8],
    hidden: Range<usize>,
) -> Result<Response, String> {
    if transcript.len_sent() != expected.len() {
        return Err(format!(
            "request is {} bytes, expected {}",
            transcript.len_sent(),
            expected.len()
        ));
    }
    if transcript.sent_unauthed() != RangeSet::from(hidden) {
        return Err("hidden request bytes are not exactly the credential".into());
    }
    // Unauthenticated bytes read back as zero, matching the zeroed credential.
    if transcript
        .sent_unsafe(expected.len())
        .map_err(|e| e.to_string())?
        != expected
    {
        return Err("request differs from the one asked for".into());
    }
    if !transcript.received_unauthed().is_empty() {
        return Err("response is partly hidden".into());
    }
    let received = transcript
        .received_unsafe(transcript.len_received())
        .map_err(|e| e.to_string())?;
    let wire::HttpResponse {
        status,
        headers,
        body,
    } = wire::parse_response(&received)?;
    Ok(Response {
        status,
        headers,
        body,
        laps: Laps::start(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_rejects_unexpected_relay_additions() {
        let offer = |name: &str, headers: Vec<(String, String)>| Offer {
            credential: wire::CredentialHeader {
                name: name.into(),
                prefix: "".into(),
            },
            hidden_len: 8,
            headers,
        };
        let allowed = ["account".to_owned()];
        assert!(
            admit(
                &offer("x-api-key", vec![("account".into(), "abc".into())]),
                &allowed
            )
            .is_ok()
        );
        assert!(admit(&offer("cookie", Vec::new()), &allowed).is_err());
        assert!(
            admit(
                &offer("x-api-key", vec![("other".into(), "abc".into())]),
                &allowed
            )
            .is_err()
        );
        assert!(
            admit(
                &offer("x-api-key", vec![("account".into(), "a\r\nb: c".into())]),
                &allowed
            )
            .is_err()
        );
    }
}
