//! What the verifier and the relay exchange before the TLSNotary session
//! starts, and the canonical request encoding both sides derive from it.

use std::ops::Range;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME: usize = 16 << 20;

/// An inference request the verifier asks the relay to perform.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// The body bytes as sent, which are compressed if the headers say so.
    #[serde(with = "body_format")]
    pub body: Vec<u8>,
}

/// Request header naming the body's compression.
pub const CONTENT_ENCODING: &str = "content-encoding";

/// The only body compression a job may use.
pub const ZSTD: &str = "zstd";

/// Largest body a compressed job may expand to.
pub const MAX_DECODED_BODY: usize = 64 << 20;

impl Job {
    /// The body with any compression removed.
    pub fn decoded_body(&self) -> Result<Vec<u8>, String> {
        match self
            .headers
            .iter()
            .find(|(name, _)| name == CONTENT_ENCODING)
        {
            None => Ok(self.body.clone()),
            Some((_, encoding)) if encoding == ZSTD => {
                zstd::bulk::decompress(&self.body, MAX_DECODED_BODY)
                    .map_err(|_| "body is not valid zstd".to_owned())
            }
            Some((_, encoding)) => Err(format!("content encoding not allowed: {encoding}")),
        }
    }

    /// Compresses the body, which must not already be compressed.
    pub fn compress(&mut self) -> Result<()> {
        ensure!(
            self.headers
                .iter()
                .all(|(name, _)| name != CONTENT_ENCODING),
            "body is already encoded"
        );
        self.body = zstd::bulk::compress(&self.body, ZSTD_LEVEL)?;
        self.headers.push((CONTENT_ENCODING.into(), ZSTD.into()));
        Ok(())
    }
}

/// Compression level Codex itself uses for request bodies.
const ZSTD_LEVEL: i32 = 3;

/// Job bodies are written as text when they are text, so captured jobs stay
/// readable, and as base64 otherwise.
mod body_format {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Body {
        Text(String),
        Binary { base64: String },
    }

    pub fn serialize<S: Serializer>(body: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(body) {
            Ok(text) => Body::Text(text.to_owned()),
            Err(_) => Body::Binary {
                base64: STANDARD.encode(body),
            },
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        match Body::deserialize(deserializer)? {
            Body::Text(text) => Ok(text.into_bytes()),
            Body::Binary { base64 } => STANDARD.decode(base64).map_err(serde::de::Error::custom),
        }
    }
}

/// The request header which carries the credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialHeader {
    pub name: String,
    /// Text between the header name and the credential, such as `Bearer `.
    pub prefix: String,
}

impl CredentialHeader {
    pub fn bearer() -> Self {
        Self {
            name: "authorization".into(),
            prefix: "Bearer ".into(),
        }
    }
}

/// What the relay will add to an accepted job's request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub credential: CredentialHeader,
    /// Number of bytes the relay will hide in place of the credential.
    pub hidden_len: usize,
    /// Headers only the relay knows, such as an account selector.
    pub headers: Vec<(String, String)>,
}

/// Encodes the exact bytes sent to the provider, returning them with the
/// range occupied by the credential.
///
/// The verifier calls this with a zeroed credential of the offered length
/// and requires the proven transcript to match it byte for byte outside
/// that range.
pub fn encode_request(job: &Job, offer: &Offer, credential: &[u8]) -> (Vec<u8>, Range<usize>) {
    encode_request_on(job, offer, credential, "close")
}

/// The request line and the headers `job` and `offer` name, without the
/// blank line which ends them, and where the credential sits.
pub fn head(method: &str, job: &Job, offer: &Offer, credential: &[u8]) -> (Vec<u8>, Range<usize>) {
    let mut out = format!(
        "{method} {} HTTP/1.1\r\nhost: {}\r\n{}: {}",
        job.path, job.host, offer.credential.name, offer.credential.prefix
    )
    .into_bytes();
    let start = out.len();
    out.extend_from_slice(credential);
    let hidden = start..out.len();
    out.extend_from_slice(b"\r\n");
    for (name, value) in offer.headers.iter().chain(&job.headers) {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    (out, hidden)
}

/// Like [`encode_request`], for a connection which is `close`d after the
/// response or kept open with `keep-alive`.
pub fn encode_request_on(
    job: &Job,
    offer: &Offer,
    credential: &[u8],
    connection: &str,
) -> (Vec<u8>, Range<usize>) {
    let (mut out, hidden) = head("POST", job, offer, credential);
    out.extend_from_slice(
        format!(
            "accept-encoding: identity\r\nconnection: {connection}\r\ncontent-length: {}\r\n\r\n",
            job.body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&job.body);
    (out, hidden)
}

pub async fn send<S: AsyncWrite + Unpin, T: Serialize>(stream: &mut S, value: &T) -> Result<()> {
    let raw = serde_json::to_vec(value)?;
    stream.write_u32(raw.len().try_into()?).await?;
    stream.write_all(&raw).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv<S: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut S) -> Result<T> {
    let len = stream.read_u32().await? as usize;
    ensure!(len <= MAX_FRAME, "frame too large: {len}");
    let mut raw = vec![0; len];
    stream.read_exact(&mut raw).await?;
    Ok(serde_json::from_slice(&raw)?)
}

/// A provider response as it appeared on the connection.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names are lowercased.
    pub headers: Vec<(String, String)>,
    /// The body with any chunked transfer encoding removed.
    pub body: Vec<u8>,
}

/// Statuses of whole responses which have no body.
const BODILESS: [u16; 3] = [101, 204, 304];

/// Parses the bytes received on a connection that carried one response.
pub fn parse_response(received: &[u8]) -> Result<HttpResponse, String> {
    let split = received
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("response has no header terminator")?;
    let head = std::str::from_utf8(&received[..split]).map_err(|_| "response head is not text")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or("response has no status")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"));
    // Digits only: `parse` alone would also take a sign.
    let digits = |value: &String| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| value.parse::<usize>().ok())
            .flatten()
    };
    // An interim response is not the response, whatever it declares.
    if (100..200).contains(&status) && !BODILESS.contains(&status) {
        return Err("response is an interim one".into());
    }
    let mut lengths = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| digits(value));
    let length = lengths.next();
    if lengths.next().is_some() || (chunked && length.is_some()) {
        return Err("response declares its length more than once".into());
    }
    let body = &received[split + 4..];
    let body = match (chunked, length) {
        (true, _) => dechunk(body).ok_or("response chunking is malformed")?,
        (false, Some(length)) if length == Some(body.len()) => body.to_vec(),
        (false, Some(_)) => return Err("response body does not have its declared length".into()),
        // Only the end of the connection would delimit a body here, and
        // nothing shows the connection ended where the provider ended it.
        (false, None) if body.is_empty() && BODILESS.contains(&status) => Vec::new(),
        (false, None) => return Err("response body is not delimited".into()),
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Removes HTTP/1.1 chunked transfer encoding from a whole body, which has
/// no trailers and nothing after it.
fn dechunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&raw[..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        // Hex digits only: `from_str_radix` alone would also take a sign.
        let size = size
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
            .then(|| usize::from_str_radix(size, 16).ok())??;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return (raw == b"\r\n").then_some(body);
        }
        body.extend_from_slice(raw.get(..size)?);
        raw = raw.get(size..)?.strip_prefix(b"\r\n")?;
    }
}

/// The id of the message a response body carries, if any.
pub fn message_id(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let id = text.split("\"id\":\"msg_").nth(1)?.split('"').next()?;
    Some(format!("msg_{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_joins_chunks_and_rejects_truncation() {
        let raw = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).as_deref(), Some(&b"hello world"[..]));
        assert_eq!(dechunk(b"5\r\nhel"), None);
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n"), None);
        assert_eq!(dechunk(b"1\r\nxZZ0\r\n\r\n"), None);
        assert_eq!(dechunk(b"+5\r\nhello\r\n0\r\n\r\n"), None);
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n\r\nmore"), None);
        assert_eq!(dechunk(b"zz\r\nhello\r\n0\r\n\r\n"), None);
    }

    #[test]
    fn response_body_must_be_delimited_and_whole() {
        let whole = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
        assert_eq!(parse_response(whole).unwrap().body, b"hello");
        assert!(parse_response(&whole[..whole.len() - 1]).is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\nhello").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 100 Continue\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 100 Continue\r\ncontent-length: 0\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: +5\r\n\r\nhello").is_err());
        assert!(
            parse_response(
                b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 9\r\n\r\nhello"
            )
            .is_err()
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .unwrap()
                .status,
            101
        );
    }

    #[test]
    fn message_id_survives_chunk_boundaries() {
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n10\r\n{\"id\":\"msg_abc12\r\n4\r\n3\"}\n\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(message_id(&response.body).as_deref(), Some("msg_abc123"));
        assert_eq!(message_id(b"{}"), None);
    }
}
