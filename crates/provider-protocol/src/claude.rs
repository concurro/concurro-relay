//! Deterministic Claude HTTP/2 requests and connection-local response state.

use anyhow::{Context, Result, bail, ensure};
use httlib_hpack::Decoder;

use crate::header_key;
use serde_json::{Map, Value};

/// HTTP/2 connection preface sent inside the protected first record.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The credential entry installed by the first header block.
pub const AUTH_INDEX: usize = 62;
/// Provider and reference maximum frame payload.
pub const MAX_FRAME_SIZE: usize = 16_384;
/// Match the reference HPACK decoder's default decoded header-list budget.
pub const MAX_HEADER_LIST_SIZE: usize = 65_536;
/// The request paths a Claude session may use: the Messages API, which
/// answers with the event streams the session reads.
const PATHS: [&[u8]; 2] = [b"/v1/messages", b"/v1/messages?beta=true"];
/// Header names a public template may not carry: the credential's, the
/// authority's and the body length's, which the relay sets, and those
/// HTTP/2 forbids (RFC 9113, section 8.2.2).
const RESERVED_HEADERS: [&[u8]; 10] = [
    b"authorization",
    b"x-api-key",
    b"host",
    b"content-length",
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
    b"te",
];

/// Public fields copied from one local Claude HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Template {
    /// Provider path, including any query string.
    pub path: Vec<u8>,
    /// Public headers in their original order.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Template {
    /// Return the fixed public first request used by bootstrap fixtures.
    pub fn fixture_default() -> Self {
        Self {
            path: b"/v1/messages".to_vec(),
            headers: vec![
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"anthropic-version".to_vec(), b"2023-06-01".to_vec()),
            ],
        }
    }

    /// Encode public fields for the Python-compatible control message.
    pub fn metadata(&self) -> Result<Map<String, Value>> {
        let path = std::str::from_utf8(&self.path)?;
        let headers: Vec<_> = self
            .headers
            .iter()
            .map(|(name, value)| {
                Ok::<_, anyhow::Error>([
                    std::str::from_utf8(name)?.to_owned(),
                    std::str::from_utf8(value)?.to_owned(),
                ])
            })
            .collect::<Result<_>>()?;
        Ok(serde_json::from_value(
            serde_json::json!({"path":path,"headers":headers}),
        )?)
    }

    /// Decode the Python-compatible control metadata shape.
    pub fn from_metadata(metadata: &Map<String, Value>) -> Result<Self> {
        let path = metadata
            .get("path")
            .and_then(Value::as_str)
            .context("Claude template path missing")?
            .as_bytes()
            .to_vec();
        let fields = metadata
            .get("headers")
            .and_then(Value::as_array)
            .context("Claude template headers missing")?;
        let mut headers = Vec::with_capacity(fields.len());
        for field in fields {
            let pair = field.as_array().context("Claude header pair missing")?;
            ensure!(pair.len() == 2, "invalid Claude header pair");
            headers.push((
                pair[0]
                    .as_str()
                    .context("Claude header name missing")?
                    .as_bytes()
                    .to_vec(),
                pair[1]
                    .as_str()
                    .context("Claude header value missing")?
                    .as_bytes()
                    .to_vec(),
            ));
        }
        let template = Self { path, headers };
        template.public_headers()?;
        Ok(template)
    }

    /// Encode public fields without mutating the request HPACK table.
    pub fn public_headers(&self) -> Result<Vec<u8>> {
        ensure!(
            PATHS.contains(&self.path.as_slice()),
            "unsupported Claude request path"
        );
        let mut block = vec![0x83, 0x87];
        block.extend(hpack_integer(1, 4, 0));
        block.extend(hpack_string(b"api.anthropic.com"));
        block.extend(hpack_integer(4, 4, 0));
        block.extend(hpack_string(&self.path));
        for (name, value) in &self.headers {
            let name = name.to_ascii_lowercase();
            ensure!(
                !name.is_empty()
                    && !name.starts_with(b":")
                    && !RESERVED_HEADERS.contains(&header_key(&name).as_slice())
                    && name.iter().all(|byte| (33..=126).contains(byte))
                    && !name.contains(&b'\r')
                    && !name.contains(&b'\n')
                    && !value.contains(&b'\r')
                    && !value.contains(&b'\n'),
                "invalid public Claude header"
            );
            block.extend(hpack_integer(0, 4, 0));
            block.extend(hpack_string(&name));
            block.extend(hpack_string(value));
        }
        Ok(block)
    }
}

/// Encode one HPACK integer with the reference prefix width.
fn hpack_integer(mut value: usize, prefix: u8, first: u8) -> Vec<u8> {
    let limit = (1usize << prefix) - 1;
    if value < limit {
        return vec![first | value as u8];
    }
    let mut bytes = vec![first | limit as u8];
    value -= limit;
    while value >= 128 {
        bytes.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

/// Encode one uncompressed HPACK string.
fn hpack_string(value: &[u8]) -> Vec<u8> {
    [&hpack_integer(value.len(), 7, 0)[..], value].concat()
}

/// Encode one bounded HTTP/2 frame.
pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= MAX_FRAME_SIZE && stream < (1 << 31),
        "HTTP/2 frame bounds exceeded"
    );
    let size = (payload.len() as u32).to_be_bytes();
    Ok([&size[1..], &[kind, flags], &stream.to_be_bytes(), payload].concat())
}

/// Build the credential-bearing first header block and return its protected slot.
pub fn bootstrap(credential: &[u8], template: &Template) -> Result<(Vec<u8>, usize)> {
    ensure!(
        !credential.is_empty() && !credential.contains(&b'\r') && !credential.contains(&b'\n'),
        "invalid Claude credential"
    );
    let mut block = template.public_headers()?;
    block.extend(hpack_integer(23, 6, 0x40));
    block.extend(hpack_string(&[b"Bearer ".as_slice(), credential].concat()));
    let mut prefix = PREFACE.to_vec();
    prefix.extend(frame(4, 0, 0, &[])?);
    prefix.extend(frame(1, 4, 1, &block)?);
    let slot = prefix
        .windows(credential.len())
        .position(|part| part == credential)
        .context("Claude credential slot missing")?;
    Ok((prefix, slot))
}

/// Public request table and outbound flow-control state for one provider socket.
pub struct IndexedConnection {
    /// Current provider generation, zero for the initial socket.
    pub generation: u64,
    /// Active request stream, until its final DATA frame.
    pub active_stream: Option<u32>,
    /// Whether GOAWAY or a table shrink ended credential-index reuse.
    pub terminal: bool,
    /// Provider-advertised header table size.
    pub table_size: u32,
    /// Next odd client stream identifier.
    pub next_stream: u32,
    /// Connection-level outbound credit.
    pub connection_window: i64,
    /// Initial per-stream outbound credit.
    pub initial_stream_window: i64,
    /// Active stream outbound credit.
    pub stream_window: i64,
}

impl IndexedConnection {
    /// Start after the bootstrap installed authorization at dynamic index 62.
    pub fn new(credential_length: usize) -> Result<Self> {
        ensure!(
            52 + credential_length <= 4096,
            "credential exceeds initial HPACK table"
        );
        Ok(Self {
            generation: 0,
            active_stream: Some(1),
            terminal: false,
            table_size: 4096,
            next_stream: 3,
            connection_window: 65_535,
            initial_stream_window: 65_535,
            stream_window: 65_535,
        })
    }

    /// Require the original usable credential index and socket generation.
    pub fn require_live(&self, generation: u64) -> Result<()> {
        ensure!(
            !self.terminal && self.generation == generation,
            "stale HTTP/2 connection state"
        );
        Ok(())
    }

    /// Apply provider SETTINGS to the request table and active flow window.
    pub fn settings(&mut self, table_size: Option<u32>, initial_window: Option<u32>) -> Result<()> {
        if let Some(size) = table_size {
            if size < self.table_size {
                self.terminal = true;
            }
            self.table_size = size;
        }
        if let Some(size) = initial_window {
            ensure!(size < (1 << 31), "invalid initial stream window");
            self.stream_window += i64::from(size) - self.initial_stream_window;
            self.initial_stream_window = i64::from(size);
        }
        Ok(())
    }

    /// Add provider credit for the connection or the active request stream.
    pub fn window_update(&mut self, stream: u32, increment: u32) -> Result<()> {
        ensure!(
            increment > 0 && increment < (1 << 31),
            "invalid provider window increment"
        );
        if stream == 0 {
            self.connection_window += i64::from(increment);
        } else if Some(stream) == self.active_stream {
            self.stream_window += i64::from(increment);
        }
        Ok(())
    }

    /// Charge one sent DATA payload against both outbound windows.
    pub fn consume_window(&mut self, size: usize) -> Result<()> {
        ensure!(
            size as i64 <= self.connection_window && size as i64 <= self.stream_window,
            "HTTP/2 flow-control window exhausted"
        );
        self.connection_window -= size as i64;
        self.stream_window -= size as i64;
        Ok(())
    }

    /// Open a later stream using only the opaque authorization index.
    pub fn later_headers(
        &mut self,
        generation: u64,
        template: &Template,
    ) -> Result<(u32, Vec<u8>)> {
        self.require_live(generation)?;
        ensure!(self.active_stream.is_none(), "request stream still active");
        let stream = self.next_stream;
        self.next_stream = self
            .next_stream
            .checked_add(2)
            .context("HTTP/2 stream ids exhausted")?;
        self.active_stream = Some(stream);
        self.stream_window = self.initial_stream_window;
        let mut block = template.public_headers()?;
        block.extend(hpack_integer(AUTH_INDEX, 7, 0x80));
        Ok((stream, frame(1, 4, stream, &block)?))
    }

    /// End the active request stream after its final DATA piece.
    pub fn data_chunk(
        &mut self,
        stream: u32,
        chunk: &[u8],
        final_piece: bool,
        generation: u64,
    ) -> Result<Vec<u8>> {
        self.require_live(generation)?;
        ensure!(
            self.active_stream == Some(stream) && !chunk.is_empty(),
            "invalid request DATA stream"
        );
        let wire = frame(0, u8::from(final_piece), stream, chunk)?;
        if final_piece {
            self.active_stream = None;
        }
        Ok(wire)
    }

    /// Invalidate all later indexed requests after connection termination.
    pub fn close(&mut self) {
        self.terminal = true;
    }
}

/// Result of a proved Sponsor request frame.
#[derive(Debug)]
pub enum AuditFrame {
    /// Permitted H2 control frame.
    Control,
    /// Partial JSON body on this stream awaiting another DATA frame.
    Partial(u32),
    /// An approved indexed header block for this later stream.
    Headers(u32),
    /// Completed JSON prompt for this request stream.
    Prompt(u32, Vec<u8>),
}

/// Audit proved request bytes without knowing the credential value.
pub struct SponsorAudit {
    /// Expected public request table state.
    state: IndexedConnection,
    /// First or next odd client stream number.
    next_stream: u32,
    /// Whether the next application frame must be DATA.
    waiting_data: bool,
    /// Accumulated JSON body across proved DATA frames.
    body: Vec<u8>,
    /// Public templates for first and later requests.
    templates: Vec<Template>,
}

impl SponsorAudit {
    /// Bind expected request frames to one credential length and first template.
    pub fn new(credential_length: usize, first: Template) -> Result<Self> {
        Ok(Self {
            state: IndexedConnection::new(credential_length)?,
            next_stream: 1,
            waiting_data: true,
            body: Vec::new(),
            templates: vec![first],
        })
    }

    /// Append the template of the next stream before its HEADERS proof;
    /// each stream has one.
    pub fn template(&mut self, template: Template) -> Result<()> {
        ensure!(
            self.templates.len() == ((self.next_stream - 1) / 2) as usize,
            "unexpected Claude request template"
        );
        self.templates.push(template);
        Ok(())
    }

    /// The public template of client stream `stream`.
    pub fn template_for(&self, stream: u32) -> Option<&Template> {
        self.templates.get((stream.checked_sub(1)? / 2) as usize)
    }

    /// The body proved so far on the stream being uploaded.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Validate one proved exact H2 frame and return its audit effect.
    pub fn accept(&mut self, plaintext: &[u8]) -> Result<AuditFrame> {
        self.state.require_live(0)?;
        let parsed = parse_frame(plaintext)?.context("partial proved HTTP/2 frame")?;
        ensure!(
            parsed.wire.len() == plaintext.len(),
            "proved HTTP/2 frame has trailing bytes"
        );
        if parsed.kind == 4 && parsed.flags == 1 && parsed.stream == 0 && parsed.payload.is_empty()
        {
            return Ok(AuditFrame::Control);
        }
        if parsed.kind == 8
            && parsed.flags == 0
            && parsed.payload.len() == 4
            && (parsed.stream == 0 || parsed.stream < self.next_stream && parsed.stream % 2 == 1)
            && u32::from_be_bytes(parsed.payload.try_into().unwrap()) & 0x7fff_ffff > 0
        {
            return Ok(AuditFrame::Control);
        }
        if parsed.kind == 6 && parsed.flags == 1 && parsed.stream == 0 && parsed.payload.len() == 8
        {
            return Ok(AuditFrame::Control);
        }
        if self.waiting_data {
            ensure!(
                parsed.kind == 0 && parsed.stream == self.next_stream && parsed.flags <= 1,
                "wrong DATA frame or stream"
            );
            self.body.extend_from_slice(parsed.payload);
            if parsed.flags == 0 {
                return Ok(AuditFrame::Partial(self.next_stream));
            }
            serde_json::from_slice::<Value>(&self.body)
                .context("proved Claude prompt is not JSON")?;
            let prompt = std::mem::take(&mut self.body);
            self.waiting_data = false;
            self.state.active_stream = None;
            let stream = self.next_stream;
            self.next_stream += 2;
            Ok(AuditFrame::Prompt(stream, prompt))
        } else {
            let template = self
                .templates
                .get(((self.next_stream - 1) / 2) as usize)
                .context("missing public request template")?;
            let (stream, expected) = self.state.later_headers(0, template)?;
            ensure!(
                stream == self.next_stream && plaintext == expected,
                "unapproved indexed HEADERS"
            );
            self.waiting_data = true;
            Ok(AuditFrame::Headers(stream))
        }
    }
}

/// A complete HTTP/2 frame or a valid partial buffer.
pub struct Frame<'a> {
    /// Frame kind.
    pub kind: u8,
    /// Frame flags.
    pub flags: u8,
    /// Stream identifier.
    pub stream: u32,
    /// Frame payload.
    pub payload: &'a [u8],
    /// Entire frame bytes.
    pub wire: &'a [u8],
}

/// Parse one bounded frame from an incremental application byte buffer.
pub fn parse_frame(bytes: &[u8]) -> Result<Option<Frame<'_>>> {
    if bytes.len() < 9 {
        return Ok(None);
    }
    let size = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
    ensure!(size <= MAX_FRAME_SIZE, "HTTP/2 frame exceeds bound");
    let stream = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
    ensure!(stream & (1 << 31) == 0, "HTTP/2 reserved stream bit set");
    if bytes.len() < 9 + size {
        return Ok(None);
    }
    Ok(Some(Frame {
        kind: bytes[3],
        flags: bytes[4],
        stream,
        payload: &bytes[9..9 + size],
        wire: &bytes[..9 + size],
    }))
}

/// Authenticated response event produced as soon as a complete frame arrives.
#[derive(Debug)]
pub enum ResponseEvent {
    /// Validated status and decoded response headers.
    Headers(u16, Vec<(Vec<u8>, Vec<u8>)>),
    /// Authenticated response body bytes.
    Data(Vec<u8>),
    /// Client control frame required by provider state or flow credit.
    Send(Vec<u8>),
    /// End of the response stream.
    Done,
}

/// Incremental H2/HPACK response decoder retaining its dynamic table.
pub struct ResponseReader {
    /// Provider frame bytes awaiting completion.
    pending: Vec<u8>,
    /// Response header block across HEADERS/CONTINUATION.
    header_block: Vec<u8>,
    /// Whether the next frame must continue the active header block.
    continuation: bool,
    /// Whether HEADERS carried END_STREAM.
    headers_end_stream: bool,
    /// Active response stream.
    stream: u32,
    /// Whether response headers were decoded.
    headers_seen: bool,
    /// Connection-local response HPACK table.
    decoder: Decoder<'static>,
}

impl ResponseReader {
    /// Create a fresh response decoder for one provider connection.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            header_block: Vec::new(),
            continuation: false,
            headers_end_stream: false,
            stream: 1,
            headers_seen: false,
            decoder: Decoder::with_dynamic_size(4096),
        }
    }

    /// Select the next request stream while retaining response HPACK state.
    pub fn stream(&mut self, stream: u32) {
        self.stream = stream;
        self.headers_seen = false;
        self.header_block.clear();
        self.continuation = false;
        self.headers_end_stream = false;
    }

    /// Decode authenticated application bytes into immediate response effects.
    pub fn push(
        &mut self,
        bytes: &[u8],
        state: &mut IndexedConnection,
    ) -> Result<Vec<ResponseEvent>> {
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some(parsed) = parse_frame(&self.pending)? {
            let size = parsed.wire.len();
            let kind = parsed.kind;
            let flags = parsed.flags;
            let stream = parsed.stream;
            let payload = parsed.payload.to_vec();
            self.pending.drain(..size);
            if self.continuation {
                ensure!(
                    kind == 9 && stream == self.stream,
                    "incomplete response HEADERS"
                );
            }
            match kind {
                4 => {
                    ensure!(
                        stream == 0
                            && flags <= 1
                            && payload.len() % 6 == 0
                            && (flags == 0 || payload.is_empty()),
                        "invalid server SETTINGS"
                    );
                    if flags == 0 {
                        for entry in payload.as_chunks::<6>().0 {
                            let setting = u16::from_be_bytes(entry[..2].try_into().unwrap());
                            let value = u32::from_be_bytes(entry[2..].try_into().unwrap());
                            match setting {
                                1 => state.settings(Some(value), None)?,
                                4 => state.settings(None, Some(value))?,
                                _ => {}
                            }
                        }
                        state.require_live(0)?;
                        events.push(ResponseEvent::Send(frame(4, 1, 0, &[])?));
                    }
                }
                7 => {
                    state.close();
                    bail!("provider GOAWAY");
                }
                3 if stream == self.stream => {
                    state.close();
                    bail!("provider reset request stream");
                }
                8 => {
                    ensure!(flags == 0 && payload.len() == 4, "invalid WINDOW_UPDATE");
                    state.window_update(
                        stream,
                        u32::from_be_bytes(payload.try_into().unwrap()) & 0x7fff_ffff,
                    )?;
                }
                1 | 9 => {
                    ensure!(
                        stream == self.stream
                            && flags & !5 == 0
                            && (kind != 1 || !self.headers_seen)
                            && (kind != 9 || self.continuation && flags & 1 == 0),
                        "unexpected response HEADERS"
                    );
                    if kind == 1 {
                        self.headers_end_stream = flags & 1 != 0;
                    }
                    self.header_block.extend(payload);
                    ensure!(
                        self.header_block.len() <= MAX_HEADER_LIST_SIZE,
                        "response HPACK block exceeds bound"
                    );
                    self.continuation = flags & 4 == 0;
                    if !self.continuation {
                        let mut block = std::mem::take(&mut self.header_block);
                        let mut headers = Vec::new();
                        let mut list_size = 0usize;
                        let mut decoded = Vec::with_capacity(1);
                        while !block.is_empty() {
                            self.decoder
                                .decode_exact(&mut block, &mut decoded)
                                .map_err(|error| {
                                    anyhow::anyhow!("HPACK response decode: {error:?}")
                                })?;
                            if let Some((name, value, _)) = decoded.pop() {
                                list_size = list_size
                                    .checked_add(name.len() + value.len() + 32)
                                    .context("response header list size overflow")?;
                                ensure!(
                                    list_size <= MAX_HEADER_LIST_SIZE,
                                    "response header list exceeds bound"
                                );
                                headers.push((name, value));
                            }
                        }
                        let status = headers
                            .iter()
                            .find(|(name, _)| name == b":status")
                            .context("missing response status")?
                            .1
                            .as_slice();
                        let status = std::str::from_utf8(status)?.parse::<u16>()?;
                        self.headers_seen = true;
                        events.push(ResponseEvent::Headers(status, headers));
                        if self.headers_end_stream {
                            events.push(ResponseEvent::Done);
                        }
                    }
                }
                0 => {
                    ensure!(
                        stream == self.stream && self.headers_seen && flags <= 1,
                        "unexpected response DATA"
                    );
                    if !payload.is_empty() {
                        events.push(ResponseEvent::Data(payload.clone()));
                        let credit = (payload.len() as u32).to_be_bytes();
                        events.push(ResponseEvent::Send(frame(8, 0, 0, &credit)?));
                        events.push(ResponseEvent::Send(frame(8, 0, stream, &credit)?));
                    }
                    if flags & 1 != 0 {
                        events.push(ResponseEvent::Done);
                    }
                }
                6 => {
                    ensure!(
                        stream == 0 && payload.len() == 8 && flags <= 1,
                        "invalid PING"
                    );
                    if flags == 0 {
                        events.push(ResponseEvent::Send(frame(6, 1, 0, &payload)?));
                    }
                }
                2 if payload.len() == 5 && stream != 0 => {}
                _ => bail!("unsupported server HTTP/2 frame {kind}"),
            }
        }
        Ok(events)
    }
}

impl Default for ResponseReader {
    /// Create a fresh response decoder.
    fn default() -> Self {
        Self::new()
    }
}

/// Completed Claude message identity and merged provider usage.
pub struct SseSummary {
    /// New message identifier from `message_start`.
    pub message_id: String,
    /// Usage merged from `message_start` and `message_delta`.
    pub usage: Value,
    /// Tool names issued by authenticated provider content blocks.
    pub tool_uses: Vec<String>,
}

/// Validate a completed SSE response after its bytes were streamed locally.
pub fn summarize_sse(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
) -> Result<SseSummary> {
    let content_type = headers
        .iter()
        .find(|(name, _)| name == b"content-type")
        .map(|(_, value)| value.as_slice())
        .unwrap_or_default();
    ensure!(
        content_type
            .windows(b"text/event-stream".len())
            .any(|part| part == b"text/event-stream"),
        "provider returned HTTP {status} without SSE"
    );
    let mut start = None;
    let mut delta = None;
    let mut tool_uses = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"data: ") {
            let event: Value = serde_json::from_slice(value)?;
            match event["type"].as_str() {
                Some("message_start") => {
                    ensure!(
                        start.replace(event).is_none(),
                        "duplicate Claude message_start"
                    );
                }
                Some("message_delta") => {
                    ensure!(
                        delta.replace(event).is_none(),
                        "duplicate Claude message_delta"
                    );
                }
                Some("content_block_start") if event["content_block"]["type"] == "tool_use" => {
                    tool_uses.push(
                        event["content_block"]["name"]
                            .as_str()
                            .context("Claude tool name missing")?
                            .to_owned(),
                    );
                }
                _ => {}
            }
        }
    }
    let start = start.context("Claude message_start missing")?;
    let delta = delta.context("Claude message_delta missing")?;
    let message_id = start["message"]["id"]
        .as_str()
        .context("Claude message id missing")?
        .to_owned();
    let mut usage = start["message"]["usage"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if let Some(update) = delta["usage"].as_object() {
        usage.extend(update.clone());
    }
    Ok(SseSummary {
        message_id,
        usage: Value::Object(usage),
        tool_uses,
    })
}

#[cfg(test)]
mod tests {
    use ring::digest::{SHA256, digest};

    use super::{
        AuditFrame, IndexedConnection, ResponseEvent, ResponseReader, SponsorAudit, Template,
        bootstrap, frame,
    };

    /// Only the Messages API paths are admitted, and no header the relay
    /// sets or HTTP/2 forbids.
    #[test]
    fn templates_keep_to_the_messages_api() {
        let with_path = |path: &[u8]| Template {
            path: path.to_vec(),
            ..Template::fixture_default()
        };
        assert!(with_path(b"/v1/messages").public_headers().is_ok());
        assert!(
            with_path(b"/v1/messages?beta=true")
                .public_headers()
                .is_ok()
        );
        for path in [
            &b"/v1/messages/batches"[..],
            b"/v1/messages/count_tokens",
            b"/v1/messages/../../api/oauth/profile",
            b"/v1/messages%2f..",
            b"/v1/messages?beta=true&x=1",
            b"/v1/messagesX",
        ] {
            assert!(with_path(path).public_headers().is_err(), "{path:?}");
        }
        for name in [
            "host",
            "Host",
            "content-length",
            "te",
            "connection",
            "x-api-key",
            "X_Api_Key",
            "content_length",
        ] {
            let mut template = Template::fixture_default();
            template
                .headers
                .push((name.as_bytes().to_vec(), b"value".to_vec()));
            assert!(template.public_headers().is_err(), "{name}");
        }
    }

    /// Match the frozen bootstrap and opaque authorization-index bytes.
    #[test]
    fn indexed_request_reference() {
        let template = Template {
            path: b"/v1/messages".to_vec(),
            headers: Vec::new(),
        };
        let (head, slot) = bootstrap(b"fixture-only-token", &template).unwrap();
        assert_eq!(slot, 86);
        assert_eq!(
            hex::encode(digest(&SHA256, &head).as_ref()),
            "898d34f8cfd4a302369a650700664e5edcf31d71d07b732315110d7536de983b"
        );
        let mut state = IndexedConnection::new(18).unwrap();
        state.active_stream = None;
        let (stream, headers) = state.later_headers(0, &template).unwrap();
        assert_eq!(stream, 3);
        assert_eq!(
            hex::encode(headers),
            "000024010400000003838701116170692e616e7468726f7069632e636f6d040c2f76312f6d65737361676573be"
        );
        assert!(state.later_headers(0, &template).is_err());
        state.settings(Some(1024), None).unwrap();
        assert!(state.later_headers(0, &template).is_err());
    }

    /// Sponsor admits only proved DATA and the expected indexed later HEADERS.
    #[test]
    fn sponsor_audit_reference() {
        let template = Template::fixture_default();
        let mut audit = SponsorAudit::new(18, template.clone()).unwrap();
        let body = br#"{"messages":[{"content":"fixture prompt"}]}"#;
        std::assert_matches!(
            audit.accept(&frame(0, 0, 1, &body[..9]).unwrap()).unwrap(),
            AuditFrame::Partial(1)
        );
        assert_eq!(audit.body(), &body[..9]);
        assert_eq!(audit.template_for(1), Some(&template));
        std::assert_matches!(
            audit.accept(&frame(0, 1, 1, &body[9..]).unwrap()).unwrap(),
            AuditFrame::Prompt(1, value) if value == body
        );
        let mut state = IndexedConnection::new(18).unwrap();
        state.active_stream = None;
        let (_, headers) = state.later_headers(0, &template).unwrap();
        audit.template(template.clone()).unwrap();
        assert!(audit.template(template.clone()).is_err());
        assert_eq!(audit.template_for(3), Some(&template));
        std::assert_matches!(audit.accept(&headers).unwrap(), AuditFrame::Headers(3));
        assert!(audit.accept(&frame(0, 1, 5, body).unwrap()).is_err());
    }

    /// Decode fragmented H2 frames, CONTINUATION, Huffman text and early DATA.
    #[test]
    fn response_fragments_and_controls() {
        let mut reader = ResponseReader::new();
        let mut state = IndexedConnection::new(18).unwrap();
        state.active_stream = None;
        let mut block = vec![0x88];
        block.extend_from_slice(&hex::decode("418cf1e3c2e5f23a6ba0ab90f4ff").unwrap());
        let mut wire = frame(1, 0, 1, &block[..4]).unwrap();
        wire.extend(frame(9, 4, 1, &block[4..]).unwrap());
        for chunk in wire.chunks(3) {
            let events = reader.push(chunk, &mut state).unwrap();
            if !events.is_empty() {
                std::assert_matches!(
                    &events[..],
                    [ResponseEvent::Headers(200, headers)] if headers.iter().any(|(name, value)| name == b":authority" && value == b"www.example.com")
                );
            }
        }
        let data = frame(0, 1, 1, b"data: hello\n\n").unwrap();
        let events = reader.push(&data, &mut state).unwrap();
        std::assert_matches!(
            &events[..],
            [ResponseEvent::Data(bytes), ResponseEvent::Send(_), ResponseEvent::Send(_), ResponseEvent::Done] if bytes == b"data: hello\n\n"
        );
        let settings = frame(4, 0, 0, &[0, 4, 0, 0, 0, 5]).unwrap();
        std::assert_matches!(
            &reader.push(&settings, &mut state).unwrap()[..],
            [ResponseEvent::Send(_)]
        );
        assert_eq!(state.initial_stream_window, 5);
        assert!(
            reader
                .push(&frame(7, 0, 0, &[0; 8]).unwrap(), &mut state)
                .is_err()
        );
    }

    /// Count HPACK's per-field overhead and stop repeated fields at the decoded budget.
    #[test]
    fn response_header_list_budget() {
        let mut state = IndexedConnection::new(18).unwrap();
        let mut reader = ResponseReader::new();
        let accepted = frame(1, 4, 1, &vec![0x88; 1_560]).unwrap();
        let events = reader.push(&accepted, &mut state).unwrap();
        std::assert_matches!(&events[..], [ResponseEvent::Headers(200, headers)] if headers.len() == 1_560);

        let mut reader = ResponseReader::new();
        let rejected = frame(1, 4, 1, &vec![0x88; 1_561]).unwrap();
        assert!(
            reader
                .push(&rejected, &mut state)
                .unwrap_err()
                .to_string()
                .contains("header list exceeds bound")
        );
    }

    /// Apply outbound credit and reject reset or an interrupted header block.
    #[test]
    fn windows_reset_and_continuation() {
        let mut state = IndexedConnection::new(18).unwrap();
        state.consume_window(65_535).unwrap();
        assert_eq!(state.connection_window, 0);
        assert_eq!(state.stream_window, 0);
        state.window_update(0, 32).unwrap();
        state.window_update(1, 16).unwrap();
        state.consume_window(16).unwrap();
        assert_eq!(state.connection_window, 16);
        assert_eq!(state.stream_window, 0);
        state.settings(None, Some(8)).unwrap();
        assert_eq!(state.stream_window, -65_527);
        assert!(state.consume_window(1).is_err());
        let mut reader = ResponseReader::new();
        assert!(
            reader
                .push(&frame(1, 0, 1, &[0x88]).unwrap(), &mut state)
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .push(&frame(0, 1, 1, b"early").unwrap(), &mut state)
                .is_err()
        );
        let mut reader = ResponseReader::new();
        assert!(
            reader
                .push(&frame(3, 0, 1, &[0; 4]).unwrap(), &mut state)
                .is_err()
        );
        assert!(state.terminal);
    }
}
