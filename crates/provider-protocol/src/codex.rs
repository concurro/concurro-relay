//! Codex WebSocket request claims, frame audit and response identity.

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_protocol::ws::{self, Asked, Inbox};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::{Number, Value, value::RawValue};
use std::fmt::{self, Write};
use tokio_tungstenite::tungstenite::{
    Message,
    protocol::frame::coding::{Control, OpCode},
};

/// Build the provider upgrade head and return the protected bearer slot.
pub fn request_head(credential: &[u8], websocket_key: &[u8]) -> (Vec<u8>, usize) {
    let mut head =
        b"GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer "
            .to_vec();
    let slot = head.len();
    head.extend_from_slice(credential);
    head.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
    head.extend_from_slice(websocket_key);
    head.extend_from_slice(b"\r\n\r\n");
    (head, slot)
}

/// JSON value retaining Python's parsed object insertion order.
enum OrderedJson {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON number.
    Number(String),
    /// JSON string.
    String(String),
    /// JSON array.
    Array(Vec<Self>),
    /// JSON object in insertion order.
    Object(Vec<(String, Self)>),
}

/// JSON object parsed with keys in source order and raw child values.
struct OrderedObject(Vec<(String, OrderedJson)>);

impl<'de> Deserialize<'de> for OrderedObject {
    /// Parse object fields without converting their numeric values.
    fn deserialize<D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        /// Visit an object whose values remain raw until recursive parsing.
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = OrderedObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut fields: Vec<(String, OrderedJson)> = Vec::new();
                while let Some((key, raw)) = map.next_entry::<String, Box<RawValue>>()? {
                    let value = parse_ordered(raw.get()).map_err(de::Error::custom)?;
                    if let Some((_, existing)) = fields.iter_mut().find(|(name, _)| *name == key) {
                        *existing = value;
                    } else {
                        fields.push((key, value));
                    }
                }
                Ok(OrderedObject(fields))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// Parse one validated raw JSON value while retaining object and number text.
fn parse_ordered(raw: &str) -> Result<OrderedJson> {
    let raw = raw.trim();
    match raw.as_bytes().first() {
        Some(b'{') => Ok(OrderedJson::Object(
            serde_json::from_str::<OrderedObject>(raw)?.0,
        )),
        Some(b'[') => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(raw)?;
            Ok(OrderedJson::Array(
                values
                    .iter()
                    .map(|value| parse_ordered(value.get()))
                    .collect::<Result<_>>()?,
            ))
        }
        Some(b'"') => Ok(OrderedJson::String(serde_json::from_str(raw)?)),
        Some(b't') => Ok(OrderedJson::Bool(true)),
        Some(b'f') => Ok(OrderedJson::Bool(false)),
        Some(b'n') => Ok(OrderedJson::Null),
        _ => Ok(OrderedJson::Number(raw.to_owned())),
    }
}

impl OrderedJson {
    /// Append compact JSON, retaining each object's insertion order.
    fn append(&self, output: &mut String) -> Result<()> {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => {
                if value.contains(['.', 'e', 'E']) {
                    let float: f64 = serde_json::from_str(value)?;
                    let number = Number::from_f64(float).context("non-finite JSON number")?;
                    output.push_str(&python_float(&number));
                } else if value == "-0" {
                    output.push('0');
                } else {
                    output.push_str(value);
                }
            }
            Self::String(value) => output.push_str(&serde_json::to_string(value)?),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    value.append(output)?;
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    value.append(output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }
}

/// Format a finite JSON float using Python's fixed/scientific cutoffs.
fn python_float(number: &Number) -> String {
    let raw = number.to_string();
    let (sign, unsigned) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |value| ("-", value));
    let (mantissa, exponent) =
        unsigned
            .split_once('e')
            .map_or((unsigned, 0), |(mantissa, exponent)| {
                (
                    mantissa,
                    exponent.parse::<i32>().expect("finite float exponent"),
                )
            });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
    let mut digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let leading = digits.bytes().take_while(|digit| *digit == b'0').count();
    if leading == digits.len() {
        return format!("{sign}0.0");
    }
    digits.drain(..leading);
    while digits.ends_with('0') {
        digits.pop();
    }
    let magnitude = decimal - leading as i32 + exponent - 1;
    if !(-4..16).contains(&magnitude) {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        return format!("{sign}{first}{fraction}e{:+03}", magnitude);
    }
    let point = magnitude + 1;
    if point <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!(
            "{sign}{digits}{}.0",
            "0".repeat(point as usize - digits.len())
        )
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{sign}{whole}.{fraction}")
    }
}

/// Match Python's compact `json.dumps` bytes while retaining integer precision.
pub fn normalize_request(raw: &str) -> Result<String> {
    let value: Box<RawValue> = serde_json::from_str(raw)?;
    let parsed = parse_ordered(value.get())?;
    let mut compact = String::new();
    parsed.append(&mut compact)?;
    let mut ascii = String::with_capacity(compact.len());
    for character in compact.chars() {
        if character.is_ascii() && character != '\u{7f}' {
            ascii.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                write!(ascii, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(ascii)
}

/// Public record bytes and Concurro's private key material bound into one proof.
#[derive(Serialize)]
pub struct RequestClaim {
    /// Public hello hash.
    pub h2: String,
    /// Authenticated server transcript hash.
    pub h3: String,
    /// Protected application-key commitment.
    pub key_commitment: String,
    /// Client traffic record key.
    pub key: String,
    /// Client traffic nonce base.
    pub iv: String,
    /// TLS client record sequence.
    pub sequence: u64,
    /// Exact application plaintext.
    pub plaintext: String,
    /// Exact TLS record to release after proof.
    pub record: String,
}

/// Public TLS transcript and protected application-key binding shared by request proofs.
pub struct RequestBinding {
    /// Public hello hash.
    pub h2: [u8; 32],
    /// Authenticated server transcript hash.
    pub h3: [u8; 32],
    /// Protected application-key commitment.
    pub key_commitment: [u8; 32],
}

impl RequestClaim {
    /// Encode the reference helper's JSON input shape.
    pub fn new(
        binding: &RequestBinding,
        key: &[u8; 16],
        iv: &[u8; 12],
        sequence: u64,
        plaintext: &[u8],
        record: &[u8],
    ) -> Self {
        Self {
            h2: hex::encode(binding.h2),
            h3: hex::encode(binding.h3),
            key_commitment: hex::encode(binding.key_commitment),
            key: hex::encode(key),
            iv: hex::encode(iv),
            sequence,
            plaintext: hex::encode(plaintext),
            record: hex::encode(record),
        }
    }
}

/// A complete masked client frame, or the exact HTTP upgrade continuation.
pub fn audited_payload(plaintext: &[u8], turn: u64, tail: &[u8]) -> Result<Option<String>> {
    if turn == 0 {
        ensure!(plaintext == tail, "request header continuation differs");
        return Ok(None);
    }
    if plaintext.first() == Some(&0x81) {
        let text = ws::client_text(plaintext).map_err(anyhow::Error::msg)?;
        serde_json::from_str::<Value>(&text).context("proved prompt is not JSON")?;
        Ok(Some(text))
    } else {
        let opcode = match plaintext.first() {
            Some(0x88) => OpCode::Control(Control::Close),
            Some(0x89) => OpCode::Control(Control::Ping),
            Some(0x8a) => OpCode::Control(Control::Pong),
            _ => bail!("invalid client WebSocket frame"),
        };
        ws::client_payload(plaintext, opcode).map_err(anyhow::Error::msg)?;
        Ok(None)
    }
}

/// Declared byte length of a single masked WebSocket frame, when known.
pub fn frame_length(bytes: &[u8]) -> Result<Option<usize>> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    ensure!(bytes[1] & 0x80 != 0, "client WebSocket frame is unmasked");
    let short = (bytes[1] & 127) as usize;
    let (header, size): (usize, usize) = match short {
        126 if bytes.len() >= 4 => (4, u16::from_be_bytes([bytes[2], bytes[3]]) as usize),
        127 if bytes.len() >= 10 => (
            10,
            usize::try_from(u64::from_be_bytes(bytes[2..10].try_into().unwrap()))?,
        ),
        126 | 127 => return Ok(None),
        _ => (2, short),
    };
    Ok(Some(
        header
            .checked_add(4)
            .and_then(|length| length.checked_add(size))
            .context("WebSocket frame length overflow")?,
    ))
}

/// Upgrade header names a CLI may not set: the credential's, the provider
/// account's and the WebSocket handshake's, which the relay sets, and those
/// which would change how the request is read.
pub const RESERVED_UPGRADE_HEADERS: [&str; 13] = [
    "authorization",
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "proxy-authorization",
    "x-api-key",
    "cookie",
    "chatgpt-account-id",
    "content-length",
    "transfer-encoding",
];

/// Validate the public HTTP continuation admitted after the protected bearer
/// slot, which names the Sponsor's own provider `account`, if it has one.
pub fn validate_request_tail(
    tail: &[u8],
    websocket_key: &[u8],
    account: Option<&str>,
) -> Result<()> {
    ensure!(
        tail.ends_with(b"\r\n\r\n"),
        "incomplete admitted request headers"
    );
    let mut connection = Vec::new();
    let mut upgrade = Vec::new();
    let mut version = Vec::new();
    let mut key = Vec::new();
    let mut accounts = Vec::new();
    for line in tail[..tail.len() - 4].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let split = line
            .iter()
            .position(|byte| *byte == b':')
            .context("invalid admitted HTTP header")?;
        let name = &line[..split];
        ensure!(
            !name.is_empty()
                && name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)),
            "invalid admitted HTTP header"
        );
        let value = line[split + 1..].trim_ascii();
        ensure!(
            value
                .iter()
                .all(|byte| *byte == b'\t' || !byte.is_ascii_control()),
            "invalid admitted HTTP header"
        );
        let lower = name.to_ascii_lowercase();
        match lower.as_slice() {
            b"connection" => connection.push(value),
            b"upgrade" => upgrade.push(value),
            b"sec-websocket-version" => version.push(value),
            b"sec-websocket-key" => key.push(value),
            b"chatgpt-account-id" => accounts.push(value),
            reserved
                if RESERVED_UPGRADE_HEADERS
                    .iter()
                    .any(|name| name.as_bytes() == reserved) =>
            {
                bail!("conflicting admitted HTTP header")
            }
            _ => {}
        }
    }
    ensure!(
        accounts == account.map(str::as_bytes).into_iter().collect::<Vec<_>>(),
        "admitted provider account differs from the Sponsor's"
    );
    ensure!(
        connection == [b"Upgrade"]
            && upgrade == [b"websocket"]
            && version == [b"13"]
            && key == [websocket_key],
        "invalid admitted WebSocket upgrade"
    );
    Ok(())
}

/// A response turn's events and associated usage.
pub struct Turn {
    /// JSON events in the provider's observed order.
    pub events: Vec<Vec<u8>>,
    /// Completed response identifier, if successful.
    pub response_id: Option<String>,
    /// Completed response usage, if successful.
    pub usage: Option<Value>,
}

/// Reassemble provider frames and bind each response to its requested parent.
#[derive(Default)]
pub struct Responses {
    /// Incremental provider WebSocket frame decoder.
    inbox: Inbox,
    /// Validated events awaiting release to local ingress.
    events: Vec<Vec<u8>>,
    /// Identifier created for the active response.
    response_id: Option<String>,
    /// Usage from the terminal completed response.
    usage: Option<Value>,
    /// Next event sequence when the provider supplies sequence numbers.
    sequence: u64,
}

impl Responses {
    /// Add authenticated application bytes, which may split a WebSocket frame.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.inbox.push(bytes)
    }

    /// Mark the point at which a request reaches the provider.
    pub fn asking(&mut self, previous: Option<String>) -> Asked {
        self.events.clear();
        self.response_id = None;
        self.usage = None;
        self.sequence = 0;
        self.inbox.asking(previous)
    }

    /// Return a completed response turn when enough authenticated frames arrived.
    pub fn take_turn(&mut self, asked: &Asked) -> Result<Option<Turn>> {
        while let Some((began, message)) = self.inbox.pop_message() {
            let Message::Text(text) = message else {
                match message {
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => bail!("provider sent a non-text response frame"),
                }
            };
            let event: Value =
                serde_json::from_str(text.as_str()).context("provider event is not JSON")?;
            let kind = event["type"]
                .as_str()
                .context("provider event type missing")?;
            if began < asked.before {
                ensure!(
                    !kind.starts_with("response.") && kind != "error",
                    "provider event preceded its request"
                );
                continue;
            }
            if let Some(number) = event["sequence_number"].as_u64() {
                ensure!(number == self.sequence, "provider event sequence differs");
                self.sequence += 1;
            }
            if kind == "response.created" {
                ensure!(
                    self.response_id.is_none(),
                    "provider started a second response"
                );
                ensure!(
                    event["response"]["previous_response_id"].as_str() == asked.previous.as_deref(),
                    "provider response parent differs from client request"
                );
                self.response_id = Some(
                    event["response"]["id"]
                        .as_str()
                        .context("response id missing")?
                        .to_owned(),
                );
            }
            if let Some(id) = event["response_id"]
                .as_str()
                .or_else(|| event["response"]["id"].as_str())
            {
                ensure!(
                    self.response_id.as_deref() == Some(id),
                    "provider response identity differs"
                );
            }
            self.events.push(text.as_bytes().to_vec());
            if ws::FINAL_EVENTS.contains(&kind) {
                if kind == "response.completed" {
                    ensure!(
                        self.response_id.is_some(),
                        "completed response was not created"
                    );
                    ensure!(
                        event["response"]["previous_response_id"].as_str()
                            == asked.previous.as_deref(),
                        "completed response parent differs"
                    );
                    self.usage = event["response"].get("usage").cloned();
                }
                return Ok(Some(Turn {
                    events: std::mem::take(&mut self.events),
                    response_id: self.response_id.take(),
                    usage: self.usage.take(),
                }));
            }
        }
        Ok(None)
    }

    /// Drain validated nonterminal events for immediate local forwarding.
    pub fn drain_events(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.events)
    }

    /// Return an unanswered provider ping, if one arrived.
    pub fn waiting_ping(&self) -> Option<Vec<u8>> {
        match self.inbox.waiting_ping() {
            Some(ws::Progress::Ping(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Mark one provider ping answered after its pong record is proved.
    pub fn answer_ping(&mut self, bytes: &[u8]) -> bool {
        self.inbox.answer(bytes)
    }
}

/// Parse and validate the authenticated provider WebSocket upgrade head.
pub fn upgrade_response(head: &[u8], expected_accept: &str) -> Result<()> {
    let text = std::str::from_utf8(head)?;
    let (status, fields) = text
        .split_once("\r\n")
        .context("provider HTTP status missing")?;
    ensure!(
        status.split_whitespace().nth(1) == Some("101"),
        "provider rejected WebSocket upgrade: {status}"
    );
    let accept = fields.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("sec-websocket-accept")
            .then_some(value.trim())
    });
    ensure!(
        accept == Some(expected_accept),
        "provider WebSocket accept differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        RequestBinding, RequestClaim, Responses, audited_payload, frame_length, normalize_request,
        request_head, upgrade_response, validate_request_tail,
    };
    use concurro_relay_protocol::ws;

    /// Encode a fixture provider text frame without a client mask.
    fn provider_frame(event: Value) -> Vec<u8> {
        let bytes = event.to_string().into_bytes();
        let mut frame = vec![0x81];
        if bytes.len() < 126 {
            frame.push(bytes.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        frame.extend(bytes);
        frame
    }

    /// The helper claim binds exact plaintext and wire while the verifier lacks the key.
    #[test]
    fn request_claim_and_masked_audit() {
        let (head, slot) = request_head(b"token", b"key");
        assert_eq!(&head[slot..slot + 5], b"token");
        let claim = RequestClaim::new(
            &RequestBinding {
                h2: [1; 32],
                h3: [2; 32],
                key_commitment: [3; 32],
            },
            &[4; 16],
            &[5; 12],
            7,
            b"hi",
            b"wire",
        );
        let value = serde_json::to_value(claim).unwrap();
        assert_eq!(value["sequence"], 7);
        assert_eq!(value["plaintext"], "6869");
        assert_eq!(value["record"], "77697265");
        assert_eq!(value["key"], "04".repeat(16));
        let tail = b"Connection: Upgrade\r\n\r\n";
        assert!(audited_payload(tail, 0, tail).unwrap().is_none());
        let frame = ws::text_frame(r#"{"type":"response.create"}"#, [1, 2, 3, 4]);
        assert_eq!(frame_length(&frame[..2]).unwrap(), Some(frame.len()));
        assert_eq!(
            audited_payload(&frame, 1, tail).unwrap().as_deref(),
            Some(r#"{"type":"response.create"}"#)
        );
        assert!(audited_payload(&frame[..frame.len() - 1], 1, tail).is_err());
        assert!(
            frame_length(&[
                0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ])
            .is_err()
        );
    }

    /// Compact forwarding follows Python's object order, duplicate keys and ASCII escaping.
    #[test]
    fn normalized_request_matches_python() {
        let raw = " { \"type\" : \"response.create\", \"prompt\": \"å😀\", \"obj\": {\"z\":1, \"a\":2}, \"prompt\": \"é\" } ";
        assert_eq!(
            normalize_request(raw).unwrap(),
            "{\"type\":\"response.create\",\"prompt\":\"\\u00e9\",\"obj\":{\"z\":1,\"a\":2}}"
        );
        assert_eq!(
            normalize_request("{\"emoji\":\"😀\",\"escaped\":\"\\u00e5\"}").unwrap(),
            "{\"emoji\":\"\\ud83d\\ude00\",\"escaped\":\"\\u00e5\"}"
        );
        assert_eq!(
            normalize_request(r#"{"temperature":0.7,"top_p":1e-5,"small":1e-6,"tiny":1e-7,"boundary":1e-4,"large":1e20,"larger":1e16,"medium":1e15,"negative":-0.0,"del":"\u007f"}"#).unwrap(),
            r#"{"temperature":0.7,"top_p":1e-05,"small":1e-06,"tiny":1e-07,"boundary":0.0001,"large":1e+20,"larger":1e+16,"medium":1000000000000000.0,"negative":-0.0,"del":"\u007f"}"#
        );
        assert_eq!(
            normalize_request(
                r#"{"x":1.234e-5,"y":1e20,"z":1.2e+9,"w":1e-3,"t":1e-2,"unit":1e0,"integer":1}"#
            )
            .unwrap(),
            r#"{"x":1.234e-05,"y":1e+20,"z":1200000000.0,"w":0.001,"t":0.01,"unit":1.0,"integer":1}"#
        );
        assert_eq!(
            normalize_request(r#"{"value":18446744073709551615,"text":"18446744073709551616"}"#)
                .unwrap(),
            r#"{"value":18446744073709551615,"text":"18446744073709551616"}"#
        );
        assert_eq!(
            normalize_request(r#"{"positive":18446744073709551616,"negative":-9223372036854775809,"minus_zero":-0,"nested":[123456789012345678901234567890]}"#).unwrap(),
            r#"{"positive":18446744073709551616,"negative":-9223372036854775809,"minus_zero":0,"nested":[123456789012345678901234567890]}"#
        );
    }

    /// Fragmented provider frames without sequence numbers still keep parent and id association.
    #[test]
    fn response_parent_and_fragmented_frames() {
        let mut responses = Responses::default();
        let asked = responses.asking(Some("parent".into()));
        let created = provider_frame(
            json!({"type":"response.created", "response":{"id":"child", "previous_response_id":"parent"}}),
        );
        responses.push(&created[..3]).unwrap();
        assert!(responses.take_turn(&asked).unwrap().is_none());
        responses.push(&created[3..]).unwrap();
        assert!(responses.take_turn(&asked).unwrap().is_none());
        assert_eq!(responses.drain_events().len(), 1);
        let completed = provider_frame(
            json!({"type":"response.completed", "response":{"id":"child", "previous_response_id":"parent", "usage":{"input_tokens":2}}}),
        );
        for chunk in completed.chunks(7) {
            responses.push(chunk).unwrap();
        }
        let turn = responses.take_turn(&asked).unwrap().unwrap();
        assert_eq!(turn.response_id.as_deref(), Some("child"));
        assert_eq!(turn.usage.unwrap()["input_tokens"], 2);
        assert_eq!(turn.events.len(), 1);

        let asked = responses.asking(Some("parent".into()));
        responses.push(&provider_frame(json!({"type":"response.created", "response":{"id":"wrong", "previous_response_id":"other"}}))).unwrap();
        assert!(responses.take_turn(&asked).is_err());
    }

    /// A provider upgrade must be bound to its public WebSocket key.
    #[test]
    fn upgrade_accept_binding() {
        let head = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: expected\r\n\r\n";
        upgrade_response(head, "expected").unwrap();
        assert!(upgrade_response(head, "other").is_err());
        let tail = b"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: public\r\n\r\n";
        validate_request_tail(tail, b"public", None).unwrap();
        let conflicting = b"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: public\r\nAuthorization: extra\r\n\r\n";
        assert!(validate_request_tail(conflicting, b"public", None).is_err());
    }

    /// The upgrade names the Sponsor's own account, once, and nothing the
    /// relay sets.
    #[test]
    fn upgrade_names_the_sponsor_account() {
        let with = |extra: &str| {
            format!(
                "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: public\r\n{extra}\r\n"
            )
        };
        let own = with("ChatGPT-Account-Id: acct-own\r\n");
        validate_request_tail(own.as_bytes(), b"public", Some("acct-own")).unwrap();
        assert!(validate_request_tail(own.as_bytes(), b"public", Some("acct-team")).is_err());
        assert!(validate_request_tail(own.as_bytes(), b"public", None).is_err());
        let none = with("");
        assert!(validate_request_tail(none.as_bytes(), b"public", Some("acct-own")).is_err());
        let twice = with("ChatGPT-Account-Id: acct-own\r\nchatgpt-account-id: acct-own\r\n");
        assert!(validate_request_tail(twice.as_bytes(), b"public", Some("acct-own")).is_err());
        for extra in [
            "Cookie: session=1\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "OpenAI-Beta: x\u{0}y\r\n",
            "OpenAI-Beta: x\ry\r\n",
        ] {
            let tail = with(&format!("ChatGPT-Account-Id: acct-own\r\n{extra}"));
            assert!(
                validate_request_tail(tail.as_bytes(), b"public", Some("acct-own")).is_err(),
                "{extra:?}"
            );
        }
        let beta = with("ChatGPT-Account-Id: acct-own\r\nOpenAI-Beta: responses=v1\r\n");
        validate_request_tail(beta.as_bytes(), b"public", Some("acct-own")).unwrap();
    }
}
