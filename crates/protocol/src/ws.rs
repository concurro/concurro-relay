//! WebSocket framing for a provider connection whose turns are proven while
//! it stays open, and what both ends conclude from what the provider sends.
//!
//! The verifier chooses every byte the relay sends, masks included, so each
//! proof can be checked against the exact frame asked for. The relay sends
//! nothing in reaction to what the provider sends.

use std::{collections::VecDeque, io::Cursor, ops::Range};

use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use tokio_tungstenite::tungstenite::{
    Message,
    protocol::frame::{
        Frame, FrameHeader,
        coding::{Control, Data, OpCode},
    },
};

use crate::wire::{self, Job, Offer};

/// Event types which end a turn's response.
pub const FINAL_EVENTS: [&str; 4] = ["response.completed", "response.failed", "response.incomplete", "error"];

/// What ends the head of an HTTP message.
pub const HEAD_END: &[u8] = b"\r\n\r\n";

/// Longest payload a control frame may carry.
const MAX_CONTROL_PAYLOAD: u64 = 125;

/// The upgrade request for `job`, and where the credential sits in it.
/// Refuses a `key` which is not sixteen bytes in base64, and so could add
/// to the request's headers.
pub fn upgrade(job: &Job, offer: &Offer, credential: &[u8], key: &str) -> Result<(Vec<u8>, Range<usize>)> {
    ensure!(STANDARD.decode(key).is_ok_and(|nonce| nonce.len() == 16), "upgrade key is not sixteen bytes in base64");
    let (mut out, hidden) = wire::head("GET", job, offer, credential);
    out.extend_from_slice(
        format!("connection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: {key}\r\n\r\n")
            .as_bytes(),
    );
    Ok((out, hidden))
}

/// The status code in the first line of the response head `head`.
pub fn status(head: &[u8]) -> Option<&str> {
    str::from_utf8(head).ok()?.lines().next()?.split(' ').nth(1)
}

/// A complete frame as a client sends it.
fn client_frame(opcode: OpCode, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let header = FrameHeader { opcode, mask: Some(mask), ..FrameHeader::default() };
    let mut out = Vec::new();
    Frame::from_payload(header, payload.to_vec().into()).format(&mut out).expect("writing to a vector does not fail");
    out
}

/// A complete text message, framed as a client sends it.
pub fn text_frame(text: &str, mask: [u8; 4]) -> Vec<u8> {
    client_frame(OpCode::Data(Data::Text), text.as_bytes(), mask)
}

/// The answer to a ping which carried `payload`, framed as a client sends
/// it.
pub fn pong_frame(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    client_frame(OpCode::Control(Control::Pong), payload, mask)
}

/// Parses the frame at the start of `bytes`, returning its header, its
/// unmasked payload and its encoded length, or `None` if it is incomplete.
fn parse_frame(bytes: &[u8]) -> Result<Option<(FrameHeader, Vec<u8>, usize)>> {
    let mut cursor = Cursor::new(bytes);
    let Some((header, length)) = FrameHeader::parse(&mut cursor)? else {
        return Ok(None);
    };
    ensure!(!(header.rsv1 || header.rsv2 || header.rsv3), "frame uses an extension");
    if let OpCode::Control(_) = header.opcode {
        ensure!(header.is_final && length <= MAX_CONTROL_PAYLOAD, "control frame is fragmented or too long");
    }
    let start = cursor.position() as usize;
    let end = usize::try_from(length).ok().and_then(|length| start.checked_add(length));
    let Some(end) = end.filter(|end| *end <= bytes.len()) else {
        return Ok(None);
    };
    let mut payload = bytes[start..end].to_vec();
    if let Some(mask) = header.mask {
        payload.iter_mut().zip(mask.iter().cycle()).for_each(|(byte, mask)| *byte ^= mask);
    }
    Ok(Some((header, payload, end)))
}

/// The payload of the one complete, masked frame of kind `opcode` which
/// makes up `bytes`.
pub fn client_payload(bytes: &[u8], opcode: OpCode) -> Result<Vec<u8>, String> {
    match parse_frame(bytes) {
        Ok(Some((header, payload, end)))
            if end == bytes.len() && header.is_final && header.mask.is_some() && header.opcode == opcode =>
        {
            Ok(payload)
        }
        _ => Err("not exactly one masked frame of the expected kind".into()),
    }
}

/// The text of the one complete, masked text frame which makes up `bytes`.
pub fn client_text(bytes: &[u8]) -> Result<String, String> {
    let payload = client_payload(bytes, OpCode::Data(Data::Text))?;
    String::from_utf8(payload).map_err(|_| "message is not text".into())
}

/// The response which the request `text` asks to continue, if any.
pub fn continued_response(text: &str) -> Option<String> {
    serde_json::from_str::<Value>(text).ok()?["previous_response_id"].as_str().map(str::to_owned)
}

/// The id of the response which `messages` report as completed.
pub fn completed_response(messages: &[Message]) -> Option<String> {
    messages.iter().find_map(|message| {
        let Message::Text(text) = message else { return None };
        let event: Value = serde_json::from_str(text.as_str()).ok()?;
        (event["type"] == "response.completed").then(|| event["response"]["id"].as_str().map(str::to_owned))?
    })
}

/// A request whose response is awaited.
#[derive(Clone, Debug, Default)]
pub struct Asked {
    /// The response which the request continues.
    pub previous: Option<String>,
    /// How much the provider had sent, in bytes of its messages since the
    /// upgrade, before the request reached it. A message which begins
    /// before then can not answer the request.
    pub before: usize,
}

/// What a side of the connection does next after a request was sent.
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    /// The response ended; these are its messages.
    Response(Vec<Message>),
    /// The provider sent a ping with this payload, which is to be answered
    /// before anything else.
    Ping(Vec<u8>),
}

/// Reassembles the messages a provider sends from the bytes received.
#[derive(Debug, Default)]
pub struct Inbox {
    /// How many bytes have been parsed into messages.
    parsed: usize,
    unparsed: Vec<u8>,
    /// A fragmented message whose last frame has not arrived, and where it
    /// began.
    partial: Option<(Data, Vec<u8>, usize)>,
    /// Whole messages, each with where it began among the bytes received.
    ready: VecDeque<(usize, Message)>,
    /// Payloads of the pings not answered yet.
    pings: VecDeque<Vec<u8>>,
}

impl Inbox {
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.unparsed.extend_from_slice(bytes);
        let mut at = 0;
        while let Some((header, payload, length)) = parse_frame(&self.unparsed[at..])? {
            let began = self.parsed + at;
            at += length;
            ensure!(header.mask.is_none(), "provider sent a masked frame");
            let kind = match header.opcode {
                OpCode::Control(Control::Ping) => {
                    self.pings.push_back(payload.clone());
                    self.ready.push_back((began, Message::Ping(payload.into())));
                    continue;
                }
                OpCode::Control(Control::Pong) => {
                    self.ready.push_back((began, Message::Pong(payload.into())));
                    continue;
                }
                OpCode::Control(Control::Close) => {
                    self.ready.push_back((began, Message::Close(None)));
                    continue;
                }
                OpCode::Control(Control::Reserved(_)) => bail!("provider sent an unknown control frame"),
                OpCode::Data(kind) => kind,
            };
            let (kind, data, began) = match (kind, self.partial.take()) {
                (Data::Continue, Some((kind, mut data, began))) => {
                    data.extend(payload);
                    (kind, data, began)
                }
                (Data::Continue, None) => bail!("provider continued a message it did not start"),
                (_, Some(_)) => bail!("provider started a message inside another"),
                (kind, None) => (kind, payload, began),
            };
            if !header.is_final {
                self.partial = Some((kind, data, began));
            } else if kind == Data::Text {
                self.ready.push_back((began, Message::Text(String::from_utf8(data)?.into())));
            } else {
                self.ready.push_back((began, Message::Binary(data.into())));
            }
        }
        self.unparsed.drain(..at);
        self.parsed += at;
        Ok(())
    }

    /// A request continuing `previous` which reaches the provider now:
    /// everything received so far was sent before it.
    pub fn asking(&self, previous: Option<String>) -> Asked {
        Asked { previous, before: self.parsed + self.unparsed.len() }
    }

    /// Takes the messages of the response to the request `asked`, once its
    /// last event has arrived.
    ///
    /// An event is part of a response if its type starts with `response.`
    /// or it carries a sequence number or a response id. Every such event
    /// must belong to the one response started after the request: each
    /// carries the next sequence number from zero, names the same response
    /// wherever it names one, and the first names the response it
    /// continues. None of them, and no error, may be among the messages the
    /// provider sent before the request reached it. Other events, and
    /// pings, are passed through. Anything else is refused, including a
    /// close before the response ended.
    pub fn take_turn(&mut self, asked: &Asked) -> Result<Option<Vec<Message>>, String> {
        let end = self.turn_end(asked)?;
        Ok(end.map(|end| self.ready.drain(..=end).map(|(_, message)| message).collect()))
    }

    /// Where among the queued messages the response to the request `asked`
    /// ends, checked as [`Self::take_turn`] describes.
    fn turn_end(&self, asked: &Asked) -> Result<Option<usize>, String> {
        let mut response: Option<String> = None;
        let mut sequence = 0;
        for (at, (began, message)) in self.ready.iter().enumerate() {
            let event: Value = match message {
                Message::Text(text) => {
                    serde_json::from_str(text.as_str()).map_err(|_| "provider sent text which is not JSON")?
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err("provider closed before the response ended".into()),
                _ => return Err("provider sent a message which is not text".into()),
            };
            let kind = event["type"].as_str().unwrap_or_default();
            let ids = [&event["response"]["id"], &event["response_id"]];
            let number = event.get("sequence_number");
            let failed = kind == "error";
            if !failed && !kind.starts_with("response.") && number.is_none() && ids.iter().all(|id| id.is_null()) {
                continue;
            }
            if *began < asked.before {
                return Err(format!("provider sent it before the request: {kind}"));
            }
            if failed {
                // An error which names a response names this turn's.
                if ids.iter().filter_map(|id| id.as_str()).any(|id| Some(id) != response.as_deref()) {
                    return Err("error names another response".into());
                }
                return Ok(Some(at));
            }
            if number.and_then(Value::as_u64) != Some(sequence) {
                return Err(format!("event is out of sequence: {kind}"));
            }
            sequence += 1;
            if kind == "response.created" {
                if response.is_some() {
                    return Err("provider started a second response".into());
                }
                if event["response"]["previous_response_id"].as_str() != asked.previous.as_deref() {
                    return Err("response does not continue the one asked for".into());
                }
                response = Some(ids[0].as_str().ok_or("response has no id")?.to_owned());
            }
            let Some(response) = &response else {
                return Err(format!("event outside a response: {kind}"));
            };
            let ends = FINAL_EVENTS.contains(&kind);
            if ids.iter().any(|id| !id.is_null() && *id != response) || (ends && ids[0].is_null()) {
                return Err(format!("event belongs to another response: {kind}"));
            }
            if ends {
                return Ok(Some(at));
            }
        }
        Ok(None)
    }

    /// The response to the request `asked` if it has ended, or else the
    /// oldest ping waiting for an answer.
    pub fn progress(&mut self, asked: &Asked) -> Result<Option<Progress>, String> {
        if let Some(messages) = self.take_turn(asked)? {
            return Ok(Some(Progress::Response(messages)));
        }
        Ok(self.waiting_ping())
    }

    /// Whether [`Self::progress`] would return something.
    pub fn can_progress(&self, asked: &Asked) -> Result<bool, String> {
        Ok(self.turn_end(asked)?.is_some() || !self.pings.is_empty())
    }

    /// The oldest ping waiting for an answer.
    pub fn waiting_ping(&self) -> Option<Progress> {
        self.pings.front().cloned().map(Progress::Ping)
    }

    /// Marks the ping which carried `payload` as answered, if there is one
    /// waiting.
    pub fn answer(&mut self, payload: &[u8]) -> bool {
        let waiting = self.pings.iter().position(|ping| ping == payload);
        waiting.and_then(|at| self.pings.remove(at)).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use serde_json::json;

    use super::*;

    fn server_frame(opcode: OpCode, is_final: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let header = FrameHeader { is_final, opcode, ..FrameHeader::default() };
        Frame::from_payload(header, payload.to_vec().into()).format(&mut out).unwrap();
        out
    }

    #[test]
    fn client_frame_round_trips_and_rejects_other_shapes() {
        let frame = text_frame("{\"a\":1}", [1, 2, 3, 4]);
        assert_eq!(client_text(&frame).as_deref(), Ok("{\"a\":1}"));
        assert!(client_text(&[frame.clone(), frame.clone()].concat()).is_err());
        assert!(client_text(&frame[..frame.len() - 1]).is_err());
        assert!(client_text(&server_frame(OpCode::Data(Data::Text), true, b"{}")).is_err());
    }

    fn continuing(previous: &str) -> Asked {
        Asked { previous: Some(previous.to_owned()), before: 0 }
    }

    fn text(event: Value) -> Vec<u8> {
        server_frame(OpCode::Data(Data::Text), true, event.to_string().as_bytes())
    }

    fn inbox(frames: &[Vec<u8>]) -> Inbox {
        let mut inbox = Inbox::default();
        inbox.push(&frames.concat()).unwrap();
        inbox
    }

    fn created(id: &str) -> Vec<u8> {
        text(json!({"type": "response.created", "sequence_number": 0, "response": {"id": id}}))
    }

    fn delta(sequence: u64) -> Vec<u8> {
        text(json!({"type": "response.output_text.delta", "sequence_number": sequence, "delta": "x"}))
    }

    fn completed(id: &str, sequence: u64) -> Vec<u8> {
        text(json!({"type": "response.completed", "sequence_number": sequence, "response": {"id": id}}))
    }

    #[test]
    fn inbox_joins_split_and_fragmented_messages() {
        let event = json!({"type": "response.completed", "sequence_number": 1, "response": {"id": "resp_1"}}).to_string();
        let mut bytes = created("resp_1");
        bytes.extend(server_frame(OpCode::Data(Data::Text), false, &event.as_bytes()[..10]));
        bytes.extend(server_frame(OpCode::Control(Control::Ping), true, b"p"));
        bytes.extend(server_frame(OpCode::Data(Data::Continue), true, &event.as_bytes()[10..]));

        let mut inbox = Inbox::default();
        let (first, second) = bytes.split_at(bytes.len() - 7);
        inbox.push(first).unwrap();
        assert_eq!(inbox.take_turn(&Asked::default()), Ok(None));
        inbox.push(second).unwrap();
        let turn = inbox.take_turn(&Asked::default()).unwrap().unwrap();
        assert_matches!(turn[..], [Message::Text(_), Message::Ping(_), Message::Text(_)]);
        assert_eq!(completed_response(&turn).as_deref(), Some("resp_1"));
    }

    #[test]
    fn inbox_rejects_masked_frames() {
        assert!(Inbox::default().push(&text_frame("{}", [9, 9, 9, 9])).is_err());
    }

    #[test]
    fn turn_takes_one_response_and_passes_other_events_through() {
        let rate_limits = text(json!({"type": "codex.rate_limits"}));
        let mut both = inbox(&[rate_limits.clone(), created("a"), delta(1), rate_limits, completed("a", 2), created("b")]);
        assert_eq!(both.take_turn(&Asked::default()).unwrap().unwrap().len(), 5);
        assert_eq!(both.take_turn(&Asked::default()), Ok(None));

        let failed = text(json!({"type": "error", "error": {}}));
        assert_eq!(inbox(&[failed]).take_turn(&continuing("a")).unwrap().unwrap().len(), 1);
    }

    #[test]
    fn turn_refuses_events_of_another_response() {
        let close = server_frame(OpCode::Control(Control::Close), true, b"");
        let continues = text(json!({"type": "response.created", "sequence_number": 0, "response": {"id": "b", "previous_response_id": "a"}}));
        let unnamed = text(json!({"type": "response.completed", "sequence_number": 1}));
        let refused: [(&[Vec<u8>], Option<&str>); 15] = [
            // Left over from an earlier response.
            (&[delta(5), created("b"), completed("b", 1)], None),
            (&[completed("a", 2), created("b"), completed("b", 1)], None),
            (&[text(json!({"type": "response.output_text.delta", "delta": "x"})), created("b")], None),
            // Mixed into this one.
            (&[created("a"), delta(1), completed("b", 2)], None),
            (&[created("a"), created("b"), completed("b", 1)], None),
            (&[created("a"), delta(3), completed("a", 4)], None),
            (&[created("a"), unnamed], None),
            // Not the response which was asked for.
            (&[continues.clone(), completed("b", 1)], None),
            (&[created("b"), completed("b", 1)], Some("a")),
            // Ended without ending the response.
            (&[created("a"), delta(1), close], None),
            // Unnumbered, or naming two responses.
            (&[text(json!({"type": "response.created", "response": {"id": "a"}})), completed("a", 1)], None),
            (&[created("a"), text(json!({"type": "response.output_text.delta", "delta": "x"})), completed("a", 1)], None),
            (&[created("a"), text(json!({"type": "response.completed", "response": {"id": "a"}}))], None),
            (&[created("a"), text(json!({"type": "response.completed", "sequence_number": 1, "response": {"id": "a"}, "response_id": "b"}))], None),
            (&[created("a"), text(json!({"type": "codex.other", "sequence_number": 7})), completed("a", 1)], None),
        ];
        for (frames, previous) in refused {
            let asked = Asked { previous: previous.map(str::to_owned), before: 0 };
            assert_matches!(inbox(frames).take_turn(&asked), Err(_), "{previous:?}");
        }
        assert_matches!(inbox(&[continues, completed("b", 1)]).take_turn(&continuing("a")), Ok(Some(_)));
    }

    #[test]
    fn turn_refuses_what_the_provider_sent_before_the_request() {
        let rate_limits = text(json!({"type": "codex.rate_limits"}));
        let failed = text(json!({"type": "error", "error": {}}));
        let ping = server_frame(OpCode::Control(Control::Ping), true, b"p");
        // A request which reached the provider after it had sent `frames`.
        let after = |frames: &[Vec<u8>]| Asked { previous: None, before: frames.concat().len() };

        // A whole response, a response which had begun, or an error does
        // not answer a request which came after it.
        let response = [created("a"), completed("a", 1)];
        assert_matches!(inbox(&response).take_turn(&after(&response)), Err(_));
        assert_matches!(inbox(&response).take_turn(&after(&response[..1])), Err(_));
        let then_response = [failed.clone(), created("a"), completed("a", 1)];
        assert_matches!(inbox(&then_response).take_turn(&after(&then_response[..1])), Err(_));

        // Nor does one whose first fragment came before it, whatever came
        // between its fragments.
        let error = json!({"type": "error", "error": {}}).to_string();
        let fragmented = [
            server_frame(OpCode::Data(Data::Text), false, &error.as_bytes()[..5]),
            ping.clone(),
            server_frame(OpCode::Data(Data::Continue), true, &error.as_bytes()[5..]),
        ];
        assert_matches!(inbox(&fragmented).take_turn(&after(&fragmented[..1])), Err(_));

        // An error which names a response other than this turn's is not
        // this turn's either.
        let named = |id: &str| text(json!({"type": "error", "response_id": id, "error": {}}));
        assert_matches!(inbox(&[named("old")]).take_turn(&after(&[])), Err(_));
        assert_matches!(inbox(&[created("a"), named("old")]).take_turn(&after(&[])), Err(_));
        assert_matches!(inbox(&[created("a"), named("a")]).take_turn(&after(&[])), Ok(Some(_)));

        // Other events and pings may have come before.
        let early = [rate_limits, ping, created("a"), completed("a", 1)];
        assert_eq!(inbox(&early).take_turn(&after(&early[..2])).unwrap().unwrap().len(), 4);
        assert_eq!(inbox(&[failed]).take_turn(&after(&[])).unwrap().unwrap().len(), 1);
    }

    #[test]
    fn upgrade_key_is_sixteen_bytes_in_base64() {
        let job = Job { host: "h".into(), path: "/".into(), headers: Vec::new(), body: Vec::new() };
        let offer = Offer { credential: wire::CredentialHeader::bearer(), hidden_len: 1, headers: Vec::new() };
        let upgrade = |key| upgrade(&job, &offer, b"x", key);
        assert!(upgrade("dGhlIHNhbXBsZSBub25jZQ==").is_ok());
        assert!(upgrade("dGhlIHNhbXBsZSBub25jZQ==\r\nx-evil: 1").is_err());
        assert!(upgrade("c2hvcnQ=").is_err());
        assert!(upgrade("").is_err());
    }
}
