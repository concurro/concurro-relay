//! What a relay is willing to send to a provider with the credential it
//! holds. A request outside the policy is refused, never rewritten.

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
};

use concurro_relay_protocol::wire::{self, Job};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

/// What the relay is willing to do with the credential.
#[derive(Clone, Debug, Deserialize)]
pub struct Policy {
    pub host: String,
    pub paths: Vec<String>,
    pub headers: Vec<String>,
    pub body_fields: Vec<String>,
}

/// Start of the refusal for a thread continuation whose parent this relay
/// never received.
pub const UNKNOWN_THREAD_PARENT: &str = "thread parent was not issued to this relay";

/// Start of the refusal for a message continuing a response which was not
/// received on the same connection.
pub const UNKNOWN_RESPONSE: &str = "response was not received on this connection";

/// Ids of the messages in responses this relay has received, which are the
/// only messages a thread continuation may build on.
///
/// Without this, whoever submits jobs could continue any conversation in
/// the sponsor's account whose message id they hold.
#[derive(Clone, Debug, Default)]
pub struct ThreadParents(Arc<Mutex<HashSet<String>>>);

impl ThreadParents {
    /// Records the message in `response` if the provider accepted the
    /// request.
    pub fn record(&self, response: &[u8]) {
        let Ok(response) = wire::parse_response(response) else { return };
        if response.status == 200
            && let Some(id) = wire::message_id(&response.body)
        {
            self.0.lock().expect("lock is not poisoned").insert(id);
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.0.lock().expect("lock is not poisoned").contains(id)
    }
}

impl Policy {
    /// Refuses anything outside the allowlist; the request is never rewritten.
    pub fn check(&self, job: &Job, parents: &ThreadParents) -> Result<(), String> {
        self.check_route(job)?;
        // One encoding header is allowed beyond the allowlist. Its value is
        // checked when the body is decoded.
        let (encodings, others): (Vec<_>, Vec<_>) =
            job.headers.iter().partition(|(name, _)| name == wire::CONTENT_ENCODING);
        if encodings.len() > 1 {
            return Err("more than one content encoding".into());
        }
        self.check_headers(others)?;
        let body = self.fields(&job.decoded_body()?)?;
        let Some(thread) = body.get("thread") else {
            return Ok(());
        };
        match thread["previous_message_id"].as_str() {
            Some(parent) if parents.contains(parent) => Ok(()),
            Some(parent) => Err(format!("{UNKNOWN_THREAD_PARENT}: {parent}")),
            None if thread["type"] == "create" => Ok(()),
            None => Err("thread request is neither a create nor a continuation".into()),
        }
    }

    /// Refuses a WebSocket message which is not a request for a response,
    /// lets the provider store it, or continues a response which is not
    /// among `responses`, those received on the same connection.
    pub fn check_message(&self, text: &str, responses: &HashSet<String>) -> Result<(), String> {
        let message = self.fields(text.as_bytes())?;
        if message.get("type") != Some(&Value::from("response.create")) {
            return Err("message is not a request for a response".into());
        }
        if message.get("store") != Some(&Value::Bool(false)) {
            return Err("message does not disable storage".into());
        }
        match message.get("previous_response_id") {
            None => Ok(()),
            Some(Value::String(id)) if responses.contains(id) => Ok(()),
            Some(id) => Err(format!("{UNKNOWN_RESPONSE}: {id}")),
        }
    }

    /// The fields of the JSON object `raw`, if all of them are allowed.
    fn fields(&self, raw: &[u8]) -> Result<Map<String, Value>, String> {
        let Ok(Unambiguous(Value::Object(body))) = serde_json::from_slice(raw) else {
            return Err("body is not a JSON object without repeated keys".into());
        };
        if let Some(key) = body.keys().find(|key| !self.body_fields.contains(key)) {
            return Err(format!("body field not allowed: {key}"));
        }
        Ok(body)
    }

    /// Refuses a host, path or header outside the allowlist.
    pub fn check_target(&self, job: &Job) -> Result<(), String> {
        self.check_route(job)?;
        self.check_headers(&job.headers)
    }

    fn check_route(&self, job: &Job) -> Result<(), String> {
        if job.host != self.host {
            return Err(format!("host not allowed: {}", job.host));
        }
        if !self.paths.contains(&job.path) {
            return Err(format!("path not allowed: {}", job.path));
        }
        Ok(())
    }

    fn check_headers<'a>(&self, headers: impl IntoIterator<Item = &'a (String, String)>) -> Result<(), String> {
        for (name, value) in headers {
            if !self.headers.contains(name) {
                return Err(format!("header not allowed: {name}"));
            }
            if value.contains(['\r', '\n']) {
                return Err(format!("header value breaks framing: {name}"));
            }
        }
        Ok(())
    }
}

/// JSON in which no object repeats a key, so that every parser reads the
/// same value for each.
struct Unambiguous(Value);

impl<'de> Deserialize<'de> for Unambiguous {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Json;

        impl<'de> Visitor<'de> for Json {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON without repeated keys")
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(value.into())
            }

            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(value.into())
            }

            fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
                Ok(value.into())
            }

            fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
                Ok(value.into())
            }

            fn visit_str<E>(self, value: &str) -> Result<Value, E> {
                Ok(value.into())
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Value, A::Error> {
                let mut array = Vec::new();
                while let Some(Unambiguous(item)) = items.next_element()? {
                    array.push(item);
                }
                Ok(array.into())
            }

            fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Value, A::Error> {
                let mut object = Map::new();
                while let Some(key) = entries.next_key::<String>()? {
                    let Unambiguous(value) = entries.next_value()?;
                    if object.contains_key(&key) {
                        return Err(de::Error::custom(format!("repeated key: {key}")));
                    }
                    object.insert(key, value);
                }
                Ok(object.into())
            }
        }

        deserializer.deserialize_any(Json).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn policy() -> Policy {
        Policy {
            host: "provider.example".into(),
            paths: vec!["/v1/responses".into()],
            headers: vec!["content-type".into()],
            body_fields: ["type", "store", "previous_response_id", "thread", "input"].map(Into::into).to_vec(),
        }
    }

    fn job(headers: &[(&str, &str)], body: &str) -> Job {
        Job {
            host: "provider.example".into(),
            path: "/v1/responses".into(),
            headers: headers.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn content_encoding_is_no_way_around_the_header_allowlist() {
        let (policy, parents) = (policy(), ThreadParents::default());
        let mut compressed = job(&[("content-type", "application/json")], "{}");
        compressed.compress().unwrap();
        assert_matches!(policy.check(&compressed, &parents), Ok(()));

        compressed.headers.push((wire::CONTENT_ENCODING.into(), "identity\r\nx-evil: 1".into()));
        assert_matches!(policy.check(&compressed, &parents), Err(_));

        let injected = job(&[(wire::CONTENT_ENCODING, "identity\r\nx-evil: 1")], "{}");
        assert_matches!(policy.check(&injected, &parents), Err(_));
        assert_matches!(policy.check_target(&injected), Err(_));
        assert_matches!(policy.check_target(&job(&[(wire::CONTENT_ENCODING, wire::ZSTD)], "")), Err(_));
    }

    #[test]
    fn repeated_json_keys_are_refused() {
        let (policy, parents) = (policy(), ThreadParents::default());
        let responses = HashSet::new();
        let allowed = r#"{"type":"response.create","store":false,"input":[{"a":1},{"a":2}]}"#;
        assert_matches!(policy.check_message(allowed, &responses), Ok(()));

        let repeated = r#"{"type":"response.create","store":true,"store":false}"#;
        assert_matches!(policy.check_message(repeated, &responses), Err(_));
        let nested = r#"{"thread":{"type":"create","previous_message_id":"msg_a","previous_message_id":"msg_b"}}"#;
        assert_matches!(policy.check(&job(&[], nested), &parents), Err(_));
    }
}
