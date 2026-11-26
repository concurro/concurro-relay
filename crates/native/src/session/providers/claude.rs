//! Compact Claude Message Threads requests for one admitted native session.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use concurro_relay_provider_protocol::tls_key_update::Template;
use serde_json::{Map, Value, json};

use super::Prepared;

const BETA: &[u8] = b"message-threads-2026-08-12";

/// Last completed provider response and the CLI history that produced it.
struct Head {
    request: Value,
    assistant: Value,
    id: String,
    template: Template,
}

/// Message Thread state owned by one native TLS session.
#[derive(Default)]
pub struct ThreadState {
    head: Option<Head>,
}

impl ThreadState {
    /// Whether the last response can anchor a compact continuation.
    pub fn ready(&self) -> bool {
        self.head.is_some()
    }

    /// Prepare a create or a compact continuation from the complete CLI body.
    pub fn prepare(&self, body: &[u8], template: &Template) -> Result<Prepared> {
        let original: Value = serde_json::from_slice(body).context("Claude request is not JSON")?;
        ensure!(
            original["thread"].is_null(),
            "CLI already selected a Claude thread"
        );
        let mut provider = original.clone();
        let mut mode = "create";
        let mut parent = None;
        let mut decision = "initial";
        let mut mismatch = None;
        if let Some(head) = &self.head {
            decision = if head.template != *template {
                "header_changed"
            } else if fixed_fields(&head.request) != fixed_fields(&original) {
                "configuration_changed"
            } else if let (Some(before), Some(after)) = (
                head.request["messages"].as_array(),
                original["messages"].as_array(),
            ) {
                if after.len() <= before.len()
                    || !before
                        .iter()
                        .zip(after)
                        .all(|(old, new)| semantic(old, true) == semantic(new, true))
                {
                    "history_changed"
                } else if semantic(&head.assistant, true) != semantic(&after[before.len()], true) {
                    let expected = &head.assistant;
                    let actual = &after[before.len()];
                    let shape = |message: &Value| {
                        message["content"].as_array().map(|blocks| blocks.iter().map(|block| {
                            json!({"type":block["type"],
                                "keys":block.as_object().map(|value| value.keys().collect::<Vec<_>>()),
                                "text_bytes":block["text"].as_str().map(str::len),
                                "thinking_bytes":block["thinking"].as_str().map(str::len),
                                "has_signature":block.get("signature").is_some(),
                                "has_tool_id":block.get("id").is_some(),
                                "has_tool_input":block.get("input").is_some()})
                        }).collect::<Vec<_>>())
                    };
                    mismatch = Some(json!({"expected_role":expected["role"],
                        "actual_role":actual["role"], "expected_blocks":shape(expected),
                        "actual_blocks":shape(actual)}));
                    "response_changed"
                } else {
                    provider["messages"] = Value::Array(after[before.len() + 1..].to_vec());
                    mode = "continue";
                    parent = Some(head.id.clone());
                    provider.as_object_mut().unwrap().remove("system");
                    provider.as_object_mut().unwrap().remove("tools");
                    "matched"
                }
            } else {
                "messages_missing"
            };
        }
        provider["thread"] = match &parent {
            Some(id) => json!({"type":"continue","previous_message_id":id}),
            None => json!({"type":"create"}),
        };
        Ok(Prepared {
            original,
            body: serde_json::to_vec(&provider)?,
            mode,
            parent,
            decision,
            mismatch,
        })
    }

    /// Replace a failed continuation with a full create request.
    pub fn replay(&self, prepared: &mut Prepared) -> Result<()> {
        let mut provider = prepared.original.clone();
        strip_old_breakpoints(&mut provider);
        provider["thread"] = json!({"type":"create"});
        prepared.body = serde_json::to_vec(&provider)?;
        prepared.mode = "replay";
        prepared.parent = None;
        prepared.decision = "parent_not_found";
        prepared.mismatch = None;
        Ok(())
    }

    /// Retain only a completed, reconstructable response as the next parent.
    pub fn complete(&mut self, prepared: &Prepared, template: &Template, id: String, body: &[u8]) {
        self.head = assistant_message(body)
            .ok()
            .flatten()
            .map(|assistant| Head {
                request: prepared.original.clone(),
                assistant,
                id,
                template: template.clone(),
            });
    }
}

/// Add the Message Threads beta to the existing CLI beta set.
pub fn beta_template(template: &mut Template) {
    if let Some((_, value)) = template
        .headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case(b"anthropic-beta"))
    {
        if !value
            .split(|byte| *byte == b',')
            .any(|item| item.trim_ascii() == BETA)
        {
            value.extend_from_slice(b",");
            value.extend_from_slice(BETA);
        }
    } else {
        template
            .headers
            .push((b"anthropic-beta".to_vec(), BETA.to_vec()));
    }
}

/// Compare configuration that must be stable across a thread.
fn fixed_fields(request: &Value) -> Map<String, Value> {
    let mut fields = request.as_object().cloned().unwrap_or_default();
    for key in [
        "messages",
        "thread",
        "max_tokens",
        "stop_sequences",
        "stream",
        "metadata",
        "service_tier",
    ] {
        fields.remove(key);
    }
    fields
}

/// Normalize only Claude message and content-block metadata, never opaque payloads.
fn semantic(value: &Value, comparison: bool) -> Value {
    let mut normalized = value.clone();
    let Some(message) = normalized.as_object_mut() else {
        return normalized;
    };
    message.remove("cache_control");
    if let Some(blocks) = message.get_mut("content").and_then(Value::as_array_mut) {
        for block in blocks {
            let Some(fields) = block.as_object_mut() else {
                continue;
            };
            fields.remove("cache_control");
            if comparison
                && fields.get("type") == Some(&Value::from("tool_use"))
                && fields.get("caller") == Some(&json!({"type":"direct"}))
            {
                fields.remove("caller");
            }
        }
    }
    if comparison
        && message.get("role") == Some(&Value::from("system"))
        && let Some(blocks) = message.get("content").and_then(Value::as_array)
        && blocks.len() == 1
        && blocks[0]["type"] == "text"
        && blocks[0].as_object().is_some_and(|block| block.len() == 2)
        && let Some(text) = blocks[0]["text"].as_str()
    {
        message.insert("content".into(), Value::from(text));
    }
    normalized
}

/// Remove historical cache breakpoints before replaying a complete conversation.
fn strip_old_breakpoints(request: &mut Value) {
    if let Some(messages) = request["messages"].as_array_mut() {
        let old = messages.len().saturating_sub(1);
        for message in &mut messages[..old] {
            *message = semantic(message, false);
        }
    }
}

/// Reconstruct an authenticated assistant message from completed Claude SSE.
fn assistant_message(body: &[u8]) -> Result<Option<Value>> {
    let mut blocks: Vec<Value> = Vec::new();
    let mut partial: BTreeMap<usize, String> = BTreeMap::new();
    let mut stopped = false;
    let mut refused = false;
    let mut fallback = false;
    for line in body.split(|byte| *byte == b'\n') {
        let Some(data) = line.strip_prefix(b"data: ") else {
            continue;
        };
        let event: Value = serde_json::from_slice(data)?;
        match event["type"].as_str() {
            Some("content_block_start") => {
                let index = event["index"].as_u64().context("content index missing")? as usize;
                ensure!(index == blocks.len(), "out-of-order Claude content block");
                blocks.push(event["content_block"].clone());
            }
            Some("content_block_delta") => {
                let index = event["index"].as_u64().context("content index missing")? as usize;
                let block = blocks
                    .get_mut(index)
                    .context("content delta without start")?;
                let delta = &event["delta"];
                match delta["type"].as_str() {
                    Some("text_delta") | Some("thinking_delta") | Some("signature_delta") => {
                        let (field, fragment) = match delta["type"].as_str().unwrap() {
                            "text_delta" => ("text", "text"),
                            "thinking_delta" => ("thinking", "thinking"),
                            _ => ("signature", "signature"),
                        };
                        let mut value = block[field].as_str().unwrap_or_default().to_owned();
                        value.push_str(
                            delta[fragment]
                                .as_str()
                                .context("content fragment missing")?,
                        );
                        block[field] = Value::String(value);
                    }
                    Some("input_json_delta") => partial.entry(index).or_default().push_str(
                        delta["partial_json"]
                            .as_str()
                            .context("tool JSON fragment missing")?,
                    ),
                    _ => return Ok(None),
                }
            }
            Some("content_block_stop") => {
                let index = event["index"].as_u64().context("content index missing")? as usize;
                if let Some(json) = partial.remove(&index) {
                    blocks.get_mut(index).context("tool block missing")?["input"] =
                        serde_json::from_str(&json)?;
                }
            }
            Some("message_delta") => {
                refused = event["delta"]["stop_reason"] == "refusal";
                fallback = !event["usage"]["iterations"].is_null()
                    && event["usage"]["iterations"]
                        .to_string()
                        .contains("fallback_message");
            }
            Some("message_stop") => stopped = true,
            _ => {}
        }
    }
    if !stopped || refused || fallback || !partial.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({"role":"assistant","content":blocks})))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ThreadState, beta_template};
    use concurro_relay_provider_protocol::tls_key_update::Template;

    /// A completed tool response that the CLI includes in its next request.
    fn tool_response() -> Vec<u8> {
        [
            r#"data: {"type":"message_start","message":{"id":"msg_a"}}"#,
            r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_a","name":"Bash","input":{},"caller":{"type":"direct"}}}"#,
            r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"cat a.txt\"}"}}"#,
            r#"data: {"type":"content_block_stop","index":0}"#,
            r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#,
            r#"data: {"type":"message_stop"}"#,
        ].join("\n").into_bytes()
    }

    /// Make one complete CLI request with the same stable provider fields.
    fn request(messages: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"model":"claude-test","stream":true,
            "max_tokens":128,"system":"Read files","tools":[{"name":"Bash"}],
            "messages":messages}))
        .unwrap()
    }

    /// Create, continue with only the new tool result, then replay full history.
    #[test]
    fn compact_and_replay_tool_result() {
        let mut state = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let first = state
            .prepare(
                &request(vec![json!({"role":"user","content":"read a"})]),
                &template,
            )
            .unwrap();
        assert_eq!(first.mode, "create");
        assert_eq!(
            serde_json::from_slice::<Value>(&first.body).unwrap()["thread"]["type"],
            "create"
        );
        state.complete(&first, &template, "msg_a".into(), &tool_response());
        assert!(state.ready());
        let next = request(vec![
            json!({"role":"user","content":"read a"}),
            json!({"role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"cat a.txt"}}]}),
            json!({"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_a","content":"a"}]}),
        ]);
        let mut prepared = state.prepare(&next, &template).unwrap();
        assert_eq!(prepared.mode, "continue");
        assert_eq!(prepared.parent.as_deref(), Some("msg_a"));
        let sent: Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(sent["messages"].as_array().unwrap().len(), 1);
        assert!(sent.get("system").is_none());
        assert!(sent.get("tools").is_none());
        state.replay(&mut prepared).unwrap();
        let replay: Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(prepared.mode, "replay");
        assert_eq!(replay["messages"].as_array().unwrap().len(), 3);
        assert_eq!(replay["thread"]["type"], "create");
    }

    /// Edits and fixed-field changes begin a new thread with full history.
    #[test]
    fn changed_history_or_configuration_creates_thread() {
        let mut state = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let first = state
            .prepare(
                &request(vec![json!({"role":"user","content":"read a"})]),
                &template,
            )
            .unwrap();
        state.complete(&first, &template, "msg_a".into(), &tool_response());
        let changed = request(vec![json!({"role":"user","content":"read b"})]);
        assert_eq!(state.prepare(&changed, &template).unwrap().mode, "create");
        let mut config: Value =
            serde_json::from_slice(&request(vec![json!({"role":"user","content":"read a"})]))
                .unwrap();
        config["tools"] = json!([{"name":"Other"}]);
        assert_eq!(
            state
                .prepare(&serde_json::to_vec(&config).unwrap(), &template)
                .unwrap()
                .mode,
            "create"
        );
    }

    /// One session cannot continue the other session's authenticated response.
    #[test]
    fn parent_is_session_local() {
        let mut a = ThreadState::default();
        let b = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let first = a
            .prepare(
                &request(vec![json!({"role":"user","content":"read a"})]),
                &template,
            )
            .unwrap();
        a.complete(&first, &template, "msg_a".into(), &tool_response());
        let next = request(vec![
            json!({"role":"user","content":"read a"}),
            json!({"role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"cat a.txt"}}]}),
            json!({"role":"user","content":"done"}),
        ]);
        assert_eq!(a.prepare(&next, &template).unwrap().mode, "continue");
        assert_eq!(b.prepare(&next, &template).unwrap().mode, "create");
    }

    /// Claude Code's cached system text becomes a plain string on the next turn.
    #[test]
    fn cached_system_text_keeps_same_history() {
        let mut state = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let first = state
            .prepare(
                &request(vec![
                    json!({"role":"user","content":"read a"}),
                    json!({"role":"system","content":[{"type":"text","text":"reminder",
                "cache_control":{"type":"ephemeral"}}]}),
                ]),
                &template,
            )
            .unwrap();
        state.complete(&first, &template, "msg_a".into(), &tool_response());
        let next = request(vec![
            json!({"role":"user","content":"read a"}),
            json!({"role":"system","content":"reminder"}),
            json!({"role":"assistant","content":[{"type":"tool_use","id":"toolu_a",
                "name":"Bash","input":{"command":"cat a.txt"}}]}),
            json!({"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_a",
                "content":"a"}]}),
        ]);
        let continued = state.prepare(&next, &template).unwrap();
        assert_eq!(continued.mode, "continue");
        assert_eq!(continued.decision, "matched");
    }

    /// A programmatic tool caller is part of the response and cannot be omitted.
    #[test]
    fn programmatic_caller_requires_full_replay() {
        let mut state = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let first = state
            .prepare(
                &request(vec![json!({"role":"user","content":"read a"})]),
                &template,
            )
            .unwrap();
        let response = String::from_utf8(tool_response()).unwrap().replace(
            r#""caller":{"type":"direct"}"#,
            r#""caller":{"type":"code_execution_20260120","tool_id":"srvtoolu_a"}"#,
        );
        state.complete(&first, &template, "msg_a".into(), response.as_bytes());
        let next = request(vec![
            json!({"role":"user","content":"read a"}),
            json!({"role":"assistant","content":[{"type":"tool_use","id":"toolu_a",
                "name":"Bash","input":{"command":"cat a.txt"}}]}),
            json!({"role":"user","content":"done"}),
        ]);
        let prepared = state.prepare(&next, &template).unwrap();
        assert_eq!(prepared.mode, "create");
        assert_eq!(prepared.decision, "response_changed");
    }

    /// Opaque tool arguments remain exact during matching and expiry replay.
    #[test]
    fn opaque_tool_arguments_survive_matching_and_replay() {
        let mut state = ThreadState::default();
        let mut template = Template::fixture_default();
        beta_template(&mut template);
        let input = json!({"cache_control":"A","caller":{"type":"direct"},
            "role":"assistant","content":[{"cache_control":"A",
            "caller":{"type":"direct"},"role":"assistant","content":"A"}]});
        let old = json!({"role":"assistant","content":[{"type":"tool_use",
            "id":"toolu_old","name":"Bash","input":input,
            "cache_control":{"type":"ephemeral"}}]});
        let previous = vec![
            json!({"role":"user","content":"read a"}),
            old,
            json!({"role":"user","content":[{"type":"tool_result",
                "tool_use_id":"toolu_old","content":"old result"}]}),
        ];
        let first = state
            .prepare(&request(previous.clone()), &template)
            .unwrap();
        let response = [
            json!({"type":"content_block_start","index":0,"content_block":
                {"type":"tool_use","id":"toolu_a","name":"Bash","input":{},
                 "caller":{"type":"direct"}}}),
            json!({"type":"content_block_delta","index":0,"delta":
                {"type":"input_json_delta","partial_json":input.to_string()}}),
            json!({"type":"content_block_stop","index":0}),
            json!({"type":"message_stop"}),
        ]
        .iter()
        .map(|event| format!("data: {event}"))
        .collect::<Vec<_>>()
        .join("\n");
        state.complete(&first, &template, "msg_a".into(), response.as_bytes());
        let mut messages = previous.clone();
        messages.push(json!({"role":"assistant","content":[{"type":"tool_use",
            "id":"toolu_a","name":"Bash","input":input}]}));
        messages.push(json!({"role":"user","content":[{"type":"tool_result",
            "tool_use_id":"toolu_a","content":"new result"}]}));
        let mut prepared = state
            .prepare(&request(messages.clone()), &template)
            .unwrap();
        assert_eq!(prepared.mode, "continue");

        for field in ["cache_control", "caller", "role", "content"] {
            let mut edited = messages.clone();
            edited[3]["content"][0]["input"][field] = json!("changed");
            let changed = state.prepare(&request(edited), &template).unwrap();
            assert_eq!(changed.mode, "create", "assistant input {field}");
            assert_eq!(changed.decision, "response_changed");

            let mut edited = messages.clone();
            edited[1]["content"][0]["input"][field] = json!("changed");
            let changed = state.prepare(&request(edited), &template).unwrap();
            assert_eq!(changed.mode, "create", "history input {field}");
            assert_eq!(changed.decision, "history_changed");
        }

        state.replay(&mut prepared).unwrap();
        let replay: Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(replay["messages"][1]["content"][0]["input"], input);
        assert_eq!(replay["messages"][3]["content"][0]["input"], input);
        assert!(
            replay["messages"][1]["content"][0]
                .get("cache_control")
                .is_none()
        );
    }
}
