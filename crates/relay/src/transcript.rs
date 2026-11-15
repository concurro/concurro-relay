//! The readable part of a request and of a response, for showing a person
//! what the relay carried.

use serde_json::Value;

/// The text in `value`: itself if it is text, or else what it holds under
/// the names providers give text.
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(parts) => {
            let texts: Vec<String> = parts.iter().map(text).filter(|text| !text.is_empty()).collect();
            texts.join("\n")
        }
        Value::Object(fields) => {
            ["text", "content", "output"].iter().find_map(|name| fields.get(*name)).map(text).unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// What the newest item of the conversation in a request body says. A body
/// which holds no conversation is given whole.
pub fn request_text(body: &str) -> String {
    let Ok(request) = serde_json::from_str::<Value>(body) else { return body.to_owned() };
    let newest = match [&request["messages"], &request["input"]].into_iter().find(|items| !items.is_null()) {
        Some(Value::Array(items)) => items.last().map(text),
        Some(other) => Some(text(other)),
        None => None,
    };
    match newest.filter(|text| !text.trim().is_empty()) {
        Some(text) => text,
        None => serde_json::to_string_pretty(&request).unwrap_or_else(|_| body.to_owned()),
    }
}

/// What a streamed response body says: its text, and the tools it calls
/// with their input. A body which is not such a stream is given whole.
pub fn response_text(body: &str) -> String {
    let mut said = String::new();
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else { continue };
        let Ok(event) = serde_json::from_str::<Value>(data.trim()) else { continue };
        // Where a tool call starts, one provider names the tool in a
        // block and the other in an item.
        let starts = event["type"].as_str().is_some_and(|kind| kind.ends_with("_start") || kind.ends_with(".added"));
        let tool = [&event["content_block"]["name"], &event["item"]["name"]].into_iter().find_map(Value::as_str);
        if let (true, Some(tool)) = (starts, tool) {
            said.push_str(&format!("\n[tool {tool}] "));
        }
        match &event["delta"] {
            Value::String(delta) => said.push_str(delta),
            delta => ["text", "partial_json", "thinking"].iter().filter_map(|name| delta[*name].as_str()).for_each(|part| said.push_str(part)),
        }
    }
    if said.trim().is_empty() { body.to_owned() } else { said.trim().to_owned() }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn stream(events: &[Value]) -> String {
        events.iter().map(|event| format!("event: {}\ndata: {event}\n\n", event["type"].as_str().unwrap())).collect()
    }

    #[test]
    fn request_text_is_what_the_newest_item_says() {
        let messages = json!({"model": "m", "messages": [
            {"role": "user", "content": "first"},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "text", "text": "file list"}]},
                {"type": "text", "text": "and now?"},
            ]},
        ]});
        assert_eq!(request_text(&messages.to_string()), "file list\nand now?");

        let input = json!({"input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hello"}]},
            {"type": "function_call_output", "call_id": "c", "output": "exit 0"},
        ]});
        assert_eq!(request_text(&input.to_string()), "exit 0");
        assert_eq!(request_text(&json!({"input": "plain"}).to_string()), "plain");

        assert!(request_text(r#"{"model":"m"}"#).contains("\"model\": \"m\""));
        assert_eq!(request_text("not json"), "not json");
    }

    #[test]
    fn response_text_joins_what_each_provider_streams() {
        let anthropic = stream(&[
            json!({"type": "message_start", "message": {"id": "msg_1"}}),
            json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Looking"}}),
            json!({"type": "content_block_delta", "delta": {"type": "text_delta", "text": " now."}}),
            json!({"type": "content_block_start", "content_block": {"type": "tool_use", "name": "Bash"}}),
            json!({"type": "content_block_delta", "delta": {"type": "input_json_delta", "partial_json": "{\"command\":\"ls\"}"}}),
        ]);
        assert_eq!(response_text(&anthropic), "Looking now.\n[tool Bash] {\"command\":\"ls\"}");

        let openai = stream(&[
            json!({"type": "response.created", "response": {"id": "resp_1"}}),
            json!({"type": "response.output_text.delta", "delta": "Done"}),
            json!({"type": "response.output_item.added", "item": {"type": "function_call", "name": "shell"}}),
            json!({"type": "response.function_call_arguments.delta", "delta": "{}"}),
            json!({"type": "response.output_item.done", "item": {"type": "function_call", "name": "shell"}}),
        ]);
        assert_eq!(response_text(&openai), "Done\n[tool shell] {}");

        assert_eq!(response_text(r#"{"error":{"type":"authentication_error"}}"#), r#"{"error":{"type":"authentication_error"}}"#);
    }
}
