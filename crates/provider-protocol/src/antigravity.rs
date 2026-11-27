//! Antigravity subscription GenerateContent SSE normalization.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::{ResponseSummary, sse::Lines};

/// Compatibility identity for the pinned agy runner client.
pub const USER_AGENT: &str = "antigravity/cli/1.5.15 (aidev_client; os_type=linux; arch=amd64)";

/// Convert a canonical Gemini model and explicit thinking level to its subscription ID.
pub fn subscription_model(model: &str, request: &Value) -> Result<String> {
    let level = request
        .pointer("/generationConfig/thinkingConfig/thinkingLevel")
        .and_then(Value::as_str)
        .context("Google thinking level is required")?
        .to_ascii_lowercase();
    let levels: &[&str] = match model {
        "gemini-4-neon" | "gemini-4-hydrogen" => &["low", "medium", "high", "xhigh"],
        "gemini-4-carbon" | "gemini-4-argon" | "gemini-3.8-flash" => &["low", "medium", "high"],
        _ => anyhow::bail!("unsupported Antigravity canonical model"),
    };
    ensure!(
        levels.contains(&level.as_str()),
        "unsupported Antigravity thinking level"
    );
    Ok(format!("{model}-{level}"))
}

/// Normalize a completed authenticated Google SSE response without altering its body.
pub fn summarize_sse(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
) -> Result<ResponseSummary> {
    ensure!(status == 200, "Antigravity returned HTTP {status}");
    ensure!(
        headers.iter().any(|(name, value)| name == b"content-type"
            && value
                .windows(b"text/event-stream".len())
                .any(|part| part == b"text/event-stream")),
        "Antigravity response is not SSE"
    );
    let mut summary = SseSummarizer::default();
    summary.push(body)?;
    summary.finish()
}

/// Incremental Google usage and response identity, without retaining content deltas.
#[derive(Default)]
pub struct SseSummarizer {
    lines: Lines,
    message_id: Option<String>,
    raw: Option<Value>,
    finished: bool,
    tool_uses: Vec<String>,
}

impl SseSummarizer {
    /// Observe complete JSON events from arbitrary body fragments.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let mut lines = std::mem::take(&mut self.lines);
        let result = lines.push(bytes, |event| self.event(event));
        self.lines = lines;
        result
    }

    /// Collect cumulative usage and tool names from a subscription envelope.
    fn event(&mut self, event: Value) -> Result<()> {
        ensure!(
            event.get("error").is_none(),
            "Antigravity returned an SSE error"
        );
        let response = event.get("response").unwrap_or(&event);
        ensure!(
            response.get("error").is_none(),
            "Antigravity returned an inference error"
        );
        if let Some(id) = response["responseId"]
            .as_str()
            .or_else(|| event["traceId"].as_str())
        {
            self.message_id = Some(id.to_owned());
        }
        if response["usageMetadata"].is_object() {
            self.raw = Some(response["usageMetadata"].clone());
        }
        if let Some(candidates) = response["candidates"].as_array() {
            for candidate in candidates {
                self.finished |= candidate["finishReason"].as_str().is_some_and(|reason| {
                    !reason.is_empty() && reason != "FINISH_REASON_UNSPECIFIED"
                });
                if let Some(parts) = candidate["content"]["parts"].as_array() {
                    for part in parts {
                        if let Some(name) = part["functionCall"]["name"].as_str() {
                            self.tool_uses.push(name.to_owned());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate terminal usage only after EOF, since usage may follow finishReason.
    pub fn finish(&mut self) -> Result<ResponseSummary> {
        let mut lines = std::mem::take(&mut self.lines);
        lines.finish(|event| self.event(event))?;
        self.lines = lines;
        ensure!(self.finished, "Antigravity response did not finish");
        let raw = self.raw.as_ref().context("Antigravity usage missing")?;
        let prompt = raw["promptTokenCount"]
            .as_u64()
            .context("Antigravity prompt usage missing")?;
        prompt
            .checked_add(raw["toolUsePromptTokenCount"].as_u64().unwrap_or(0))
            .context("Antigravity input usage overflow")?;
        raw["candidatesTokenCount"]
            .as_u64()
            .unwrap_or(0)
            .checked_add(raw["thoughtsTokenCount"].as_u64().unwrap_or(0))
            .context("Antigravity output usage overflow")?;
        Ok(ResponseSummary {
            message_id: self
                .message_id
                .clone()
                .context("Antigravity response ID missing")?,
            usage: self.usage(),
            tool_uses: self.tool_uses.clone(),
        })
    }

    /// Normalize the last provider usage snapshot, including partial input usage.
    pub fn usage(&self) -> Value {
        let Some(raw) = &self.raw else {
            return json!({});
        };
        let mut usage = json!({"google":raw});
        if let Some(prompt) = raw["promptTokenCount"].as_u64() {
            usage["input_tokens"] =
                json!(prompt.saturating_add(raw["toolUsePromptTokenCount"].as_u64().unwrap_or(0)));
        }
        if raw["candidatesTokenCount"].is_u64()
            || raw["thoughtsTokenCount"].is_u64()
            || self.finished
        {
            usage["output_tokens"] = json!(
                raw["candidatesTokenCount"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_add(raw["thoughtsTokenCount"].as_u64().unwrap_or(0))
            );
        }
        usage
    }
}

#[cfg(test)]
mod tests {
    use super::summarize_sse;
    use serde_json::json;

    /// Normalize subscription envelopes, tool calls and final cumulative usage.
    #[test]
    fn subscription_response_usage() {
        let headers = vec![(
            b"content-type".to_vec(),
            b"text/event-stream; charset=utf-8".to_vec(),
        )];
        let start = json!({"response":{"responseId":"google-1","usageMetadata":{"promptTokenCount":5},"candidates":[{"content":{"parts":[{"functionCall":{"name":"read_file","args":{"path":"README.md"}}}]}}]}});
        let end = json!({"response":{"responseId":"google-1","candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"cachedContentTokenCount":4,"toolUsePromptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":7}}});
        let body = format!("data: {start}\r\n\r\ndata: {end}\n\n");
        let summary = summarize_sse(200, &headers, body.as_bytes()).unwrap();
        assert_eq!(summary.message_id, "google-1");
        assert_eq!(summary.tool_uses, ["read_file"]);
        assert_eq!(summary.usage["input_tokens"], 12);
        assert_eq!(summary.usage["output_tokens"], 10);
        assert_eq!(summary.usage["google"]["cachedContentTokenCount"], 4);
        assert!(summarize_sse(403, &headers, body.as_bytes()).is_err());
        assert!(summarize_sse(200, &[], body.as_bytes()).is_err());
        for invalid in [
            format!("data: {start}\n"),
            "data: {\"error\":{\"message\":\"failed\"}}\n".into(),
            "data: {\"response\":{\"error\":{\"message\":\"failed\"}}}\n".into(),
            "data: {\"response\":{\"responseId\":\"upgrade\",\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"upgrade required\"}]}}]}}\n".into(),
        ] {
            assert!(summarize_sse(200, &headers, invalid.as_bytes()).is_err());
        }
    }
    /// Arbitrary chunk boundaries preserve partial and final cumulative usage.
    #[test]
    fn fragmented_google_sse() {
        let body = b"data: {\"response\":{\"responseId\":\"g1\",\"candidates\":[{\"finishReason\":\"STOP\"}]}}\r\n\r\ndata: {\"response\":{\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":3,\"thoughtsTokenCount\":4}}}";
        for size in 1..body.len() {
            let mut tap = super::SseSummarizer::default();
            for part in body.chunks(size) {
                tap.push(part).unwrap();
            }
            let summary = tap.finish().unwrap();
            assert_eq!(summary.message_id, "g1");
            assert_eq!(summary.usage["input_tokens"], 2);
            assert_eq!(summary.usage["output_tokens"], 7);
        }
    }
}
