//! Claude Messages SSE decoding and usage normalization.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::{ResponseSummary, sse::Lines};

/// Validate a completed SSE response after its bytes were streamed locally.
pub fn summarize_sse(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
) -> Result<ResponseSummary> {
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
    let mut summary = SseSummarizer::default();
    summary.push(body)?;
    summary.finish()
}

/// Incrementally summarize the same raw SSE body without retaining its content deltas.
#[derive(Default)]
pub struct SseSummarizer {
    lines: Lines,
    start: Option<Value>,
    delta: Option<Value>,
    stopped: bool,
    tool_uses: Vec<String>,
}

impl SseSummarizer {
    /// Accept a body fragment; an event may span more than one fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let mut lines = std::mem::take(&mut self.lines);
        let result = lines.push(bytes, |event| self.event(event));
        self.lines = lines;
        result
    }

    /// Collect identity, usage and tool names from one complete SSE data line.
    fn event(&mut self, event: Value) -> Result<()> {
        match event["type"].as_str() {
            Some("message_start") => {
                ensure!(
                    self.start.replace(event).is_none(),
                    "duplicate Claude message_start"
                );
            }
            Some("message_delta") => {
                ensure!(
                    self.delta.replace(event).is_none(),
                    "duplicate Claude message_delta"
                );
            }
            Some("message_stop") => self.stopped = true,
            Some("content_block_start") if event["content_block"]["type"] == "tool_use" => {
                self.tool_uses.push(
                    event["content_block"]["name"]
                        .as_str()
                        .context("Claude tool name missing")?
                        .to_owned(),
                );
            }
            _ => {}
        }
        Ok(())
    }

    /// Return usage as soon as the authenticated message_stop has arrived.
    pub fn completed(&self) -> Option<ResponseSummary> {
        self.stopped.then(|| self.summary().ok()).flatten()
    }

    /// Resolve usage at EOF and validate any final line without a newline.
    pub fn finish(&mut self) -> Result<ResponseSummary> {
        let mut lines = std::mem::take(&mut self.lines);
        lines.finish(|event| self.event(event))?;
        self.lines = lines;
        self.summary()
    }

    /// Build the common usage projection from complete SSE events.
    fn summary(&self) -> Result<ResponseSummary> {
        let start = self
            .start
            .as_ref()
            .context("Claude message_start missing")?;
        self.delta
            .as_ref()
            .context("Claude message_delta missing")?;
        let message_id = start["message"]["id"]
            .as_str()
            .context("Claude message id missing")?
            .to_owned();
        Ok(ResponseSummary {
            message_id,
            usage: self.usage(),
            tool_uses: self.tool_uses.clone(),
        })
    }

    /// Provider-reported usage seen so far, including input-only partial usage.
    pub fn usage(&self) -> Value {
        let mut usage = self
            .start
            .as_ref()
            .and_then(|start| start["message"]["usage"].as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(update) = self
            .delta
            .as_ref()
            .and_then(|delta| delta["usage"].as_object())
        {
            usage.extend(update.clone());
        }
        Value::Object(usage)
    }
}

#[cfg(test)]
mod tests {
    use super::SseSummarizer;

    /// Shared line decoding keeps Claude identity, tool names and merged usage intact.
    #[test]
    fn fragmented_claude_sse() {
        let body = b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"c1\",\"usage\":{\"input_tokens\":6}}}\r\n\r\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"Read\"}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\ndata: {\"type\":\"message_stop\"}";
        for size in 1..body.len() {
            let mut tap = SseSummarizer::default();
            for part in body.chunks(size) {
                tap.push(part).unwrap();
            }
            let summary = tap.finish().unwrap();
            assert_eq!(summary.message_id, "c1");
            assert_eq!(summary.usage["input_tokens"], 6);
            assert_eq!(summary.usage["output_tokens"], 7);
            assert_eq!(summary.tool_uses, ["Read"]);
            assert!(tap.completed().is_some());
        }
    }
}
