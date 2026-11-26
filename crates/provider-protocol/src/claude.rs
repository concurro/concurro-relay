//! Claude Messages SSE decoding and usage normalization.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::ResponseSummary;

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
    partial: Vec<u8>,
    start: Option<Value>,
    delta: Option<Value>,
    stopped: bool,
    tool_uses: Vec<String>,
}

impl SseSummarizer {
    /// Accept a body fragment; an event may span more than one fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            if let Some(line) = part.strip_suffix(b"\n") {
                if self.partial.is_empty() {
                    self.event(line)?;
                } else {
                    let mut complete = std::mem::take(&mut self.partial);
                    complete.extend_from_slice(line);
                    self.event(&complete)?;
                    complete.clear();
                    self.partial = complete;
                }
            } else {
                self.partial.extend_from_slice(part);
            }
        }
        Ok(())
    }

    /// Collect identity, usage and tool names from one complete SSE data line.
    fn event(&mut self, line: &[u8]) -> Result<()> {
        let Some(value) = line.strip_prefix(b"data: ") else {
            return Ok(());
        };
        let event: Value = serde_json::from_slice(value)?;
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
        let last = std::mem::take(&mut self.partial);
        self.event(&last)?;
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
