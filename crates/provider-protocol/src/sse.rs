//! Shared incremental data-line decoding for provider SSE streams.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::{HttpProvider, ResponseSummary, antigravity, claude};

/// A partial SSE data line; complete JSON events are released immediately.
#[derive(Default)]
pub struct Lines {
    partial: Vec<u8>,
}

impl Lines {
    /// Decode complete lines without retaining provider content after delivery.
    pub fn push(&mut self, bytes: &[u8], mut event: impl FnMut(Value) -> Result<()>) -> Result<()> {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            self.partial.extend_from_slice(part);
            if part.ends_with(b"\n") {
                self.finish(&mut event)?;
            }
        }
        Ok(())
    }

    /// Deliver a final data line even when EOF has no trailing newline.
    pub fn finish(&mut self, mut event: impl FnMut(Value) -> Result<()>) -> Result<()> {
        if let Some(data) = self.partial.strip_prefix(b"data:") {
            event(serde_json::from_slice(data)?)?;
        }
        self.partial.clear();
        Ok(())
    }
}

/// Provider-selected usage tap over authenticated SSE bytes.
pub enum Summary {
    /// Claude Messages events.
    Claude(claude::SseSummarizer),
    /// Google subscription envelopes.
    Antigravity(antigravity::SseSummarizer),
}

impl Summary {
    /// Select the response codec for a native HTTP session.
    pub fn new(provider: HttpProvider) -> Self {
        match provider {
            HttpProvider::Claude => Self::Claude(claude::SseSummarizer::default()),
            HttpProvider::Antigravity => Self::Antigravity(antigravity::SseSummarizer::default()),
        }
    }

    /// Observe one authenticated response fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Claude(tap) => tap.push(bytes),
            Self::Antigravity(tap) => tap.push(bytes),
        }
    }

    /// Resolve terminal usage at the end of the authenticated HTTP stream.
    pub fn finish(&mut self) -> Result<ResponseSummary> {
        match self {
            Self::Claude(tap) => {
                tap.finish()?;
                tap.completed().context("Claude message_stop missing")
            }
            Self::Antigravity(tap) => tap.finish(),
        }
    }

    /// Claude has a distinct terminal event; Google usage may follow its finish reason.
    pub fn completed(&self) -> Option<ResponseSummary> {
        match self {
            Self::Claude(tap) => tap.completed(),
            Self::Antigravity(_) => None,
        }
    }

    /// Partial provider-reported usage for interrupted requests.
    pub fn usage(&self) -> Value {
        match self {
            Self::Claude(tap) => tap.usage(),
            Self::Antigravity(tap) => tap.usage(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Summary;
    use crate::HttpProvider;

    /// EOF preserves partial usage but cannot replace Claude's terminal event.
    #[test]
    fn claude_completion_requires_message_stop() {
        let mut tap = Summary::new(HttpProvider::Claude);
        tap.push(b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg\",\"usage\":{\"input_tokens\":7}}}\n").unwrap();
        tap.push(b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n")
            .unwrap();
        assert!(tap.finish().is_err());
        assert_eq!(tap.usage()["input_tokens"], 7);
        assert_eq!(tap.usage()["output_tokens"], 3);
        tap.push(b"data: {\"type\":\"message_stop\"}\n").unwrap();
        assert_eq!(tap.finish().unwrap().message_id, "msg");
    }
}
