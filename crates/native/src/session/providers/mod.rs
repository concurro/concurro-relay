//! Provider-specific request preparation and continuation state.

use anyhow::{Context, Result, ensure};
use concurro_relay_provider_protocol::{HttpProvider, tls_key_update::Template};
use serde_json::Value;

mod claude;
use claude::ThreadState;

/// The provider request selected from one complete CLI request.
pub struct Prepared {
    /// The complete CLI request retained for replay and lineage checks.
    pub original: Value,
    /// Bytes proved to Sponsor and sent to the provider.
    pub body: Vec<u8>,
    /// Whether this request creates, continues, or replays a thread.
    pub mode: &'static str,
    /// Authenticated response ID used by a continuation.
    pub parent: Option<String>,
    /// Why a full create was selected when a prior response exists.
    pub decision: &'static str,
    /// Content-free shape of a mismatched assistant response.
    pub mismatch: Option<Value>,
}

/// Provider semantics kept outside the shared TLS/HTTP2 connection loop.
pub struct ProviderState {
    provider: HttpProvider,
    threads: Option<ThreadState>,
}

/// Apply only the headers required by the selected provider's continuation mode.
pub fn configure_template(template: &mut Template, compact: bool) {
    if template.provider == HttpProvider::Claude && compact {
        claude::beta_template(template);
    }
}

impl ProviderState {
    /// Start independent provider state for one native session.
    pub fn new(provider: HttpProvider, compact: bool) -> Self {
        Self {
            provider,
            threads: (provider == HttpProvider::Claude && compact).then(ThreadState::default),
        }
    }

    /// Build the final provider body while retaining the complete client input.
    pub fn prepare(&self, body: &[u8], template: &Template) -> Result<Prepared> {
        ensure!(
            template.provider == self.provider,
            "HTTP provider changed within a session"
        );
        match &self.threads {
            Some(threads) => threads.prepare(body, template),
            None => Ok(Prepared {
                original: serde_json::from_slice(body).context("HTTP request is not JSON")?,
                body: body.to_vec(),
                mode: "full",
                parent: None,
                decision: "disabled",
                mismatch: None,
            }),
        }
    }

    /// Rebuild a full request when this provider rejects an unavailable thread parent.
    pub fn replay(&self, prepared: &mut Prepared, status: u16, error: &Value) -> Result<bool> {
        if let Some(threads) = &self.threads {
            if status == 404
                && prepared.mode == "continue"
                && error["error"]["details"]["error_code"] == "thread_not_found"
            {
                threads.replay(prepared)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Retain provider-owned continuation state after an authenticated completion.
    pub fn complete(&mut self, prepared: &Prepared, template: &Template, id: String, body: &[u8]) {
        if let Some(threads) = &mut self.threads {
            threads.complete(prepared, template, id, body);
        }
    }

    /// Whether the provider has a usable remote continuation parent.
    pub fn ready(&self) -> bool {
        self.threads.as_ref().is_some_and(ThreadState::ready)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderState, configure_template};
    use concurro_relay_provider_protocol::{HttpProvider, tls_key_update::Template};
    use serde_json::json;

    /// Claude's continuation setting never changes an Antigravity request.
    #[test]
    fn antigravity_preserves_full_history() {
        let mut template = Template {
            provider: HttpProvider::Antigravity,
            path: b"/v1internal:streamGenerateContent?alt=sse".to_vec(),
            headers: Vec::new(),
        };
        configure_template(&mut template, true);
        assert!(template.headers.is_empty());
        let mut state = ProviderState::new(HttpProvider::Antigravity, true);
        let body = br#"{ "request": {"contents": [{"role":"user","parts":[{"text":"hello"}]}]} }"#;
        let mut prepared = state.prepare(body, &template).unwrap();
        assert_eq!(prepared.body, body);
        assert_eq!(prepared.mode, "full");
        assert!(
            !state
                .replay(
                    &mut prepared,
                    404,
                    &json!({"error":{"details":{"error_code":"thread_not_found"}}})
                )
                .unwrap()
        );
        state.complete(&prepared, &template, "response-1".into(), b"");
        assert!(!state.ready());
        assert!(state.prepare(body, &Template::fixture_default()).is_err());
    }
}
