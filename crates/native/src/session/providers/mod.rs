//! Provider-specific request preparation and continuation state.

use anyhow::{Context, Result, ensure};
use concurro_relay_provider_protocol::{HttpProvider, header_key, tls_key_update::Template};
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
    project: Option<String>,
}

/// Apply gzip transport encoding and provider continuation headers.
pub fn configure_template(template: &mut Template, compact: bool) {
    if template.provider == HttpProvider::Claude && compact {
        claude::beta_template(template);
    }
    template
        .headers
        .retain(|(name, _)| header_key(name) != b"content-encoding");
    template
        .headers
        .push((b"content-encoding".to_vec(), b"gzip".to_vec()));
}

impl ProviderState {
    /// Start independent provider state for one native session.
    pub fn new(provider: HttpProvider, compact: bool, account: Option<&str>) -> Self {
        Self {
            provider,
            project: (provider == HttpProvider::Antigravity)
                .then(|| account.map(str::to_owned))
                .flatten(),
            threads: (provider == HttpProvider::Claude && compact).then(ThreadState::default),
        }
    }

    /// Build the final provider body while retaining the complete client input.
    pub fn prepare(&self, body: &[u8], template: &Template) -> Result<Prepared> {
        ensure!(
            template.provider == self.provider,
            "HTTP provider changed within a session"
        );
        if let Some(project) = &self.project {
            let mut original: Value =
                serde_json::from_slice(body).context("HTTP request is not JSON")?;
            original
                .as_object_mut()
                .context("Google request must be an object")?
                .insert("project".into(), Value::String(project.clone()));
            return Ok(Prepared {
                body: serde_json::to_vec(&original)?,
                original,
                mode: "full",
                parent: None,
                decision: "local_history",
                mismatch: None,
            });
        }
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
        assert_eq!(
            template.headers,
            vec![(b"content-encoding".to_vec(), b"gzip".to_vec())]
        );
        let mut state = ProviderState::new(HttpProvider::Antigravity, true, None);
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
    /// The Sponsor's project replaces caller routing while preserving signed conversation parts.
    #[test]
    fn google_project_is_sponsor_owned() {
        let template = Template {
            provider: HttpProvider::Antigravity,
            path: b"/v1internal:streamGenerateContent?alt=sse".to_vec(),
            headers: Vec::new(),
        };
        let state = ProviderState::new(HttpProvider::Antigravity, true, Some("sponsor-project"));
        let input = json!({"project":"caller-project","model":"gemini-4-neon-low","request":{
        "sessionId":"retained-session","contents":[{"role":"model","parts":[{
            "thoughtSignature":"opaque-signature","functionCall":{"name":"read_file","args":{"Path":"README.md"}}
        }]}]}});
        let prepared = state
            .prepare(&serde_json::to_vec(&input).unwrap(), &template)
            .unwrap();
        let output: serde_json::Value = serde_json::from_slice(&prepared.body).unwrap();
        assert_eq!(output["project"], "sponsor-project");
        assert_eq!(output["request"], input["request"]);
        assert_eq!(output["model"], input["model"]);
    }
}
