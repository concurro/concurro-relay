//! What the relay does for each provider route. The allowlists are fixed
//! here: they are the relay's own judgement of what a credential may be
//! used for, not something Concurro or the sponsor edits.

use concurro_relay_protocol::{route::Route, wire::CredentialHeader};

use crate::policy::Policy;

/// One route as a relay serves it.
#[derive(Clone)]
pub struct Served {
    pub route: Route,
    /// The requests the relay will send on the route.
    pub policy: Policy,
    /// The WebSocket connections it will open on the route and the
    /// messages it will send on them, if the route has any.
    pub websocket: Option<Policy>,
    /// The request header which carries the route's credential.
    pub credential_header: CredentialHeader,
}

impl Served {
    /// `route` as the relay serves it for a real provider.
    pub fn builtin(route: Route) -> Self {
        Self {
            route,
            policy: policy(route),
            websocket: websocket(route),
            credential_header: CredentialHeader::bearer(),
        }
    }
}

/// The WebSocket connections the relay will open on `route` and the
/// messages it will send on them.
fn websocket(route: Route) -> Option<Policy> {
    let (paths, headers, body_fields): (&[&str], &[&str], &[&str]) = match route {
        Route::ClaudeSubscription => return None,
        Route::ChatgptSubscription => (
            &["/backend-api/codex/responses"],
            &[
                "openai-beta",
                "originator",
                "session-id",
                "thread-id",
                "user-agent",
                "x-client-request-id",
                "x-codex-beta-features",
                "x-codex-turn-metadata",
                "x-codex-window-id",
            ],
            &[
                "client_metadata",
                "generate",
                "include",
                "input",
                "model",
                "parallel_tool_calls",
                "previous_response_id",
                "prompt_cache_key",
                "reasoning",
                "store",
                "stream",
                "text",
                "tool_choice",
                "type",
            ],
        ),
    };
    Some(Policy {
        host: route.host().into(),
        paths: names(paths),
        headers: names(headers),
        body_fields: names(body_fields),
    })
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// The requests the relay will send on `route`.
fn policy(route: Route) -> Policy {
    let (paths, headers, body_fields): (&[&str], &[&str], &[&str]) = match route {
        Route::ClaudeSubscription => (
            &["/v1/messages?beta=true"],
            &[
                "accept",
                "anthropic-beta",
                "anthropic-dangerous-direct-browser-access",
                "anthropic-version",
                "content-type",
                "user-agent",
                "x-app",
                "x-claude-code-session-id",
                "x-stainless-arch",
                "x-stainless-lang",
                "x-stainless-os",
                "x-stainless-package-version",
                "x-stainless-retry-count",
                "x-stainless-runtime",
                "x-stainless-runtime-version",
                "x-stainless-timeout",
            ],
            &[
                "context_management",
                "max_tokens",
                "messages",
                "metadata",
                "model",
                "output_config",
                "stream",
                "system",
                "thinking",
                "thread",
                "tools",
            ],
        ),
        Route::ChatgptSubscription => (
            &["/backend-api/codex/responses"],
            &[
                "accept",
                "content-type",
                "originator",
                "session-id",
                "thread-id",
                "user-agent",
                "x-client-request-id",
                "x-codex-beta-features",
                "x-codex-turn-metadata",
                "x-codex-window-id",
                "x-openai-internal-codex-responses-lite",
            ],
            &[
                "client_metadata",
                "include",
                "input",
                "model",
                "parallel_tool_calls",
                "prompt_cache_key",
                "reasoning",
                "store",
                "stream",
                "text",
                "tool_choice",
            ],
        ),
    };
    Policy {
        host: route.host().into(),
        paths: names(paths),
        headers: names(headers),
        body_fields: names(body_fields),
    }
}
