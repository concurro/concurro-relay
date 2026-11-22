//! Provider requests and their hosted dispatch endpoints.

use serde::Deserialize;

/// Header carrying the exchange's compact JWS.
pub const CLAIM_HEADER: &str = "x-concurro-claim";
/// Header carrying the exchange's inference request ID.
pub const REQUEST_HEADER: &str = "x-concurro-request";
/// Dispatch a Claude Messages request.
pub const MESSAGES_PATH: &str = "/dispatch/v2/messages";
/// Dispatch a Codex Responses request.
pub const RESPONSES_PATH: &str = "/dispatch/v2/responses";
/// An approved Claude subscription route in the hosted registry.
pub const CLAUDE_SUBSCRIPTION: &str = "claude-subscription";
/// An approved ChatGPT subscription route in the hosted registry.
pub const CHATGPT_SUBSCRIPTION: &str = "chatgpt-subscription";

/// Claim signature, validity, scope or revocation refusal.
pub const CLAIM_REFUSED_CODE: &str = "claim_refused";
/// An already-admitted exchange request ID.
pub const REQUEST_REUSED_CODE: &str = "request_reused";
/// Claim call or token allowance exhaustion, distinct from a provider throttle.
pub const ALLOWANCE_SPENT_CODE: &str = "allowance_spent";

/// The common part of the otherwise provider-native dispatch JSON body.
#[derive(Deserialize)]
pub struct ModelRequest {
    /// The exact model requested from the provider.
    pub model: String,
}
