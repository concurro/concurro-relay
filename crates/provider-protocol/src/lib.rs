//! Provider application framing and authenticated event semantics.

pub mod antigravity;
pub mod claude;
pub mod codex;
mod provider;
pub mod sse;
pub mod tls_key_update;
pub use provider::HttpProvider;

/// A header name as servers may compare it: without case, and with `_` read
/// as `-`.
pub fn header_key(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|byte| match byte {
            b'_' => b'-',
            byte => byte.to_ascii_lowercase(),
        })
        .collect()
}

/// Completed provider response identity and normalized usage.
pub struct ResponseSummary {
    /// Provider response identifier.
    pub message_id: String,
    /// Provider usage normalized by its adapter.
    pub usage: serde_json::Value,
    /// Tool names issued by authenticated provider content blocks.
    pub tool_uses: Vec<String>,
}
