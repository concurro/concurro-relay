//! Provider application framing and authenticated event semantics.

pub mod claude;
pub mod codex;

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
