//! Claim release endpoint. The POST has no body and returns 204 on success.

use std::borrow::Cow;

use anyhow::{Result, ensure};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// Append the claim ID as one path segment and POST to revoke it.
pub const CLAIMS_PREFIX: &str = "/release/v1/claims/";

/// Identity supplied in the release endpoint's path.
pub struct ReleaseClaim<'a> {
    /// ID of the claim to revoke (its JWS payload's jti).
    pub claim_id: Cow<'a, str>,
}

impl<'a> ReleaseClaim<'a> {
    /// Decode the claim ID from a single HTTP path segment.
    pub fn from_segment(segment: &'a str) -> Result<Self> {
        ensure!(
            !segment.is_empty() && !segment.contains('/'),
            "expected one claim ID segment"
        );
        Ok(Self {
            claim_id: percent_decode_str(segment).decode_utf8()?,
        })
    }

    /// Build the private endpoint for this ID.
    pub fn path(&self) -> String {
        format!(
            "{CLAIMS_PREFIX}{}",
            utf8_percent_encode(&self.claim_id, NON_ALPHANUMERIC)
        )
    }
}
