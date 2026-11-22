//! Wire contracts for the hosted relay's private owner, inference and release APIs.

pub mod claim;
pub mod dispatch;
pub mod owner;
pub mod release;

use serde::{Deserialize, Serialize};

/// The body of a private API error.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    /// Machine-readable code and human-readable explanation.
    pub error: ErrorDetail,
}

/// Error information shared by the versioned private APIs.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorDetail {
    /// Stable code callers can match.
    pub code: String,
    /// Explanation safe to report to callers.
    pub message: String,
}
