//! Provider identities layered over the shared HTTP/2 transport.

use std::{fmt, str::FromStr};

use anyhow::{Result, bail, ensure};
use concurro_relay_protocol::route::Route;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ResponseSummary, antigravity, claude};

/// Provider semantics for a TLS KeyUpdate HTTP/2 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpProvider {
    /// Anthropic Messages with optional Message Threads.
    Claude,
    /// Google Antigravity subscription GenerateContent.
    Antigravity,
}

impl HttpProvider {
    /// Certificate identity and HTTP authority for this provider.
    pub fn hostname(self) -> &'static str {
        match self {
            Self::Claude => Route::ClaudeSubscription.host(),
            Self::Antigravity => Route::AntigravitySubscription.host(),
        }
    }

    /// Admit only inference paths implemented by this provider adapter.
    pub fn validate_path(self, path: &[u8]) -> Result<()> {
        let paths: &[&[u8]] = match self {
            Self::Claude => &[b"/v1/messages", b"/v1/messages?beta=true"],
            Self::Antigravity => &[b"/v1internal:streamGenerateContent?alt=sse"],
        };
        ensure!(paths.contains(&path), "unsupported {self} request path");
        Ok(())
    }

    /// Render a local refusal using the provider's error envelope.
    pub fn error(self, status: u16, message: &str) -> Value {
        match self {
            Self::Claude => {
                json!({"type":"error","error":{"type": if status == 403 { "permission_error" } else { "invalid_request_error" },"message":message}})
            }
            Self::Antigravity => {
                json!({"error":{"code":status,"status":if status == 403 { "PERMISSION_DENIED" } else { "INVALID_ARGUMENT" },"message":message}})
            }
        }
    }

    /// Provider-owned error classification without its potentially sensitive message.
    pub fn error_kind(self, error: &Value) -> &Value {
        match self {
            Self::Claude => &error["error"]["type"],
            Self::Antigravity => &error["error"]["status"],
        }
    }

    /// Provider-owned numeric or symbolic error code for audit evidence.
    pub fn error_code(self, error: &Value) -> &Value {
        match self {
            Self::Claude => &error["error"]["details"]["error_code"],
            Self::Antigravity => &error["error"]["code"],
        }
    }

    /// Summarize an authenticated provider response with its own codec.
    pub fn summarize(
        self,
        status: u16,
        headers: &[(Vec<u8>, Vec<u8>)],
        body: &[u8],
    ) -> Result<ResponseSummary> {
        match self {
            Self::Claude => claude::summarize_sse(status, headers, body),
            Self::Antigravity => antigravity::summarize_sse(status, headers, body),
        }
    }
}

impl fmt::Display for HttpProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Claude => "claude",
            Self::Antigravity => "antigravity",
        })
    }
}

impl FromStr for HttpProvider {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "claude" => Ok(Self::Claude),
            "antigravity" => Ok(Self::Antigravity),
            _ => bail!("unknown HTTP provider {value}"),
        }
    }
}
