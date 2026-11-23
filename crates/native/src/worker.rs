//! Worker command-line configuration and parent-facing events.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufRead, Lines};

use crate::{NativeAudit, NativeLimits, NativeRequest, NativeRole, NativeVerdict, session::Gate};

/// Provider protocol selected for this session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum WorkerRoute {
    /// Codex WebSocket.
    Codex,
    /// Claude HTTP/2.
    #[value(name = "claude_h2")]
    ClaudeH2,
}

/// Arguments supplied to the bundled native worker.
#[derive(Debug, Parser)]
pub struct WorkerConfig {
    /// Local native role.
    #[arg(long, value_enum)]
    pub role: NativeRole,
    /// Provider protocol.
    #[arg(long, value_enum)]
    pub route: WorkerRoute,
    /// Parent-side control socket.
    #[arg(long)]
    pub control: PathBuf,
    /// Parent-side auxiliary socket.
    #[arg(long)]
    pub aux: PathBuf,
    /// Packaged native helper runtime.
    #[arg(long)]
    pub runtime: PathBuf,
    /// Per-session evidence directory.
    #[arg(long)]
    pub output: PathBuf,
    /// Provider TCP destination; TLS certificate identity is route-bound.
    #[arg(long, default_value = "127.0.0.1")]
    pub provider_host: String,
    /// Provider TCP port.
    #[arg(long, default_value_t = 443)]
    pub provider_port: u16,
    /// Provider trust anchor file.
    #[arg(long, default_value = "/etc/ssl/cert.pem")]
    pub provider_ca: PathBuf,
    /// Local Concurro CLI ingress address.
    #[arg(long, default_value = "127.0.0.1:7050")]
    pub listen: String,
    /// Shared generated-circuit cache; beside the output directory by default.
    #[arg(long)]
    pub circuit_cache: Option<PathBuf>,
    /// Longest Sponsor credential Concurro builds a prefix circuit for.
    #[arg(long, default_value_t = NativeLimits::DEFAULT.credential_bytes)]
    pub max_credential_bytes: NonZeroUsize,
    /// MiB of generated prefix circuits kept in the cache.
    #[arg(long, default_value_t = NativeLimits::DEFAULT.circuit_cache_mib)]
    pub circuit_cache_mib: NonZeroU64,
}

impl WorkerConfig {
    /// The configured resource bounds.
    pub fn limits(&self) -> NativeLimits {
        NativeLimits {
            credential_bytes: self.max_credential_bytes,
            circuit_cache_mib: self.circuit_cache_mib,
        }
    }
}

/// A line emitted to the parent bridge on standard output.
pub enum WorkerEvent {
    /// Bound local ingress address.
    Ready(String),
    /// Sponsor audit projection.
    Audit(NativeAudit),
    /// A request awaiting the parent's verdict on standard input.
    Review(NativeRequest),
    /// Native worker cancellation reason.
    Cancel(String),
}

impl WorkerEvent {
    /// Serialize with the existing parent bridge's event prefixes.
    pub fn line(&self) -> Result<String> {
        Ok(match self {
            Self::Ready(address) => format!("NATIVE_READY {address}"),
            Self::Audit(audit) => format!("NATIVE_AUDIT {}", serde_json::to_string(audit)?),
            Self::Review(request) => format!("NATIVE_REVIEW {}", serde_json::to_string(request)?),
            Self::Cancel(reason) => format!("NATIVE_CANCEL {reason}"),
        })
    }
}

/// Asks the parent bridge for each verdict: the request goes out on
/// standard output and the verdict comes back as a line on `answers`.
pub struct ParentGate<R> {
    pub answers: Lines<R>,
}

impl<R: AsyncBufRead + Unpin> Gate for ParentGate<R> {
    async fn decide(&mut self, request: &NativeRequest) -> Result<NativeVerdict> {
        println!("{}", WorkerEvent::Review(request.clone()).line()?);
        let answer = self
            .answers
            .next_line()
            .await?
            .context("parent closed the verdict pipe")?;
        Ok(serde_json::from_str(&answer)?)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use tokio::io::{AsyncBufReadExt, BufReader};

    use super::{ParentGate, WorkerConfig, WorkerEvent, WorkerRoute};
    use crate::{NativeAudit, NativeRequest, NativeRole, session::Gate};

    /// Keep the Python command-line shape and parent event prefixes stable.
    #[test]
    fn launcher_contract() {
        let config = WorkerConfig::try_parse_from([
            "concurro-native-worker",
            "--role",
            "sponsor",
            "--route",
            "claude_h2",
            "--control",
            "/tmp/c.sock",
            "--aux",
            "/tmp/a.sock",
            "--runtime",
            "/tmp/r",
            "--output",
            "/tmp/o",
        ])
        .unwrap();
        assert_eq!(config.role, NativeRole::Sponsor);
        assert_eq!(config.route, WorkerRoute::ClaudeH2);
        assert_eq!(config.provider_port, 443);
        assert_eq!(
            WorkerEvent::Ready("127.0.0.1:7050".into()).line().unwrap(),
            "NATIVE_READY 127.0.0.1:7050"
        );
        assert_eq!(
            WorkerEvent::Cancel("cli_disconnect".into()).line().unwrap(),
            "NATIVE_CANCEL cli_disconnect"
        );
        let audit = NativeAudit {
            request: 2,
            sha256: "abc".into(),
            usage: None,
            session_id: "fixture-session".into(),
        };
        let line = WorkerEvent::Audit(audit.clone()).line().unwrap();
        let decoded: NativeAudit =
            serde_json::from_str(line.strip_prefix("NATIVE_AUDIT ").unwrap()).unwrap();
        assert_eq!(decoded, audit);
        let request = request();
        let line = WorkerEvent::Review(request.clone()).line().unwrap();
        let decoded: NativeRequest =
            serde_json::from_str(line.strip_prefix("NATIVE_REVIEW ").unwrap()).unwrap();
        assert_eq!(decoded, request);
    }

    fn request() -> NativeRequest {
        NativeRequest {
            request: 3,
            prompt: "fixture prompt".into(),
            sha256: "abc".into(),
            path: Some("/v1/messages".into()),
            headers: vec![("anthropic-version".into(), "2023-06-01".into())],
            session_id: "fixture-session".into(),
        }
    }

    /// Each verdict is read from its own line of the parent's answers.
    #[tokio::test]
    async fn verdicts_come_from_the_parent() {
        let answers = b"{\"request\":3,\"accept\":true,\"reason\":null}\n{\"request\":3,\"accept\":false,\"reason\":\"no\"}\n";
        let mut gate = ParentGate {
            answers: BufReader::new(&answers[..]).lines(),
        };
        let accepted = gate.decide(&request()).await.unwrap();
        assert!(accepted.accept);
        let rejected = gate.decide(&request()).await.unwrap();
        assert_eq!(rejected.reason.as_deref(), Some("no"));
        assert!(gate.decide(&request()).await.is_err());
    }
}
