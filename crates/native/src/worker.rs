//! Worker command-line configuration and parent-facing events.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};

use crate::{NativeAudit, NativeRole};

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
}

/// A line emitted to the parent bridge on standard output.
pub enum WorkerEvent {
    /// Bound local ingress address.
    Ready(String),
    /// Sponsor audit projection.
    Audit(NativeAudit),
    /// Native worker cancellation reason.
    Cancel(String),
}

impl WorkerEvent {
    /// Serialize with the existing parent bridge's event prefixes.
    pub fn line(&self) -> Result<String> {
        Ok(match self {
            Self::Ready(address) => format!("NATIVE_READY {address}"),
            Self::Audit(audit) => format!("NATIVE_AUDIT {}", serde_json::to_string(audit)?),
            Self::Cancel(reason) => format!("NATIVE_CANCEL {reason}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{WorkerConfig, WorkerEvent, WorkerRoute};
    use crate::{NativeAudit, NativeRole};

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
            turn: 2,
            prompt: "fixture".into(),
            sha256: "abc".into(),
            proof: "quicksilver".into(),
            usage: None,
            session_id: "fixture-session".into(),
        };
        let line = WorkerEvent::Audit(audit.clone()).line().unwrap();
        let decoded: NativeAudit =
            serde_json::from_str(line.strip_prefix("NATIVE_AUDIT ").unwrap()).unwrap();
        assert_eq!(decoded, audit);
    }
}
