//! The Concurro relay: runs on a sponsor's machine, keeps their provider
//! login there, and performs the inference requests Concurro orders,
//! proving each one without revealing the credential.

pub mod codex;
pub mod credentials;
pub mod events;
pub mod link;
pub mod live;
pub mod login;
pub mod plain;
pub mod policy;
pub mod routes;
pub mod serve;
pub mod state;
pub mod transcript;
pub mod transport;
pub mod tui;
pub mod ws;
