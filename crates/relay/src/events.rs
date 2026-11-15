//! What a running relay reports to whoever is watching it.

use std::fmt;

use concurro_relay_protocol::route::Route;

/// The state of one of the relay's links to Concurro.
#[derive(Clone, Debug, PartialEq)]
pub enum LinkState {
    Connecting,
    Up,
    /// The link ended and will be opened again.
    Down(String),
    /// Concurro refused the relay; the link is not tried again.
    Refused(String),
}

/// One request the relay performed and proved.
#[derive(Clone, Debug, PartialEq)]
pub struct Exchange {
    pub route: Route,
    pub model: Option<String>,
    /// Bytes of the request and of the provider's response.
    pub sent: usize,
    pub received: usize,
    /// Bytes exchanged with Concurro to prove it.
    pub upload: u64,
    pub download: u64,
    pub seconds: f64,
    /// The bodies of the request and of the provider's response, as text.
    pub request: String,
    pub response: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Link { link: usize, state: LinkState },
    Proved { link: usize, exchange: Exchange },
    /// The relay did not perform a request, and why.
    Refused { link: usize, reason: String },
}

/// A number of bytes as a person reads it.
pub fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1e3),
        _ => format!("{:.2} MB", bytes as f64 / 1e6),
    }
}

impl fmt::Display for LinkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => f.write_str("connecting"),
            Self::Up => f.write_str("up"),
            Self::Down(reason) => write!(f, "down: {reason}"),
            Self::Refused(reason) => write!(f, "refused: {reason}"),
        }
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: sent {}, received {}, proved in {:.1}s with {} up and {} down",
            self.route.label(),
            self.model.as_deref().unwrap_or("request"),
            size(self.sent as u64),
            size(self.received as u64),
            self.seconds,
            size(self.upload),
            size(self.download),
        )
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link { link, state } => write!(f, "link {link} {state}"),
            Self::Proved { link, exchange } => write!(f, "link {link} {exchange}"),
            Self::Refused { link, reason } => write!(f, "link {link} refused a request: {reason}"),
        }
    }
}
