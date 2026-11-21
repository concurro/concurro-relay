//! What a running relay reports to whoever is watching it.

use std::fmt;

use concurro_relay_native::{NativeAudit, NativeRequest};
use concurro_relay_protocol::route::Route;

use crate::review::Decision;

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
    Link {
        link: usize,
        state: LinkState,
    },
    Proved {
        link: usize,
        exchange: Exchange,
    },
    /// Concurro asks for a request the Sponsor is to decide on, under
    /// `ticket`.
    Asked {
        link: usize,
        route: Route,
        ticket: u64,
        request: NativeRequest,
    },
    /// A native TLS request was decided on before any of it reached the
    /// provider.
    Reviewed {
        link: usize,
        route: Route,
        request: NativeRequest,
        decision: Decision,
    },
    /// Usage Concurro reports for an accepted native TLS request.
    NativeAudit {
        link: usize,
        route: Route,
        audit: NativeAudit,
    },
    /// The relay did not perform a request, and why.
    Refused {
        link: usize,
        reason: String,
    },
}

/// A number of bytes as a person reads it.
pub fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1e3),
        _ => format!("{:.2} MB", bytes as f64 / 1e6),
    }
}

/// A native request as its number and, for HTTP, its path, without the
/// characters a terminal would act on.
pub fn described(request: &NativeRequest) -> String {
    match &request.path {
        Some(path) => {
            let path: String = path.chars().filter(|shown| !shown.is_control()).collect();
            format!("request {} to {path}", request.request)
        }
        None => format!("request {}", request.request),
    }
}

/// `text` without the characters a terminal would act on, other than line
/// breaks and tabs.
pub fn printable(text: &str) -> String {
    text.chars()
        .filter(|shown| !shown.is_control() || matches!(shown, '\n' | '\t'))
        .collect()
}

/// `text` as one line, without the characters a terminal would act on.
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(|shown| if shown.is_control() { ' ' } else { shown })
        .collect()
}

/// What a native request asks the provider: its path and public headers,
/// when it has them, then its body.
pub fn request_text(request: &NativeRequest) -> String {
    let mut text = String::new();
    if let Some(path) = &request.path {
        text.push_str(&format!("POST {path}\n"));
        for (name, value) in &request.headers {
            text.push_str(&format!("{name}: {value}\n"));
        }
        text.push('\n');
    }
    text.push_str(&request.prompt);
    printable(&text)
}

/// The usage Concurro reported for a request.
pub fn usage(audit: &NativeAudit) -> String {
    audit
        .usage
        .as_ref()
        .map(|usage| printable(&usage.to_string()))
        .unwrap_or_else(|| "unavailable".into())
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
            Self::Asked {
                link,
                route,
                request,
                ..
            } => write!(
                f,
                "link {link} {} {} waits for review (sha256 {})",
                route.label(),
                described(request),
                request.sha256,
            ),
            Self::Reviewed {
                link,
                route,
                request,
                decision,
            } => write!(
                f,
                "link {link} {} {} {decision} (sha256 {})",
                route.label(),
                described(request),
                request.sha256,
            ),
            Self::NativeAudit { link, route, audit } => write!(
                f,
                "link {link} {} request {}: Concurro-reported provider usage: {}",
                route.label(),
                audit.request,
                usage(audit),
            ),
            Self::Refused { link, reason } => write!(f, "link {link} refused a request: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use concurro_relay_native::NativeRequest;

    use super::request_text;

    /// A request shows its path and headers, without terminal controls.
    #[test]
    fn request_text_shows_headers_without_controls() {
        let request = NativeRequest {
            request: 1,
            prompt: "{\"a\":\"\u{1b}]52;c;x\u{7}\"}\n".into(),
            sha256: "abc".into(),
            path: Some("/v1/messages".into()),
            headers: vec![("anthropic-version".into(), "2023-06-01".into())],
            session_id: "session".into(),
        };
        assert_eq!(
            request_text(&request),
            "POST /v1/messages\nanthropic-version: 2023-06-01\n\n{\"a\":\"]52;c;x\"}\n"
        );
    }

    /// A string shown on one line keeps no line breaks or terminal controls.
    #[test]
    fn one_line_has_no_breaks_or_controls() {
        assert_eq!(
            super::one_line("m\nlink 1 \u{1b}]52;c;x\u{7} ok"),
            "m link 1  ]52;c;x  ok"
        );
    }
}
