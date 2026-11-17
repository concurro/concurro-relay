//! How a harness request maps to a job for each provider route, mirroring
//! what the Concurro gateway does today.

use anyhow::{Result, ensure};
use concurro_relay_protocol::{route::Route, wire::Job};

/// Headers which describe the harness's connection or carry its credential.
const DROPPED: [&str; 16] = [
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "accept-encoding",
    "transfer-encoding",
    "te",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "authorization",
    "x-api-key",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-accept",
];

/// Beta flag the Claude subscription route adds for subscription tokens.
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Whether a request to `path` on `route` is an inference request.
pub fn is_inference(route: Route, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    match route {
        Route::ClaudeSubscription => path.ends_with("/messages"),
        Route::ChatgptSubscription => path.ends_with("/responses"),
    }
}

/// Builds the job for a harness request on `route`, dropping the harness's
/// own credential and connection headers.
pub fn job<'a>(
    route: Route,
    path: &str,
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: String,
) -> Result<Job> {
    let mut kept: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        ensure!(
            name != "content-encoding",
            "compressed request bodies are not supported"
        );
        if DROPPED.contains(&name.as_str()) {
            continue;
        }
        // Repeated headers are joined, as the gateway does.
        match kept.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, existing)) => *existing = format!("{existing}, {value}"),
            None => kept.push((name, value.to_owned())),
        }
    }
    if let Route::ClaudeSubscription = route {
        match kept.iter_mut().find(|(name, _)| name == "anthropic-beta") {
            Some((_, value)) if value.contains(OAUTH_BETA) => {}
            Some((_, value)) => *value = format!("{value}, {OAUTH_BETA}"),
            None => kept.push(("anthropic-beta".into(), OAUTH_BETA.into())),
        }
    }

    let path = match route {
        Route::ClaudeSubscription => path.to_owned(),
        Route::ChatgptSubscription => format!(
            "/backend-api/codex{}",
            path.strip_prefix("/v1").unwrap_or(path)
        ),
    };
    Ok(Job {
        host: route.host().into(),
        path,
        headers: kept,
        body: body.into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_job_drops_credentials_and_adds_oauth_beta() {
        let headers = [
            ("Authorization", "Bearer harness"),
            ("x-api-key", "harness"),
            ("anthropic-beta", "a"),
            ("anthropic-beta", "b"),
            ("user-agent", "cli"),
        ];
        let job = job(
            Route::ClaudeSubscription,
            "/v1/messages?beta=true",
            headers,
            "{}".into(),
        )
        .unwrap();
        assert_eq!(job.host, "api.anthropic.com");
        assert_eq!(job.path, "/v1/messages?beta=true");
        assert_eq!(
            job.headers,
            [
                (
                    "anthropic-beta".to_owned(),
                    "a, b, oauth-2025-04-20".to_owned()
                ),
                ("user-agent".to_owned(), "cli".to_owned())
            ]
        );
    }

    #[test]
    fn chatgpt_job_maps_the_path() {
        let mapped = job(Route::ChatgptSubscription, "/v1/responses", [], "{}".into()).unwrap();
        assert_eq!(
            (mapped.host.as_str(), mapped.path.as_str()),
            ("chatgpt.com", "/backend-api/codex/responses")
        );
        assert!(
            job(
                Route::ChatgptSubscription,
                "/v1/responses",
                [("content-encoding", "zstd")],
                "{}".into()
            )
            .is_err()
        );
    }
}
