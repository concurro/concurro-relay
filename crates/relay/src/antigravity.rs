//! Antigravity account binding using agy's provider-owned login and refresh.

use std::{
    fs,
    process::Stdio,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_protocol::route::Route;
use concurro_relay_provider_protocol::antigravity::USER_AGENT;
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{process::Command, time::timeout};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    credentials::{Credential, usable},
    state::{self, Store},
    transport::Server,
};

/// Subscription identity selected when the Sponsor connects this route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Provider-reported signed-in account identifier.
    pub email: String,
    /// Google subscription routing project, supplied only by Sponsor.
    pub project: String,
}

/// Parse agy's stored OAuth record without retaining its refresh token.
fn parse(raw: &str) -> Result<(Credential, String)> {
    let decoded = match raw.trim().strip_prefix("go-keyring-base64:") {
        Some(encoded) => STANDARD
            .decode(encoded)
            .context("agy login encoding is invalid")?,
        None => raw.as_bytes().to_vec(),
    };
    let record: Value = serde_json::from_slice(&decoded).context("agy login is unreadable")?;
    let token = record["token"]["access_token"]
        .as_str()
        .context("agy login has no access token")?;
    ensure!(usable(token), "agy login has an invalid access token");
    let email = record["id_token_email"]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("agy login has no account identity")?
        .to_owned();
    let expiry = record["token"]["expiry"]
        .as_str()
        .context("agy login has no expiry")?;
    let expires_at = OffsetDateTime::parse(expiry, &Rfc3339)
        .context("agy login expiry is invalid")?
        .unix_timestamp()
        .try_into()
        .context("agy login expiry predates Unix time")?;
    let mut credential = Credential::token(token);
    credential.expires_at = Some(expires_at);
    Ok((credential, email))
}

/// Read the same keyring entry, or file fallback, that agy owns.
fn current() -> Result<(Credential, String)> {
    let raw = match state::provider_secret("gemini", "antigravity")? {
        Some(raw) => raw,
        None => {
            let home = dirs::home_dir().context("home directory unavailable")?;
            fs::read_to_string(home.join(".gemini/antigravity-cli/antigravity-oauth-token"))
                .context("no agy login found; sign in using `agy` first")?
        }
    };
    parse(&raw)
}

/// Ask agy to validate and renew its own login without running inference.
async fn renew() -> Result<()> {
    let status = timeout(
        Duration::from_secs(60),
        Command::new("agy")
            .arg("models")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .context("agy credential refresh timed out")?
    .context("could not run `agy models`; install agy and sign in first")?;
    ensure!(
        status.success(),
        "agy could not refresh its login; run `agy` to sign in again"
    );
    Ok(())
}

/// Whether a provider bearer needs renewal before opening another TLS session.
fn needs_refresh(credential: &Credential) -> bool {
    credential
        .expiry()
        .is_none_or(|expiry| expiry <= SystemTime::now() + Duration::from_secs(60))
}

/// Read a current bearer and reject an account switch after Sponsor onboarding.
pub fn load(store: &Store) -> Result<Credential> {
    let binding = store
        .credential(Route::AntigravitySubscription)?
        .and_then(|credential| credential.antigravity)
        .context(
            "connect the Antigravity route with `concurro-relay connect antigravity_subscription`",
        )?;
    let (mut credential, email) = current()?;
    ensure!(
        email == binding.email,
        "agy's active account changed; reconnect the Antigravity route explicitly"
    );
    credential.antigravity = Some(binding);
    Ok(credential)
}

/// Renew through agy when required, then verify the refreshed account binding.
pub async fn refresh_if_needed(store: &Store) -> Result<()> {
    if needs_refresh(&load(store)?) {
        renew().await?;
        ensure!(
            !needs_refresh(&load(store)?),
            "agy did not provide a current access token"
        );
    }
    Ok(())
}

/// Resolve the subscription routing project from authenticated account metadata.
fn project(metadata: &Value) -> Result<String> {
    let project = &metadata["cloudaicompanionProject"];
    project
        .as_str()
        .or_else(|| project["id"].as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .context("Google returned no Antigravity subscription project")
}

/// Bind the active provider login and its subscription project to Sponsor.
pub async fn connect(store: &Store) -> Result<Credential> {
    renew().await?;
    let (mut credential, email) = current()?;
    ensure!(
        !needs_refresh(&credential),
        "agy did not provide a current access token"
    );
    let host = Route::AntigravitySubscription.host();
    let server = Server {
        address: format!("{host}:443"),
        ca_file: None,
    };
    let metadata = timeout(Duration::from_secs(30), async {
        let stream = server.connect().await?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
        let request = Request::post("/v1internal:loadCodeAssist")
            .header("host", host)
            .header("authorization", format!("Bearer {}", credential.token))
            .header("content-type", "application/json")
            .header("user-agent", USER_AGENT)
            .body(Full::new(Bytes::from(
                json!({"metadata":{"ideType":"ANTIGRAVITY"}}).to_string(),
            )))?;
        let response = sender.send_request(request).await?;
        ensure!(
            response.status().is_success(),
            "Google account lookup returned HTTP {}",
            response.status()
        );
        let bytes = response.into_body().collect().await?.to_bytes();
        serde_json::from_slice::<Value>(&bytes).context("Google account metadata is invalid")
    })
    .await
    .context("Google account lookup timed out")??;
    credential.antigravity = Some(Account {
        email,
        project: project(&metadata)?,
    });
    let mut binding = Credential::token("");
    binding.antigravity = credential.antigravity.clone();
    store.save_credential(Route::AntigravitySubscription, &binding)?;
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// File and go-keyring records yield only a bearer, identity and expiry.
    #[test]
    fn provider_record_formats() {
        let raw = json!({"id_token_email":"sponsor@example.test", "token":{
            "access_token":"opaque-bearer", "refresh_token":"must-not-be-copied", "expiry":"2030-01-01T00:00:00Z"}}).to_string();
        for input in [
            raw.clone(),
            format!("go-keyring-base64:{}", STANDARD.encode(&raw)),
        ] {
            let (credential, email) = parse(&input).unwrap();
            assert_eq!(email, "sponsor@example.test");
            assert_eq!(credential.token, "opaque-bearer");
            assert_eq!(
                credential.expiry(),
                Some(UNIX_EPOCH + Duration::from_secs(1893456000))
            );
            assert!(
                !serde_json::to_string(&credential)
                    .unwrap()
                    .contains("must-not-be-copied")
            );
        }
        assert!(parse("{}").is_err());
        assert!(parse(&raw.replace("opaque-bearer", "invalid token")).is_err());
        assert!(parse(&raw.replace("2030-01-01T00:00:00Z", "invalid")).is_err());
    }

    /// Both metadata representations refer to the provider-selected billing project.
    #[test]
    fn subscription_project_metadata() {
        for value in [
            json!({"cloudaicompanionProject":"project-a"}),
            json!({"cloudaicompanionProject":{"id":"project-a"}}),
        ] {
            assert_eq!(project(&value).unwrap(), "project-a");
        }
        assert!(project(&json!({})).is_err());
        assert!(needs_refresh(&Credential::token("opaque")));
    }
}
