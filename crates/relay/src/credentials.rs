//! The provider credentials the relay uses.
//!
//! The relay keeps a credential of its own for each route, given to it at
//! sign-in, and does not borrow the logins of the providers' own tools: a
//! token from `claude setup-token` for Claude, and for ChatGPT the login
//! Codex's device sign-in produces. A credential is read again for every
//! request, so a renewed one is picked up without restarting the relay,
//! and it is sent nowhere but to the provider.

use std::{
    env, fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use concurro_relay_protocol::route::Route;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::Store;

/// Request header naming the ChatGPT account a token is used for.
pub const CHATGPT_ACCOUNT_HEADER: &str = "chatgpt-account-id";

/// Environment variable in which Claude Code accepts the token its
/// `setup-token` command issues, and the relay does too.
pub const CLAUDE_TOKEN_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// A provider credential as a request uses it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub token: String,
    /// Headers which must accompany the token. Unlike the token they are
    /// revealed to Concurro.
    pub headers: Vec<(String, String)>,
}

/// Shows everything but the token.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("token", &"<hidden>")
            .field("headers", &self.headers)
            .finish()
    }
}

impl Credential {
    /// A credential which is a token alone.
    pub fn token(token: &str) -> Self {
        Self {
            token: token.to_owned(),
            headers: Vec::new(),
        }
    }

    /// When the token says it stops being valid, if it says.
    pub fn expiry(&self) -> Option<SystemTime> {
        let claims = URL_SAFE_NO_PAD.decode(self.token.split('.').nth(1)?).ok()?;
        let expires = serde_json::from_slice::<Value>(&claims).ok()?["exp"].as_u64()?;
        Some(UNIX_EPOCH + Duration::from_secs(expires))
    }
}

/// Where a route's credential comes from.
#[derive(Clone)]
pub enum Source {
    /// The credentials kept in this store.
    Kept(Store),
    /// A fixed credential, for tests.
    Fixed(Credential),
}

impl Source {
    /// The credential for `route` as it is now.
    pub fn load(&self, route: Route) -> Result<Credential> {
        let credential = match (self, route) {
            (Self::Fixed(credential), _) => credential.clone(),
            (Self::Kept(store), Route::ChatgptSubscription) => store
                .credential(route)?
                .context("needs a ChatGPT sign-in")?,
            (Self::Kept(store), Route::ClaudeSubscription) => {
                claude(env::var(CLAUDE_TOKEN_VAR).ok(), || store.credential(route))?
            }
        };
        ensure!(
            usable(&credential.token),
            "the {} credential is not a usable token",
            route.label()
        );
        if let Some(expired) = credential.expiry().and_then(|expiry| expiry.elapsed().ok()) {
            bail!(
                "the {} sign-in expired {} ago; sign in again with `concurro-relay connect {route}`",
                route.label(),
                ago(expired)
            );
        }
        Ok(credential)
    }
}

/// Whether `token` can be hidden in a header value: anything else could
/// reframe the request it is sent in.
pub fn usable(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A length of time as a person reads it.
pub fn ago(elapsed: Duration) -> String {
    match elapsed.as_secs() / 60 {
        minutes @ 0..60 => format!("{minutes}m"),
        minutes @ 60..1440 => format!("{}h {}m", minutes / 60, minutes % 60),
        minutes => format!("{}d", minutes / 1440),
    }
}

/// The relay's Claude credential: the token `from_environment` holds, or
/// else what `kept` finds in the relay's store.
fn claude(
    from_environment: Option<String>,
    kept: impl FnOnce() -> Result<Option<Credential>>,
) -> Result<Credential> {
    match from_environment
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
    {
        Some(token) => Ok(Credential::token(&token)),
        None => kept()?.context("needs a token from `claude setup-token`"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn claude_token_comes_from_the_environment_before_the_store() {
        let kept = || Ok(Some(Credential::token("kept")));
        assert_eq!(claude(None, kept).unwrap().token, "kept");
        assert_eq!(
            claude(Some(" from-env\n".into()), kept).unwrap().token,
            "from-env"
        );
        assert_eq!(claude(Some("  ".into()), kept).unwrap().token, "kept");
        assert!(claude(None, || Ok(None)).is_err());
    }

    #[test]
    fn a_token_which_could_not_be_hidden_in_a_header_is_refused() {
        let fixed = |token: &str| Source::Fixed(Credential::token(token));
        assert!(fixed("plain-token").load(Route::ClaudeSubscription).is_ok());
        assert!(fixed("two words").load(Route::ClaudeSubscription).is_err());
        assert!(
            fixed("line\r\nbreak")
                .load(Route::ClaudeSubscription)
                .is_err()
        );
        assert!(fixed("").load(Route::ClaudeSubscription).is_err());
    }

    /// A token which says it expires `seconds` from now.
    fn expiring(seconds: i64) -> Credential {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = URL_SAFE_NO_PAD.encode(json!({"exp": now + seconds}).to_string());
        Credential::token(&format!("header.{claims}.signature"))
    }

    #[test]
    fn a_token_which_says_it_has_expired_is_not_used() {
        assert!(
            Source::Fixed(expiring(3600))
                .load(Route::ChatgptSubscription)
                .is_ok()
        );
        let expired = Source::Fixed(expiring(-3900))
            .load(Route::ChatgptSubscription)
            .unwrap_err()
            .to_string();
        assert!(
            expired.contains("expired 1h 5m ago")
                && expired.contains("connect chatgpt_subscription"),
            "{expired}"
        );
        assert_eq!(Credential::token("opaque-token").expiry(), None);
    }
}
