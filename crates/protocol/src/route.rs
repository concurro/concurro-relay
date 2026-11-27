//! The provider routes a relay can serve.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    ClaudeSubscription,
    ChatgptSubscription,
    /// Google Antigravity personal subscription.
    AntigravitySubscription,
}

impl Route {
    pub const ALL: [Self; 3] = [
        Self::ClaudeSubscription,
        Self::ChatgptSubscription,
        Self::AntigravitySubscription,
    ];

    /// The route's name in Concurro's records.
    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeSubscription => "claude_subscription",
            Self::ChatgptSubscription => "chatgpt_subscription",
            Self::AntigravitySubscription => "antigravity_subscription",
        }
    }

    /// The route's name as shown to a person.
    pub fn label(self) -> &'static str {
        match self {
            Self::ClaudeSubscription => "Claude subscription",
            Self::ChatgptSubscription => "ChatGPT subscription",
            Self::AntigravitySubscription => "Antigravity subscription",
        }
    }

    pub fn host(self) -> &'static str {
        match self {
            Self::ClaudeSubscription => "api.anthropic.com",
            Self::ChatgptSubscription => "chatgpt.com",
            Self::AntigravitySubscription => "daily-cloudcode-pa.googleapis.com",
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

impl FromStr for Route {
    type Err = String;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|route| route.id() == id)
            .ok_or_else(|| format!("unknown route: {id}"))
    }
}
