//! Owner API v1 registration, approval and liveness payloads.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Obtain a registration by appending the displayed Sponsor code.
pub const REGISTRATIONS_PREFIX: &str = "/owner/v1/registrations/";
/// Approve a pending Sponsor registration.
pub const APPROVALS_PATH: &str = "/owner/v1/approvals";
/// List the relays for the supplied owner ID.
pub const RELAYS_PATH: &str = "/owner/v1/relays";

/// An unexpired, unapproved registration.
#[derive(Debug, Deserialize, Serialize)]
pub struct Registration {
    /// Device name the Sponsor displayed.
    pub name: String,
    /// Subscription routes in registration order.
    pub routes: Vec<String>,
    /// When the registration code expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Approve every registered route for one owner.
#[derive(Debug, Deserialize, Serialize)]
pub struct Approval {
    /// Sponsor's displayed registration code.
    pub code: String,
    /// Verified owner.
    pub user: User,
    /// Exact record version approved for each registered route.
    pub bindings: Vec<Binding>,
}

/// Verified GitHub identity of a Sponsor's owner.
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    /// Numeric GitHub user ID.
    pub id: u64,
    /// GitHub login shown to the Sponsor.
    pub login: String,
}

/// One relay route and its exact credential version.
#[derive(Debug, Deserialize, Serialize)]
pub struct Binding {
    /// Subscription route in the verifier's registry.
    pub route: String,
    /// Credential entry ID.
    pub entry_id: String,
    /// Immutable credential record ID.
    pub record_id: String,
    /// Credential version.
    pub version: u64,
}

/// The durable result of a successful approval.
#[derive(Debug, Deserialize, Serialize)]
pub struct Approved {
    /// Registered relay identity.
    pub relay_id: String,
}

/// Query parameters for the relay list.
#[derive(Debug, Deserialize, Serialize)]
pub struct RelaysQuery {
    /// Owner whose relays are returned.
    pub user_id: u64,
}

/// Relay availability for one owner.
#[derive(Debug, Deserialize, Serialize)]
pub struct Relays {
    /// Verifier start time. Earlier liveness is unknown.
    #[serde(with = "time::serde::rfc3339")]
    pub started: OffsetDateTime,
    /// Time the pool was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub checked: OffsetDateTime,
    /// Registered relays for the requested user.
    pub relays: Vec<Relay>,
}

/// One registered relay's capacity and activity.
#[derive(Debug, Deserialize, Serialize)]
pub struct Relay {
    /// Registered relay identity.
    pub relay_id: String,
    /// Number of idle links available on the relay.
    pub idle: usize,
    /// Latest observed liveness, or null when unknown.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_seen: Option<OffsetDateTime>,
    /// Active slots, oldest lease first.
    pub active: Vec<ActiveSlot>,
}

/// One retained native session visible to the Sponsor owner.
#[derive(Debug, Deserialize, Serialize)]
pub struct ActiveSlot {
    /// Sponsor link slot.
    pub slot: u32,
    /// Subscription route in use.
    pub route: String,
    /// Entry whose credential version is in use.
    pub entry_id: String,
    /// Approved credential version.
    pub version: u64,
    /// When the link was leased.
    #[serde(with = "time::serde::rfc3339")]
    pub since: OffsetDateTime,
    /// Associated task, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
}

/// Display identity of a task using a relay.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Task {
    /// Repository as owner/name.
    pub repository: String,
    /// Issue number.
    pub issue: u64,
}
