//! Durable owner-approved relay identities for the hosted verifier.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use concurro_relay_protocol::{
    identity,
    link::{DeviceCode, Registered, Registration},
    route::Route,
};
use concurro_relay_verifier::accept::Registry;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

const CODE_LIFETIME: Duration = Duration::from_secs(600);

/// How large a relay's public key is: an Ed25519 key.
const PUBLIC_KEY_BYTES: usize = 32;

/// How many registrations may wait for approval, and how long a relay's
/// name may be. Each may be set.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Unapproved registrations kept, at least one; a new one evicts the
    /// oldest.
    pub pending: usize,
    /// Bytes of a relay's name.
    pub name_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pending: 1000,
            name_bytes: 256,
        }
    }
}
const CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Exact owner and immutable Vault record approved for one relay key.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Binding {
    /// Owner's verified GitHub user ID.
    pub user_id: u64,
    /// Owner login shown to the Sponsor.
    pub login: String,
    /// Approved provider route.
    pub route: String,
    /// Ordered Vault entry that owns this key.
    pub entry_id: String,
    /// Immutable record identity for this version.
    pub record_id: String,
    /// Vault credential version approved for this key.
    pub version: u64,
}

/// Exact route bindings approved together for one Sponsor registration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
enum Bindings {
    /// The original Claude-only registry record.
    One(Binding),
    /// A route-indexed approval for one registration key.
    Routes(Vec<Binding>),
}

impl Bindings {
    /// Find one exact route without falling back to another provider.
    fn get(&self, route: &str) -> Option<&Binding> {
        match self {
            Self::One(binding) => (binding.route == route).then_some(binding),
            Self::Routes(bindings) => bindings.iter().find(|binding| binding.route == route),
        }
    }

    /// Iterate over the binding set for registration validation.
    fn iter(&self) -> impl Iterator<Item = &Binding> {
        match self {
            Self::One(binding) => std::slice::from_ref(binding).iter(),
            Self::Routes(bindings) => bindings.iter(),
        }
    }
}

/// One pending device-code registration, possibly approved but not yet polled.
#[derive(Clone, Deserialize, Serialize)]
struct Pending {
    /// Sponsor registration awaiting owner approval.
    registration: Registration,
    /// Short code displayed to the owner.
    user_code: String,
    /// Unix expiry for this pending code.
    expires: u64,
    /// Relay identity after owner approval.
    approved: Option<String>,
}

/// Keys and pending approvals. Unapproved registrations are kept in memory
/// only; see [`Persisted`].
#[derive(Clone, Default, Deserialize, Serialize)]
struct State {
    /// Unexpired device-code registrations.
    pending: HashMap<String, Pending>,
    /// Approved public keys and exact Vault bindings.
    approved: HashMap<String, (Vec<u8>, Bindings)>,
    /// Locally quarantined keys whose durable withdrawal needs a retry.
    #[serde(default)]
    blocked: HashSet<String>,
}

/// What of a [`State`] is written: everything but unapproved registrations,
/// which a flood of registrations would otherwise turn into a flood of
/// writes. Read back, it is a `State`.
#[derive(Serialize)]
struct Persisted<'a> {
    pending: HashMap<&'a String, &'a Pending>,
    approved: &'a HashMap<String, (Vec<u8>, Bindings)>,
    blocked: &'a HashSet<String>,
}

impl<'a> From<&'a State> for Persisted<'a> {
    fn from(state: &'a State) -> Self {
        Self {
            pending: state
                .pending
                .iter()
                .filter(|(_, pending)| pending.approved.is_some())
                .collect(),
            approved: &state.approved,
            blocked: &state.blocked,
        }
    }
}

/// Registry whose approval is driven only by the owner-authenticated Vault.
pub struct HostedRegistry {
    file: PathBuf,
    state: Mutex<State>,
    verification_uri: String,
    /// Serializes complete records in the withdrawal journal.
    journal: Mutex<()>,
    withdrawals: Option<UnboundedSender<String>>,
    limits: Limits,
}

impl HostedRegistry {
    /// Open a durable registry file, retaining approved registrations and
    /// the approved codes their relays poll with.
    pub fn open(file: PathBuf, withdrawals: Option<UnboundedSender<String>>) -> Result<Self> {
        let mut state: State = if file.exists() {
            serde_json::from_slice(&fs::read(&file)?)
                .with_context(|| format!("invalid registry {}", file.display()))?
        } else {
            State::default()
        };
        // Unapproved codes live in memory only, even those an older
        // verifier wrote.
        state
            .pending
            .retain(|_, pending| pending.approved.is_some());
        let journal = file.with_extension("withdrawn");
        if journal.exists() {
            let retired = fs::read_to_string(&journal)?;
            ensure!(
                retired.ends_with('\n'),
                "incomplete relay withdrawal journal"
            );
            for relay in retired.lines() {
                ensure!(
                    relay.starts_with("relay-"),
                    "invalid relay withdrawal journal"
                );
                state.approved.remove(relay);
                state
                    .pending
                    .retain(|_, pending| pending.approved.as_deref() != Some(relay));
                state.blocked.remove(relay);
            }
        }
        let pending: Vec<_> = state.blocked.iter().cloned().collect();
        let registry = Self {
            file,
            state: Mutex::new(state),
            verification_uri: "/credentials/relay".into(),
            journal: Mutex::new(()),
            withdrawals,
            limits: Limits::default(),
        };
        for relay in pending {
            if let Err(error) = registry.deregister(&relay) {
                eprintln!("relay withdrawal remains quarantined: {error}");
            }
        }
        Ok(registry)
    }

    /// This registry with `limits` instead of the defaults.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the public owner page printed by Sponsor during registration.
    pub fn with_verification_uri(mut self, uri: String) -> Self {
        self.verification_uri = uri;
        self
    }

    /// Approve a displayed user code for one exact Claude Vault record.
    pub fn approve(&self, code: &str, binding: Binding) -> Result<String> {
        self.approve_set(code, Bindings::One(binding))
    }

    /// Approve every registered route as one indivisible owner decision.
    pub fn approve_routes(&self, code: &str, mut bindings: Vec<Binding>) -> Result<String> {
        bindings.sort_by(|left, right| left.route.cmp(&right.route));
        self.approve_set(code, Bindings::Routes(bindings))
    }

    /// Persist a complete binding set before the Sponsor can poll successfully.
    fn approve_set(&self, code: &str, bindings: Bindings) -> Result<String> {
        let selected: Vec<_> = bindings.iter().collect();
        ensure!(
            !selected.is_empty()
                && selected.len() <= Route::ALL.len()
                && selected.iter().all(|binding| binding.user_id > 0
                    && binding.version > 0
                    && !binding.login.is_empty()
                    && binding.entry_id.len() == 32
                    && binding.record_id.len() == 64)
                && selected
                    .iter()
                    .all(|binding| binding.user_id == selected[0].user_id
                        && binding.login == selected[0].login),
            "invalid relay binding"
        );
        let routes: HashSet<_> = selected
            .iter()
            .map(|binding| binding.route.as_str())
            .collect();
        ensure!(
            routes.len() == selected.len(),
            "duplicate relay route binding"
        );
        let mut current = self.state.lock().expect("registry lock is not poisoned");
        let mut state = current.clone();
        let (registration, existing) = state
            .pending
            .values()
            .find(|pending| {
                pending.user_code == code && (pending.approved.is_some() || pending.expires > now())
            })
            .map(|pending| (pending.registration.clone(), pending.approved.clone()))
            .context("unknown or expired relay code")?;
        let registered: HashSet<_> = registration
            .routes
            .iter()
            .copied()
            .map(vault_route)
            .collect();
        ensure!(
            registered == routes && registered.len() == registration.routes.len(),
            "relay binding routes differ from registration"
        );
        if let Some(relay) = existing {
            ensure!(
                !state.blocked.contains(&relay)
                    && state
                        .approved
                        .get(&relay)
                        .is_some_and(|(_, prior)| *prior == bindings),
                "relay code is already bound"
            );
            return Ok(relay);
        }
        let relay = format!("relay-{}", hex::encode(identity::random::<16>()));
        state
            .approved
            .insert(relay.clone(), (registration.public_key, bindings));
        state
            .pending
            .values_mut()
            .find(|pending| pending.user_code == code)
            .expect("pending registration was just found")
            .approved = Some(relay.clone());
        self.keep(&state)?;
        *current = state;
        Ok(relay)
    }

    /// Return the exact route binding of an approved authenticated relay.
    pub fn binding_for(&self, relay: &str, route: &str) -> Option<Binding> {
        let state = self.state.lock().expect("registry lock is not poisoned");
        state
            .approved
            .get(relay)
            .filter(|_| !state.blocked.contains(relay))
            .and_then(|(_, bindings)| bindings.get(route).cloned())
    }

    /// The device name and exact Vault routes of an unapproved, unexpired code.
    pub fn pending(&self, code: &str) -> Option<PendingCode> {
        let state = self.state.lock().expect("registry lock is not poisoned");
        state
            .pending
            .values()
            .find(|pending| {
                pending.user_code == code && pending.approved.is_none() && pending.expires > now()
            })
            .map(|pending| PendingCode {
                name: pending.registration.name.clone(),
                routes: pending
                    .registration
                    .routes
                    .iter()
                    .copied()
                    .map(vault_route)
                    .collect(),
                expires: pending.expires,
            })
    }

    /// The owner every route binding of an approved, unwithdrawn relay belongs to.
    pub fn owner(&self, relay: &str) -> Option<u64> {
        let state = self.state.lock().expect("registry lock is not poisoned");
        state
            .approved
            .get(relay)
            .filter(|_| !state.blocked.contains(relay))
            .and_then(|(_, bindings)| bindings.iter().next().map(|binding| binding.user_id))
    }

    /// Atomically replace the state file with what of `state` is kept.
    fn keep(&self, state: &State) -> Result<()> {
        let parent = self.file.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let temp = self.file.with_extension("tmp");
        fs::write(&temp, serde_json::to_vec(&Persisted::from(state))?)?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
        fs::File::open(&temp)?.sync_all()?;
        fs::rename(temp, &self.file)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

/// What an owner sees of a pending code before approving it.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct PendingCode {
    /// Name the Sponsor registered, usually its host name.
    pub name: String,
    /// Exact Vault routes the approval must bind, in registration order.
    pub routes: Vec<&'static str>,
    /// Unix expiry of the code.
    pub expires: u64,
}

/// A route's name in Vault records.
fn vault_route(route: Route) -> &'static str {
    match route {
        Route::ClaudeSubscription => "claude-subscription",
        Route::ChatgptSubscription => "chatgpt-subscription",
    }
}

/// Current Unix time for device-code expiry.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes epoch")
        .as_secs()
}

impl Registry for HostedRegistry {
    fn register(&self, registration: Registration) -> Result<DeviceCode, String> {
        if registration.routes.is_empty()
            || registration.routes.len() > Route::ALL.len()
            || registration.routes.iter().collect::<HashSet<_>>().len() != registration.routes.len()
        {
            return Err("invalid relay routes".into());
        }
        if registration.public_key.len() != PUBLIC_KEY_BYTES {
            return Err("invalid relay key".into());
        }
        if registration.name.len() > self.limits.name_bytes {
            return Err(format!(
                "relay name longer than {} bytes",
                self.limits.name_bytes
            ));
        }
        // Held only for memory work: unapproved registrations are not written.
        let mut state = self.state.lock().expect("registry lock is not poisoned");
        state
            .pending
            .retain(|_, pending| pending.approved.is_some() || pending.expires > now());
        // The oldest unapproved codes make room for this one, at once.
        let mut unapproved: Vec<_> = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.approved.is_none())
            .map(|(code, pending)| (pending.expires, code.clone()))
            .collect();
        let excess = (unapproved.len() + 1).saturating_sub(self.limits.pending.max(1));
        if excess > 0 {
            unapproved.sort_unstable();
            for (_, code) in &unapproved[..excess] {
                state.pending.remove(code);
            }
        }
        let device_code = loop {
            let code = hex::encode(identity::random::<16>());
            if !state.pending.contains_key(&code) {
                break code;
            }
        };
        let user_code = loop {
            let letters: Vec<u8> = identity::random::<8>()
                .iter()
                .map(|byte| CODE_LETTERS[*byte as usize % CODE_LETTERS.len()])
                .collect();
            let code = format!(
                "{}-{}",
                String::from_utf8_lossy(&letters[..4]),
                String::from_utf8_lossy(&letters[4..])
            );
            if !state
                .pending
                .values()
                .any(|pending| pending.user_code == code)
            {
                break code;
            }
        };
        state.pending.insert(
            device_code.clone(),
            Pending {
                registration,
                user_code: user_code.clone(),
                expires: now() + CODE_LIFETIME.as_secs(),
                approved: None,
            },
        );
        Ok(DeviceCode {
            device_code,
            user_code,
            verification_uri: self.verification_uri.clone(),
            interval_secs: 1,
            expires_secs: CODE_LIFETIME.as_secs(),
        })
    }

    fn poll(&self, device_code: &str) -> Result<Option<Registered>, String> {
        let state = self.state.lock().expect("registry lock is not poisoned");
        let pending = state.pending.get(device_code).ok_or("unknown relay code")?;
        if pending.expires <= now() && pending.approved.is_none() {
            return Err("expired relay code".into());
        }
        if pending
            .approved
            .as_ref()
            .is_some_and(|relay| state.blocked.contains(relay))
        {
            return Err("relay withdrawal pending".into());
        }
        Ok(pending.approved.as_ref().and_then(|relay| {
            state.approved.get(relay).map(|(_, bindings)| Registered {
                relay: relay.clone(),
                login: bindings
                    .iter()
                    .next()
                    .expect("approved binding set is nonempty")
                    .login
                    .clone(),
            })
        }))
    }

    fn public_key(&self, relay: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("registry lock is not poisoned")
            .approved
            .get(relay)
            .map(|(key, _)| key.clone())
    }

    fn deregister(&self, relay: &str) -> Result<(), String> {
        let primary = {
            let mut state = self.state.lock().expect("registry lock is not poisoned");
            state.blocked.insert(relay.to_owned());
            self.keep(&state)
        };
        if let Some(withdrawals) = &self.withdrawals {
            let _ = withdrawals.send(relay.to_owned());
        }
        let journal = self.file.with_extension("withdrawn");
        let result = (|| -> Result<()> {
            let _guard = self.journal.lock().expect("journal lock is not poisoned");
            let mut log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal)?;
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
            log.write_all(format!("{relay}\n").as_bytes())?;
            log.sync_all()?;
            fs::File::open(journal.parent().unwrap_or(Path::new(".")))?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err(format!(
                "relay withdrawal is pending: {error:#}; registry quarantine: {}",
                primary.map_or_else(|error| format!("failed: {error:#}"), |()| "durable".into())
            ));
        }
        let mut state = self.state.lock().expect("registry lock is not poisoned");
        state.approved.remove(relay);
        state
            .pending
            .retain(|_, pending| pending.approved.as_deref() != Some(relay));
        state.blocked.remove(relay);
        if let Err(error) = self.keep(&state) {
            eprintln!("relay withdrawal journal is durable; registry compaction failed: {error:#}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::*;

    /// One Sponsor code approves both routes together and survives registry reopen.
    #[test]
    fn mixed_routes_require_one_complete_owner_approval() {
        let path = std::env::temp_dir().join(format!(
            "hosted-registry-{}.json",
            hex::encode(identity::random::<8>())
        ));
        let registry = HostedRegistry::open(path.clone(), None)
            .unwrap()
            .with_verification_uri("https://concurro.example/credentials/relay".into());
        let code = registry
            .register(Registration {
                version: 4,
                name: "mixed".into(),
                public_key: vec![2; 32],
                routes: vec![Route::ClaudeSubscription, Route::ChatgptSubscription],
            })
            .unwrap();
        assert_eq!(
            code.verification_uri,
            "https://concurro.example/credentials/relay"
        );
        let claude = Binding {
            user_id: 7,
            login: "owner".into(),
            route: "claude-subscription".into(),
            entry_id: "a".repeat(32),
            record_id: "b".repeat(64),
            version: 1,
        };
        let codex = Binding {
            route: "chatgpt-subscription".into(),
            entry_id: "c".repeat(32),
            record_id: "d".repeat(64),
            ..claude.clone()
        };
        assert!(registry.approve(&code.user_code, claude.clone()).is_err());
        assert!(registry.poll(&code.device_code).unwrap().is_none());
        let pending = registry.pending(&code.user_code).unwrap();
        assert_eq!(
            (pending.name.as_str(), pending.routes.as_slice()),
            (
                "mixed",
                &["claude-subscription", "chatgpt-subscription"][..]
            )
        );
        assert_eq!(registry.pending("BCDF-GHJK"), None);
        let relay = registry
            .approve_routes(&code.user_code, vec![claude.clone(), codex.clone()])
            .unwrap();
        assert_eq!(
            registry.binding_for(&relay, "claude-subscription"),
            Some(claude.clone())
        );
        assert_eq!(
            registry.binding_for(&relay, "chatgpt-subscription"),
            Some(codex.clone())
        );
        // An approved code is no longer offered for lookup; the owner is exact.
        assert_eq!(registry.pending(&code.user_code), None);
        assert_eq!(registry.owner(&relay), Some(7));
        assert_eq!(registry.owner("relay-unknown"), None);
        assert_eq!(
            registry
                .approve_routes(&code.user_code, vec![claude.clone(), codex.clone()])
                .unwrap(),
            relay
        );
        assert_eq!(
            registry
                .approve_routes(&code.user_code, vec![codex.clone(), claude.clone()])
                .unwrap(),
            relay
        );
        drop(registry);
        let reopened = HostedRegistry::open(path.clone(), None).unwrap();
        assert_eq!(
            reopened.poll(&code.device_code).unwrap().unwrap().login,
            "owner"
        );
        assert_eq!(
            reopened.binding_for(&relay, "chatgpt-subscription"),
            Some(codex)
        );
        fs::remove_file(path).unwrap();
    }

    /// Failed writes stay unpublished; approval and withdrawal survive reopen,
    /// but an unapproved registration does not.
    #[test]
    fn registration_reopens_and_requires_owner_approval() {
        let path = std::env::temp_dir().join(format!(
            "hosted-registry-{}.json",
            hex::encode(identity::random::<8>())
        ));
        let registration = Registration {
            version: 4,
            name: "fixture".into(),
            public_key: vec![1; 32],
            routes: vec![Route::ClaudeSubscription],
        };
        let registry = HostedRegistry::open(path.clone(), None).unwrap();
        let code = registry.register(registration.clone()).unwrap();
        assert!(registry.poll(&code.device_code).unwrap().is_none());
        drop(registry);
        // An unapproved registration is not kept across a restart.
        let registry = HostedRegistry::open(path.clone(), None).unwrap();
        assert!(registry.poll(&code.device_code).is_err());
        let code = registry.register(registration.clone()).unwrap();
        let binding = Binding {
            user_id: 7,
            login: "owner".into(),
            route: "claude-subscription".into(),
            entry_id: "a".repeat(32),
            record_id: "b".repeat(64),
            version: 3,
        };
        let blocked = path.with_extension("tmp");
        fs::create_dir(&blocked).unwrap();
        assert!(registry.approve(&code.user_code, binding.clone()).is_err());
        assert!(registry.poll(&code.device_code).unwrap().is_none());
        fs::remove_dir(&blocked).unwrap();
        let relay = registry.approve(&code.user_code, binding.clone()).unwrap();
        assert_eq!(
            registry.binding_for(&relay, "claude-subscription"),
            Some(binding.clone())
        );
        assert_eq!(
            registry.poll(&code.device_code).unwrap().unwrap().login,
            "owner"
        );
        {
            let mut state = registry.state.lock().unwrap();
            state.pending.get_mut(&code.device_code).unwrap().expires = now() - 1;
            registry.keep(&state).unwrap();
        }
        drop(registry);
        let (withdrawals, mut received) = mpsc::unbounded_channel();
        let reopened = HostedRegistry::open(path.clone(), Some(withdrawals)).unwrap();
        assert_eq!(
            reopened.binding_for(&relay, "claude-subscription"),
            Some(binding.clone())
        );
        assert_eq!(reopened.approve(&code.user_code, binding).unwrap(), relay);
        let expired = reopened.register(registration.clone()).unwrap();
        {
            let mut state = reopened.state.lock().unwrap();
            state.pending.get_mut(&expired.device_code).unwrap().expires = now() - 1;
        }
        reopened.register(registration).unwrap();
        assert_eq!(reopened.pending(&expired.user_code), None);
        assert!(
            reopened
                .approve(
                    &expired.user_code,
                    Binding {
                        user_id: 7,
                        login: "owner".into(),
                        route: "claude-subscription".into(),
                        entry_id: "a".repeat(32),
                        record_id: "b".repeat(64),
                        version: 4,
                    }
                )
                .is_err()
        );
        let journal = path.with_extension("withdrawn");
        fs::create_dir(&journal).unwrap();
        assert_eq!(reopened.owner(&relay), Some(7));
        assert!(reopened.deregister(&relay).is_err());
        assert_eq!(received.try_recv().unwrap(), relay);
        assert_eq!(reopened.owner(&relay), None);
        assert_eq!(reopened.binding_for(&relay, "claude-subscription"), None);
        assert!(reopened.public_key(&relay).is_some());
        assert!(HostedRegistry::open(path.clone(), None).is_err());
        fs::remove_dir(&journal).unwrap();
        drop(reopened);
        let reopened = HostedRegistry::open(path.clone(), None).unwrap();
        assert_eq!(reopened.binding_for(&relay, "claude-subscription"), None);
        assert!(reopened.public_key(&relay).is_none());
        fs::remove_file(path).unwrap();
        fs::remove_file(journal).unwrap();
    }

    /// Concurrent withdrawals remain complete when only the journal can persist.
    #[test]
    fn concurrent_withdrawals_reopen_without_json_compaction() {
        let path = std::env::temp_dir().join(format!(
            "hosted-registry-{}.json",
            hex::encode(identity::random::<8>())
        ));
        let registry = Arc::new(HostedRegistry::open(path.clone(), None).unwrap());
        let mut relays = Vec::new();
        for version in 1..=2 {
            let code = registry
                .register(Registration {
                    version: 4,
                    name: "fixture".into(),
                    public_key: vec![version as u8; 32],
                    routes: vec![Route::ClaudeSubscription],
                })
                .unwrap();
            relays.push(
                registry
                    .approve(
                        &code.user_code,
                        Binding {
                            user_id: 7,
                            login: "owner".into(),
                            route: "claude-subscription".into(),
                            entry_id: "a".repeat(32),
                            record_id: format!("{version:064x}"),
                            version,
                        },
                    )
                    .unwrap(),
            );
        }
        let blocked = path.with_extension("tmp");
        fs::create_dir(&blocked).unwrap();
        let workers: Vec<_> = relays
            .iter()
            .map(|relay| {
                let registry = registry.clone();
                let relay = relay.clone();
                std::thread::spawn(move || registry.deregister(&relay))
            })
            .collect();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        fs::remove_dir(blocked).unwrap();
        drop(registry);
        let reopened = HostedRegistry::open(path.clone(), None).unwrap();
        for relay in &relays {
            assert_eq!(reopened.binding_for(relay, "claude-subscription"), None);
            assert_eq!(reopened.public_key(relay), None);
        }
        let journal = path.with_extension("withdrawn");
        let records = fs::read_to_string(&journal).unwrap();
        assert_eq!(
            records.lines().collect::<HashSet<_>>(),
            relays.iter().map(String::as_str).collect()
        );
        fs::remove_file(path).unwrap();
        fs::remove_file(journal).unwrap();
    }

    /// Registrations need a valid key and a short name, and at most the
    /// configured number wait, the oldest giving way; none is written.
    #[test]
    fn registrations_are_bounded_and_unwritten() {
        let path = std::env::temp_dir().join(format!(
            "hosted-registry-{}.json",
            hex::encode(identity::random::<8>())
        ));
        let registry = HostedRegistry::open(path.clone(), None)
            .unwrap()
            .with_limits(Limits {
                pending: 2,
                name_bytes: 8,
            });
        let registration = |name: &str, key: usize| Registration {
            version: 5,
            name: name.into(),
            public_key: vec![1; key],
            routes: vec![Route::ClaudeSubscription],
        };
        assert!(registry.register(registration("laptop", 65)).is_err());
        assert!(registry.register(registration("a-long-name", 32)).is_err());
        let first = registry.register(registration("laptop", 32)).unwrap();
        let second = registry.register(registration("laptop", 32)).unwrap();
        // The first is the oldest.
        registry
            .state
            .lock()
            .unwrap()
            .pending
            .get_mut(&first.device_code)
            .unwrap()
            .expires -= 1;
        let third = registry.register(registration("laptop", 32)).unwrap();
        let codes = [first, second, third];
        assert!(registry.poll(&codes[0].device_code).is_err());
        assert!(registry.poll(&codes[1].device_code).unwrap().is_none());
        assert!(registry.poll(&codes[2].device_code).unwrap().is_none());
        assert!(!path.exists());
    }

    /// Unapproved codes an older verifier wrote are dropped on load, and a
    /// registration beyond the limit evicts all the excess at once.
    #[test]
    fn stale_codes_are_dropped_and_excess_evicted() {
        let path = std::env::temp_dir().join(format!(
            "hosted-registry-{}.json",
            hex::encode(identity::random::<8>())
        ));
        let registration = Registration {
            version: 5,
            name: "laptop".into(),
            public_key: vec![1; 32],
            routes: vec![Route::ClaudeSubscription],
        };
        let mut state = State::default();
        for at in 0..5 {
            state.pending.insert(
                format!("code-{at}"),
                Pending {
                    registration: registration.clone(),
                    user_code: format!("CODE-{at:04}"),
                    expires: now() + 600,
                    approved: None,
                },
            );
        }
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let registry = HostedRegistry::open(path.clone(), None).unwrap();
        assert!(registry.state.lock().unwrap().pending.is_empty());
        {
            let mut current = registry.state.lock().unwrap();
            *current = state;
        }
        let registry = registry.with_limits(Limits {
            pending: 2,
            name_bytes: 256,
        });
        let code = registry.register(registration).unwrap();
        let pending = &registry.state.lock().unwrap().pending;
        assert_eq!(pending.len(), 2);
        assert!(pending.contains_key(&code.device_code));
        fs::remove_file(path).unwrap();
    }
}
