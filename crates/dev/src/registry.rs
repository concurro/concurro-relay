//! A registry which approves every registration by itself, in place of a
//! person approving it in Concurro's portal. It can keep its relays in a
//! file, so that they stay registered when the verifier is started again.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use concurro_relay_protocol::{
    identity,
    link::{DeviceCode, Registered, Registration},
};
use concurro_relay_verifier::accept::Registry;

/// How long a registration may wait for approval.
const CODE_LIFETIME: Duration = Duration::from_secs(600);

/// Letters a user code is made of, without those easily confused.
const CODE_LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

#[derive(Default)]
struct Relays {
    /// Registrations awaiting approval, by device code, with when each was
    /// made.
    pending: HashMap<String, (Registration, Instant)>,
    /// Public keys of registered relays, by relay.
    registered: HashMap<String, Vec<u8>>,
}

pub struct DevRegistry {
    /// The account every relay is registered to.
    login: String,
    /// How long a registration waits before it counts as approved.
    approve_after: Duration,
    /// Where the registered relays are kept, if anywhere.
    file: Option<PathBuf>,
    relays: Mutex<Relays>,
}

impl DevRegistry {
    /// A registry which registers every relay to `login` once it has
    /// waited `approve_after`, starting with the relays kept in `file`.
    pub fn new(login: String, approve_after: Duration, file: Option<PathBuf>) -> Result<Self> {
        let registered = match file.as_ref().filter(|file| file.exists()) {
            Some(file) => serde_json::from_slice(&fs::read(file)?).with_context(|| format!("{} is unreadable", file.display()))?,
            None => HashMap::new(),
        };
        Ok(Self { login, approve_after, file, relays: Mutex::new(Relays { pending: HashMap::new(), registered }) })
    }

    /// Writes the registered relays to the file they are kept in.
    fn keep(&self, relays: &Relays) {
        if let Some(file) = &self.file {
            let kept = serde_json::to_vec(&relays.registered).expect("relays serialize");
            if let Err(error) = fs::write(file, kept) {
                eprintln!("could not keep the registered relays in {}: {error}", file.display());
            }
        }
    }

    /// How many relays are registered.
    pub fn registered(&self) -> usize {
        self.relays.lock().expect("lock is not poisoned").registered.len()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Registry for DevRegistry {
    fn register(&self, registration: Registration) -> Result<DeviceCode, String> {
        let device_code = hex(&identity::random::<16>());
        let letters: Vec<u8> = identity::random::<8>().iter().map(|byte| CODE_LETTERS[*byte as usize % CODE_LETTERS.len()]).collect();
        let user_code = format!("{}-{}", String::from_utf8_lossy(&letters[..4]), String::from_utf8_lossy(&letters[4..]));
        let mut relays = self.relays.lock().expect("lock is not poisoned");
        relays.pending.insert(device_code.clone(), (registration, Instant::now()));
        Ok(DeviceCode {
            device_code,
            user_code,
            verification_uri: "the dev verifier, which approves by itself".into(),
            interval_secs: 1,
            expires_secs: CODE_LIFETIME.as_secs(),
        })
    }

    fn poll(&self, device_code: &str) -> Result<Option<Registered>, String> {
        let mut relays = self.relays.lock().expect("lock is not poisoned");
        let (_, made) = relays.pending.get(device_code).ok_or("unknown or expired code")?;
        if made.elapsed() < self.approve_after {
            return Ok(None);
        }
        let (registration, _) = relays.pending.remove(device_code).expect("the code was just found");
        let relay = format!("relay-{}", hex(&identity::random::<4>()));
        relays.registered.insert(relay.clone(), registration.public_key);
        self.keep(&relays);
        Ok(Some(Registered { relay, login: self.login.clone() }))
    }

    fn public_key(&self, relay: &str) -> Option<Vec<u8>> {
        self.relays.lock().expect("lock is not poisoned").registered.get(relay).cloned()
    }

    fn deregister(&self, relay: &str) {
        let mut relays = self.relays.lock().expect("lock is not poisoned");
        relays.registered.remove(relay);
        self.keep(&relays);
    }
}
