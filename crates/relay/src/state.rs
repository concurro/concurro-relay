//! What the relay keeps between runs: its registration, its key, and the
//! provider credentials it was given.

use std::{
    env, fs,
    io::{self, Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use concurro_relay_protocol::{identity::Identity, route::Route};
use serde::{Deserialize, Serialize};

use crate::{credentials::Credential, transport::Server};

/// Environment variable naming the directory the relay keeps its state in.
pub const HOME_VAR: &str = "CONCURRO_RELAY_HOME";

/// A relay's registration with Concurro.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Registration {
    pub server: Server,
    /// Concurro's name for this relay.
    pub relay: String,
    /// The account the relay is registered to.
    pub login: String,
    /// The name the relay registered under.
    pub name: String,
    pub routes: Vec<Route>,
}

/// The system's tool for the macOS keychain, and the service the relay's
/// credentials are kept under there.
const KEYCHAIN_TOOL: &str = "/usr/bin/security";
const KEYCHAIN_SERVICE: &str = "concurro-relay";

/// Longest the keychain tool may take, which allows for a person
/// unlocking the keychain.
const KEYCHAIN_LIMIT: Duration = Duration::from_secs(30);

/// Runs the keychain tool with `arguments` and `input`, returning what it
/// printed if it succeeded.
fn keychain(arguments: &[&str], input: &str) -> Result<Option<String>> {
    secret_tool(KEYCHAIN_TOOL, arguments, input)
}

/// Run a platform credential tool with the same bounded lifetime as relay keychain access.
fn secret_tool(program: &str, arguments: &[&str], input: &str) -> Result<Option<String>> {
    let mut tool = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    tool.stdin
        .take()
        .context("the keychain tool has no input")?
        .write_all(input.as_bytes())?;
    let deadline = Instant::now() + KEYCHAIN_LIMIT;
    let status = loop {
        if let Some(status) = tool.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = tool.kill();
            let _ = tool.wait();
            bail!("the keychain did not answer");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut printed = String::new();
    tool.stdout
        .take()
        .context("the keychain tool has no output")?
        .read_to_string(&mut printed)?;
    Ok(status.success().then_some(printed))
}

/// Read a provider-owned secret; no write or delete is performed on that store.
pub fn provider_secret(service: &str, account: &str) -> Result<Option<String>> {
    let result = if cfg!(target_os = "macos") {
        keychain(
            &["find-generic-password", "-s", service, "-a", account, "-w"],
            "",
        )
    } else {
        secret_tool(
            "secret-tool",
            &["lookup", "service", service, "username", account],
            "",
        )
    };
    match result {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        other => other,
    }
}

/// The directory holding the relay's state.
#[derive(Clone, Debug)]
pub struct Store {
    directory: PathBuf,
    /// Whether provider credentials are kept in the macOS keychain, not
    /// in files only the owner can read.
    keychain: bool,
}

/// Writes `secret` to a new file at `path` which only the owner can read.
fn write_private(path: &Path, secret: &[u8]) -> Result<()> {
    let _ = fs::remove_file(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok(file.write_all(secret)?)
}

fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

impl Store {
    /// The store at `directory`, or else where [`HOME_VAR`] or the
    /// platform's configuration directory puts it.
    pub fn open(directory: Option<PathBuf>) -> Result<Self> {
        let directory = match directory.or_else(|| env::var_os(HOME_VAR).map(PathBuf::from)) {
            Some(directory) => directory,
            None => dirs::config_dir()
                .context("no configuration directory")?
                .join("concurro-relay"),
        };
        Ok(Self {
            directory,
            keychain: cfg!(target_os = "macos"),
        })
    }

    /// Creates the directory, which only the owner can enter.
    fn prepare(&self) -> Result<()> {
        fs::create_dir_all(&self.directory)?;
        Ok(fs::set_permissions(
            &self.directory,
            fs::Permissions::from_mode(0o700),
        )?)
    }

    fn registration(&self) -> PathBuf {
        self.directory.join("relay.json")
    }

    fn key(&self) -> PathBuf {
        self.directory.join("relay.key")
    }

    /// The registration and key saved by [`Self::save`], if any.
    pub fn load(&self) -> Result<Option<(Registration, Identity)>> {
        let registration = match fs::read(self.registration()) {
            Ok(registration) => registration,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("could not read the relay's registration"),
        };
        let registration = serde_json::from_slice(&registration)
            .context("the relay's registration is unreadable")?;
        let key = fs::read(self.key()).context("could not read the relay's key")?;
        Ok(Some((registration, Identity::from_pkcs8(&key)?)))
    }

    /// Saves a registration and the PKCS #8 private key it was made with.
    /// Only the owner can read the key.
    pub fn save(&self, registration: &Registration, private_key: &[u8]) -> Result<()> {
        self.prepare()?;
        write_private(&self.key(), private_key)?;
        fs::write(
            self.registration(),
            serde_json::to_vec_pretty(registration)?,
        )?;
        Ok(())
    }

    /// Removes the registration, the key and every provider credential.
    pub fn clear(&self) -> Result<()> {
        remove(&self.registration())?;
        remove(&self.key())?;
        Route::ALL
            .into_iter()
            .try_for_each(|route| self.remove_credential(route))
    }

    fn credential_file(&self, route: Route) -> PathBuf {
        self.directory.join(format!("{}.credential", route.id()))
    }

    /// The keychain account for `route`'s credential, which is particular
    /// to this store and has no character the keychain tool gives a
    /// meaning.
    fn keychain_account(&self, route: Route) -> String {
        let directory: String = self
            .directory
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{}:{directory}", route.id())
    }

    /// Keeps `credential` as the relay's own for `route`: in the keychain
    /// on macOS, elsewhere in a file only the owner can read.
    pub fn save_credential(&self, route: Route, credential: &Credential) -> Result<()> {
        // Encoded, it has no character which would end a quoted argument.
        let kept = STANDARD.encode(serde_json::to_vec(credential)?);
        if !self.keychain {
            self.prepare()?;
            return write_private(&self.credential_file(route), kept.as_bytes());
        }
        // The tool reads the command from its input, so the credential is
        // never an argument other processes can see.
        let command = format!(
            "add-generic-password -U -s {KEYCHAIN_SERVICE} -a \"{}\" -l \"Concurro relay: {} credential\" -w \"{kept}\"\n",
            self.keychain_account(route),
            route.label(),
        );
        keychain(&["-i"], &command)?;
        ensure!(
            self.credential(route)?.as_ref() == Some(credential),
            "the keychain did not keep the credential"
        );
        Ok(())
    }

    /// The credential kept by [`Self::save_credential`] for `route`, if
    /// any.
    pub fn credential(&self, route: Route) -> Result<Option<Credential>> {
        let kept = if self.keychain {
            keychain(
                &[
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    &self.keychain_account(route),
                    "-w",
                ],
                "",
            )?
        } else {
            match fs::read_to_string(self.credential_file(route)) {
                Ok(kept) => Some(kept),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error).context("could not read the relay's credential"),
            }
        };
        let Some(kept) = kept else { return Ok(None) };
        let kept = kept.trim();
        let credential = STANDARD
            .decode(kept)
            .ok()
            .and_then(|credential| serde_json::from_slice(&credential).ok());
        // The first version of the relay kept a bare token.
        Ok(Some(credential.unwrap_or_else(|| Credential::token(kept))))
    }

    /// Removes the credential kept for `route`, if any.
    pub fn remove_credential(&self, route: Route) -> Result<()> {
        if !self.keychain {
            return remove(&self.credential_file(route));
        }
        // The tool fails if there is nothing to remove, which is as well.
        keychain(
            &[
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                &self.keychain_account(route),
            ],
            "",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store which keeps tokens in files whatever the platform, so that
    /// tests leave the keychain alone.
    fn store(name: &str) -> Store {
        let directory = env::temp_dir().join(format!(
            "concurro-relay-state-{}-{name}",
            std::process::id()
        ));
        Store {
            keychain: false,
            ..Store::open(Some(directory)).unwrap()
        }
    }

    #[test]
    fn a_credential_is_kept_per_route_and_removed_with_the_registration() {
        let store = store("credentials");
        let route = Route::ChatgptSubscription;
        assert_eq!(store.credential(route).unwrap(), None);
        store
            .save_credential(route, &Credential::token("first"))
            .unwrap();
        let credential = Credential {
            expires_at: None,
            antigravity: None,
            token: "to.k\"en".into(),
            headers: vec![("account".into(), "a b".into())],
        };
        store.save_credential(route, &credential).unwrap();
        assert_eq!(store.credential(route).unwrap(), Some(credential));
        assert_eq!(store.credential(Route::ClaudeSubscription).unwrap(), None);
        assert_eq!(
            fs::metadata(store.credential_file(route))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // A bare token, as the first version kept one.
        fs::write(
            store.credential_file(Route::ClaudeSubscription),
            "sk-ant-oat01-bare_token\n",
        )
        .unwrap();
        assert_eq!(
            store.credential(Route::ClaudeSubscription).unwrap(),
            Some(Credential::token("sk-ant-oat01-bare_token"))
        );

        store.clear().unwrap();
        assert_eq!(store.credential(route).unwrap(), None);
        assert_eq!(store.credential(Route::ClaudeSubscription).unwrap(), None);
    }

    #[test]
    fn keychain_accounts_differ_by_route_and_store() {
        let (one, other) = (store("account-one"), store("account-other"));
        let account = one.keychain_account(Route::ClaudeSubscription);
        assert_ne!(account, one.keychain_account(Route::ChatgptSubscription));
        assert_ne!(account, other.keychain_account(Route::ClaudeSubscription));
        assert!(
            account
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:".contains(&byte)),
            "{account}"
        );
    }

    #[test]
    fn registration_and_key_survive_a_save_and_are_private() {
        let store = store("registration");
        assert!(store.load().unwrap().is_none());

        let (identity, private_key) = Identity::generate().unwrap();
        let registration = Registration {
            server: Server {
                address: "localhost:7443".into(),
                ca_file: None,
            },
            relay: "relay-1".into(),
            login: "octocat".into(),
            name: "laptop".into(),
            routes: vec![Route::ChatgptSubscription],
        };
        store.save(&registration, &private_key).unwrap();
        let (loaded, key) = store.load().unwrap().unwrap();
        assert_eq!(loaded, registration);
        assert_eq!(key.public_key(), identity.public_key());
        assert_eq!(
            fs::metadata(store.key()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
