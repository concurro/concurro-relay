//! Signing in to ChatGPT through Codex's own device login.
//!
//! Codex is run with a new directory of its own as its home, so the login
//! the person already has with Codex is left alone. The login it produces
//! is taken from that directory, which is then removed.

use std::{
    ffi::OsStr,
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, ensure};
use concurro_relay_protocol::identity;
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    sync::mpsc::UnboundedSender,
};

use crate::credentials::{CHATGPT_ACCOUNT_HEADER, Credential};

/// The program which signs in.
const CODEX: &str = "codex";

/// A device login which the person has yet to complete.
pub struct DeviceLogin {
    codex: Child,
    /// Codex's home for this login.
    home: PathBuf,
}

/// `line` without the sequences which colour it on a terminal.
fn uncoloured(line: &str) -> String {
    let mut plain = String::new();
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            plain.push(character);
        } else if characters.next() == Some('[') {
            // The sequence ends with its first letter.
            characters.by_ref().find(char::is_ascii_alphabetic);
        }
    }
    plain
}

/// Sends what `printed` carries on `output`, a line at a time.
fn forward(printed: impl AsyncRead + Send + Unpin + 'static, output: UnboundedSender<String>) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(printed).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if output.send(uncoloured(&line)).is_err() {
                return;
            }
        }
    });
}

/// The login Codex keeps in `home` after a sign-in.
fn login(home: &Path) -> Result<Credential> {
    let path = home.join("auth.json");
    let login = fs::read_to_string(&path).context("Codex kept no login")?;
    let login: Value = serde_json::from_str(&login).context("Codex's login is unreadable")?;
    let token = login["tokens"]["access_token"]
        .as_str()
        .context("Codex's login holds no ChatGPT token")?;
    let account = login["tokens"]["account_id"].as_str();
    Ok(Credential {
        token: token.to_owned(),
        expires_at: None,
        antigravity: None,
        headers: account
            .map(|account| (CHATGPT_ACCOUNT_HEADER.to_owned(), account.to_owned()))
            .into_iter()
            .collect(),
    })
}

impl DeviceLogin {
    /// Starts Codex's device login. What Codex prints, which tells the
    /// person where to go and what to enter, is sent a line at a time on
    /// `output`, or goes to the terminal if there is none.
    pub fn start(output: Option<UnboundedSender<String>>) -> Result<Self> {
        Self::start_with(CODEX.as_ref(), output)
    }

    fn start_with(program: &OsStr, output: Option<UnboundedSender<String>>) -> Result<Self> {
        let name: String = identity::random::<8>()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let home = std::env::temp_dir().join(format!("concurro-relay-codex-{name}"));
        DirBuilder::new().mode(0o700).create(&home)?;
        let mut command = Command::new(program);
        command
            // The login is to be in the directory, not in a keyring.
            .args([
                "login",
                "--device-auth",
                "-c",
                "cli_auth_credentials_store=\"file\"",
            ])
            .env("CODEX_HOME", &home)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if output.is_some() {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let started = command
            .spawn()
            .context("could not run `codex`; the ChatGPT route needs Codex installed");
        let mut login = Self {
            codex: started.inspect_err(|_| drop(fs::remove_dir_all(&home)))?,
            home,
        };
        if let Some(output) = output {
            forward(
                login.codex.stdout.take().context("Codex has no output")?,
                output.clone(),
            );
            forward(
                login.codex.stderr.take().context("Codex has no output")?,
                output,
            );
        }
        Ok(login)
    }

    /// Waits for the person to complete the sign-in and returns the login
    /// Codex was given.
    pub async fn finished(mut self) -> Result<Credential> {
        let ended = self.codex.wait().await?;
        ensure!(ended.success(), "Codex did not complete the sign-in");
        login(&self.home)
    }
}

impl Drop for DeviceLogin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

#[cfg(test)]
mod tests {
    use std::{env, os::unix::fs::PermissionsExt};

    use tokio::sync::mpsc;

    use super::*;

    /// A program standing in for Codex, which does what `script` says.
    fn stand_in(name: &str, script: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "concurro-relay-codex-stand-in-{}-{name}",
            std::process::id()
        ));
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[tokio::test]
    async fn device_login_shows_what_codex_prints_and_takes_its_login() {
        let codex = stand_in(
            "signs-in",
            r#"printf 'Open \033[94mhttps://example.test/device\033[0m\n'; echo "asked: $*" >&2
               printf '{"tokens":{"access_token":"tok.en","account_id":"acct"}}' > "$CODEX_HOME/auth.json""#,
        );
        let (output, mut printed) = mpsc::unbounded_channel();
        let login = DeviceLogin::start_with(codex.as_os_str(), Some(output)).unwrap();
        let home = login.home.clone();
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let credential = login.finished().await.unwrap();
        assert_eq!(credential.token, "tok.en");
        assert_eq!(
            credential.headers,
            [(CHATGPT_ACCOUNT_HEADER.to_owned(), "acct".to_owned())]
        );
        assert!(!home.exists(), "the login's directory is removed");

        let mut lines = Vec::new();
        while let Some(line) = printed.recv().await {
            lines.push(line);
        }
        lines.sort();
        assert_eq!(
            lines,
            [
                "Open https://example.test/device",
                "asked: login --device-auth -c cli_auth_credentials_store=\"file\""
            ]
        );
    }

    #[tokio::test]
    async fn a_sign_in_which_fails_or_is_abandoned_leaves_nothing_behind() {
        let failing =
            DeviceLogin::start_with(stand_in("fails", "exit 1").as_os_str(), None).unwrap();
        let home = failing.home.clone();
        assert!(failing.finished().await.is_err());
        assert!(!home.exists());

        // `exec`, so the process killed on drop is the one holding the test's output; a
        // `sleep` forked by the shell would outlive it.
        let abandoned =
            DeviceLogin::start_with(stand_in("waits", "exec sleep 30").as_os_str(), None).unwrap();
        let home = abandoned.home.clone();
        drop(abandoned);
        assert!(!home.exists());

        assert!(DeviceLogin::start_with("/nonexistent/codex".as_ref(), None).is_err());
    }
}
