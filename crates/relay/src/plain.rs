//! The relay's commands as lines of text, for terminals which are not
//! interactive and for people who prefer them.

use std::{
    io::{self, IsTerminal, Write as _},
    process::Command,
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Context, Result, bail, ensure};
use concurro_relay_protocol::{Roots, route::Route};
use tokio::{signal, sync::mpsc};

use crate::{
    codex::DeviceLogin,
    credentials::{self, Credential, Source},
    link::{self, Relay},
    login,
    routes::Served,
    serve::RelayConfig,
    state::{Registration, Store},
    transport::Server,
};

/// Whether the relay can serve `route` with the credential it has: how
/// ready it is, or why it is not.
pub fn readiness(credentials: &Source, route: Route) -> Result<String, String> {
    let credential = credentials.load(route).map_err(|error| format!("{error:#}"))?;
    let left = credential.expiry().and_then(|expiry| expiry.duration_since(SystemTime::now()).ok());
    Ok(left.map_or_else(|| "ready".into(), |left| format!("ready, signed in for another {}", credentials::ago(left))))
}

/// The [`readiness`] of each of `routes`.
pub fn logins(credentials: &Source, routes: &[Route]) -> Vec<(Route, Result<String, String>)> {
    routes.iter().map(|route| (*route, readiness(credentials, *route))).collect()
}

/// The relay registered in `store`, serving real providers with the
/// logins on this machine.
pub fn relay(store: &Store) -> Result<Relay> {
    let (registration, identity) = store.load()?.context("this relay is not registered; run `concurro-relay login`")?;
    let config = RelayConfig {
        served: registration.routes.iter().copied().map(Served::builtin).collect(),
        credentials: Source::Kept(store.clone()),
        roots: Roots::Mozilla,
        parents: Default::default(),
    };
    Ok(Relay { registration, identity, config })
}

/// Checks that `token` can serve as `route`'s credential and keeps it in
/// `store` as the relay's own.
pub fn keep_token(store: &Store, route: Route, token: &str) -> Result<()> {
    let token = token.trim();
    ensure!(credentials::usable(token), "that is not a token: it is empty or has spaces in it");
    store.save_credential(route, &Credential::token(token))
}

/// Reads a line the person types, without showing it if they type it at a
/// terminal.
fn read_secret(prompt: &str) -> Result<String> {
    let hidden = io::stdin().is_terminal();
    print!("{prompt}");
    io::stdout().flush()?;
    // The terminal's own tool turns echo off and back on.
    let echo = |setting: &str| hidden.then(|| Command::new("stty").arg(setting).status());
    echo("-echo");
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line);
    echo("echo");
    println!();
    read?;
    Ok(line)
}

/// Signs in to `route`'s provider at the terminal and keeps the credential
/// in `store` as the relay's own.
pub async fn connect(store: &Store, route: Route) -> Result<()> {
    match route {
        Route::ClaudeSubscription => {
            println!("The relay keeps a Claude token of its own. Run `claude setup-token` in another terminal");
            println!("and paste the token it prints.");
            keep_token(store, route, &read_secret("Token: ")?)?;
        }
        Route::ChatgptSubscription => {
            println!("Signing in to ChatGPT through Codex, in a directory of the relay's own.");
            println!("Your own Codex login is not touched.");
            let login = DeviceLogin::start(None)?;
            // Interrupting the sign-in still removes its directory.
            let credential = tokio::select! {
                credential = login.finished() => credential?,
                _ = signal::ctrl_c() => bail!("the sign-in was interrupted"),
            };
            store.save_credential(route, &credential)?;
        }
    }
    let ready = readiness(&Source::Kept(store.clone()), route).map_err(anyhow::Error::msg)?;
    println!("{}: {ready}", route.label());
    Ok(())
}

/// Registers the relay with `server` for `routes`, signing in to the
/// provider of each which has no credential. If none is named, the routes
/// are those which have a credential already.
pub async fn login(store: &Store, server: Server, name: String, routes: Vec<Route>) -> Result<Registration> {
    let credentials = Source::Kept(store.clone());
    let routes = if routes.is_empty() {
        let (found, missing): (Vec<_>, Vec<_>) = logins(&credentials, &Route::ALL).into_iter().partition(|(_, login)| login.is_ok());
        for (route, _) in &missing {
            println!("{} is not served; name it with --route {route} to serve it.", route.label());
        }
        ensure!(!found.is_empty(), "the relay has no credential for any route; name one with --route to sign in");
        found.into_iter().map(|(route, _)| route).collect()
    } else {
        routes
    };
    for route in &routes {
        if credentials.load(*route).is_err() {
            connect(store, *route).await?;
        }
    }
    let pending = login::begin(server, name, routes).await?;
    println!("To approve this relay, open {}", pending.device.verification_uri);
    println!("and enter the code {}", pending.device.user_code);
    println!("Waiting for approval…");
    let registration = pending.approved(store).await?;
    println!("Registered as {} to {}.", registration.relay, registration.login);
    Ok(registration)
}

/// Serves requests on `links` links until every link has been refused,
/// printing what happens.
pub async fn run(relay: Relay, links: usize) -> Result<()> {
    let registration = &relay.registration;
    println!("Relay {} for {}, serving {}.", registration.relay, registration.login, registration.server.address);
    for (route, login) in logins(&relay.config.credentials, &registration.routes) {
        match login {
            Ok(ready) => println!("{}: {ready}", route.label()),
            Err(reason) => println!("{}: {reason}", route.label()),
        }
    }
    let (events, mut reported) = mpsc::unbounded_channel();
    let running = tokio::spawn(link::run(Arc::new(relay), links, events));
    while let Some(event) = reported.recv().await {
        println!("{event}");
    }
    running.await?;
    anyhow::bail!("Concurro refused this relay")
}

/// Prints the relay's registration and whether each route has a login.
pub fn status(store: &Store) -> Result<()> {
    let Some((registration, _)) = store.load()? else {
        println!("Not registered. Run `concurro-relay login`.");
        return Ok(());
    };
    println!("Relay {} ({}), registered to {}", registration.relay, registration.name, registration.login);
    println!("Concurro at {}", registration.server.address);
    for (route, login) in logins(&Source::Kept(store.clone()), &registration.routes) {
        match login {
            Ok(ready) => println!("{}: {ready}", route.label()),
            Err(reason) => println!("{}: {reason}", route.label()),
        }
    }
    Ok(())
}
