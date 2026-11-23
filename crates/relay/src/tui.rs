//! The relay as a full-screen view: it signs in if the relay is not
//! registered, then serves and shows what it is doing.

use std::{
    cell::Cell,
    collections::VecDeque,
    mem,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use concurro_relay_native::{NativeLimits, NativeRequest};
use concurro_relay_protocol::{link::DeviceCode, route::Route};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event as Input, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::Stylize,
    text::{Line, Span},
    widgets::{Block, BorderType, Padding, Paragraph, Wrap},
};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::JoinHandle,
    time,
};

use crate::{
    codex::DeviceLogin,
    credentials::Source,
    events::{self, Event, LinkState},
    link,
    login::{self, Pending},
    plain,
    review::{ANSWER_LIMIT, Reviewer},
    state::{Registration, Store},
    transcript,
    transport::Server,
};

/// How often the view redraws with nothing happening.
const TICK: Duration = Duration::from_millis(120);

/// How many ticks pass between looks at the provider logins.
const LOGIN_CHECK_TICKS: usize = 40;

/// How many activity entries are kept, and how many of the newest keep
/// what their exchange said.
const ACTIVITY_KEPT: usize = 500;
const TEXT_KEPT: usize = 50;

/// The most lines of an exchange's text which are shown.
const TEXT_LINES_SHOWN: usize = 2000;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A route the person can choose to serve.
struct Choice {
    route: Route,
    selected: bool,
    /// How ready the relay is to serve it, or why it is not.
    login: Result<String, String>,
}

/// What the person enters to sign in.
struct Setup {
    address: String,
    ca_file: Option<PathBuf>,
    choices: Vec<Choice>,
    /// The field with the cursor: 0 is the address, then the routes.
    focus: usize,
    /// Why the last attempt failed.
    error: Option<String>,
    /// Whether Concurro is being asked for a code.
    asking: bool,
}

impl Setup {
    fn new(server: Option<Server>, credentials: &Source) -> Self {
        let choices = plain::logins(credentials, &Route::ALL)
            .into_iter()
            .map(|(route, login)| Choice {
                route,
                selected: login.is_ok(),
                login,
            })
            .collect();
        let (address, ca_file) =
            server.map_or_else(Default::default, |server| (server.address, server.ca_file));
        Self {
            address,
            ca_file,
            choices,
            focus: 0,
            error: None,
            asking: false,
        }
    }

    fn selected(&self) -> Vec<Route> {
        self.choices
            .iter()
            .filter(|choice| choice.selected)
            .map(|choice| choice.route)
            .collect()
    }

    /// The first chosen route the relay has no credential for.
    fn missing(&self) -> Option<Route> {
        self.choices
            .iter()
            .find(|choice| choice.selected && choice.login.is_err())
            .map(|choice| choice.route)
    }

    /// Looks again for each route's credential.
    fn refresh(&mut self, credentials: &Source) {
        for choice in &mut self.choices {
            choice.login = plain::readiness(credentials, choice.route);
        }
    }
}

/// The token the person is pasting for a route which needs one.
#[derive(Default)]
struct TokenEntry {
    token: String,
    error: Option<String>,
}

/// Codex signing in to ChatGPT for the relay.
struct CodexLogin {
    /// What Codex has printed.
    said: Vec<String>,
    signing_in: JoinHandle<()>,
}

/// A registration waiting for the person's approval.
struct Approval {
    device: DeviceCode,
    since: Instant,
    waiting: JoinHandle<()>,
}

/// Which half of an exchange an open entry shows.
#[derive(Clone, Copy, PartialEq)]
enum Side {
    Request,
    Response,
}

/// Something which happened, as the activity list shows it.
struct Entry {
    at: Instant,
    event: Event,
    /// What the request and the response said, if this is an exchange and
    /// that is still kept.
    said: Option<(String, String)>,
    open: bool,
    side: Side,
}

/// A request waiting for the Sponsor's decision.
struct Waiting {
    ticket: u64,
    link: usize,
    request: NativeRequest,
    since: Instant,
}

/// A registered relay at work.
struct Dashboard {
    registration: Registration,
    reviewer: Arc<Reviewer>,
    /// Requests waiting for the Sponsor, oldest first.
    waiting: VecDeque<Waiting>,
    logins: Vec<(Route, Result<String, String>)>,
    links: Vec<LinkState>,
    /// What happened, oldest first.
    activity: VecDeque<Entry>,
    /// The entry the cursor is on.
    selected: usize,
    /// Whether the cursor stays on the newest entry as entries arrive. It
    /// never moves onto a waiting request by itself.
    following: bool,
    /// The waiting request the Sponsor moved the cursor to, which alone an
    /// answer is for.
    chosen: Option<u64>,
    /// The first activity line shown and how many fit, as last drawn.
    top: Cell<usize>,
    page: Cell<usize>,
    /// Whether the person has moved the view away from the cursor.
    paged: bool,
    /// Requests proved, per route in `logins`' order.
    proved: Vec<usize>,
    upload: u64,
    since: Instant,
}

impl Dashboard {
    fn new(
        registration: Registration,
        credentials: &Source,
        links: usize,
        reviewer: Arc<Reviewer>,
    ) -> Self {
        let logins = plain::logins(credentials, &registration.routes);
        Self {
            proved: vec![0; logins.len()],
            logins,
            registration,
            reviewer,
            waiting: VecDeque::new(),
            links: vec![LinkState::Connecting; links],
            activity: VecDeque::new(),
            selected: 0,
            following: true,
            chosen: None,
            top: Cell::new(0),
            page: Cell::new(1),
            paged: false,
            upload: 0,
            since: Instant::now(),
        }
    }

    fn apply(&mut self, mut event: Event) {
        // The cursor stays on a waiting request, so that what is answered
        // is what was read.
        let pinned = self.answering().is_some();
        let mut said = None;
        let mut open = false;
        match &mut event {
            Event::Link { link, state } => {
                if let Some(shown) = self.links.get_mut(*link - 1) {
                    *shown = state.clone();
                }
                // Coming up is shown by the link itself.
                if matches!(state, LinkState::Connecting | LinkState::Up) {
                    return;
                }
            }
            Event::Proved { exchange, .. } => {
                self.upload += exchange.upload;
                if let Some(at) = self
                    .logins
                    .iter()
                    .position(|(route, _)| *route == exchange.route)
                {
                    self.proved[at] += 1;
                }
                let (request, response) = (
                    mem::take(&mut exchange.request),
                    mem::take(&mut exchange.response),
                );
                said = Some((
                    transcript::request_text(&request),
                    transcript::response_text(&response),
                ));
            }
            Event::Asked {
                link,
                ticket,
                request,
                ..
            } => {
                self.waiting.push_back(Waiting {
                    ticket: *ticket,
                    link: *link,
                    request: NativeRequest {
                        prompt: String::new(),
                        ..request.clone()
                    },
                    since: Instant::now(),
                });
                said = Some((
                    events::request_text(request),
                    "Waiting for your review.".into(),
                ));
                request.prompt = String::new();
                open = true;
            }
            Event::Reviewed {
                request, decision, ..
            } => {
                self.waiting
                    .retain(|waiting| !same(&waiting.request, request));
                let asked = self
                    .activity
                    .iter()
                    .rev()
                    .find_map(|entry| match &entry.event {
                        Event::Asked {
                            ticket,
                            request: asked,
                            ..
                        } if same(asked, request) => Some(*ticket),
                        _ => None,
                    });
                if let Some(ticket) = asked {
                    self.settle(ticket, decision.to_string());
                }
                said = Some((events::request_text(request), decision.to_string()));
                request.prompt = String::new();
            }
            // Usage is reported once a request was sent and answered. It
            // belongs to the request's entry while that keeps its text.
            Event::NativeAudit { route, audit, .. } => {
                if let Some(at) = self.logins.iter().position(|(served, _)| served == route) {
                    self.proved[at] += 1;
                }
                let reviewed =
                    self.activity
                        .iter_mut()
                        .rev()
                        .find_map(|entry| match &entry.event {
                            Event::Reviewed {
                                request, decision, ..
                            } if request.session_id == audit.session_id
                                && request.request == audit.request =>
                            {
                                Some((decision.to_string(), &mut entry.said))
                            }
                            _ => None,
                        });
                if let Some((decision, Some((_, response)))) = reviewed {
                    *response = format!(
                        "{decision}\nConcurro-reported provider usage: {}",
                        events::usage(audit)
                    );
                    return;
                }
            }
            Event::Refused { .. } => {}
        }
        self.activity.push_back(Entry {
            at: Instant::now(),
            event,
            said,
            open,
            side: Side::Request,
        });
        let waiting = &self.waiting;
        // A request still waiting for the Sponsor keeps its entry and text.
        let waits = |entry: &Entry| {
            matches!(entry.event, Event::Asked { ticket, .. }
                if waiting.iter().any(|waiting| waiting.ticket == ticket))
        };
        // Nor is the entry under the cursor evicted, which would move the
        // cursor.
        let selected = self.selected;
        if self.activity.len() > ACTIVITY_KEPT
            && let Some(oldest) = self
                .activity
                .iter()
                .enumerate()
                .position(|(at, entry)| at != selected && !waits(entry))
        {
            self.activity.remove(oldest);
            if oldest < self.selected {
                self.selected -= 1;
            }
        }
        let outdated = self.activity.len().checked_sub(TEXT_KEPT + 1);
        if let Some(entry) = outdated
            .and_then(|at| self.activity.get_mut(at))
            .filter(|entry| !waits(entry))
        {
            entry.said = None;
            entry.open = false;
        }
        let newest = self.activity.iter().rposition(|entry| !waits(entry));
        if let (true, false, Some(newest)) = (self.following, pinned, newest) {
            self.selected = newest;
        }
    }

    /// Which waiting request an answer is for: the one the Sponsor moved the
    /// cursor to and which is still under it.
    fn answering(&self) -> Option<usize> {
        let Some(Event::Asked { ticket, .. }) =
            self.activity.get(self.selected).map(|entry| &entry.event)
        else {
            return None;
        };
        if self.chosen != Some(*ticket) {
            return None;
        }
        self.waiting
            .iter()
            .position(|waiting| waiting.ticket == *ticket)
    }

    /// Forgets the requests which no longer wait, having been decided
    /// otherwise or abandoned, and says so on their entries.
    fn prune(&mut self) {
        let reviewer = &self.reviewer;
        let (kept, withdrawn): (VecDeque<_>, VecDeque<_>) = mem::take(&mut self.waiting)
            .into_iter()
            .partition(|waiting| reviewer.is_waiting(waiting.ticket));
        self.waiting = kept;
        for waiting in withdrawn {
            self.settle(
                waiting.ticket,
                "Withdrawn without an answer: the request was abandoned.".into(),
            );
        }
    }

    /// Replaces what the entry asking under `ticket` says of its answer.
    fn settle(&mut self, ticket: u64, answer: String) {
        let asked = self.activity.iter_mut().rev().find(
            |entry| matches!(entry.event, Event::Asked { ticket: asked, .. } if asked == ticket),
        );
        if let Some(entry) = asked {
            entry.open = false;
            if let Some((_, response)) = &mut entry.said {
                *response = answer;
            }
        }
    }

    /// Moves the cursor to entry `at`, which an answer is then for if it is
    /// a waiting request.
    fn select(&mut self, at: usize) {
        self.selected = at;
        self.following = at + 1 >= self.activity.len();
        self.paged = false;
        self.chosen = match self.activity.get(at).map(|entry| &entry.event) {
            Some(Event::Asked { ticket, .. }) => Some(*ticket),
            _ => None,
        };
    }

    /// Acts on a key, returning whether it asks to quit.
    fn key(&mut self, key: KeyCode) -> bool {
        let last = self.activity.len().saturating_sub(1);
        let exchange = self
            .activity
            .get_mut(self.selected)
            .filter(|entry| entry.said.is_some());
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('a') => self.reviewer.set_asking(!self.reviewer.asking()),
            KeyCode::Char(answer @ ('y' | 'n')) => {
                if let Some(waiting) = self.answering().and_then(|at| self.waiting.remove(at)) {
                    self.reviewer.answer(waiting.ticket, answer == 'y');
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.select(self.selected.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select((self.selected + 1).min(last)),
            KeyCode::Home => self.select(0),
            KeyCode::End => self.select(last),
            KeyCode::PageUp => {
                self.top.set(self.top.get().saturating_sub(self.page.get()));
                self.paged = true;
            }
            KeyCode::PageDown => {
                self.top.set(self.top.get() + self.page.get());
                self.paged = true;
            }
            KeyCode::Enter => {
                if let Some(entry) = exchange {
                    entry.open = !entry.open;
                    self.paged = false;
                }
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                if let Some(entry) = exchange {
                    entry.side = if entry.side == Side::Request {
                        Side::Response
                    } else {
                        Side::Request
                    };
                    entry.open = true;
                    self.paged = false;
                }
            }
            _ => {}
        }
        false
    }

    /// The first of `total` activity lines to show in `height` lines, given
    /// the line each entry `starts` at. Unless the person moved the view,
    /// the entry under the cursor is brought into it: whole if it fits,
    /// and otherwise from its first line.
    fn scrolled(&self, starts: &[usize], total: usize, height: usize) -> usize {
        let mut top = self.top.get();
        if let (false, Some(start)) = (self.paged, starts.get(self.selected)) {
            let end = starts.get(self.selected + 1).copied().unwrap_or(total);
            if *start < top || end - start > height {
                top = *start;
            } else if end > top + height {
                top = end - height;
            }
        }
        let top = top.min(total.saturating_sub(height));
        self.top.set(top);
        self.page.set(height.max(1));
        top
    }
}

enum Screen {
    Setup,
    Token(TokenEntry),
    Codex(CodexLogin),
    Approval(Approval),
    Dashboard(Dashboard),
}

/// Everything the view shows.
struct State {
    screen: Screen,
    /// Kept while another screen shows, to return to.
    setup: Setup,
    ticks: usize,
}

enum Message {
    Key(KeyEvent),
    Tick,
    /// Codex printed a line while signing in.
    CodexSaid(String),
    /// Codex's sign-in ended, and its login was kept if it succeeded.
    CodexDone(Result<()>),
    /// Concurro answered a registration with a code, or did not.
    Begun(Result<Pending>),
    /// The person approved the registration, or it failed.
    Approved(Result<Registration>),
    Relay(Event),
}

struct App {
    state: State,
    store: Store,
    credentials: Source,
    /// What this relay registers as.
    name: String,
    links: usize,
    reviewer: Arc<Reviewer>,
    native: NativeLimits,
    messages: UnboundedSender<Message>,
    /// The relay at work, while it is.
    serving: Option<JoinHandle<()>>,
    quit: bool,
}

impl App {
    /// Starts serving as the relay registered in the store.
    fn serve(&mut self) -> Result<()> {
        let relay = plain::relay(&self.store, self.reviewer.clone(), self.native)?;
        self.state.screen = Screen::Dashboard(Dashboard::new(
            relay.registration.clone(),
            &self.credentials,
            self.links,
            self.reviewer.clone(),
        ));
        let (events, mut reported) = mpsc::unbounded_channel();
        self.serving = Some(tokio::spawn(link::run(Arc::new(relay), self.links, events)));
        let messages = self.messages.clone();
        tokio::spawn(async move {
            while let Some(event) = reported.recv().await {
                if messages.send(Message::Relay(event)).is_err() {
                    return;
                }
            }
        });
        Ok(())
    }

    /// Returns to signing in, showing `error`.
    fn fail(&mut self, error: String) {
        self.state.setup.error = Some(error);
        self.state.setup.asking = false;
        self.state.screen = Screen::Setup;
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::Key(key) => self.key(key),
            Message::Tick => {
                self.state.ticks += 1;
                if let Screen::Dashboard(dashboard) = &mut self.state.screen {
                    dashboard.prune();
                    if self.state.ticks.is_multiple_of(LOGIN_CHECK_TICKS) {
                        dashboard.logins =
                            plain::logins(&self.credentials, &dashboard.registration.routes);
                    }
                }
            }
            Message::Begun(Ok(pending)) => {
                let device = pending.device.clone();
                let (store, messages) = (self.store.clone(), self.messages.clone());
                let waiting = tokio::spawn(async move {
                    let _ = messages.send(Message::Approved(pending.approved(&store).await));
                });
                self.state.screen = Screen::Approval(Approval {
                    device,
                    since: Instant::now(),
                    waiting,
                });
            }
            Message::Approved(Ok(_)) => {
                if let Err(error) = self.serve() {
                    self.fail(format!("{error:#}"));
                }
            }
            Message::CodexSaid(line) => {
                if let Screen::Codex(codex) = &mut self.state.screen
                    && !line.trim().is_empty()
                {
                    codex.said.push(line);
                }
            }
            Message::CodexDone(Ok(())) => {
                self.state.screen = Screen::Setup;
                self.advance();
            }
            Message::Begun(Err(error))
            | Message::Approved(Err(error))
            | Message::CodexDone(Err(error)) => {
                self.fail(format!("{error:#}"));
            }
            Message::Relay(event) => {
                if let Screen::Dashboard(dashboard) = &mut self.state.screen {
                    dashboard.apply(event);
                }
            }
        }
    }

    fn key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        match &mut self.state.screen {
            Screen::Dashboard(dashboard) if key.code == KeyCode::Char('r') => {
                // Registering again keeps the provider sign-ins.
                let registration = &dashboard.registration;
                let setup = &mut self.state.setup;
                (setup.address, setup.ca_file) = (
                    registration.server.address.clone(),
                    registration.server.ca_file.clone(),
                );
                for choice in &mut setup.choices {
                    choice.selected = registration.routes.contains(&choice.route);
                }
                (setup.focus, setup.error, setup.asking) = (0, None, false);
                if let Some(serving) = self.serving.take() {
                    serving.abort();
                }
                self.state.screen = Screen::Setup;
            }
            Screen::Dashboard(dashboard) => self.quit = dashboard.key(key.code),
            Screen::Approval(approval) => {
                if key.code == KeyCode::Esc {
                    approval.waiting.abort();
                    self.state.setup.asking = false;
                    self.state.screen = Screen::Setup;
                }
            }
            Screen::Token(entry) => match key.code {
                KeyCode::Esc => self.state.screen = Screen::Setup,
                KeyCode::Backspace => {
                    entry.token.pop();
                }
                KeyCode::Char(typed) if !typed.is_whitespace() => entry.token.push(typed),
                KeyCode::Enter => {
                    match plain::keep_token(&self.store, Route::ClaudeSubscription, &entry.token) {
                        Ok(()) => {
                            self.state.screen = Screen::Setup;
                            self.advance();
                        }
                        Err(error) => entry.error = Some(format!("{error:#}")),
                    }
                }
                _ => {}
            },
            Screen::Codex(codex) => {
                if key.code == KeyCode::Esc {
                    // Ends Codex and removes its directory.
                    codex.signing_in.abort();
                    self.state.screen = Screen::Setup;
                }
            }
            Screen::Setup => self.setup_key(key.code),
        }
    }

    /// Signs in to the provider of the next chosen route which has no
    /// credential or, once each has one, asks Concurro to register the
    /// relay.
    fn advance(&mut self) {
        self.state.setup.refresh(&self.credentials);
        match self.state.setup.missing() {
            Some(Route::ClaudeSubscription) => {
                self.state.screen = Screen::Token(TokenEntry::default())
            }
            Some(Route::ChatgptSubscription) => {
                let (said, mut printed) = mpsc::unbounded_channel();
                let (store, messages) = (self.store.clone(), self.messages.clone());
                let signing_in = tokio::spawn(async move {
                    let shown = messages.clone();
                    tokio::spawn(async move {
                        while let Some(line) = printed.recv().await {
                            if shown.send(Message::CodexSaid(line)).is_err() {
                                return;
                            }
                        }
                    });
                    let signed_in = async {
                        let credential = DeviceLogin::start(Some(said))?.finished().await?;
                        store.save_credential(Route::ChatgptSubscription, &credential)
                    };
                    let _ = messages.send(Message::CodexDone(signed_in.await));
                });
                self.state.screen = Screen::Codex(CodexLogin {
                    said: Vec::new(),
                    signing_in,
                });
            }
            None => self.begin(),
        }
    }

    /// Asks Concurro to register the relay for the chosen routes.
    fn begin(&mut self) {
        let setup = &mut self.state.setup;
        setup.error = None;
        setup.asking = true;
        let server = Server {
            address: setup.address.trim().to_owned(),
            ca_file: setup.ca_file.clone(),
        };
        let (name, routes, messages) = (self.name.clone(), setup.selected(), self.messages.clone());
        tokio::spawn(async move {
            let _ = messages.send(Message::Begun(login::begin(server, name, routes).await));
        });
    }

    fn setup_key(&mut self, key: KeyCode) {
        let setup = &mut self.state.setup;
        if setup.asking {
            self.quit = key == KeyCode::Esc;
            return;
        }
        let fields = setup.choices.len() + 1;
        match key {
            KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Down => setup.focus = (setup.focus + 1) % fields,
            KeyCode::BackTab | KeyCode::Up => setup.focus = (setup.focus + fields - 1) % fields,
            KeyCode::Backspace if setup.focus == 0 => {
                setup.address.pop();
            }
            KeyCode::Char(typed) if setup.focus == 0 => setup.address.push(typed),
            KeyCode::Char(' ') => {
                let choice = &mut setup.choices[setup.focus - 1];
                choice.selected = !choice.selected;
            }
            KeyCode::Enter => {
                if setup.address.trim().is_empty() {
                    setup.error = Some("Enter Concurro's address, as host:port.".into());
                } else if setup.selected().is_empty() {
                    setup.error = Some("Choose at least one route to serve.".into());
                } else {
                    self.advance();
                }
            }
            _ => {}
        }
    }
}

/// Whether `one` and `other` are the same request of the same session.
fn same(one: &NativeRequest, other: &NativeRequest) -> bool {
    one.session_id == other.session_id && one.request == other.request
}

/// A duration as hours, minutes and seconds.
fn clock(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn spinner(ticks: usize) -> &'static str {
    SPINNER[ticks % SPINNER.len()]
}

/// A provider login's state as one span.
fn login_span(login: &Result<String, String>) -> Span<'static> {
    match login {
        Ok(ready) => ready.clone().green(),
        Err(reason) => reason.clone().yellow(),
    }
}

fn setup_lines(setup: &Setup, ticks: usize) -> (Vec<Line<'static>>, &'static str) {
    let marker = |focused: bool| {
        if focused {
            "› ".cyan().bold()
        } else {
            "  ".into()
        }
    };
    let cursor = if setup.focus == 0 && !setup.asking {
        "▏"
    } else {
        ""
    };
    let mut lines = vec![
        Line::from("Sign in".bold()),
        Line::default(),
        Line::from(vec![
            marker(setup.focus == 0),
            "Concurro address  ".into(),
            setup.address.clone().bold(),
            cursor.into(),
        ]),
        Line::default(),
        Line::from("  Routes to serve"),
    ];
    for (at, choice) in setup.choices.iter().enumerate() {
        let check = if choice.selected { "[x] " } else { "[ ] " };
        lines.push(Line::from(vec![
            marker(setup.focus == at + 1),
            check.into(),
            format!("{:<22}", choice.route.label()).into(),
            login_span(&choice.login),
        ]));
    }
    lines.push(Line::default());
    if setup.asking {
        lines.push(Line::from(vec![
            format!("  {} ", spinner(ticks)).cyan(),
            "Asking Concurro for a code…".into(),
        ]));
    } else if let Some(error) = &setup.error {
        lines.push(Line::from(format!("  {error}").red()));
    }
    (lines, "enter continue · tab move · space choose · esc quit")
}

fn token_lines(entry: &TokenEntry) -> (Vec<Line<'static>>, &'static str) {
    let hidden = "•".repeat(entry.token.chars().count().min(48));
    let mut lines = vec![
        Line::from("Claude token".bold()),
        Line::default(),
        Line::from(
            "  The relay keeps a Claude token of its own, since Claude Code's login lasts only hours.",
        ),
        Line::from(vec![
            "  Run ".into(),
            "claude setup-token".cyan(),
            " in another terminal and paste the token it prints.".into(),
        ]),
        Line::default(),
        Line::from(vec![
            "› ".cyan().bold(),
            "Token  ".into(),
            hidden.into(),
            "▏".into(),
        ]),
        Line::default(),
        Line::from("  It is kept in this machine's keychain and sent only to Anthropic.".dim()),
    ];
    if let Some(error) = &entry.error {
        lines.push(Line::from(format!("  {error}").red()));
    }
    (lines, "enter continue · esc back")
}

/// How many of the lines Codex printed are shown.
const CODEX_LINES_SHOWN: usize = 14;

fn codex_lines(codex: &CodexLogin, ticks: usize) -> (Vec<Line<'static>>, &'static str) {
    let mut lines = vec![
        Line::from("ChatGPT sign-in".bold()),
        Line::default(),
        Line::from("  Codex is signing in for the relay, in a directory of the relay's own.".dim()),
        Line::from("  Your own Codex login is not touched.".dim()),
        Line::default(),
    ];
    let skipped = codex.said.len().saturating_sub(CODEX_LINES_SHOWN);
    lines.extend(
        codex
            .said
            .iter()
            .skip(skipped)
            .map(|line| Line::from(format!("  {line}"))),
    );
    lines.push(Line::default());
    lines.push(Line::from(vec![
        format!("  {} ", spinner(ticks)).cyan(),
        "Waiting for you to finish in the browser…".into(),
    ]));
    (lines, "esc cancel")
}

fn approval_lines(approval: &Approval, ticks: usize) -> (Vec<Line<'static>>, &'static str) {
    let left =
        Duration::from_secs(approval.device.expires_secs).saturating_sub(approval.since.elapsed());
    let lines = vec![
        Line::from("Approve this relay".bold()),
        Line::default(),
        Line::from(vec![
            "  Open  ".into(),
            approval.device.verification_uri.clone().cyan(),
        ]),
        Line::from(vec![
            "  Code  ".into(),
            approval.device.user_code.clone().bold(),
        ]),
        Line::default(),
        Line::from(vec![
            format!("  {} ", spinner(ticks)).cyan(),
            "Waiting for approval…  ".into(),
            format!("the code expires in {}", &clock(left)[3..]).dim(),
        ]),
    ];
    (lines, "esc cancel")
}

/// `text` as lines of at most `width` characters, without the characters
/// a terminal would act on.
fn wrapped(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let line: Vec<char> = line
            .chars()
            .map(|shown| if shown.is_control() { ' ' } else { shown })
            .collect();
        if line.is_empty() {
            lines.push(String::new());
        }
        for part in line.chunks(width.max(1)) {
            if lines.len() == TEXT_LINES_SHOWN {
                lines.push("…".into());
                return lines;
            }
            lines.push(part.iter().collect());
        }
    }
    lines
}

/// The line which heads `entry` in the activity list, `since` being when
/// the relay started.
fn entry_line(entry: &Entry, selected: bool, waits: bool, since: Instant) -> Line<'static> {
    let cursor = if selected {
        "› ".cyan().bold()
    } else {
        "  ".into()
    };
    let fold = match (&entry.said, entry.open) {
        (None, _) => "  ",
        (Some(_), false) => "▸ ",
        (Some(_), true) => "▾ ",
    };
    let when = format!("+{}  ", clock(entry.at.duration_since(since))).dim();
    let mut spans = vec![cursor, fold.into(), when];
    match &entry.event {
        Event::Proved { exchange, .. } => spans.extend([
            format!("{:<22}", exchange.route.label()).into(),
            format!(
                "{:<18}",
                events::one_line(exchange.model.as_deref().unwrap_or(""))
            )
            .cyan(),
            format!(
                "sent {:>9}  received {:>9}  ",
                events::size(exchange.sent as u64),
                events::size(exchange.received as u64)
            )
            .into(),
            format!(
                "{:>9} up  {:.1}s",
                events::size(exchange.upload),
                exchange.seconds
            )
            .dim(),
        ]),
        Event::Asked { route, request, .. } => spans.extend([
            format!("{:<22}", route.label()).into(),
            format!("{}  ", events::described(request)).cyan(),
            if waits {
                "waits for your review".yellow().bold()
            } else {
                "no longer waits for your review".dim()
            },
        ]),
        Event::Reviewed {
            route,
            request,
            decision,
            ..
        } => spans.extend([
            format!("{:<22}", route.label()).into(),
            format!("{}  ", events::described(request)).cyan(),
            if decision.accept {
                format!("{decision}  ").green()
            } else {
                format!("{decision}  ").red()
            },
            format!("sha256 {}", request.sha256).dim(),
        ]),
        Event::NativeAudit { route, audit, .. } => spans.extend([
            format!("{:<22}", route.label()).into(),
            format!("request {}  ", audit.request).cyan(),
            format!("usage {}", events::usage(audit)).dim(),
        ]),
        Event::Refused { reason, .. } => {
            spans.extend(["refused  ".yellow(), events::one_line(reason).into()])
        }
        Event::Link { link, state } => {
            spans.push(events::one_line(&format!("link {link} {state}")).red())
        }
    }
    let line = Line::from(spans);
    if selected { line.bold() } else { line }
}

/// The activity list for a view `width` characters wide, and the line at
/// which each entry starts.
fn activity_lines(dashboard: &Dashboard, width: usize) -> (Vec<Line<'static>>, Vec<usize>) {
    if dashboard.activity.is_empty() {
        return (
            vec![Line::from(
                "  Waiting for Concurro to send a request.".dim(),
            )],
            Vec::new(),
        );
    }
    let (mut lines, mut starts) = (Vec::new(), Vec::new());
    for (at, entry) in dashboard.activity.iter().enumerate() {
        starts.push(lines.len());
        let waits = matches!(entry.event, Event::Asked { ticket, .. }
            if dashboard.waiting.iter().any(|waiting| waiting.ticket == ticket));
        lines.push(entry_line(
            entry,
            at == dashboard.selected,
            waits,
            dashboard.since,
        ));
        let (true, Some((request, response))) = (entry.open, &entry.said) else {
            continue;
        };
        let (text, sides) = match entry.side {
            Side::Request => (request, ["request".bold().underlined(), "response".dim()]),
            Side::Response => (response, ["request".dim(), "response".bold().underlined()]),
        };
        let [first, second] = sides;
        lines.push(Line::from(vec![
            "      ".into(),
            first,
            "  ".into(),
            second,
        ]));
        lines.extend(
            wrapped(text, width.saturating_sub(6))
                .into_iter()
                .map(|line| Line::from(format!("      {line}"))),
        );
        lines.push(Line::default());
    }
    (lines, starts)
}

/// What stands above the activity list.
fn summary_lines(dashboard: &Dashboard) -> Vec<Line<'static>> {
    let registration = &dashboard.registration;
    let mut lines = vec![
        Line::from(vec![
            "Signed in as ".into(),
            registration.login.clone().bold(),
            format!(
                " · relay {} ({}) · {}",
                registration.name, registration.relay, registration.server.address
            )
            .into(),
            format!(" · up {}", clock(dashboard.since.elapsed())).dim(),
        ]),
        Line::default(),
        Line::from("Routes".bold()),
    ];
    for ((route, login), proved) in dashboard.logins.iter().zip(&dashboard.proved) {
        lines.push(Line::from(vec![
            format!("  {:<22}", route.label()).into(),
            login_span(login),
            format!("  {proved} proved").dim(),
        ]));
    }
    lines.push(Line::default());
    let mut links = vec!["Links  ".bold()];
    for (at, state) in dashboard.links.iter().enumerate() {
        let shown = match state {
            LinkState::Up => format!("{} up  ", at + 1).green(),
            LinkState::Connecting => format!("{} connecting  ", at + 1).yellow(),
            LinkState::Down(_) => format!("{} down  ", at + 1).red(),
            LinkState::Refused(_) => format!("{} refused  ", at + 1).red(),
        };
        links.push(shown);
    }
    lines.push(Line::from(links));
    let reviewer = &dashboard.reviewer;
    let mut review = vec![
        "Review ".bold(),
        if reviewer.asking() {
            " asking you about each request".yellow()
        } else {
            " accepting each request".into()
        },
    ];
    if let Some(hook) = reviewer.hook() {
        review.push(format!(" the review hook leaves undecided · hook: {hook}").dim());
    }
    lines.push(Line::from(review));
    if let Some(waiting) = dashboard
        .answering()
        .and_then(|at| dashboard.waiting.get(at))
    {
        let left = ANSWER_LIMIT.saturating_sub(waiting.since.elapsed());
        let mut asked = vec![
            format!(
                "  Link {} {} waits for you: ",
                waiting.link,
                events::described(&waiting.request)
            )
            .yellow()
            .bold(),
            "y accept · n reject".bold(),
            format!(" · rejected in {}", &clock(left)[3..]).dim(),
        ];
        if dashboard.waiting.len() > 1 {
            asked.push(format!(" · {} more waiting", dashboard.waiting.len() - 1).dim());
        }
        lines.push(Line::from(asked));
    } else if !dashboard.waiting.is_empty() {
        lines.push(Line::from(vec![
            format!(
                "  {} waiting for you: ",
                match dashboard.waiting.len() {
                    1 => "A request is".to_owned(),
                    waiting => format!("{waiting} requests are"),
                }
            )
            .yellow()
            .bold(),
            "select one with ↑↓ to answer it".bold(),
        ]));
    }
    if dashboard
        .links
        .iter()
        .all(|state| matches!(state, LinkState::Refused(_)))
    {
        lines.push(Line::from(
            "  Concurro refused this relay. Press r to register it again; your sign-ins are kept."
                .yellow(),
        ));
    }
    lines.push(Line::default());
    let proved: usize = dashboard.proved.iter().sum();
    lines.push(Line::from(vec![
        "Activity".bold(),
        format!(
            "  {proved} proved, {} uploaded",
            events::size(dashboard.upload)
        )
        .dim(),
    ]));
    lines
}

fn draw(frame: &mut Frame, state: &State) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let title = format!(" Concurro relay v{} ", env!("CARGO_PKG_VERSION"));
    let about = Paragraph::new(vec![
        Line::from("Keeps your provider login on this machine and proves each request"),
        Line::from("to Concurro without revealing it.".dim()),
    ])
    .block(
        Block::bordered()
            .border_type(BorderType::Rounded)
            .title(title.bold())
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(about, header);

    let padded = Block::new().padding(Padding::new(2, 2, 1, 0));
    let hints = match &state.screen {
        Screen::Dashboard(dashboard) => {
            let summary = summary_lines(dashboard);
            let [above, list] = Layout::vertical([
                Constraint::Length(summary.len() as u16 + 1),
                Constraint::Min(0),
            ])
            .areas(body);
            frame.render_widget(Paragraph::new(summary).block(padded), above);
            let (lines, starts) = activity_lines(dashboard, list.width.saturating_sub(4) as usize);
            let height = list.height as usize;
            let top = dashboard.scrolled(&starts, lines.len(), height);
            let shown: Vec<Line> = lines.into_iter().skip(top).take(height).collect();
            frame.render_widget(
                Paragraph::new(shown).block(Block::new().padding(Padding::horizontal(2))),
                list,
            );
            if dashboard.waiting.is_empty() {
                "↑↓ select · enter open · tab request/response · pgup/pgdn scroll · a ask/accept · r register again · q quit"
            } else {
                "y accept · n reject · ↑↓ select · enter open · tab request/response · a ask/accept · q quit"
            }
        }
        screen => {
            let (lines, hints) = match screen {
                Screen::Setup => setup_lines(&state.setup, state.ticks),
                Screen::Token(entry) => token_lines(entry),
                Screen::Codex(codex) => codex_lines(codex, state.ticks),
                Screen::Approval(approval) => approval_lines(approval, state.ticks),
                Screen::Dashboard(_) => unreachable!("the dashboard is drawn above"),
            };
            frame.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .block(padded),
                body,
            );
            hints
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(format!("  {hints}").dim())),
        footer,
    );
}

/// Sends the person's key presses on `messages` until `stop` is set.
fn read_keys(messages: UnboundedSender<Message>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        match event::poll(TICK) {
            Ok(true) => {
                if let Ok(Input::Key(key)) = event::read()
                    && messages.send(Message::Key(key)).is_err()
                {
                    return;
                }
            }
            Ok(false) => {}
            Err(_) => return,
        }
    }
}

async fn run_in(
    terminal: &mut DefaultTerminal,
    mut app: App,
    mut received: mpsc::UnboundedReceiver<Message>,
) -> Result<()> {
    let mut ticks = time::interval(TICK);
    while !app.quit {
        terminal.draw(|frame| draw(frame, &app.state))?;
        let message = tokio::select! {
            message = received.recv() => message,
            _ = ticks.tick() => Some(Message::Tick),
        };
        let Some(message) = message else { break };
        app.update(message);
    }
    Ok(())
}

/// Runs the view until the person quits. The relay signs in to `server`
/// under `name` if the store holds no registration, and then serves on
/// `links` links.
pub async fn run(
    store: Store,
    server: Option<Server>,
    name: String,
    links: usize,
    reviewer: Arc<Reviewer>,
    native: NativeLimits,
) -> Result<()> {
    let credentials = Source::Kept(store.clone());
    let (messages, received) = mpsc::unbounded_channel();
    let state = State {
        screen: Screen::Setup,
        setup: Setup::new(server, &credentials),
        ticks: 0,
    };
    let mut app = App {
        state,
        store,
        credentials,
        name,
        links,
        reviewer,
        native,
        messages: messages.clone(),
        serving: None,
        quit: false,
    };
    if app.store.load()?.is_some() {
        app.serve()?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let keys = thread::spawn({
        let stop = stop.clone();
        move || read_keys(messages, stop)
    });
    let mut terminal = ratatui::init();
    let ran = run_in(&mut terminal, app, received).await;
    ratatui::restore();
    stop.store(true, Ordering::Relaxed);
    let _ = keys.join();
    ran
}

#[cfg(test)]
mod tests {
    use concurro_relay_native::NativeAudit;
    use concurro_relay_protocol::route::Route;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{
        credentials::Credential,
        events::Exchange,
        review::{Decider, Decision},
    };

    fn credentials() -> Source {
        Source::Fixed(Credential {
            token: "token".into(),
            headers: Vec::new(),
        })
    }

    /// What `state` looks like on a terminal of 110 by 24.
    fn shown(state: &State) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, state)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    fn setup() -> Setup {
        Setup::new(
            Some(Server {
                address: "localhost:7443".into(),
                ca_file: None,
            }),
            &credentials(),
        )
    }

    #[test]
    fn setup_shows_the_address_and_each_route_with_its_login() {
        let mut setup = setup();
        setup.choices[0].login = Err("needs a token from `claude setup-token`".into());
        setup.choices[0].selected = false;
        let screen = shown(&State {
            screen: Screen::Setup,
            setup,
            ticks: 0,
        });
        for expected in [
            "Sign in",
            "localhost:7443",
            "[ ] Claude subscription",
            "needs a token",
            "[x] ChatGPT subscription",
            "ready",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
    }

    #[test]
    fn token_entry_never_shows_the_token() {
        let entry = TokenEntry {
            token: "sk-ant-oat01-secret".into(),
            error: Some("that is not a token".into()),
        };
        let screen = shown(&State {
            screen: Screen::Token(entry),
            setup: setup(),
            ticks: 0,
        });
        for expected in [
            "Claude token",
            "claude setup-token",
            "•••",
            "that is not a token",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
        assert!(!screen.contains("secret"));
    }

    #[tokio::test]
    async fn codex_sign_in_shows_what_codex_says() {
        let said = vec![
            "Open this link in your browser".to_owned(),
            "   https://auth.example/device".to_owned(),
        ];
        let codex = CodexLogin {
            said,
            signing_in: tokio::spawn(async {}),
        };
        let screen = shown(&State {
            screen: Screen::Codex(codex),
            setup: setup(),
            ticks: 0,
        });
        for expected in [
            "ChatGPT sign-in",
            "Your own Codex login is not touched",
            "https://auth.example/device",
            "Waiting for you",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
    }

    #[test]
    fn the_next_route_without_a_credential_is_signed_in_to() {
        let mut setup = setup();
        assert_eq!(setup.missing(), None);
        for choice in &mut setup.choices {
            choice.login = Err("needs a sign-in".into());
        }
        assert_eq!(setup.missing(), Some(Route::ClaudeSubscription));
        setup.choices[0].selected = false;
        assert_eq!(setup.missing(), Some(Route::ChatgptSubscription));
    }

    #[tokio::test]
    async fn approval_shows_the_code_and_where_to_enter_it() {
        let device = DeviceCode {
            device_code: "secret".into(),
            user_code: "BCDF-GHJK".into(),
            verification_uri: "https://concurro.example/relay".into(),
            interval_secs: 1,
            expires_secs: 600,
        };
        let approval = Approval {
            device,
            since: Instant::now(),
            waiting: tokio::spawn(async {}),
        };
        let screen = shown(&State {
            screen: Screen::Approval(approval),
            setup: setup(),
            ticks: 3,
        });
        for expected in [
            "Approve this relay",
            "https://concurro.example/relay",
            "BCDF-GHJK",
            "Waiting for approval",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
        assert!(!screen.contains("secret"));
    }

    fn registration() -> Registration {
        Registration {
            server: Server {
                address: "localhost:7443".into(),
                ca_file: None,
            },
            relay: "relay-1a2b".into(),
            login: "octocat".into(),
            name: "laptop".into(),
            routes: vec![Route::ChatgptSubscription],
        }
    }

    /// An exchange which asked `asked` and was answered `answered`.
    fn exchange(asked: &str, answered: &str) -> Event {
        let exchange = Exchange {
            route: Route::ChatgptSubscription,
            model: Some("some-model".into()),
            sent: 68_000,
            received: 98_200,
            upload: 3_460_000,
            download: 1_600_000,
            seconds: 2.9,
            request: serde_json::json!({"input": asked}).to_string(),
            response: format!(
                "data: {}\n\n",
                serde_json::json!({"type": "response.output_text.delta", "delta": answered})
            ),
        };
        Event::Proved { link: 1, exchange }
    }

    fn dashboard_state(dashboard: Dashboard) -> State {
        State {
            screen: Screen::Dashboard(dashboard),
            setup: setup(),
            ticks: 0,
        }
    }

    #[test]
    fn dashboard_counts_what_was_proved_and_shows_what_went_wrong() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 2, Default::default());
        dashboard.apply(Event::Link {
            link: 1,
            state: LinkState::Up,
        });
        dashboard.apply(exchange("what is here?", "two files"));
        dashboard.apply(Event::Refused {
            link: 1,
            reason: "body field not allowed: tools".into(),
        });
        dashboard.apply(Event::Link {
            link: 2,
            state: LinkState::Down("connection reset".into()),
        });

        let screen = shown(&dashboard_state(dashboard));
        assert!(
            !screen.contains("what is here?"),
            "a closed entry shows no text: {screen}"
        );
        for expected in [
            "Signed in as octocat",
            "relay laptop (relay-1a2b)",
            "1 proved",
            "1 up",
            "2 down",
            "3.46 MB uploaded",
            "some-model",
            "sent   68.0 KB",
            "body field not allowed: tools",
            "link 2 down: connection reset",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
    }

    #[test]
    fn a_refused_relay_is_told_how_to_register_again() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, Default::default());
        assert!(
            !shown(&dashboard_state(Dashboard::new(
                registration(),
                &credentials(),
                1,
                Default::default(),
            )))
            .contains("register it again")
        );
        dashboard.apply(Event::Link {
            link: 1,
            state: LinkState::Refused("this relay is not registered".into()),
        });
        let screen = shown(&dashboard_state(dashboard));
        assert!(
            screen.contains("Press r to register it again; your sign-ins are kept."),
            "{screen}"
        );
    }

    #[test]
    fn an_entry_opens_on_its_request_and_switches_to_its_response() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, Default::default());
        dashboard.apply(exchange("first question", "first answer"));
        dashboard.apply(exchange("second question", "second answer"));
        assert_eq!(dashboard.selected, 1, "the cursor follows the newest entry");

        assert!(!dashboard.key(KeyCode::Up));
        dashboard.key(KeyCode::Enter);
        dashboard.apply(exchange("third question", "third answer"));
        assert_eq!(
            dashboard.selected, 0,
            "a cursor which was moved stays where it is"
        );
        let mut state = dashboard_state(dashboard);
        let screen = shown(&state);
        assert!(
            screen.contains("first question") && !screen.contains("first answer"),
            "{screen}"
        );
        assert!(!screen.contains("second question"));

        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!()
        };
        dashboard.key(KeyCode::Tab);
        let screen = shown(&state);
        assert!(
            screen.contains("first answer") && !screen.contains("first question"),
            "{screen}"
        );

        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!()
        };
        dashboard.key(KeyCode::Enter);
        dashboard.key(KeyCode::End);
        assert!(dashboard.following);
        assert!(!shown(&state).contains("first answer"));
        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!()
        };
        assert!(dashboard.key(KeyCode::Char('q')));
    }

    #[test]
    fn a_long_entry_starts_at_the_top_and_pages() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, Default::default());
        dashboard.apply(exchange("short", "short"));
        let long: String = (1..=60)
            .map(|line| format!("line {line} of the answer\n"))
            .collect();
        dashboard.apply(exchange("long question", &long));
        dashboard.key(KeyCode::Tab);
        let mut state = dashboard_state(dashboard);
        let screen = shown(&state);
        assert!(
            screen.contains("line 1 of the answer") && !screen.contains("line 40 of the answer"),
            "{screen}"
        );

        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!()
        };
        dashboard.key(KeyCode::PageDown);
        dashboard.key(KeyCode::PageDown);
        let screen = shown(&state);
        assert!(
            !screen.contains("line 1 of the answer") && screen.contains("line 20 of the answer"),
            "{screen}"
        );
        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!()
        };
        dashboard.key(KeyCode::Up);
        assert!(shown(&state).contains("sent   68.0 KB"));
    }

    #[test]
    fn only_the_newest_entries_keep_what_was_said() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, Default::default());
        for _ in 0..TEXT_KEPT + 3 {
            dashboard.apply(exchange("question", "answer"));
        }
        assert_eq!(
            dashboard
                .activity
                .iter()
                .filter(|entry| entry.said.is_some())
                .count(),
            TEXT_KEPT
        );
        assert!(dashboard.activity[2].said.is_none() && dashboard.activity[3].said.is_some());
    }

    fn native_request(number: u64) -> NativeRequest {
        NativeRequest {
            request: number,
            prompt: format!("{{\"input\":\"question {number}\"}}"),
            sha256: format!("digest-{number}"),
            path: None,
            headers: Vec::new(),
            session_id: "session".into(),
        }
    }

    /// A request the Sponsor is asked about is shown and answered, and its
    /// decision and usage reach its entry.
    #[tokio::test]
    async fn a_request_waits_for_the_sponsor_and_gets_its_usage() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, reviewer.clone());
        let (events, mut reported) = mpsc::unbounded_channel();
        let reviewing = {
            let (reviewer, events) = (reviewer.clone(), events.clone());
            tokio::spawn(async move {
                reviewer
                    .review(1, Route::ChatgptSubscription, &native_request(7), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        let mut state = dashboard_state(dashboard);
        let screen = shown(&state);
        for expected in [
            "asking you about each request",
            "A request is waiting for you",
            "select one with ↑↓",
            "question 7",
        ] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!("the dashboard is shown")
        };
        // Nothing is answered until the Sponsor moves the cursor to it.
        assert!(!dashboard.key(KeyCode::Char('y')));
        assert_eq!(dashboard.waiting.len(), 1);
        assert!(!dashboard.key(KeyCode::Home));
        let screen = shown(&state);
        for expected in ["Link 1 request 7 waits for you", "y accept · n reject"] {
            assert!(
                screen.contains(expected),
                "{expected} is missing from: {screen}"
            );
        }
        let Screen::Dashboard(dashboard) = &mut state.screen else {
            unreachable!("the dashboard is shown")
        };
        assert!(!dashboard.key(KeyCode::Char('y')));
        let decision = reviewing.await.unwrap();
        assert_eq!((decision.accept, decision.by), (true, Decider::Sponsor));
        dashboard.apply(Event::Reviewed {
            link: 1,
            route: Route::ChatgptSubscription,
            request: native_request(7),
            decision,
        });
        dashboard.apply(Event::NativeAudit {
            link: 1,
            route: Route::ChatgptSubscription,
            audit: NativeAudit {
                request: 7,
                sha256: "digest-7".into(),
                usage: Some(serde_json::json!({"input_tokens": 5})),
                session_id: "session".into(),
            },
        });
        assert!(dashboard.waiting.is_empty());
        assert_eq!(dashboard.activity.len(), 2);
        assert!(!dashboard.activity[0].open);
        assert_eq!(dashboard.proved, [1]);
        let (_, response) = dashboard.activity[1].said.as_ref().unwrap();
        assert_eq!(
            response,
            "accepted by the Sponsor\nConcurro-reported provider usage: {\"input_tokens\":5}"
        );
        assert!(!dashboard.key(KeyCode::Char('a')));
        assert!(!reviewer.asking());
        assert!(shown(&state).contains("accepting each request"));
    }

    /// A rejected request is not counted, and a request abandoned elsewhere
    /// stops waiting.
    #[tokio::test]
    async fn rejected_and_abandoned_requests() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, reviewer.clone());
        let (events, mut reported) = mpsc::unbounded_channel();
        let reviewing = {
            let reviewer = reviewer.clone();
            tokio::spawn(async move {
                reviewer
                    .review(1, Route::ChatgptSubscription, &native_request(1), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        assert_eq!(dashboard.waiting.len(), 1);
        reviewing.abort();
        let _ = reviewing.await;
        dashboard.prune();
        assert!(dashboard.waiting.is_empty());
        let (_, answer) = dashboard.activity[0].said.as_ref().unwrap();
        assert!(answer.starts_with("Withdrawn without an answer"));
        let (lines, _) = activity_lines(&dashboard, 120);
        assert!(
            lines[0]
                .to_string()
                .contains("no longer waits for your review")
        );
        dashboard.apply(Event::Reviewed {
            link: 1,
            route: Route::ChatgptSubscription,
            request: native_request(1),
            decision: Decision {
                accept: false,
                by: Decider::Hook,
                reason: Some("off topic".into()),
            },
        });
        assert_eq!(dashboard.proved, [0]);
        assert!(
            shown(&dashboard_state(dashboard)).contains("rejected by the review hook: off topic")
        );
    }

    /// A request waiting for the Sponsor keeps its text however much happens
    /// meanwhile, and usage whose request lost its text gets an entry.
    #[tokio::test]
    async fn waiting_text_is_kept_and_usage_is_not_lost() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, reviewer.clone());
        let (events, mut reported) = mpsc::unbounded_channel();
        let _reviewing = {
            let reviewer = reviewer.clone();
            tokio::spawn(async move {
                reviewer
                    .review(1, Route::ChatgptSubscription, &native_request(1), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        dashboard.apply(Event::Reviewed {
            link: 1,
            route: Route::ChatgptSubscription,
            request: native_request(2),
            decision: Decision {
                accept: true,
                by: Decider::Automatic,
                reason: None,
            },
        });
        for _ in 0..TEXT_KEPT + 5 {
            dashboard.apply(exchange("later", "answer"));
        }
        assert!(dashboard.activity[0].said.is_some());
        assert!(dashboard.activity[1].said.is_none());
        dashboard.apply(Event::NativeAudit {
            link: 1,
            route: Route::ChatgptSubscription,
            audit: NativeAudit {
                request: 2,
                sha256: "digest-2".into(),
                usage: None,
                session_id: "session".into(),
            },
        });
        assert!(matches!(
            dashboard.activity.back().unwrap().event,
            Event::NativeAudit { .. }
        ));
    }

    /// A request waiting for the Sponsor outlasts the activity list's limit.
    #[tokio::test]
    async fn a_waiting_request_outlasts_the_activity_limit() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, reviewer.clone());
        let (events, mut reported) = mpsc::unbounded_channel();
        let _reviewing = {
            let reviewer = reviewer.clone();
            tokio::spawn(async move {
                reviewer
                    .review(1, Route::ChatgptSubscription, &native_request(1), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        for _ in 0..ACTIVITY_KEPT + 5 {
            dashboard.apply(exchange("later", "answer"));
        }
        assert_eq!(dashboard.activity.len(), ACTIVITY_KEPT);
        let (request, _) = dashboard.activity[0].said.as_ref().unwrap();
        assert!(request.contains("question 1"));
        assert!(matches!(dashboard.activity[0].event, Event::Asked { .. }));
        // The cursor follows what arrives, but not onto the waiting request.
        assert_eq!(dashboard.selected, ACTIVITY_KEPT - 1);
    }

    /// An answer is only for the waiting request the Sponsor moved the
    /// cursor to, which stays there as other requests arrive.
    #[tokio::test]
    async fn an_answer_is_for_the_request_chosen() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 2, reviewer.clone());
        dashboard.apply(exchange("before", "answer"));
        let (events, mut reported) = mpsc::unbounded_channel();
        let reviewing: Vec<_> = (1..=3)
            .map(|number| {
                let (reviewer, events) = (reviewer.clone(), events.clone());
                tokio::spawn(async move {
                    reviewer
                        .review(
                            1,
                            Route::ChatgptSubscription,
                            &native_request(number),
                            &events,
                        )
                        .await
                })
            })
            .collect();
        let mut asked = Vec::new();
        let event = reported.recv().await.unwrap();
        let Event::Asked { request, .. } = &event else {
            unreachable!("only questions are reported")
        };
        asked.push(request.request);
        dashboard.apply(event);
        // The cursor does not move onto the waiting request by itself.
        assert_eq!(dashboard.selected, 0);
        assert!(!dashboard.key(KeyCode::Char('y')));
        dashboard.select(1);
        for _ in 0..2 {
            let event = reported.recv().await.unwrap();
            let Event::Asked { request, .. } = &event else {
                unreachable!("only questions are reported")
            };
            asked.push(request.request);
            dashboard.apply(event);
        }
        // The chosen request kept the cursor while the others arrived.
        assert_eq!(dashboard.selected, 1);
        assert!(!dashboard.key(KeyCode::Char('n')));
        // Answered, it no longer takes an answer, nor passes one on.
        assert!(!dashboard.key(KeyCode::Char('n')));
        assert_eq!(dashboard.waiting.len(), 2);
        dashboard.select(3);
        assert!(!dashboard.key(KeyCode::Char('y')));
        dashboard.select(2);
        assert!(!dashboard.key(KeyCode::Char('y')));
        assert!(dashboard.waiting.is_empty());
        let mut decisions = Vec::new();
        for reviewing in reviewing {
            decisions.push(reviewing.await.unwrap().accept);
        }
        let answered =
            |number: u64| decisions[asked.iter().position(|asked| *asked == number).unwrap()];
        assert!(!answered(asked[0]));
        assert!(answered(asked[1]) && answered(asked[2]));
    }

    /// A request withdrawn from under the cursor leaves the cursor there, so
    /// an answer meant for it is not taken by a request arriving next.
    #[tokio::test]
    async fn a_withdrawn_request_does_not_pass_its_answer_on() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let mut dashboard = Dashboard::new(registration(), &credentials(), 2, reviewer.clone());
        let (events, mut reported) = mpsc::unbounded_channel();
        let first = {
            let (reviewer, events) = (reviewer.clone(), events.clone());
            tokio::spawn(async move {
                reviewer
                    .review(1, Route::ChatgptSubscription, &native_request(1), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        first.abort();
        let _ = first.await;
        dashboard.prune();
        let second = {
            let reviewer = reviewer.clone();
            tokio::spawn(async move {
                reviewer
                    .review(2, Route::ChatgptSubscription, &native_request(2), &events)
                    .await
            })
        };
        dashboard.apply(reported.recv().await.unwrap());
        assert_eq!(dashboard.selected, 0);
        assert!(!dashboard.key(KeyCode::Char('y')));
        assert_eq!(dashboard.waiting.len(), 1);
        dashboard.select(1);
        assert!(!dashboard.key(KeyCode::Char('n')));
        assert!(!second.await.unwrap().accept);
    }

    /// Eviction never takes the entry under the cursor.
    #[test]
    fn eviction_spares_the_entry_under_the_cursor() {
        let mut dashboard = Dashboard::new(registration(), &credentials(), 1, Default::default());
        dashboard.apply(Event::Refused {
            link: 1,
            reason: "kept".into(),
        });
        dashboard.select(0);
        dashboard.following = false;
        for _ in 0..ACTIVITY_KEPT {
            dashboard.apply(exchange("later", "answer"));
        }
        assert_eq!(dashboard.activity.len(), ACTIVITY_KEPT);
        assert_eq!(dashboard.selected, 0);
        assert!(matches!(
            &dashboard.activity[0].event,
            Event::Refused { reason, .. } if reason == "kept"
        ));
    }
}
