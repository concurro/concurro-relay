//! Decides whether each request Concurro asks for may reach the provider:
//! by the Sponsor's review hook, automatically, or by the Sponsor.

use std::{
    collections::HashMap,
    fmt,
    process::Stdio,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use concurro_relay_native::NativeRequest;
use concurro_relay_protocol::route::Route;
use serde_json::json;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{mpsc::UnboundedSender, oneshot},
    time,
};

use crate::events::Event;

/// How long a review hook may take before it counts as undecided.
const HOOK_LIMIT: Duration = Duration::from_secs(60);

/// How long a request waits for the Sponsor before it is rejected.
pub const ANSWER_LIMIT: Duration = Duration::from_secs(300);

/// The most characters of a hook's reason which are kept.
const REASON_CHARS: usize = 200;

/// Who decided a request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decider {
    Hook,
    Automatic,
    Sponsor,
    /// Nobody answered within [`ANSWER_LIMIT`].
    Unanswered,
}

/// Whether a request may reach the provider, who decided, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub accept: bool,
    pub by: Decider,
    /// The hook's reason, when it gave one.
    pub reason: Option<String>,
}

impl Decision {
    /// What Concurro is told about a rejection.
    pub fn told(&self) -> Option<String> {
        (!self.accept).then(|| self.to_string())
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = if self.accept { "accepted" } else { "rejected" };
        match self.by {
            Decider::Hook => write!(f, "{verdict} by the review hook")?,
            Decider::Automatic => write!(f, "{verdict} automatically")?,
            Decider::Sponsor => write!(f, "{verdict} by the Sponsor")?,
            Decider::Unanswered => write!(
                f,
                "{verdict}: no answer within {} minutes",
                ANSWER_LIMIT.as_secs() / 60
            )?,
        }
        match &self.reason {
            Some(reason) => write!(f, ": {reason}"),
            None => Ok(()),
        }
    }
}

/// Reviews requests for every link of a relay.
#[derive(Default)]
pub struct Reviewer {
    /// A shell command given each request; see [`Reviewer::review`].
    hook: Option<String>,
    /// Whether the Sponsor is asked about requests the hook leaves
    /// undecided, rather than accepting them.
    asking: AtomicBool,
    /// Requests waiting for the Sponsor, by ticket.
    waiting: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    tickets: AtomicU64,
}

/// Withdraws a ticket from the waiting requests when its review ends.
struct Ticket<'a> {
    reviewer: &'a Reviewer,
    number: u64,
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        self.reviewer.waiting().remove(&self.number);
    }
}

impl Reviewer {
    pub fn new(hook: Option<String>) -> Self {
        Self {
            hook: hook.filter(|hook| !hook.trim().is_empty()),
            ..Self::default()
        }
    }

    pub fn hook(&self) -> Option<&str> {
        self.hook.as_deref()
    }

    pub fn asking(&self) -> bool {
        self.asking.load(Ordering::Relaxed)
    }

    /// Asks the Sponsor about each request from now on, or accepts them
    /// automatically, as do the requests already waiting.
    pub fn set_asking(&self, asking: bool) {
        self.asking.store(asking, Ordering::Relaxed);
        if !asking {
            for (_, waiting) in self.waiting().drain() {
                let _ = waiting.send(true);
            }
        }
    }

    /// Answers the request waiting under `ticket`, returning whether it was
    /// still waiting.
    pub fn answer(&self, ticket: u64, accept: bool) -> bool {
        self.waiting()
            .remove(&ticket)
            .is_some_and(|waiting| waiting.send(accept).is_ok())
    }

    pub fn is_waiting(&self, ticket: u64) -> bool {
        self.waiting().contains_key(&ticket)
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, HashMap<u64, oneshot::Sender<bool>>> {
        self.waiting.lock().expect("review lock is not poisoned")
    }

    /// Decides `request` on `link`. The hook decides first: it gets the
    /// request as JSON on standard input, and exiting with 0 accepts it and
    /// with 1 rejects it, the first line it prints being the reason. Any
    /// other outcome leaves the request to the Sponsor when asking, and
    /// accepts it otherwise. A request the Sponsor is asked about is
    /// reported on `events` and rejected after [`ANSWER_LIMIT`].
    pub async fn review(
        &self,
        link: usize,
        route: Route,
        request: &NativeRequest,
        events: &UnboundedSender<Event>,
    ) -> Decision {
        if let Some(hook) = &self.hook
            && let Some(decision) = run_hook(hook, link, route, request).await
        {
            return decision;
        }
        let automatic = Decision {
            accept: true,
            by: Decider::Automatic,
            reason: None,
        };
        if !self.asking() {
            return automatic;
        }
        let ticket = Ticket {
            reviewer: self,
            number: self.tickets.fetch_add(1, Ordering::Relaxed),
        };
        let (waiting, answered) = oneshot::channel();
        self.waiting().insert(ticket.number, waiting);
        // Accepting may have been chosen since asking was checked.
        if !self.asking() {
            return automatic;
        }
        let _ = events.send(Event::Asked {
            link,
            route,
            ticket: ticket.number,
            request: request.clone(),
        });
        match time::timeout(ANSWER_LIMIT, answered).await {
            Ok(Ok(true)) if !self.asking() => automatic,
            Ok(Ok(accept)) => Decision {
                accept,
                by: Decider::Sponsor,
                reason: None,
            },
            _ => Decision {
                accept: false,
                by: Decider::Unanswered,
                reason: None,
            },
        }
    }
}

/// Runs `hook` on `request`, returning its decision, or `None` when it left
/// the request undecided.
async fn run_hook(
    hook: &str,
    link: usize,
    route: Route,
    request: &NativeRequest,
) -> Option<Decision> {
    let input = serde_json::to_vec(&json!({
        "route": route,
        "link": link,
        "request": request.request,
        "session_id": request.session_id,
        "sha256": request.sha256,
        "path": request.path,
        "headers": request.headers,
        "prompt": request.prompt,
    }))
    .ok()?;
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(hook)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let fed = async move {
        // A hook may decide without reading all of its input.
        let _ = stdin.write_all(&input).await;
    };
    let ran = async { tokio::join!(fed, child.wait_with_output()).1 };
    let output = time::timeout(HOOK_LIMIT, ran).await.ok()?.ok()?;
    let reason = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(|line| {
            line.chars()
                .filter(|shown| !shown.is_control())
                .take(REASON_CHARS)
                .collect::<String>()
        })
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty());
    let accept = match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        _ => return None,
    };
    Some(Decision {
        accept,
        by: Decider::Hook,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use concurro_relay_native::NativeRequest;
    use concurro_relay_protocol::route::Route;
    use tokio::sync::mpsc;

    use super::{Decider, Decision, Reviewer};
    use crate::events::Event;

    fn request() -> NativeRequest {
        NativeRequest {
            request: 4,
            prompt: r#"{"messages":[]}"#.into(),
            sha256: "abc".into(),
            path: Some("/v1/messages".into()),
            headers: vec![("anthropic-version".into(), "2023-06-01".into())],
            session_id: "session".into(),
        }
    }

    async fn reviewed(reviewer: &Reviewer) -> Decision {
        let (events, _) = mpsc::unbounded_channel();
        reviewer
            .review(1, Route::ClaudeSubscription, &request(), &events)
            .await
    }

    /// The hook's exit status decides, and its first line is the reason.
    #[tokio::test]
    async fn the_hook_decides_by_its_exit_status() {
        let accepted = reviewed(&Reviewer::new(Some("cat >/dev/null; echo fine".into()))).await;
        assert_eq!(
            accepted,
            Decision {
                accept: true,
                by: Decider::Hook,
                reason: Some("fine".into())
            }
        );
        let rejected = reviewed(&Reviewer::new(Some(
            "grep -q '\"anthropic-version\",\"2023-06-01\"' && printf 'too \\033[31mlong\\nmore' && exit 1".into(),
        )))
        .await;
        assert_eq!(
            rejected,
            Decision {
                accept: false,
                by: Decider::Hook,
                reason: Some("too [31mlong".into())
            }
        );
        assert_eq!(
            rejected.told().as_deref(),
            Some("rejected by the review hook: too [31mlong")
        );
    }

    /// A hook which fails otherwise leaves the request to the fallback.
    #[tokio::test]
    async fn an_undecided_hook_falls_back() {
        let decision = reviewed(&Reviewer::new(Some("exit 3".into()))).await;
        assert_eq!(decision.by, Decider::Automatic);
        assert!(decision.accept);
        assert_eq!(decision.told(), None);
    }

    /// When asking, the Sponsor's answer decides, and switching to accepting
    /// accepts what waits.
    #[tokio::test]
    async fn the_sponsor_answers_when_asked() {
        let reviewer = Arc::new(Reviewer::new(None));
        reviewer.set_asking(true);
        let (events, mut reported) = mpsc::unbounded_channel();
        let reviewing = {
            let (reviewer, events) = (reviewer.clone(), events.clone());
            tokio::spawn(async move {
                reviewer
                    .review(2, Route::ChatgptSubscription, &request(), &events)
                    .await
            })
        };
        let Some(Event::Asked { ticket, link, .. }) = reported.recv().await else {
            panic!("the Sponsor was not asked");
        };
        assert_eq!(link, 2);
        assert!(reviewer.is_waiting(ticket));
        assert!(reviewer.answer(ticket, false));
        assert!(!reviewer.answer(ticket, true));
        let decision = reviewing.await.unwrap();
        assert_eq!((decision.accept, decision.by), (false, Decider::Sponsor));
        assert!(!reviewer.is_waiting(ticket));

        let reviewing = {
            let reviewer = reviewer.clone();
            tokio::spawn(async move {
                reviewer
                    .review(2, Route::ChatgptSubscription, &request(), &events)
                    .await
            })
        };
        reported.recv().await.unwrap();
        reviewer.set_asking(false);
        let decision = reviewing.await.unwrap();
        assert_eq!((decision.accept, decision.by), (true, Decider::Automatic));
    }

    /// An unanswered request is rejected once the wait runs out.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_request_is_rejected() {
        let reviewer = Reviewer::new(None);
        reviewer.set_asking(true);
        let decision = reviewed(&reviewer).await;
        assert_eq!((decision.accept, decision.by), (false, Decider::Unanswered));
        assert_eq!(
            decision.told().as_deref(),
            Some("rejected: no answer within 5 minutes")
        );
    }
}
