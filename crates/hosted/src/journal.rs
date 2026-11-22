//! Durable claim revocation and request allowance.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::PathBuf,
    sync::{Arc, Weak},
};

use anyhow::{Context, Result, ensure};
use concurro_relay_hosted_api::claim::SessionClaim;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::storage;

/// One durable update. A null expiry is a release received before the first dispatch.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    Admitted {
        claim_id: String,
        expires: i64,
        request_id: String,
    },
    Charged {
        claim_id: String,
        request_id: String,
        tokens: u64,
        complete: bool,
    },
    Revoked {
        claim_id: String,
        expires: Option<i64>,
    },
}

impl Record {
    /// Encode one newline-terminated journal record.
    fn write(&self, bytes: &mut Vec<u8>) -> Result<()> {
        serde_json::to_writer(&mut *bytes, self)?;
        bytes.push(b'\n');
        Ok(())
    }
}

/// Expiry, settled token total and one call charge per exchange request ID.
#[derive(Default)]
struct Ledger {
    expires: Option<i64>,
    revoked: bool,
    requests: HashMap<String, Option<TokenCharge>>,
    tokens: u64,
}

/// Observed usage for a call, which may be a lower bound after interruption.
struct TokenCharge {
    tokens: u64,
    complete: bool,
}

impl Ledger {
    /// A claim's expiry must stay the same across all its journal records.
    fn observe_expiry(&mut self, expires: i64) -> Result<()> {
        ensure!(
            self.expires.is_none_or(|prior| prior == expires),
            "claim expiry changed"
        );
        self.expires = Some(expires);
        Ok(())
    }
}

/// Reasons a signed request cannot spend allowance.
#[derive(Debug)]
pub enum Refusal {
    /// The claim was durably revoked.
    Revoked,
    /// The claim expired or its recorded expiry differs.
    Invalid,
    /// This request ID already spent a call.
    Duplicate,
    /// The call or token allowance was spent.
    Spent,
    /// The journal could not provide durable accounting.
    Storage(anyhow::Error),
}

/// One verifier's replayed claim journal and per-session request serialization.
pub struct Journal {
    file: PathBuf,
    claims: HashMap<String, Ledger>,
    sessions: HashMap<String, Weak<Mutex<()>>>,
    failed: bool,
}

impl Journal {
    /// Replay durable records, discarding a torn final append and expired claims.
    pub fn open(file: PathBuf, now: i64) -> Result<Self> {
        let mut journal = Self {
            file,
            claims: HashMap::new(),
            sessions: HashMap::new(),
            failed: false,
        };
        let bytes = match fs::read(&journal.file) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(journal),
            Err(error) => return Err(error.into()),
        };
        let end = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |i| i + 1);
        for line in bytes[..end].split_inclusive(|byte| *byte == b'\n') {
            journal.apply(serde_json::from_slice(line).context("invalid claim journal record")?)?;
        }
        if end < bytes.len() {
            storage::replace(&journal.file, &bytes[..end])?;
        }
        journal.prune(now)?;
        Ok(journal)
    }

    /// Serialize a session's admitted requests through their token settlement.
    pub fn session(&mut self, id: &str) -> Arc<Mutex<()>> {
        if let Some(session) = self.sessions.get(id).and_then(Weak::upgrade) {
            return session;
        }
        self.sessions.retain(|_, gate| gate.strong_count() > 0);
        let session = Arc::new(Mutex::new(()));
        self.sessions
            .insert(id.to_owned(), Arc::downgrade(&session));
        session
    }

    /// Refuse a revoked, expired, replayed or exhausted dispatch.
    pub fn check(&mut self, claim: &SessionClaim, request: &str, now: i64) -> Result<(), Refusal> {
        self.prune(now).map_err(Refusal::Storage)?;
        if claim.exp <= now {
            return Err(Refusal::Invalid);
        }
        if let Some(ledger) = self.claims.get(&claim.jti) {
            if ledger.expires.is_some_and(|expiry| expiry != claim.exp) {
                return Err(Refusal::Invalid);
            }
            if ledger.revoked {
                if ledger.expires.is_none() {
                    self.commit(Record::Revoked {
                        claim_id: claim.jti.clone(),
                        expires: Some(claim.exp),
                    })
                    .map_err(Refusal::Storage)?;
                }
                return Err(Refusal::Revoked);
            }
            if ledger.requests.contains_key(request) {
                return Err(Refusal::Duplicate);
            }
            if ledger.requests.len() as u64 >= claim.calls || ledger.tokens >= claim.tokens {
                return Err(Refusal::Spent);
            }
        } else if claim.calls == 0 || claim.tokens == 0 {
            return Err(Refusal::Spent);
        }
        Ok(())
    }

    /// Make an already-checked request admission durable before it reaches native ingress.
    pub fn admit(&mut self, claim: &SessionClaim, request_id: &str) -> Result<()> {
        self.commit(Record::Admitted {
            claim_id: claim.jti.clone(),
            expires: claim.exp,
            request_id: request_id.to_owned(),
        })
    }

    /// Charge provider-reported usage once, preserving whether the count is complete.
    pub fn charge(
        &mut self,
        claim_id: &str,
        request_id: &str,
        tokens: u64,
        complete: bool,
    ) -> Result<()> {
        if !self
            .claims
            .get(claim_id)
            .is_some_and(|ledger| ledger.requests.get(request_id).is_some_and(Option::is_none))
        {
            return Ok(());
        }
        self.commit(Record::Charged {
            claim_id: claim_id.to_owned(),
            request_id: request_id.to_owned(),
            tokens,
            complete,
        })
    }

    /// Make release durable even if the verifier has never seen the claim.
    pub fn revoke(&mut self, claim_id: &str, now: i64) -> Result<()> {
        let already_expired = self
            .claims
            .get(claim_id)
            .and_then(|ledger| ledger.expires)
            .is_some_and(|exp| exp <= now);
        self.prune(now)?;
        if already_expired {
            return Ok(());
        }
        let current = self.claims.get(claim_id);
        if current.is_some_and(|ledger| ledger.revoked) {
            return Ok(());
        }
        self.commit(Record::Revoked {
            claim_id: claim_id.to_owned(),
            expires: current.and_then(|ledger| ledger.expires),
        })
    }

    /// Reclaim expired records by atomically compacting the journal.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        ensure!(!self.failed, "claim journal needs to be reopened");
        if !self
            .claims
            .values()
            .any(|ledger| ledger.expires.is_some_and(|exp| exp <= now))
        {
            return Ok(());
        }
        let mut bytes = Vec::new();
        for (claim_id, ledger) in &self.claims {
            if let Some(expires) = ledger.expires {
                if expires <= now {
                    continue;
                }
                for (request_id, usage) in &ledger.requests {
                    Record::Admitted {
                        claim_id: claim_id.clone(),
                        expires,
                        request_id: request_id.clone(),
                    }
                    .write(&mut bytes)?;
                    if let Some(usage) = usage {
                        Record::Charged {
                            claim_id: claim_id.clone(),
                            request_id: request_id.clone(),
                            tokens: usage.tokens,
                            complete: usage.complete,
                        }
                        .write(&mut bytes)?;
                    }
                }
            }
            if ledger.revoked {
                Record::Revoked {
                    claim_id: claim_id.clone(),
                    expires: ledger.expires,
                }
                .write(&mut bytes)?;
            }
        }
        storage::replace(&self.file, &bytes)?;
        self.claims
            .retain(|_, ledger| ledger.expires.is_none_or(|exp| exp > now));
        Ok(())
    }

    /// Persist a record before applying it. A failed append may have left a torn tail.
    fn commit(&mut self, record: Record) -> Result<()> {
        ensure!(!self.failed, "claim journal needs to be reopened");
        let mut bytes = Vec::new();
        record.write(&mut bytes)?;
        let committed = storage::append(&self.file, &bytes).and_then(|()| self.apply(record));
        self.failed = committed.is_err();
        committed
    }

    /// Reconstruct a claim's state from successive durable updates.
    fn apply(&mut self, record: Record) -> Result<()> {
        match record {
            Record::Admitted {
                claim_id,
                expires,
                request_id,
            } => {
                let ledger = self.claims.entry(claim_id).or_default();
                ledger.observe_expiry(expires)?;
                ensure!(!ledger.revoked, "admission follows revocation");
                ensure!(
                    ledger.requests.insert(request_id, None).is_none(),
                    "duplicate admission"
                );
            }
            Record::Charged {
                claim_id,
                request_id,
                tokens,
                complete,
            } => {
                let ledger = self
                    .claims
                    .get_mut(&claim_id)
                    .context("charge without claim")?;
                let usage = ledger
                    .requests
                    .get_mut(&request_id)
                    .context("charge without admission")?;
                ensure!(
                    usage.replace(TokenCharge { tokens, complete }).is_none(),
                    "duplicate charge"
                );
                ledger.tokens = ledger.tokens.saturating_add(tokens);
            }
            Record::Revoked { claim_id, expires } => {
                let ledger = self.claims.entry(claim_id).or_default();
                if let Some(expires) = expires {
                    ledger.observe_expiry(expires)?;
                }
                ledger.revoked = true;
            }
        }
        Ok(())
    }
}
