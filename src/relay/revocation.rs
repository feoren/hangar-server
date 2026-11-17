//! Revocation list of the website (official mode, format: `docs/revocation-format.md`).
//!
//! Every `REVOCATION_INTERVAL_SECS` (default 15 s) the relay fetches
//! `GET <REVOCATION_URL>?after=<cursor>` with `Authorization: Bearer <RELAY_REVOCATION_TOKEN>`.
//! The response is a compact, Ed25519-signed document like a ticket, context
//! `hangar-revoke-v1`, verified with the ticket keys (`TICKET_PUBLIC_KEYS`). Outgoing requests
//! go only to exactly this address, without redirects, with time and size limits.
//!
//! Effect per entry (idempotent per `rid`):
//! - `member_removed`, `seat_lost`: member removed (reservations released, close 4403); a
//!   ticket issued after the entry lets the member in again.
//! - `role_changed`: apply the new role silently to the running connections; without a known
//!   role, close the connections (4401), the app comes back with a new ticket. In both cases,
//!   tickets with `iat` up to `at` are no longer valid (`hello` and `ticket.renew`), otherwise a
//!   demoted member could regain the old role with a hoarded ticket.
//! - `project_deleted`: close the team (4404), delete relay data.
//!
//! Errors and unreachability stop nothing: the relay keeps trying, with increasing interval
//! (up to 5 min), and logs it.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::watch;

use super::{store, Relay};
use crate::config::RevocationSource;
use crate::signed::{self, KeySet, SignedError, REVOKE_CONTEXT};
use crate::ticket::{Role, CLOCK_SKEW_S};
use crate::util::{is_opaque, now_ms, now_s};

/// Largest response in bytes.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Entries per response.
pub const MAX_ITEMS: usize = 1000;
/// Longest validity of a list (the website issues 120 s).
pub const MAX_LIFETIME_S: i64 = 300;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// At most this many pages in a row (`more`), then wait until the next fetch.
const MAX_PAGES_PER_ROUND: usize = 50;

/// Identifiers of the website come as number or text; the relay compares text.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum Id {
    Number(u64),
    Text(String),
}

impl Id {
    fn text(&self) -> String {
        match self {
            Id::Number(n) => n.to_string(),
            Id::Text(t) => t.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Item {
    rid: Id,
    prj: Id,
    #[serde(default)]
    sub: Option<Id>,
    kind: String,
    #[serde(default)]
    role: Option<String>,
    at: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct List {
    v: u32,
    kid: String,
    aud: String,
    iat: i64,
    exp: i64,
    after: Id,
    last: Id,
    more: bool,
    items: Vec<Item>,
}

/// A verified entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    MemberRemoved {
        prj: String,
        sub: String,
        at_ms: u64,
    },
    SeatLost {
        prj: String,
        sub: String,
        at_ms: u64,
    },
    /// `role`: the new role; if it is missing (or unknown), the app has to reconnect.
    RoleChanged {
        prj: String,
        sub: String,
        role: Option<Role>,
        at_ms: u64,
    },
    ProjectDeleted {
        prj: String,
    },
}

/// A verified page of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub last: String,
    pub more: bool,
    /// Per entry the `rid` and, if it fits the format, its effect.
    pub items: Vec<(String, Option<Revocation>)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RevocationError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("the payload does not match the format")]
    Payload,
    #[error("version {0} is not supported")]
    Version(u32),
    #[error("the list is for a different relay")]
    Audience,
    #[error("the list has expired or is not yet valid")]
    Time,
    #[error("the list answers a different cursor")]
    Cursor,
    #[error("the list is too long")]
    TooMany,
}

fn opaque(id: &Id) -> Option<String> {
    let text = id.text();
    is_opaque(&text, 128).then_some(text)
}

/// Verifies a document: signature, context, kid, `aud`, time window and that it answers
/// `after`. Entries that do not fit the format come back as `None` with their `rid` (they are
/// skipped, but remembered).
pub fn verify(
    document: &str,
    keys: &KeySet,
    audience: &str,
    after: &str,
    now_s: i64,
) -> Result<Page, RevocationError> {
    let (payload, kid) = signed::verify(document.trim(), REVOKE_CONTEXT, keys, MAX_RESPONSE_BYTES)?;
    let list: List = serde_json::from_slice(&payload).map_err(|_| RevocationError::Payload)?;
    if list.v != 1 {
        return Err(RevocationError::Version(list.v));
    }
    if list.kid != kid {
        return Err(RevocationError::Payload);
    }
    if list.aud != audience {
        return Err(RevocationError::Audience);
    }
    if list.exp <= list.iat
        || list.exp - list.iat > MAX_LIFETIME_S
        || list.iat > now_s + CLOCK_SKEW_S
        || now_s >= list.exp + CLOCK_SKEW_S
    {
        return Err(RevocationError::Time);
    }
    if list.after.text() != after {
        return Err(RevocationError::Cursor);
    }
    if list.items.len() > MAX_ITEMS {
        return Err(RevocationError::TooMany);
    }
    let last = opaque(&list.last).ok_or(RevocationError::Payload)?;
    let mut items = Vec::with_capacity(list.items.len());
    for item in list.items {
        let rid = opaque(&item.rid).ok_or(RevocationError::Payload)?;
        let at_ms = u64::try_from(item.at).unwrap_or(0).saturating_mul(1000);
        let prj = opaque(&item.prj);
        let sub = item.sub.as_ref().and_then(opaque);
        let parsed = match (item.kind.as_str(), prj, sub) {
            ("member_removed", Some(prj), Some(sub)) => {
                Some(Revocation::MemberRemoved { prj, sub, at_ms })
            }
            ("seat_lost", Some(prj), Some(sub)) => Some(Revocation::SeatLost { prj, sub, at_ms }),
            ("role_changed", Some(prj), Some(sub)) => Some(Revocation::RoleChanged {
                prj,
                sub,
                role: item.role.as_deref().and_then(Role::parse),
                at_ms,
            }),
            ("project_deleted", Some(prj), None) => Some(Revocation::ProjectDeleted { prj }),
            _ => None,
        };
        items.push((rid, parsed));
    }
    Ok(Page {
        last,
        more: list.more,
        items,
    })
}

/// Applies an entry.
pub async fn apply(relay: &Relay, revocation: &Revocation) -> Result<(), sqlx::Error> {
    match revocation {
        Revocation::MemberRemoved { prj, sub, at_ms }
        | Revocation::SeatLost { prj, sub, at_ms } => relay.revoke_member(prj, sub, *at_ms).await,
        Revocation::RoleChanged {
            prj,
            sub,
            role: Some(role),
            at_ms,
        } => relay.apply_role(prj, sub, *role, *at_ms).await,
        Revocation::RoleChanged {
            prj,
            sub,
            role: None,
            at_ms,
        } => relay.renew_member(prj, sub, *at_ms).await,
        Revocation::ProjectDeleted { prj } => relay.close_team(prj).await,
    }
}

/// Percent-encoding for the cursor in the query (everything except unreserved characters).
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum PollError {
    #[error("fetch: {0}")]
    Http(String),
    #[error("response with status {0}")]
    Status(u16),
    #[error("response too large")]
    TooLarge,
    #[error("verification: {0}")]
    Invalid(#[from] RevocationError),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

/// Fetches and processes the list.
pub struct Poller {
    relay: Arc<Relay>,
    source: RevocationSource,
    keys: KeySet,
    audience: String,
    client: reqwest::Client,
}

impl Poller {
    pub fn new(
        relay: Arc<Relay>,
        source: RevocationSource,
        keys: KeySet,
        audience: String,
    ) -> Result<Self, String> {
        crate::tls::install_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("hangar-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Poller {
            relay,
            source,
            keys,
            audience,
            client,
        })
    }

    async fn fetch(&self, after: &str) -> Result<String, PollError> {
        let separator = if self.source.url.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{separator}after={}",
            self.source.url,
            percent_encode(after)
        );
        let mut response = self
            .client
            .get(url)
            .bearer_auth(&self.source.token)
            .send()
            .await
            .map_err(|e| PollError::Http(e.without_url().to_string()))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(PollError::Status(status));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(PollError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PollError::Http(e.without_url().to_string()))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(PollError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| PollError::Invalid(RevocationError::Payload))
    }

    /// One round: fetch, verify, apply, store the cursor; with `more` continue right away
    /// (at most [`MAX_PAGES_PER_ROUND`] pages). Returns the number of newly applied entries.
    pub async fn poll_once(&self) -> Result<usize, PollError> {
        let mut applied = 0;
        for _ in 0..MAX_PAGES_PER_ROUND {
            let after = store::revocation_cursor(&self.relay.db)
                .await?
                .unwrap_or_else(|| "0".into());
            let document = self.fetch(&after).await?;
            let page = verify(&document, &self.keys, &self.audience, &after, now_s())?;
            for (rid, revocation) in &page.items {
                if store::revocation_seen(&self.relay.db, rid).await? {
                    continue;
                }
                match revocation {
                    Some(revocation) => {
                        apply(&self.relay, revocation).await?;
                        applied += 1;
                    }
                    None => tracing::warn!(rid, "skipped revocation of unknown kind or shape"),
                }
                store::mark_revocation(&self.relay.db, rid, now_ms()).await?;
            }
            store::set_revocation_cursor(&self.relay.db, &page.last, now_ms()).await?;
            if !page.more {
                break;
            }
        }
        if applied > 0 {
            tracing::info!(applied, "revocations applied");
        }
        Ok(applied)
    }

    /// Runs until `shutdown`; errors extend the interval up to at most 5 min.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.source.interval_s);
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => break,
            }
            wait = match self.poll_once().await {
                Ok(_) => interval,
                Err(error) => {
                    let next = (wait.max(interval) * 2).min(MAX_BACKOFF);
                    tracing::warn!(%error, next_s = next.as_secs(), "revocation list not processed");
                    next
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64;
    use ed25519_dalek::SigningKey;

    fn keys(k: &SigningKey) -> KeySet {
        KeySet::parse(&format!("w1:{}", b64(k.verifying_key().as_bytes()))).unwrap()
    }

    fn doc(k: &SigningKey, json: &str, context: &str) -> String {
        signed::sign(json.as_bytes(), context, k)
    }

    const LIST: &str = r#"{"v":1,"kid":"w1","aud":"hangar-relay","iat":1000,"exp":1120,"after":0,"last":7,"more":false,"items":[
        {"rid":5,"prj":317,"sub":1042,"kind":"member_removed","at":990},
        {"rid":6,"prj":"317","sub":"1043","kind":"role_changed","role":"admin","at":995},
        {"rid":7,"prj":318,"sub":null,"kind":"project_deleted","at":999},
        {"rid":8,"prj":318,"sub":null,"kind":"unknown","at":999}]}"#;

    #[test]
    fn valid_list() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let page = verify(
            &doc(&k, LIST, REVOKE_CONTEXT),
            &keys(&k),
            "hangar-relay",
            "0",
            1010,
        )
        .unwrap();
        assert_eq!(page.last, "7");
        assert_eq!(
            page.items[0],
            (
                "5".into(),
                Some(Revocation::MemberRemoved {
                    prj: "317".into(),
                    sub: "1042".into(),
                    at_ms: 990_000
                })
            )
        );
        assert_eq!(
            page.items[1].1,
            Some(Revocation::RoleChanged {
                prj: "317".into(),
                sub: "1043".into(),
                role: Some(Role::Admin),
                at_ms: 995_000
            })
        );
        assert_eq!(
            page.items[2].1,
            Some(Revocation::ProjectDeleted { prj: "318".into() })
        );
        assert_eq!(page.items[3], ("8".into(), None));
    }

    #[test]
    fn rejected_lists() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let good = doc(&k, LIST, REVOKE_CONTEXT);
        assert_eq!(
            verify(&good, &keys(&k), "other", "0", 1010),
            Err(RevocationError::Audience)
        );
        assert_eq!(
            verify(&good, &keys(&k), "hangar-relay", "0", 2000),
            Err(RevocationError::Time)
        );
        assert_eq!(
            verify(&good, &keys(&k), "hangar-relay", "3", 1010),
            Err(RevocationError::Cursor)
        );
        let ticket_ctx = doc(&k, LIST, crate::signed::TICKET_CONTEXT);
        assert_eq!(
            verify(&ticket_ctx, &keys(&k), "hangar-relay", "0", 1010),
            Err(RevocationError::Signed(SignedError::BadSignature))
        );
        let foreign = doc(&SigningKey::from_bytes(&[6; 32]), LIST, REVOKE_CONTEXT);
        assert_eq!(
            verify(&foreign, &keys(&k), "hangar-relay", "0", 1010),
            Err(RevocationError::Signed(SignedError::BadSignature))
        );
    }
}
