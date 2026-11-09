//! Widerrufsliste der Webseite (offizieller Betrieb, Format: `docs/revocation-format.md`).
//!
//! Das Relay holt alle `REVOCATION_INTERVAL_SECS` (Vorgabe 15 s)
//! `GET <REVOCATION_URL>?after=<cursor>` mit `Authorization: Bearer <RELAY_REVOCATION_TOKEN>`.
//! Die Antwort ist ein kompaktes, Ed25519-signiertes Dokument wie ein Ticket, Kontext
//! `hangar-revoke-v1`, geprüft mit den Schlüsseln der Tickets (`TICKET_PUBLIC_KEYS`). Ausgehend
//! nur an genau diese Adresse, ohne Weiterleitungen, mit Zeit- und Größenlimit.
//!
//! Wirkung je Eintrag (idempotent je `rid`):
//! - `member_removed`, `seat_lost`: Mitglied entfernt (Reservierungen frei, Close 4403); ein
//!   Ticket, das nach dem Eintrag ausgestellt wurde, lässt es wieder zu.
//! - `role_changed`: neue Rolle still auf den laufenden Verbindungen anwenden; ohne bekannte
//!   Rolle die Verbindungen schließen (4401), die App kommt mit neuem Ticket. In beiden Fällen
//!   gelten Tickets mit `iat` bis `at` nicht mehr (`hello` und `ticket.renew`), sonst holte
//!   sich ein herabgestuftes Mitglied mit einem gehorteten Ticket die alte Rolle zurück.
//! - `project_deleted`: Team schließen (4404), Relay-Daten löschen.
//!
//! Fehler und Unerreichbarkeit halten nichts an: das Relay versucht es weiter, mit wachsendem
//! Abstand (bis 5 min), und schreibt es ins Protokoll.

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

/// Größte Antwort in Bytes.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Einträge je Antwort.
pub const MAX_ITEMS: usize = 1000;
/// Längste Gültigkeit einer Liste (die Webseite stellt 120 s aus).
pub const MAX_LIFETIME_S: i64 = 300;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Höchstens so viele Seiten hintereinander (`more`), dann bis zum nächsten Abruf warten.
const MAX_PAGES_PER_ROUND: usize = 50;

/// Kennungen der Webseite kommen als Zahl oder Text; das Relay vergleicht Text.
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

/// Ein geprüfter Eintrag.
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
    /// `role`: die neue Rolle; fehlt sie (oder ist sie unbekannt), muss die App neu verbinden.
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

/// Eine geprüfte Seite der Liste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub last: String,
    pub more: bool,
    /// Je Eintrag die `rid` und, wenn er ins Format passt, seine Wirkung.
    pub items: Vec<(String, Option<Revocation>)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RevocationError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("der Inhalt passt nicht zum Format")]
    Payload,
    #[error("Version {0} wird nicht unterstützt")]
    Version(u32),
    #[error("die Liste gilt für ein anderes Relay")]
    Audience,
    #[error("die Liste ist abgelaufen oder noch nicht gültig")]
    Time,
    #[error("die Liste antwortet auf einen anderen Cursor")]
    Cursor,
    #[error("die Liste ist zu lang")]
    TooMany,
}

fn opaque(id: &Id) -> Option<String> {
    let text = id.text();
    is_opaque(&text, 128).then_some(text)
}

/// Prüft ein Dokument: Signatur, Kontext, kid, `aud`, Zeitfenster und dass es auf `after`
/// antwortet. Einträge, die nicht ins Format passen, kommen als `None` mit ihrer `rid` zurück
/// (sie werden übersprungen, aber gemerkt).
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

/// Wendet einen Eintrag an.
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

/// Prozentkodierung für den Cursor in der Abfrage (alles außer unreservierten Zeichen).
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
    #[error("Abruf: {0}")]
    Http(String),
    #[error("Antwort mit Status {0}")]
    Status(u16),
    #[error("Antwort zu groß")]
    TooLarge,
    #[error("Prüfung: {0}")]
    Invalid(#[from] RevocationError),
    #[error("Datenbank: {0}")]
    Db(#[from] sqlx::Error),
}

/// Holt und verarbeitet die Liste.
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
            .user_agent(concat!("hangar-team-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("HTTP-Client: {e}"))?;
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

    /// Eine Runde: abholen, prüfen, anwenden, Cursor speichern; bei `more` sofort weiter
    /// (höchstens [`MAX_PAGES_PER_ROUND`] Seiten). Gibt die Zahl neu angewendeter Einträge zurück.
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
                    None => tracing::warn!(rid, "Widerruf unbekannter Art oder Form übersprungen"),
                }
                store::mark_revocation(&self.relay.db, rid, now_ms()).await?;
            }
            store::set_revocation_cursor(&self.relay.db, &page.last, now_ms()).await?;
            if !page.more {
                break;
            }
        }
        if applied > 0 {
            tracing::info!(applied, "Widerrufe angewendet");
        }
        Ok(applied)
    }

    /// Läuft bis `shutdown`; Fehler verlängern den Abstand bis höchstens 5 min.
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
                    tracing::warn!(%error, next_s = next.as_secs(), "Widerrufsliste nicht verarbeitet");
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
        {"rid":8,"prj":318,"sub":null,"kind":"unbekannt","at":999}]}"#;

    #[test]
    fn gültige_liste() {
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
    fn abgelehnte_listen() {
        let k = SigningKey::from_bytes(&[5; 32]);
        let good = doc(&k, LIST, REVOKE_CONTEXT);
        assert_eq!(
            verify(&good, &keys(&k), "anderes", "0", 1010),
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
