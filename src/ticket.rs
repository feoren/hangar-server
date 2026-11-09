//! Tickets für die Live-Verbindung (Format: `docs/ticket-format.md`).
//!
//! Die Webseite (offizieller Betrieb) oder die eigene Identität (Selbstbetrieb) stellt ein
//! kurzlebiges Ticket aus; die App reicht es unverändert in `hello` weiter. Das Relay prüft
//! Signatur, kid, Zeitfenster und Zielgruppe; die einmalige Verwendung der `jti` prüft
//! [`crate::relay::store`] in der Datenbank.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signed::{self, KeySet, SignedError, TICKET_CONTEXT};
use crate::util::{is_id, is_opaque};

/// Längstes Ticket (wie `MAX_TICKET_LEN` des Protokolls).
pub const MAX_TICKET_LEN: usize = 2048;
/// Längste opake Kennung (Konto, Projekt).
pub const MAX_OPAQUE_LEN: usize = 128;
/// Erlaubte Abweichung der Uhren zwischen Aussteller und Relay, in Sekunden.
pub const CLOCK_SKEW_S: i64 = 30;
/// Längste erlaubte Gültigkeit eines Tickets; die Webseite stellt 60 s aus.
pub const MAX_LIFETIME_S: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "owner" => Some(Role::Owner),
            "admin" => Some(Role::Admin),
            "member" => Some(Role::Member),
            _ => None,
        }
    }

    /// Rang: owner > admin > member.
    pub fn rank(self) -> u8 {
        match self {
            Role::Owner => 3,
            Role::Admin => 2,
            Role::Member => 1,
        }
    }
}

/// Inhalt eines Tickets. Unbekannte Felder werden ignoriert (spätere Erweiterungen der Webseite
/// brechen alte Relays nicht); eine inkompatible Änderung erhöht `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketClaims {
    pub v: u32,
    pub kid: String,
    /// Konto-ID der Webseite (opak).
    pub sub: String,
    /// Projekt-ID der Webseite = Team (opak).
    pub prj: String,
    pub role: Role,
    /// Die Webseite bestätigt, dass diese Person einen Platz im Team hat.
    pub seat_ok: bool,
    pub iat: i64,
    pub exp: i64,
    /// Einmalige Kennung gegen Wiederverwendung.
    pub jti: String,
    /// Optional: für welches Relay das Ticket gilt (Ursprung, z. B. `https://team.hangar.feoren.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TicketError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("der Inhalt passt nicht zum Ticketformat")]
    Payload,
    #[error("Version {0} wird nicht unterstützt")]
    Version(u32),
    #[error("das Ticket ist abgelaufen")]
    Expired,
    #[error("das Ticket ist noch nicht gültig")]
    NotYetValid,
    #[error("die Gültigkeit ist länger als erlaubt")]
    Lifetime,
    #[error("das Ticket gilt für ein anderes Relay")]
    Audience,
}

/// Prüft ein Ticket vollständig außer der `jti`-Wiederverwendung.
pub fn verify(
    ticket: &str,
    keys: &KeySet,
    now_s: i64,
    audience: Option<&str>,
) -> Result<TicketClaims, TicketError> {
    let (payload, kid) = signed::verify(ticket, TICKET_CONTEXT, keys, MAX_TICKET_LEN)?;
    let claims: TicketClaims =
        serde_json::from_slice(&payload).map_err(|_| TicketError::Payload)?;
    if claims.v != 1 {
        return Err(TicketError::Version(claims.v));
    }
    if claims.kid != kid
        || !is_opaque(&claims.sub, MAX_OPAQUE_LEN)
        || !is_opaque(&claims.prj, MAX_OPAQUE_LEN)
        || !is_id(&claims.jti, 64)
        || claims.jti.len() < 16
    {
        return Err(TicketError::Payload);
    }
    if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_LIFETIME_S {
        return Err(TicketError::Lifetime);
    }
    if claims.iat > now_s + CLOCK_SKEW_S {
        return Err(TicketError::NotYetValid);
    }
    if now_s >= claims.exp + CLOCK_SKEW_S {
        return Err(TicketError::Expired);
    }
    if let Some(expected) = audience {
        if claims.aud.as_deref() != Some(expected) {
            return Err(TicketError::Audience);
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64;
    use ed25519_dalek::SigningKey;

    fn keys(k: &SigningKey) -> KeySet {
        KeySet::parse(&format!("t1:{}", b64(k.verifying_key().as_bytes()))).unwrap()
    }

    fn claims(iat: i64, exp: i64) -> TicketClaims {
        TicketClaims {
            v: 1,
            kid: "t1".into(),
            sub: "u-42".into(),
            prj: "p-7".into(),
            role: Role::Member,
            seat_ok: true,
            iat,
            exp,
            jti: "0123456789abcdef".into(),
            aud: None,
        }
    }

    fn ticket(k: &SigningKey, c: &TicketClaims) -> String {
        signed::sign(&serde_json::to_vec(c).unwrap(), TICKET_CONTEXT, k)
    }

    #[test]
    fn gültiges_ticket() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let t = ticket(&k, &claims(1000, 1060));
        assert_eq!(verify(&t, &keys(&k), 1010, None).unwrap().sub, "u-42");
    }

    #[test]
    fn zeitfenster() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let t = ticket(&k, &claims(1000, 1060));
        assert_eq!(verify(&t, &keys(&k), 1090, None), Err(TicketError::Expired));
        assert_eq!(
            verify(&t, &keys(&k), 900, None),
            Err(TicketError::NotYetValid)
        );
        let long = ticket(&k, &claims(1000, 2000));
        assert_eq!(
            verify(&long, &keys(&k), 1010, None),
            Err(TicketError::Lifetime)
        );
    }

    #[test]
    fn zielgruppe() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let mut c = claims(1000, 1060);
        c.aud = Some("https://a.example".into());
        let t = ticket(&k, &c);
        assert!(verify(&t, &keys(&k), 1010, Some("https://a.example")).is_ok());
        assert_eq!(
            verify(&t, &keys(&k), 1010, Some("https://b.example")),
            Err(TicketError::Audience)
        );
    }

    #[test]
    fn kid_in_payload_muss_passen_und_jti_lang_genug() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let mut c = claims(1000, 1060);
        c.jti = "kurz".into();
        assert_eq!(
            verify(&ticket(&k, &c), &keys(&k), 1010, None),
            Err(TicketError::Payload)
        );
    }
}
