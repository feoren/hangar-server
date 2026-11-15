//! Tickets for the live connection (format: `docs/ticket-format.md`).
//!
//! The website (official mode) or the built-in identity (self-hosting) issues a short-lived
//! ticket; the app passes it on unchanged in `hello`. The relay checks signature, kid, time
//! window and audience; single use of the `jti` is checked by [`crate::relay::store`] in the
//! database.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signed::{self, KeySet, SignedError, TICKET_CONTEXT};
use crate::util::{is_id, is_opaque};

/// Longest ticket (same as the protocol's `MAX_TICKET_LEN`).
pub const MAX_TICKET_LEN: usize = 2048;
/// Longest opaque identifier (account, project).
pub const MAX_OPAQUE_LEN: usize = 128;
/// Allowed clock skew between issuer and relay, in seconds.
pub const CLOCK_SKEW_S: i64 = 30;
/// Longest allowed validity of a ticket; the website issues 60 s.
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

    /// Rank: owner > admin > member.
    pub fn rank(self) -> u8 {
        match self {
            Role::Owner => 3,
            Role::Admin => 2,
            Role::Member => 1,
        }
    }
}

/// Contents of a ticket. Unknown fields are ignored (later extensions on the website do not
/// break old relays); an incompatible change increments `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketClaims {
    pub v: u32,
    pub kid: String,
    /// Account ID of the website (opaque).
    pub sub: String,
    /// Project ID of the website = team (opaque).
    pub prj: String,
    pub role: Role,
    /// The website confirms that this person has a seat in the team.
    pub seat_ok: bool,
    pub iat: i64,
    pub exp: i64,
    /// One-time identifier against reuse.
    pub jti: String,
    /// Optional: which relay the ticket is valid for (origin, e.g. `https://team.hangar.feoren.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TicketError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("the payload does not match the ticket format")]
    Payload,
    #[error("version {0} is not supported")]
    Version(u32),
    #[error("the ticket has expired")]
    Expired,
    #[error("the ticket is not yet valid")]
    NotYetValid,
    #[error("the validity is longer than allowed")]
    Lifetime,
    #[error("the ticket is for a different relay")]
    Audience,
}

/// Fully verifies a ticket except for `jti` reuse.
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
    fn valid_ticket() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let t = ticket(&k, &claims(1000, 1060));
        assert_eq!(verify(&t, &keys(&k), 1010, None).unwrap().sub, "u-42");
    }

    #[test]
    fn time_window() {
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
    fn audience() {
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
    fn kid_in_payload_must_match_and_jti_long_enough() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let mut c = claims(1000, 1060);
        c.jti = "short".into();
        assert_eq!(
            verify(&ticket(&k, &c), &keys(&k), 1010, None),
            Err(TicketError::Payload)
        );
    }
}
