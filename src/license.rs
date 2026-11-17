//! License documents of the website for self-hosting (format: `docs/license-format.md`).
//!
//! Model: seats per account. The owner buys `seats` seats; they apply to all teams the owner
//! has on this server. Distinct people are counted across all of the owner's teams, the owner
//! included. Without a valid license, Free with [`FREE_SEATS`] applies. When a license expires,
//! nothing is deleted; only joins beyond the Free limit are rejected.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signed::{self, KeySet, SignedError, LICENSE_CONTEXT};
use crate::util::{is_id, is_opaque, normalize_email};

/// Public key of the official website (hangar.feoren.com, `GET /api/v1/keys`) that signs license
/// documents. Used when `LICENSE_PUBLIC_KEYS` is empty; a non-empty value replaces it.
pub const OFFICIAL_LICENSE_KEYS: &str = "prod-20261109:7pwgqsy67kGFeqcHXk-59mFmkXESTE4xt33Y9bxwuJc";
/// Seats without a license (Free): three people.
pub const FREE_SEATS: u32 = 3;
/// Longest license document.
pub const MAX_LICENSE_LEN: usize = 4096;
/// Highest seat count a document may carry (guards against overflows in counts).
pub const MAX_SEATS: u32 = 100_000;
/// Allowed clock skew for `iat`, in seconds.
const CLOCK_SKEW_S: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub v: u32,
    pub kid: String,
    /// License ID of the website; on a server, the same license can be stored by one account only.
    pub lid: String,
    /// Account ID of the website (opaque).
    pub sub: String,
    /// Email address of the account; must match the address of the account storing it.
    pub email: String,
    /// Plan, e.g. `team`. Open for later tiers.
    pub plan: String,
    pub seats: u32,
    /// Optional extra features; in version 1 the server knows none and ignores them.
    #[serde(default)]
    pub features: Vec<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LicenseError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("the payload does not match the license format")]
    Payload,
    #[error("version {0} is not supported")]
    Version(u32),
    #[error("the license has been revoked")]
    Revoked,
    #[error("the license has expired")]
    Expired,
    #[error("the license is issued to a different email address")]
    EmailMismatch,
}

/// Checks signature, kid and shape. Time is checked by [`LicenseClaims::active`], so that an
/// expired license can still be displayed.
pub fn verify(
    document: &str,
    keys: &KeySet,
    revoked: &[String],
) -> Result<LicenseClaims, LicenseError> {
    let (payload, kid) = signed::verify(document.trim(), LICENSE_CONTEXT, keys, MAX_LICENSE_LEN)?;
    let claims: LicenseClaims =
        serde_json::from_slice(&payload).map_err(|_| LicenseError::Payload)?;
    if claims.v != 1 {
        return Err(LicenseError::Version(claims.v));
    }
    let plan_ok = !claims.plan.is_empty()
        && claims.plan.len() <= 32
        && claims
            .plan
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let features_ok = claims.features.len() <= 32 && claims.features.iter().all(|f| is_id(f, 64));
    if claims.kid != kid
        || !is_id(&claims.lid, 64)
        || !is_opaque(&claims.sub, 128)
        || normalize_email(&claims.email).as_deref() != Some(claims.email.as_str())
        || !plan_ok
        || !features_ok
        || claims.seats == 0
        || claims.seats > MAX_SEATS
        || claims.exp <= claims.iat
    {
        return Err(LicenseError::Payload);
    }
    if revoked.iter().any(|lid| lid == &claims.lid) {
        return Err(LicenseError::Revoked);
    }
    Ok(claims)
}

impl LicenseClaims {
    /// Valid at time `now_s`.
    pub fn active(&self, now_s: i64) -> bool {
        self.iat <= now_s + CLOCK_SKEW_S && now_s < self.exp
    }

    /// Seats that apply at time `now_s`.
    pub fn effective_seats(&self, now_s: i64) -> u32 {
        if self.active(now_s) {
            self.seats.max(FREE_SEATS)
        } else {
            FREE_SEATS
        }
    }
}

/// Seats of an account with or without a license.
pub fn seats_for(license: Option<&LicenseClaims>, now_s: i64) -> u32 {
    license.map_or(FREE_SEATS, |l| l.effective_seats(now_s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64;
    use ed25519_dalek::SigningKey;

    fn claims() -> LicenseClaims {
        LicenseClaims {
            v: 1,
            kid: "web-1".into(),
            lid: "lic_1".into(),
            sub: "42".into(),
            email: "owner@example.org".into(),
            plan: "team".into(),
            seats: 10,
            features: vec![],
            iat: 1000,
            exp: 2000,
        }
    }

    fn doc(k: &SigningKey, c: &LicenseClaims) -> String {
        signed::sign(&serde_json::to_vec(c).unwrap(), LICENSE_CONTEXT, k)
    }

    fn keys(k: &SigningKey) -> KeySet {
        KeySet::parse(&format!("web-1:{}", b64(k.verifying_key().as_bytes()))).unwrap()
    }

    #[test]
    fn seats_over_time() {
        let k = SigningKey::from_bytes(&[9; 32]);
        let c = verify(&doc(&k, &claims()), &keys(&k), &[]).unwrap();
        assert_eq!(c.effective_seats(1500), 10);
        assert_eq!(c.effective_seats(2000), FREE_SEATS);
        assert_eq!(seats_for(None, 1500), FREE_SEATS);
        let mut small = claims();
        small.seats = 1;
        assert_eq!(
            verify(&doc(&k, &small), &keys(&k), &[])
                .unwrap()
                .effective_seats(1500),
            FREE_SEATS
        );
    }

    #[test]
    fn revocation_and_shape() {
        let k = SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            verify(&doc(&k, &claims()), &keys(&k), &["lic_1".into()]),
            Err(LicenseError::Revoked)
        );
        let mut bad = claims();
        bad.email = "Owner@Example.org".into();
        assert_eq!(
            verify(&doc(&k, &bad), &keys(&k), &[]),
            Err(LicenseError::Payload)
        );
        let mut zero = claims();
        zero.seats = 0;
        assert_eq!(
            verify(&doc(&k, &zero), &keys(&k), &[]),
            Err(LicenseError::Payload)
        );
    }
}
