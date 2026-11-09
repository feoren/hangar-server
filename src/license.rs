//! Lizenzdokumente der Webseite für den Selbstbetrieb (Format: `docs/license-format.md`).
//!
//! Modell: Plätze je Konto. Der Eigentümer kauft `seats` Plätze; sie gelten für alle Teams, die
//! ihm auf diesem Server gehören. Gezählt werden verschiedene Personen über alle seine Teams,
//! der Eigentümer eingeschlossen. Ohne gültige Lizenz gilt Free mit [`FREE_SEATS`]. Läuft eine
//! Lizenz ab, wird nichts gelöscht; nur Beitritte über die Free-Grenze werden abgelehnt.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signed::{self, KeySet, SignedError, LICENSE_CONTEXT};
use crate::util::{is_id, is_opaque, normalize_email};

/// Plätze ohne Lizenz (Free): drei Personen.
pub const FREE_SEATS: u32 = 3;
/// Längstes Lizenzdokument.
pub const MAX_LICENSE_LEN: usize = 4096;
/// Höchste Platzzahl, die ein Dokument tragen darf (Schutz vor Überläufen in Zählungen).
pub const MAX_SEATS: u32 = 100_000;
/// Erlaubte Uhrenabweichung für `iat`, in Sekunden.
const CLOCK_SKEW_S: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub v: u32,
    pub kid: String,
    /// Lizenz-ID der Webseite; dieselbe Lizenz kann auf einem Server nur ein Konto hinterlegen.
    pub lid: String,
    /// Konto-ID der Webseite (opak).
    pub sub: String,
    /// E-Mail-Adresse des Kontos; muss zur Adresse des hinterlegenden Kontos passen.
    pub email: String,
    /// Tarif, z. B. `team`. Für spätere Staffelungen offen.
    pub plan: String,
    pub seats: u32,
    /// Optionale Zusatzfunktionen; der Server kennt in Version 1 keine und ignoriert sie.
    #[serde(default)]
    pub features: Vec<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LicenseError {
    #[error(transparent)]
    Signed(#[from] SignedError),
    #[error("der Inhalt passt nicht zum Lizenzformat")]
    Payload,
    #[error("Version {0} wird nicht unterstützt")]
    Version(u32),
    #[error("die Lizenz wurde widerrufen")]
    Revoked,
    #[error("die Lizenz ist abgelaufen")]
    Expired,
    #[error("die Lizenz ist auf eine andere E-Mail-Adresse ausgestellt")]
    EmailMismatch,
}

/// Prüft Signatur, kid und Form. Die Zeit prüft [`LicenseClaims::active`], damit eine
/// abgelaufene Lizenz weiter angezeigt werden kann.
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
    /// Gültig zum Zeitpunkt `now_s`.
    pub fn active(&self, now_s: i64) -> bool {
        self.iat <= now_s + CLOCK_SKEW_S && now_s < self.exp
    }

    /// Plätze, die zum Zeitpunkt `now_s` gelten.
    pub fn effective_seats(&self, now_s: i64) -> u32 {
        if self.active(now_s) {
            self.seats.max(FREE_SEATS)
        } else {
            FREE_SEATS
        }
    }
}

/// Plätze eines Kontos mit oder ohne Lizenz.
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
    fn plätze_nach_zeit() {
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
    fn widerruf_und_form() {
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
