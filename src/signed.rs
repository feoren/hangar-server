//! Kompakte, Ed25519-signierte Dokumente (Tickets und Lizenzen), Format in
//! `docs/ticket-format.md` und `docs/license-format.md`.
//!
//! Aufbau: `base64url(payload) "." base64url(signature)`, beide ohne Auffüllung. Signiert wird
//! nicht das JSON selbst, sondern die ASCII-Bytes `"<kontext>." + base64url(payload)`. Damit
//! braucht keine Seite kanonisches JSON (geprüft werden genau die gesendeten Bytes), und der
//! Kontext trennt die Dokumentarten: eine Lizenz gilt nie als Ticket und umgekehrt.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;

use crate::util::{b64, is_id, unb64};

/// Kontext der Tickets für die Live-Verbindung.
pub const TICKET_CONTEXT: &str = "hangar-ticket-v1";
/// Kontext der Lizenzdokumente.
pub const LICENSE_CONTEXT: &str = "hangar-license-v1";
/// Kontext der Widerrufsliste, die das Relay im offiziellen Betrieb von der Webseite holt.
pub const REVOKE_CONTEXT: &str = "hangar-revoke-v1";
/// Längste Schlüssel-ID.
pub const MAX_KID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignedError {
    #[error("das Dokument ist zu lang")]
    TooLong,
    #[error("das Dokument hat nicht die Form payload.signature")]
    Shape,
    #[error("die Kodierung ist kein base64url ohne Auffüllung")]
    Encoding,
    #[error("der Inhalt ist kein JSON-Objekt mit gültiger kid")]
    Payload,
    #[error("die Schlüssel-ID ist unbekannt")]
    UnknownKey,
    #[error("die Signatur ist ungültig")]
    BadSignature,
}

/// Öffentliche Schlüssel nach Schlüssel-ID. Mehrere gleichzeitig erlauben die Rotation: der
/// neue Schlüssel wird ergänzt, bevor die Webseite mit ihm signiert, der alte entfernt, wenn
/// keine mit ihm signierten Dokumente mehr gültig sind.
#[derive(Clone, Default)]
pub struct KeySet {
    keys: BTreeMap<String, VerifyingKey>,
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.keys.keys()).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeySetError {
    #[error("Eintrag {0}: erwartet kid:base64url")]
    Entry(usize),
    #[error("Eintrag {0}: die kid ist ungültig ([A-Za-z0-9_-], höchstens 64 Zeichen)")]
    Kid(usize),
    #[error("Eintrag {0}: kein öffentlicher Ed25519-Schlüssel (32 Byte base64url)")]
    Key(usize),
    #[error("die kid {0} kommt doppelt vor")]
    Duplicate(String),
}

impl KeySet {
    /// Liest `kid:base64url,kid2:base64url`. Leerer Text ergibt eine leere Menge.
    pub fn parse(text: &str) -> Result<Self, KeySetError> {
        let mut set = KeySet::default();
        for (index, entry) in text
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .enumerate()
        {
            let number = index + 1;
            let (kid, key) = entry.split_once(':').ok_or(KeySetError::Entry(number))?;
            let (kid, key) = (kid.trim(), key.trim());
            if !is_id(kid, MAX_KID_LEN) {
                return Err(KeySetError::Kid(number));
            }
            let bytes: [u8; 32] = unb64(key)
                .and_then(|b| b.try_into().ok())
                .ok_or(KeySetError::Key(number))?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| KeySetError::Key(number))?;
            if set.keys.insert(kid.to_owned(), key).is_some() {
                return Err(KeySetError::Duplicate(kid.to_owned()));
            }
        }
        Ok(set)
    }

    pub fn insert(&mut self, kid: &str, key: VerifyingKey) {
        self.keys.insert(kid.to_owned(), key);
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}

#[derive(Deserialize)]
struct KidOnly {
    kid: String,
}

/// Prüft ein kompaktes Dokument und gibt die signierten Payload-Bytes und die kid zurück.
/// Die Payload wird vor der Prüfung nur gelesen, um die kid zu finden; ihr übriger Inhalt zählt
/// erst nach erfolgreicher Prüfung.
pub fn verify(
    document: &str,
    context: &str,
    keys: &KeySet,
    max_len: usize,
) -> Result<(Vec<u8>, String), SignedError> {
    if document.len() > max_len {
        return Err(SignedError::TooLong);
    }
    let (payload_b64, sig_b64) = document.split_once('.').ok_or(SignedError::Shape)?;
    if payload_b64.is_empty() || sig_b64.contains('.') {
        return Err(SignedError::Shape);
    }
    let payload = unb64(payload_b64).ok_or(SignedError::Encoding)?;
    let signature: [u8; 64] = unb64(sig_b64)
        .and_then(|s| s.try_into().ok())
        .ok_or(SignedError::Encoding)?;
    let kid = serde_json::from_slice::<KidOnly>(&payload)
        .map_err(|_| SignedError::Payload)?
        .kid;
    if !is_id(&kid, MAX_KID_LEN) {
        return Err(SignedError::Payload);
    }
    let key = keys.keys.get(&kid).ok_or(SignedError::UnknownKey)?;
    let input = signing_input(context, payload_b64);
    key.verify_strict(input.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| SignedError::BadSignature)?;
    Ok((payload, kid))
}

/// Signiert JSON-Bytes (Selbstbetrieb stellt so Tickets aus; die Tests bauen so Testvektoren).
pub fn sign(payload_json: &[u8], context: &str, key: &SigningKey) -> String {
    let payload_b64 = b64(payload_json);
    let signature = key.sign(signing_input(context, &payload_b64).as_bytes());
    format!("{payload_b64}.{}", b64(&signature.to_bytes()))
}

fn signing_input(context: &str, payload_b64: &str) -> String {
    format!("{context}.{payload_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn set(kid: &str, key: &SigningKey) -> KeySet {
        KeySet::parse(&format!("{kid}:{}", b64(key.verifying_key().as_bytes()))).unwrap()
    }

    #[test]
    fn signieren_und_prüfen() {
        let k = key(7);
        let doc = sign(br#"{"kid":"a1","x":1}"#, TICKET_CONTEXT, &k);
        let (payload, kid) = verify(&doc, TICKET_CONTEXT, &set("a1", &k), 4096).unwrap();
        assert_eq!(kid, "a1");
        assert_eq!(payload, br#"{"kid":"a1","x":1}"#);
    }

    #[test]
    fn kontext_trennt_dokumentarten() {
        let k = key(7);
        let doc = sign(br#"{"kid":"a1"}"#, LICENSE_CONTEXT, &k);
        assert_eq!(
            verify(&doc, TICKET_CONTEXT, &set("a1", &k), 4096),
            Err(SignedError::BadSignature)
        );
    }

    #[test]
    fn fremder_schlüssel_und_unbekannte_kid() {
        let doc = sign(br#"{"kid":"a1"}"#, TICKET_CONTEXT, &key(7));
        assert_eq!(
            verify(&doc, TICKET_CONTEXT, &set("a1", &key(8)), 4096),
            Err(SignedError::BadSignature)
        );
        assert_eq!(
            verify(&doc, TICKET_CONTEXT, &set("b2", &key(7)), 4096),
            Err(SignedError::UnknownKey)
        );
    }

    #[test]
    fn veränderte_payload_scheitert() {
        let k = key(7);
        let doc = sign(br#"{"kid":"a1","seats":3}"#, LICENSE_CONTEXT, &k);
        let (_, sig) = doc.split_once('.').unwrap();
        let forged = format!("{}.{sig}", b64(br#"{"kid":"a1","seats":300}"#));
        assert_eq!(
            verify(&forged, LICENSE_CONTEXT, &set("a1", &k), 4096),
            Err(SignedError::BadSignature)
        );
    }

    #[test]
    fn form_und_länge() {
        let keys = set("a1", &key(7));
        assert_eq!(
            verify("abc", TICKET_CONTEXT, &keys, 4096),
            Err(SignedError::Shape)
        );
        assert_eq!(
            verify("a.b.c", TICKET_CONTEXT, &keys, 4096),
            Err(SignedError::Shape)
        );
        assert_eq!(
            verify(&"a".repeat(5000), TICKET_CONTEXT, &keys, 4096),
            Err(SignedError::TooLong)
        );
        assert_eq!(
            verify("e30.AAAA", TICKET_CONTEXT, &keys, 4096),
            Err(SignedError::Encoding)
        );
    }

    #[test]
    fn schlüsselliste() {
        let k = key(1);
        let pk = b64(k.verifying_key().as_bytes());
        assert!(KeySet::parse("").unwrap().is_empty());
        assert_eq!(
            KeySet::parse(&format!("a:{pk}, b:{pk}"))
                .unwrap()
                .kids()
                .count(),
            2
        );
        assert_eq!(KeySet::parse("a").err(), Some(KeySetError::Entry(1)));
        assert_eq!(
            KeySet::parse(&format!("a b:{pk}")).err(),
            Some(KeySetError::Kid(1))
        );
        assert_eq!(KeySet::parse("a:AAAA").err(), Some(KeySetError::Key(1)));
        assert!(matches!(
            KeySet::parse(&format!("a:{pk},a:{pk}")),
            Err(KeySetError::Duplicate(_))
        ));
    }
}
