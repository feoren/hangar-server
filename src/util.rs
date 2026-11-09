//! Kleine Helfer ohne Zustand: Zeit, Zufall, Kodierung, Hashes.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Unix-Zeit in Millisekunden nach der Uhr des Servers.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Unix-Zeit in Sekunden.
pub fn now_s() -> i64 {
    i64::try_from(now_ms() / 1000).unwrap_or(i64::MAX)
}

/// Kryptografisch sichere Zufallsbytes aus dem Betriebssystem. Ein Fehler hier ist nicht
/// behebbar (kein Zufall heißt keine sicheren Tokens), deshalb bricht der Aufruf ab.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut out)
        .expect("der Zufallsgenerator des Betriebssystems ist nicht verfügbar");
    out
}

/// 32 Zufallsbytes als base64url ohne Auffüllung (43 Zeichen).
pub fn random_token() -> String {
    b64(&random_bytes::<32>())
}

/// 16 Zufallsbytes als base64url (22 Zeichen); für Kennungen, die keine Geheimnisse sind.
pub fn random_id() -> String {
    b64(&random_bytes::<16>())
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strenges base64url ohne Auffüllung; alles andere ist ein Fehler.
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.as_bytes()).ok()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// SHA-256 eines Tokens als Hex; so liegen Tokens in der Datenbank.
pub fn token_hash(token: &str) -> String {
    hex(&sha256(token.as_bytes()))
}

/// HMAC-SHA256 mit dem Server-Geheimnis, als Hex.
pub fn hmac_hex(key: &[u8], parts: &[&[u8]]) -> String {
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC nimmt Schlüssel jeder Länge");
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        mac.update(&len.to_be_bytes());
        mac.update(part);
    }
    hex(&mac.finalize().into_bytes())
}

/// Vergleich in konstanter Zeit.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Kennungen, die der Server oder ein Client erzeugt: `[A-Za-z0-9_-]`, 1 bis `max` Zeichen.
pub fn is_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Opake Kennungen von außen (Projekt- und Konto-ID der Webseite): kein Steuerzeichen.
pub fn is_opaque(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// Normalisiert eine E-Mail-Adresse für Vergleiche (Kleinschreibung, ohne Rand). Prüft grob
/// die Form: genau ein `@`, beide Teile nicht leer, keine Leer- oder Steuerzeichen, höchstens
/// 254 Zeichen.
pub fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    if email.len() > 254 || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.len() < 3 || domain.contains('@') || !domain.contains('.') {
        return None;
    }
    if domain.starts_with('.') || domain.ends_with('.') || local.contains(['<', '>', '"', ',', ';'])
    {
        return None;
    }
    Some(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_wird_normalisiert_und_geprüft() {
        assert_eq!(
            normalize_email(" A@Example.ORG "),
            Some("a@example.org".into())
        );
        assert_eq!(normalize_email("a@b"), None);
        assert_eq!(normalize_email("a b@example.org"), None);
        assert_eq!(normalize_email("a@@example.org"), None);
        assert_eq!(normalize_email("<a>@example.org"), None);
        assert_eq!(normalize_email("a@example.org\r\nBcc: x@y.z"), None);
    }

    #[test]
    fn kennungen() {
        assert!(is_id("abc-DEF_09", 64));
        assert!(!is_id("", 64));
        assert!(!is_id("a b", 64));
        assert!(is_opaque("projekt 12 / ä", 128));
        assert!(!is_opaque("a\nb", 128));
    }

    #[test]
    fn base64url_ist_streng() {
        assert_eq!(unb64(&b64(b"hangar")), Some(b"hangar".to_vec()));
        assert_eq!(unb64("aGFuZ2Fy="), None);
        assert_eq!(unb64("aGFu+2Fy"), None);
    }
}
