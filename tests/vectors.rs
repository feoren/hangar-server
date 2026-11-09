//! Testvektoren für Tickets und Lizenzen (`testdata/*.json`), damit die PHP-Seite der Webseite
//! dasselbe Format bauen und gegenprüfen kann. Ed25519 ist deterministisch: dieselbe Payload mit
//! demselben Schlüssel ergibt dieselbe Signatur.
//!
//! Neu schreiben: `REGENERATE_VECTORS=1 cargo test --test vectors`.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use hangar_team_server::license::{self, LicenseError};
use hangar_team_server::signed::{self, KeySet, SignedError, LICENSE_CONTEXT, TICKET_CONTEXT};
use hangar_team_server::ticket::{self, TicketError};
use hangar_team_server::util::{b64, hex};
use serde_json::{json, Value};

/// Geheimer Schlüssel aus RFC 8032, Abschnitt 7.1, Test 1: öffentlich bekannt, nur für Tests.
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// Ein zweiter Testschlüssel für "fremde Signatur" (RFC 8032, Test 2).
const OTHER_SEED_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const KID: &str = "test-2026-1";
/// Feste Prüfzeit: 2026-11-09T12:00:00Z.
const NOW: i64 = 1_794_225_600;

fn seed(hex_text: &str) -> SigningKey {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex_text[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    SigningKey::from_bytes(&bytes.try_into().unwrap())
}

fn keys() -> KeySet {
    KeySet::parse(&format!(
        "{KID}:{}",
        b64(seed(SEED_HEX).verifying_key().as_bytes())
    ))
    .unwrap()
}

struct Case {
    name: &'static str,
    payload: String,
    context: &'static str,
    other_key: bool,
    tamper: bool,
    expect: &'static str,
}

/// Zielgruppe des offiziellen Relays; jedes Ticket trägt sie (Pflicht im Relay).
const AUD: &str = "hangar-relay";

fn ticket_payload(iat: i64, exp: i64, kid: &str, jti: &str) -> String {
    format!(
        r#"{{"v":1,"kid":"{kid}","sub":"1042","prj":"317","role":"member","seat_ok":true,"iat":{iat},"exp":{exp},"jti":"{jti}","aud":"{AUD}"}}"#
    )
}

fn ticket_payload_without_aud(iat: i64, exp: i64) -> String {
    format!(
        r#"{{"v":1,"kid":"{KID}","sub":"1042","prj":"317","role":"member","seat_ok":true,"iat":{iat},"exp":{exp},"jti":"Zx8qW2u0Tt6m1d9KcPq3vA"}}"#
    )
}

fn license_payload(email: &str, exp: i64, extra: &str) -> String {
    format!(
        r#"{{"v":1,"kid":"{KID}","lid":"lic_8f3a2c","sub":"1042","email":"{email}","plan":"team","seats":10{extra},"iat":1793900000,"exp":{exp}}}"#
    )
}

fn ticket_cases() -> Vec<Case> {
    let jti = "Zx8qW2u0Tt6m1d9KcPq3vA";
    let c = |name, payload, context, other_key, tamper, expect| Case {
        name,
        payload,
        context,
        other_key,
        tamper,
        expect,
    };
    vec![
        c(
            "valid",
            ticket_payload(NOW - 10, NOW + 50, KID, jti),
            TICKET_CONTEXT,
            false,
            false,
            "ok",
        ),
        c(
            "expired",
            ticket_payload(NOW - 200, NOW - 140, KID, jti),
            TICKET_CONTEXT,
            false,
            false,
            "expired",
        ),
        c(
            "not_yet_valid",
            ticket_payload(NOW + 120, NOW + 180, KID, jti),
            TICKET_CONTEXT,
            false,
            false,
            "not_yet_valid",
        ),
        c(
            "lifetime_too_long",
            ticket_payload(NOW - 10, NOW + 3600, KID, jti),
            TICKET_CONTEXT,
            false,
            false,
            "lifetime",
        ),
        c(
            "foreign_signature",
            ticket_payload(NOW - 10, NOW + 50, KID, jti),
            TICKET_CONTEXT,
            true,
            false,
            "bad_signature",
        ),
        c(
            "unknown_kid",
            ticket_payload(NOW - 10, NOW + 50, "test-2099-9", jti),
            TICKET_CONTEXT,
            false,
            false,
            "unknown_key",
        ),
        c(
            "tampered_payload",
            ticket_payload(NOW - 10, NOW + 50, KID, jti),
            TICKET_CONTEXT,
            false,
            true,
            "bad_signature",
        ),
        c(
            "license_context",
            ticket_payload(NOW - 10, NOW + 50, KID, jti),
            LICENSE_CONTEXT,
            false,
            false,
            "bad_signature",
        ),
        c(
            "short_jti",
            ticket_payload(NOW - 10, NOW + 50, KID, "abc"),
            TICKET_CONTEXT,
            false,
            false,
            "payload",
        ),
        c(
            "missing_aud",
            ticket_payload_without_aud(NOW - 10, NOW + 50),
            TICKET_CONTEXT,
            false,
            false,
            "audience",
        ),
    ]
}

fn license_cases() -> Vec<Case> {
    let c = |name, payload, context, other_key, tamper, expect| Case {
        name,
        payload,
        context,
        other_key,
        tamper,
        expect,
    };
    vec![
        c(
            "valid",
            license_payload("owner@example.org", 1_825_502_400, ""),
            LICENSE_CONTEXT,
            false,
            false,
            "ok:10",
        ),
        c(
            "valid_with_features",
            license_payload("owner@example.org", 1_825_502_400, r#","features":["sso"]"#),
            LICENSE_CONTEXT,
            false,
            false,
            "ok:10",
        ),
        c(
            "expired",
            license_payload("owner@example.org", NOW - 1, ""),
            LICENSE_CONTEXT,
            false,
            false,
            "ok:3",
        ),
        c(
            "foreign_signature",
            license_payload("owner@example.org", 1_825_502_400, ""),
            LICENSE_CONTEXT,
            true,
            false,
            "bad_signature",
        ),
        c(
            "tampered_payload",
            license_payload("owner@example.org", 1_825_502_400, ""),
            LICENSE_CONTEXT,
            false,
            true,
            "bad_signature",
        ),
        c(
            "ticket_context",
            license_payload("owner@example.org", 1_825_502_400, ""),
            TICKET_CONTEXT,
            false,
            false,
            "bad_signature",
        ),
        c(
            "email_not_normalized",
            license_payload("Owner@Example.org", 1_825_502_400, ""),
            LICENSE_CONTEXT,
            false,
            false,
            "payload",
        ),
    ]
}

fn document(case: &Case) -> String {
    let key = seed(if case.other_key {
        OTHER_SEED_HEX
    } else {
        SEED_HEX
    });
    let doc = signed::sign(case.payload.as_bytes(), case.context, &key);
    if !case.tamper {
        return doc;
    }
    // Plätze bzw. Rolle verändern, Signatur behalten.
    let (_, sig) = doc.split_once('.').unwrap();
    let forged = case
        .payload
        .replace("\"seats\":10", "\"seats\":1000")
        .replace("\"role\":\"member\"", "\"role\":\"owner\"");
    format!("{}.{sig}", b64(forged.as_bytes()))
}

fn ticket_outcome(doc: &str) -> String {
    match ticket::verify(doc, &keys(), NOW, Some(AUD)) {
        Ok(_) => "ok".into(),
        Err(TicketError::Expired) => "expired".into(),
        Err(TicketError::NotYetValid) => "not_yet_valid".into(),
        Err(TicketError::Lifetime) => "lifetime".into(),
        Err(TicketError::Payload) => "payload".into(),
        Err(TicketError::Audience) => "audience".into(),
        Err(TicketError::Signed(SignedError::BadSignature)) => "bad_signature".into(),
        Err(TicketError::Signed(SignedError::UnknownKey)) => "unknown_key".into(),
        Err(other) => format!("{other:?}"),
    }
}

fn license_outcome(doc: &str) -> String {
    match license::verify(doc, &keys(), &[]) {
        Ok(claims) => format!("ok:{}", claims.effective_seats(NOW)),
        Err(LicenseError::Payload) => "payload".into(),
        Err(LicenseError::Signed(SignedError::BadSignature)) => "bad_signature".into(),
        Err(other) => format!("{other:?}"),
    }
}

fn file(kind: &str, context: &str, cases: &[Case]) -> Value {
    let key = seed(SEED_HEX);
    json!({
        "description": format!("Testvektoren {kind} (docs/{kind}-format.md). Schlüssel aus RFC 8032 7.1, nur für Tests."),
        "context": context,
        "now": NOW,
        "key": {
            "kid": KID,
            "seed_hex": SEED_HEX,
            "public_key_base64url": b64(key.verifying_key().as_bytes()),
            "public_key_hex": hex(key.verifying_key().as_bytes()),
        },
        "other_key_seed_hex": OTHER_SEED_HEX,
        "vectors": cases.iter().map(|c| json!({
            "name": c.name,
            "payload_json": c.payload,
            "signing_context": c.context,
            "signed_with": if c.other_key { "other_key" } else { "key" },
            "tampered": c.tamper,
            "document": document(c),
            "expect": c.expect,
        })).collect::<Vec<_>>(),
    })
}

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

fn check(name: &str, kind: &str, context: &str, cases: &[Case], outcome: fn(&str) -> String) {
    let built = file(kind, context, cases);
    if std::env::var("REGENERATE_VECTORS").is_ok() {
        std::fs::write(
            path(name),
            serde_json::to_string_pretty(&built).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(path(name)).expect("Testvektoren vorhanden"))
            .unwrap();
    assert_eq!(
        stored, built,
        "{name} ist veraltet: REGENERATE_VECTORS=1 setzen"
    );
    for vector in stored["vectors"].as_array().unwrap() {
        let doc = vector["document"].as_str().unwrap();
        assert_eq!(
            outcome(doc),
            vector["expect"].as_str().unwrap(),
            "{name}: {}",
            vector["name"]
        );
    }
}

#[test]
fn ticket_vektoren() {
    check(
        "tickets.json",
        "ticket",
        TICKET_CONTEXT,
        &ticket_cases(),
        ticket_outcome,
    );
}

#[test]
fn lizenz_vektoren() {
    check(
        "licenses.json",
        "license",
        LICENSE_CONTEXT,
        &license_cases(),
        license_outcome,
    );
}

#[test]
fn widerrufene_lizenz() {
    let doc = document(&license_cases()[0]);
    assert_eq!(
        license::verify(&doc, &keys(), &["lic_8f3a2c".into()]),
        Err(LicenseError::Revoked)
    );
}

/// Gegenprobe gegen RFC 8032: der öffentliche Schlüssel des Testsamens ist bekannt.
#[test]
fn rfc8032_schlüssel() {
    assert_eq!(
        hex(seed(SEED_HEX).verifying_key().as_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
}

/// Gegenprobe mit dem Testvektor der Webseite (`tests/php/fixtures/revocations-vector.json`
/// im Webseiten-Repository, hier als `testdata/revocations-website.json`): was die PHP-Seite
/// signiert, muss `revocation::verify` annehmen bzw. ablehnen wie dort angegeben.
#[test]
fn widerrufsliste_der_webseite() {
    use hangar_team_server::relay::revocation::{self, Revocation, RevocationError};
    use hangar_team_server::ticket::Role;

    let stored: Value = serde_json::from_str(
        &std::fs::read_to_string(path("revocations-website.json")).expect("Vektor der Webseite"),
    )
    .unwrap();
    assert_eq!(stored["context"], "hangar-revoke-v1");
    let keys = KeySet::parse(&format!(
        "{}:{}",
        stored["key"]["kid"].as_str().unwrap(),
        stored["key"]["public_key_base64url"].as_str().unwrap()
    ))
    .unwrap();
    let audience = stored["audience"].as_str().unwrap();
    let now = stored["now"].as_i64().unwrap();
    let vectors = stored["vectors"].as_array().unwrap();
    let names: Vec<&str> = vectors
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "valid",
            "empty",
            "expired",
            "ticket_context",
            "other_key",
            "tampered"
        ]
    );
    for vector in vectors {
        let payload: Value =
            serde_json::from_str(vector["payload_json"].as_str().unwrap()).unwrap();
        let after = payload["after"].as_str().unwrap();
        let result = revocation::verify(
            vector["document"].as_str().unwrap(),
            &keys,
            audience,
            after,
            now,
        );
        let outcome = match &result {
            Ok(_) => "ok".to_owned(),
            Err(RevocationError::Time) => "expired".to_owned(),
            Err(RevocationError::Signed(SignedError::BadSignature)) => "bad_signature".to_owned(),
            Err(other) => format!("{other:?}"),
        };
        assert_eq!(
            outcome,
            vector["expect"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
        // Eine angenommene Liste gilt nur für den angefragten Cursor.
        if result.is_ok() {
            assert_eq!(
                revocation::verify(
                    vector["document"].as_str().unwrap(),
                    &keys,
                    audience,
                    "0",
                    now
                ),
                Err(RevocationError::Cursor)
            );
        }
    }
    let page = revocation::verify(
        vectors[0]["document"].as_str().unwrap(),
        &keys,
        audience,
        "40",
        now,
    )
    .unwrap();
    assert_eq!((page.last.as_str(), page.more), ("44", false));
    assert_eq!(
        page.items,
        vec![
            (
                "41".to_owned(),
                Some(Revocation::MemberRemoved {
                    prj: "317".into(),
                    sub: "1042".into(),
                    at_ms: 1_794_225_500_000
                })
            ),
            (
                "42".to_owned(),
                Some(Revocation::RoleChanged {
                    prj: "317".into(),
                    sub: "1043".into(),
                    role: Some(Role::Member),
                    at_ms: 1_794_225_510_000
                })
            ),
            (
                "43".to_owned(),
                Some(Revocation::ProjectDeleted { prj: "318".into() })
            ),
            (
                "44".to_owned(),
                Some(Revocation::SeatLost {
                    prj: "317".into(),
                    sub: "1044".into(),
                    at_ms: 1_794_225_530_000
                })
            ),
        ]
    );
    let empty = revocation::verify(
        vectors[1]["document"].as_str().unwrap(),
        &keys,
        audience,
        "44",
        now,
    )
    .unwrap();
    assert_eq!((empty.last.as_str(), empty.items.len()), ("44", 0));
    // Die Beispielantwort ist das gültige Dokument.
    assert_eq!(stored["response_example"]["body"], vectors[0]["document"]);
}
