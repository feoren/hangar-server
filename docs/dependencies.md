# Abhängigkeiten

Versionen sind in `Cargo.lock` fest (`cargo build --locked`). Stand der Auswahl: 2026-11-09.
Alle Laufzeit-Abhängigkeiten stehen unter MIT, Apache-2.0, BSD-3-Clause oder ISC
(bzw. Doppellizenzen daraus) und vertragen sich mit der Elastic License 2.0 des Servers. Über das
Protokoll-Crate kommt `unicode-normalization` ((MIT OR Apache-2.0) AND Unicode-3.0, eine von der
App dokumentierte, freizügige Ausnahme für die Unicode-Tabellen) hinzu.

| Crate | Version | Lizenz | Zweck und Begründung | Alternative |
| --- | --- | --- | --- | --- |
| hangar-team-crypto | Kopie aus `b30b9d5` (`vendor/`) | MIT | Prüfung des Mitgliedschafts-Logs, der Rotationen, Geräteentfernungen und Schlüsselpakete (Schritt E); gehört der App, keine Geheimnisse im Relay. Bringt `hpke` 0.15, `chacha20poly1305` 0.11, `ed25519-dalek` 3, `hkdf` 0.13, `getrandom` 0.4, `data-encoding` 2 mit (alle MIT/Apache-2.0 bzw. BSD-3-Clause/MIT) | eigene Prüfung (zweite Quelle für dieselben Regeln) |
| hangar-team-protocol | Kopie aus `b30b9d5` (`vendor/`) | MIT | Wire-Format, Keyed Hashes, Reservierung, Claims, Log, E2E-Regeln; gehört der App (Schritt C), eine Quelle für beide Seiten. Per `git`/`rev` gepinnt statt `path`, damit nicht committete Arbeit im Worktree der App den Server nicht verändert | `path` auf den Worktree (nur zum Entwickeln) |
| axum | 0.8.9 | MIT | HTTP und WebSocket, Plan-Vorgabe; tokio-Projekt, aktiv gepflegt | actix-web (eigene Laufzeit), hyper direkt (viel eigener Code) |
| tokio | 1.54 | MIT | Laufzeit, Zeitgeber, Signale; Standard im Rust-Ökosystem | smol (kleineres Ökosystem) |
| sqlx | 0.9.0 | MIT/Apache-2.0 | SQLite (WAL), Migrationen (`migrate!` bettet `migrations/` ein); Plan-Vorgabe; `sqlite-bundled` baut SQLite mit ein (statisches Binary) | rusqlite (synchron, eigenes Pooling) |
| serde, serde_json | 1 | MIT/Apache-2.0 | JSON-Rahmen und Dokumente, wie in der App | keine sinnvolle |
| thiserror | 2 | MIT/Apache-2.0 | Fehlertypen, wie in der App | von Hand |
| ed25519-dalek | 2.2 | BSD-3-Clause | Prüfung der Tickets und Lizenzen, Ausstellen der Tickets im Selbstbetrieb; `verify_strict`; dalek-cryptography, geprüft und verbreitet. Version 3.0 ist erschienen, aber jung; 2.2 teilt sich sha2 0.10 mit dem übrigen Baum | ring (kein Ed25519-Import roher Schlüssel in allen Varianten), libsodium (C) |
| sha2 0.10, hmac 0.12, subtle 2.6 | | MIT/Apache-2.0 bzw. BSD-3-Clause | Token-Hashes, HMAC für CSRF und Ratenbegrenzungs-Schlüssel, Vergleich in konstanter Zeit; RustCrypto | ring |
| base64 | 0.22 | MIT/Apache-2.0 | base64url ohne Auffüllung, streng | von Hand |
| getrandom | 0.3 | MIT/Apache-2.0 | Zufall direkt vom Betriebssystem für Tokens und Schlüssel | rand (größer, hier unnötig) |
| futures-util | 0.3 | MIT/Apache-2.0 | `split` des WebSockets in Lesen und Schreiben | schon über axum im Baum |
| tracing, tracing-subscriber | 0.1 / 0.3 | MIT | strukturiertes JSON-Logging, Plan-Vorgabe | log + env_logger (kein JSON) |
| dotenvy | 0.15 | MIT | `.env` lesen (gepflegter Nachfolger von dotenv) | nur Umgebungsvariablen |
| reqwest | 0.13 | MIT/Apache-2.0 | Abruf der Widerrufsliste der Webseite (nur offizieller Betrieb). Ohne Standardfunktionen, `rustls-no-provider`: kein aws-lc-rs (C, cmake) im statischen Binary, Wurzelzertifikate über `rustls-platform-verifier` (System). Keine Weiterleitungen, kein Proxy, 10 s Zeitlimit, 1 MiB Größenlimit im Code; hyper ist über axum schon im Baum | hyper-util direkt (TLS, Zeitlimits und Umleitungsverbot selbst bauen) |
| rustls | 0.23 | MIT/Apache-2.0/ISC | Anbieter `ring` für reqwest einmal je Prozess setzen (`src/tls.rs`); schon über lettre im Baum | keine |
| lettre | 0.11.23 | MIT | SMTP mit TLS (rustls, ring, webpki-roots, kein OpenSSL im statischen Binary), Mehrteil-Mails | eigener SMTP-Client (zu viel Fehlerfläche) |

Nur für Tests: `tokio-tungstenite` 0.29 (MIT, WebSocket-Client, gleiche tungstenite-Version
wie axum), `tower` 0.5 (MIT, `oneshot` gegen den Router), `http-body-util` 0.1 (MIT).

Bewusst nicht verwendet: `tower-http` (CORS, Header und Limits sind wenige Zeilen eigener
Middleware, kein CORS nötig, da die App keinen Browser nutzt), `jsonwebtoken` (JWT bringt
Algorithmus-Auswahl und Header mit, die hier nicht gebraucht werden; das eigene Format ist
kleiner und ohne `alg`-Verwechslung), `openmls` (Plan: kein MLS in Version 1).

Pflege: `cargo update` nur gezielt, danach `cargo test`; Sicherheitsmeldungen mit
`cargo audit` prüfen (cargo-audit 0.22.2, Stand 2026-11-09: 271 Abhängigkeiten, ein Fund).

Offener Fund: RUSTSEC-2026-0459 (CVE-2026-119375, mittel, 6.8) in `libsqlite3-sys` 0.37.0, das
`sqlx-sqlite` 0.9.0 fest verlangt. Das gebündelte SQLite vor 3.54.0 kann nicht initialisierten
Speicher zurückgeben, wenn es eine Datenbank zusammen mit einer manipulierten `-wal`-Datei
anderer Seitengröße öffnet. Angriffsweg nur lokal: der Server öffnet ausschließlich seine
eigene Datei im eigenen Volume. Wer dort schreiben kann, hat den Server ohnehin. Folge für den
Betrieb: nur eigene Sicherungen zurückspielen, nie eine fremde `-wal`-Datei mitkopieren
(`sqlite3 .backup` erzeugt keine). Behebung, sobald sqlx eine Version mit `libsqlite3-sys`
>= 0.39 veröffentlicht; bis dahin bewusst hingenommen (nicht per Ausnahme unterdrückt).
