# Sicherheit und Bedrohungsmodell

> **Vor echten Daten:** Das Krypto-Design der App (hangar-team-crypto) ist ein eigenes
> Protokoll und braucht vor echten Teamdaten eine externe kryptografische Prüfung. Das Relay
> prüft Signaturen, Rechte und Ketten mit dem Crate, hält aber keine Schlüssel.
>
> **Vor jeder Freigabe:** Das E2E-Verfahren (Geräteschlüssel, Mitgliedschafts-Log, Epochen,
> HPKE-Verpackung, Keyed Hashes) ist ein eigenes Protokoll und braucht eine **externe
> kryptografische Prüfung**. Dieser Server enthält nur den Unterbau (Ablage und Verteilung
> opaker Daten); die Kryptografie liegt in der App und ist hier nicht geprüft.

## Was der Server sieht

| Daten | Sichtbar für den Betreiber | Anmerkung |
| --- | --- | --- |
| Mitglieder | ja | Konto-IDs (offiziell) bzw. E-Mail-Adressen (Selbstbetrieb), Rollen, Beitrittszeiten |
| Geräte | ja | Geräte-IDs je Mitglied, öffentliche Signatur- und KEM-Schlüssel, letzte Verbindung |
| Epochen | ja | Nummer, wer rotiert hat, wann; Anzahl und Größe der verpackten Schlüssel |
| Mitgliedschafts-Log | Struktur | Index, Hash, Größe, Autor, Zeit; der Inhalt ist für den Server opak |
| Reservierungen | Hashes | wer welchen Hash hält, seit wann, Freigabewünsche; nicht, welche Aufgabe |
| Claims | Hashes | wie viele Dateien und Ordnerebenen je Sitzung, welche Hashes gleich sind (also: zwei Personen arbeiten an derselben Datei); nicht welche |
| Präsenz | ja | aktiv/ruhig/abwesend und Zeitpunkte; der Status-Text ist verschlüsselt |
| Ablage | Metadaten | Art (Entscheidung, Aufgabe, Transkript), Größe, Epoche, Autor, Zeit |
| Verkehr | ja | wer wann mit wem verbunden ist, Anfragezeiten, Größen, IP-Adressen (nur im Speicher für Ratenbegrenzung, gehasht) |
| Teamnamen | ja (Selbstbetrieb) | stehen im Klartext, weil sie in Einladungsmails vorkommen |
| Inhalte | **nein** | Aufgaben, Notizen, Dateipfade, Zeilen, Entscheidungen, Transkripte liegen nur verschlüsselt vor |

Weitere Folgen der Hashes: Ordnerebenen verraten die Tiefe der Pfade; gleiche Hashes über die
Zeit verraten, wie lange an derselben Datei gearbeitet wird. Keyed Hashes einer Epoche lassen
sich ohne Schlüssel nicht umkehren, aber innerhalb der Epoche vergleichen.

## Angreifer und Schutz

| Angreifer | Ziel | Schutz |
| --- | --- | --- |
| Fremder im Netz | mitlesen, Sitzung übernehmen | TLS über Caddy; Tokens nur im Header; HSTS; keine Cookies für die App |
| Fremder ohne Konto | Teams betreten | Tickets: Ed25519, 60 s gültig, `jti` einmalig, Team aus dem Ticket; Geräte an ein Mitglied gebunden |
| Mitglied | fremde Reservierungen lösen, Platzgrenze umgehen | Halterprüfung je Absicht; Platz entscheidet Webseite bzw. Annahme-Transaktion; Rotation nur owner/admin |
| Gestohlenes Erneuerungstoken | dauerhaft angemeldet bleiben | Rotation; Wiederverwendung widerruft die ganze Sitzung |
| Browser auf fremder Seite | CSRF, Login-CSRF, WebSocket-Hijacking | `Origin`-Prüfung (WebSocket und schreibende Anfragen), Browserformulare nur mit passendem `Origin`/`Sec-Fetch-Site`, Synchronizer-Token, `SameSite=Lax`, `HttpOnly`, `__Host-`-Cookie unter https |
| Linkprüfer in Mailprogrammen | Anmeldelinks verbrauchen | GET zeigt nur eine Bestätigung; eingelöst wird per POST |
| Phishing mit eigenem Gerätecode | fremdes Konto auf das eigene Gerät holen (Anmeldelink mit `return_to=/device?code=...` an fremde Adresse anfordern) | Der Code im Rücksprung gilt nur in dem Browser, der den Link angefordert hat (Cookie, Hash in `magic_links.browser_hash`); sonst landet die Person auf `/device` ohne Code. Die Bestätigungsseite nennt den Gerätenamen und zeigt für unbekannte Codes keinen Zulassen-Knopf. Restrisiko: wer selbst einen fremden Code eintippt oder einen `verification_uri_complete`-Link anklickt und bestätigt (RFC 8628, 5.4) |
| Verbindungen ohne Ticket | Verbindungsplätze belegen | 15 s Frist bis zum ersten gültigen `hello`; abgelehnte `hello` zählen als kaputte Rahmen |
| Massenanfragen | Raten von Codes, Mailflut, Speicher | Ratenbegrenzung je IP/Adresse/Konto, Gerätecode 20^8, `slow_down` beim Abfragen, Rahmen- und Listen-Grenzen, Kontingent der Ablage, Begrenzung der Verbindungen |
| Betreiber des Servers | Inhalte lesen | E2E (App); der Server kennt weder Teamschlüssel noch Hash-Schlüssel |
| Betreiber des Servers | Schlüssel unterschieben | Schutz liegt im signierten Mitgliedschafts-Log, das die Clients prüfen; der Server prüft nur die Kette |
| Betreiber des Servers | Ereignisse unterdrücken, umsortieren, Metadaten auswerten | nicht verhindert; Clients erkennen Lücken in `seq`, nicht aber Weglassen am Ende |
| Selbstbetreiber | Platzgrenze umgehen | eigener Lizenzschlüssel in der Konfiguration ist möglich; untersagt durch die Elastic License 2.0 (siehe license-format.md) |

## Umgesetzte Maßnahmen (Auszug, ASVS Level 2 als Maßstab)

- Prepared Statements überall, SQL-Texte statisch; Kennungen und Hashes vor Gebrauch geprüft.
- Tokens: 32 Zufallsbytes aus dem Betriebssystem, gespeichert als SHA-256; Zugriff 1 h,
  Erneuerung 30 Tage, Browser 12 h, Anmeldelink 15 min, Gerätecode 10 min, Einladung 7 Tage.
- Sitzungen sind einzeln widerrufbar (`DELETE /v1/sessions/{id}`, im Browser `/account/devices`
  mit CSRF-Token und Ursprungsprüfung), Abmelden widerruft die eigene; die App meldet sich über
  `POST /api/v1/oauth/revoke` (RFC 7009) ab, ein Erneuerungstoken beendet die ganze
  Gerätesitzung. Wiederverwendung eines rotierten Erneuerungstokens widerruft die Sitzung.
- Konto-API `/api/v1` ([account-api.md](account-api.md)): Körper höchstens 16 KiB, nur Formular
  oder flaches JSON, Fehler als problem+json ohne interne Einzelheiten, 401 mit
  `WWW-Authenticate`; Ratenbegrenzung für Gerätestart, Token, Widerruf und Tickets; nur im
  Selbstbetrieb vorhanden.
- Keine Auskunft, ob eine Adresse existiert (gleiche Antwort; Mail nur an erlaubte Adressen).
- Fremde Teams antworten mit 404, nicht 403.
- Sicherheitsheader: CSP ohne Skripte (`default-src 'none'`), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer` (Tokens in Pfaden), COOP/CORP, `no-store`, HSTS bei
  https.
- Protokoll: JSON, nur Routenmuster statt Pfaden (keine Tokens im Log), keine Tickets, keine
  E-Mail-Adressen in Fehlermeldungen an Clients.
- Mails: keine externen Bilder, kein Tracking, keine Inhalte aus Aufgaben oder Dateien;
  Betreffzeilen ohne Steuerzeichen; SMTP nur mit TLS (STARTTLS Pflicht oder SMTPS),
  Zertifikate werden geprüft.
- Container: distroless, ohne Shell, Nutzer `nonroot`, Dateisystem nur lesbar außer `/data`,
  alle Capabilities entzogen.
- Der Ticket-Schlüssel des Selbstbetriebs liegt unter `DATA_DIR/ticket-signing.key` (0600).

## Prüfungen des Relays mit hangar-team-crypto

- Das Relay speichert nur Log-Einträge, die `LogVerifier` zugelassen hat (Signatur des sendenden
  Geräts, Rechte nach der niedrigeren aus Log- und Ticket-Rolle, Team, Index, `prev`). Damit
  kann kein Mitglied über das Relay Einträge unterschieben, die andere Clients ohnehin ablehnen
  würden, und das Relay und die Clients sehen dasselbe Log.
- Neue Geräte im Log müssen die Schlüssel tragen, die dieser Holder über seine eigene
  authentisierte Verbindung registriert hat (`check_registered_keys`): ein Admin kann keine
  Schlüssel eigener Wahl für fremde Holder eintragen.
- Rotation und Geräteentfernung kommen nur mit ihrem signierten Eintrag und werden atomar
  gespeichert; Verzeichnis des Relays und Log laufen nie auseinander.
- `key.wrap`: höchstens ein Paket je Absender und vier je Ziel und Epoche, nie ersetzt; ein
  einzelnes Gerät kann die Plätze nicht belegen.
- Restrisiko: Das Relay sieht Klartext der Log-Einträge (Mitglieder, Geräte, Rollen, öffentliche
  Schlüssel); das ist so vorgesehen (die Clients lesen das Log ebenfalls im Klartext).

## Offene Punkte

- Externe Krypto-Prüfung (siehe oben) und Testvektoren für Schritt E in der App.
- Rechteentzug im offiziellen Betrieb ist zweistufig: die Widerrufsliste der Webseite
  (`hangar-revoke-v1`, alle 15 s, docs/revocation-format.md) und `ticket.renew` der App (etwa
  alle 5 min). Ist die Webseite nicht erreichbar, wirkt ein Entzug spätestens mit dem nächsten
  Ticket (`ticket.renew` oder `CONNECTION_MAX_AGE_SECS`). Im Selbstbetrieb sofort.
- Vorgaben, die Restrisiken begrenzen, bis `ticket.renew` überall wirkt: Höchstalter einer
  Verbindung je Team 10 min (`CONNECTION_MAX_AGE_SECS=600`), höchstens 20 Verbindungen je
  Client-Adresse (`MAX_CONNECTIONS_PER_IP=20`, IPv6 je /64).
- Ein verlorenes Gerät entfernt ein Owner, Admin oder ein anderes Gerät desselben Mitglieds mit
  `device.remove`: Reservierungen frei, Schlüsselpakete gelöscht, `hello` des Geräts danach
  abgelehnt (Sperrliste je Team und Holder). Es kennt den aktuellen Teamschlüssel weiter; erst
  `key.rotate` schließt es aus.
- `notify` trägt nie Klartext: höchstens die verschlüsselte Notiz eines Freigabewunsches.
- Der Zustand für den Neustart (Reservierungen, Log-Position, Notizen) liegt in SQLite; er enthält
  nur Hashes, Holder und verschlüsselte Notizen.
- Rollenänderungen gelten still auf der laufenden Verbindung; Rechte werden je Nachricht aus
  der aktuellen Rolle geprüft. Eine Herabstufung kann also eine schon laufende, einzelne
  Absicht nicht mehr aufhalten, jede folgende schon.
- `key.wrap` ersetzt nie ein vorhandenes Paket (`conflict`), nur owner/admin oder ein anderes
  Gerät desselben Mitglieds dürfen wrappen, nie das Zielgerät selbst (`e2e::check_wrap`).
- Ausgehende Anfragen: nur der Abruf der Widerrufsliste, nur an `REVOCATION_URL` (https, ohne
  Weiterleitungen und Proxy, 10 s, 1 MiB). Das Bearer-Token liegt nur in der Umgebung.
- Ratenbegrenzung und Operations-IDs liegen im Speicher eines Prozesses; mehrere Knoten
  bräuchten Redis oder die Datenbank.
- Passkeys und OIDC (GitHub, eigene Forges) sind für später geplant.
- Konto löschen und Datenexport im Selbstbetrieb fehlen noch (DSGVO Art. 17 und 20).
- Die Ablage hat ein Kontingent je Team und eine Frist nur für Transkripte
  (`TRANSCRIPT_RETENTION_DAYS`); Entscheidungen und Aufgaben bleiben, bis das Team gelöscht ist.
