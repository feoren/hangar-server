# Ticketformat (Version 1)

Ein Ticket ist der kurzlebige Nachweis, mit dem die App eine Live-Verbindung zu einem Team
öffnet. Im offiziellen Betrieb stellt es die Webseite hangar.feoren.com aus (Konto, Projekt,
Rolle, Platz entscheidet dort), im Selbstbetrieb die eigene Identität des Teamservers. Die App
reicht es unverändert in `hello.ticket` weiter; nur das Relay prüft es.

## Aufbau

```
ticket   = base64url(payload) "." base64url(signature)
payload  = UTF-8-JSON-Objekt (Felder unten)
signature = Ed25519(secret_key, "hangar-ticket-v1." + base64url(payload))
```

- base64url nach RFC 4648 Abschnitt 5, **ohne** `=`-Auffüllung; andere Schreibweisen werden
  abgelehnt.
- Signiert werden die ASCII-Bytes von `hangar-ticket-v1.` gefolgt vom base64url-Text der
  Payload, nicht das JSON selbst. Darum braucht keine Seite kanonisches JSON: geprüft werden
  genau die gesendeten Bytes. Der Kontext `hangar-ticket-v1` trennt Tickets von Lizenzen
  (`hangar-license-v1`), sodass kein Dokument als das andere durchgeht.
- Höchstlänge 2048 Zeichen.

## Felder

| Feld | Typ | Pflicht | Bedeutung |
| --- | --- | --- | --- |
| `v` | Zahl | ja | Formatversion, `1` |
| `kid` | Text `[A-Za-z0-9_-]{1,64}` | ja | Schlüssel-ID; das Relay wählt danach den öffentlichen Schlüssel |
| `sub` | Text, 1 bis 128 Zeichen, keine Steuerzeichen | ja | Konto-ID der Webseite (opak) |
| `prj` | Text, 1 bis 128 Zeichen, keine Steuerzeichen | ja | Projekt-ID der Webseite = Team; muss dem `team` des Rahmens entsprechen |
| `role` | `owner`, `admin`, `member` | ja | Rolle im Projekt; `key.rotate` nur für owner/admin |
| `seat_ok` | bool | ja | Die Webseite bestätigt den Platz. `false`: Relay antwortet `err limit` |
| `iat` | Unix-Sekunden | ja | Ausstellungszeit |
| `exp` | Unix-Sekunden | ja | Ablauf; die Webseite stellt `iat + 60` aus |
| `jti` | Text `[A-Za-z0-9_-]{16,64}` | ja | Einmalige Kennung; ein zweites `hello` mit derselben `jti` wird abgelehnt |
| `aud` | Text | ja | Zielgruppe. Die Webseite stellt `hangar-relay` aus (`TEAM_TICKET_AUDIENCE`), der Selbstbetrieb seinen `PUBLIC_URL`. Das Relay verlangt genau seinen `TICKET_AUDIENCE` (Vorgabe: `hangar-relay` bei `IDENTITY=official`, `PUBLIC_URL` bei `local`); fehlt `aud`, wird abgelehnt |

Unbekannte Felder werden ignoriert (Erweiterung ohne neue Version). Eine inkompatible Änderung
erhöht `v`; das Relay lehnt fremde Versionen ab.

## Prüfregeln des Relays

1. Form und Länge, base64url streng.
2. `kid` aus der Payload lesen (nur dieses Feld vor der Prüfung), Schlüssel aus
   `TICKET_PUBLIC_KEYS` wählen, unbekannte `kid` ablehnen.
3. Signatur mit `verify_strict` (Ed25519 nach RFC 8032, ohne schwache Schlüssel).
4. `v == 1`, `kid` in der Payload gleich der gewählten, Felder in Form.
5. `exp > iat` und `exp - iat <= 300`.
6. `iat <= jetzt + 30 s` und `jetzt < exp + 30 s` (Uhrenabweichung 30 s).
7. `aud` gleich `TICKET_AUDIENCE` (Pflicht).
8. `prj` gleich dem Team des `hello`-Rahmens; `seat_ok` wahr.
9. `jti` noch nie verwendet (in SQLite bis zum Ablauf gespeichert, übersteht Neustarts).
10. Das Gerät (`hello.device`) gehört diesem `sub` oder wird ihm jetzt zugeordnet.

Jede Ablehnung ist für den Client `err forbidden` (bzw. `limit` bei `seat_ok: false`); den
Grund schreibt nur das Serverprotokoll, nie das Ticket selbst.

## Schlüsselrotation

- `TICKET_PUBLIC_KEYS=web-2026-1:<b64>,web-2026-2:<b64>` hält mehrere Schlüssel.
- Ablauf: neuen Schlüssel im Relay ergänzen und neu starten, dann auf der Webseite mit ihm
  signieren, nach 5 Minuten (längste Gültigkeit plus Abweichung) den alten entfernen.
- Der geheime Schlüssel liegt nur auf der Webseite (`.env`, nie im Repository).

## So signiert die Webseite (PHP, libsodium)

```php
function hangar_b64url(string $bytes): string {
    return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

function hangar_ticket(array $claims, string $kid, string $seed32): string {
    // Feste Reihenfolge nur der Lesbarkeit wegen; geprüft werden die gesendeten Bytes.
    $payload = [
        'v' => 1, 'kid' => $kid, 'sub' => (string) $claims['sub'], 'prj' => (string) $claims['prj'],
        'role' => $claims['role'], 'seat_ok' => (bool) $claims['seat_ok'],
        'iat' => time(), 'exp' => time() + 60,
        'jti' => hangar_b64url(random_bytes(16)),
        'aud' => 'hangar-relay',
    ];
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed32));
    $p = hangar_b64url($json);
    return $p . '.' . hangar_b64url(sodium_crypto_sign_detached('hangar-ticket-v1.' . $p, $secret));
}
```

`sub` und `prj` als Text senden (auch wenn es Zahlen sind); das Relay vergleicht Text.
Öffentlichen Schlüssel für das Relay: `hangar_b64url(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed32)))`.

## Testvektoren

`testdata/tickets.json` enthält den Testschlüssel (RFC 8032, Abschnitt 7.1, Test 1; öffentlich
bekannt, nur für Tests), eine feste Prüfzeit `now` und je Fall die exakte Payload, das
Dokument und das erwartete Ergebnis (`ok`, `expired`, `not_yet_valid`, `lifetime`,
`bad_signature`, `unknown_key`, `payload`). Gegenprobe:

```sh
cargo test --test vectors                                   # Rust-Seite
php tools/php/verify_vectors.php testdata/tickets.json      # PHP baut byte-gleiche Dokumente
```

Beispiel (`valid`, Prüfzeit 1794225600):

```
payload  {"v":1,"kid":"test-2026-1","sub":"1042","prj":"317","role":"member","seat_ok":true,"iat":1794225590,"exp":1794225650,"jti":"Zx8qW2u0Tt6m1d9KcPq3vA"}
ticket   eyJ2IjoxLCJraWQiOiJ0ZXN0LTIwMjYtMSIsInN1YiI6IjEwNDIiLCJwcmoiOiIzMTciLCJyb2xlIjoibWVtYmVyIiwic2VhdF9vayI6dHJ1ZSwiaWF0IjoxNzk0MjI1NTkwLCJleHAiOjE3OTQyMjU2NTAsImp0aSI6Ilp4OHFXMnUwVHQ2bTFkOUtjUHEzdkEifQ.DaX2WEcL6DFRgNLKnEsY945sqKDLug1OOgDhPt60qdIh7Tm5VydoPEbtJkdA_Cn5VPwQf2Dwd_Txn4RZnaLzDQ
```
