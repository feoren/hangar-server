# Lizenzformat (Version 1)

Lizenzdokumente gelten für den **Selbstbetrieb** (`IDENTITY=local`). Die Webseite
hangar.feoren.com verkauft Plätze und stellt nach dem Kauf ein signiertes Dokument aus; der
Eigentümer hinterlegt es auf seinem Teamserver (`PUT /v1/license`). Der Server prüft es nur mit
öffentlichen Schlüsseln aus seiner Konfiguration (`LICENSE_PUBLIC_KEYS`), offline.

Im offiziellen Betrieb gibt es keine Lizenzprüfung im Teamserver: dort entscheidet die Webseite
über den Platz und meldet ihn im Ticket (`seat_ok`).

## Modell: Plätze je Konto

- Der Eigentümer kauft `seats` Plätze. Sie gelten für **alle Teams, die ihm auf diesem Server
  gehören**.
- Gezählt werden **verschiedene Personen** über alle seine Teams, er selbst eingeschlossen.
  Wer schon in einem seiner Teams ist, braucht für ein weiteres keinen neuen Platz.
- Ohne gültige Lizenz gilt **Free: 3 Personen**. Eine Lizenz mit weniger als 3 Plätzen ergibt 3.
- Geprüft wird **beim Annehmen** einer Einladung, in derselben Schreibtransaktion wie der
  Beitritt. Offene Einladungen belegen keinen Platz.
- **Ablauf:** nichts wird gelöscht, niemand entfernt. Nur Beitritte über die dann geltende
  Grenze (3) werden abgelehnt.

## Aufbau

Gleiches Verfahren wie Tickets ([ticket-format.md](ticket-format.md)), anderer Kontext:

```
license   = base64url(payload) "." base64url(signature)
signature = Ed25519(secret_key, "hangar-license-v1." + base64url(payload))
```

Höchstlänge 4096 Zeichen. Leerraum am Anfang und Ende wird beim Hinterlegen entfernt.

## Felder

| Feld | Typ | Pflicht | Bedeutung |
| --- | --- | --- | --- |
| `v` | Zahl | ja | `1` |
| `kid` | Text `[A-Za-z0-9_-]{1,64}` | ja | Schlüssel-ID der Webseite |
| `lid` | Text `[A-Za-z0-9_-]{1,64}` | ja | Lizenz-ID; auf einem Server kann sie nur ein Konto hinterlegen; Widerruf über `LICENSE_REVOKED` |
| `sub` | Text, bis 128 Zeichen | ja | Konto-ID der Webseite (nur zur Zuordnung, der Server vergleicht sie nicht) |
| `email` | Text, klein geschrieben, ohne Rand | ja | Adresse des Kontos; muss der Adresse des hinterlegenden Kontos auf dem Server entsprechen |
| `plan` | Text `[a-z0-9-]{1,32}` | ja | Tarif, z. B. `team`; später Staffelungen |
| `seats` | Zahl 1 bis 100000 | ja | Plätze |
| `features` | Liste von `[A-Za-z0-9_-]{1,64}`, höchstens 32 | nein | Zusatzfunktionen; Version 1 kennt keine und ignoriert sie |
| `iat` | Unix-Sekunden | ja | Ausstellung |
| `exp` | Unix-Sekunden | ja | Ablauf, `exp > iat` |

Unbekannte Felder werden ignoriert. So bleibt Raum für `plan`-Staffelungen oder eine spätere
Kombination mit Projekten, ohne neue Version.

## Prüfregeln

1. Signatur, `kid`, Form wie beim Ticket (Kontext `hangar-license-v1`).
2. `v == 1`; Felder wie oben; `email` muss schon normalisiert sein (`Owner@…` wird abgelehnt).
3. `lid` nicht in `LICENSE_REVOKED`.
4. Beim Hinterlegen: `email` gleich der Kontoadresse, `iat <= jetzt + 300 s`, `jetzt < exp`.
5. Bei jeder Platzprüfung wird das gespeicherte Dokument erneut geprüft (rotierte oder
   widerrufene Schlüssel wirken sofort); abgelaufen heißt Free.

## So signiert die Webseite (PHP)

```php
function hangar_license(string $kid, string $seed32, string $licenseId, string $accountId,
                        string $email, string $plan, int $seats, int $validUntil, array $features = []): string {
    $payload = [
        'v' => 1, 'kid' => $kid, 'lid' => $licenseId, 'sub' => $accountId,
        'email' => mb_strtolower(trim($email)), 'plan' => $plan, 'seats' => $seats,
    ];
    if ($features !== []) { $payload['features'] = array_values($features); }
    $payload['iat'] = time();
    $payload['exp'] = $validUntil;
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed32));
    $p = sodium_bin2base64($json, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $s = sodium_crypto_sign_detached('hangar-license-v1.' . $p, $secret);
    return $p . '.' . sodium_bin2base64($s, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}
```

Empfehlung: Laufzeit an das Abo koppeln (z. B. Ende der bezahlten Periode plus 14 Tage) und
bei Verlängerung ein neues Dokument ausstellen, das der Eigentümer im Konto herunterlädt.
`lid` = ID der Lizenzzeile der Webseite.

## Testvektoren

`testdata/licenses.json` (Testschlüssel aus RFC 8032, nur für Tests): `valid` (10 Plätze),
`valid_with_features`, `expired` (Signatur gültig, wirksam 3 Plätze), `foreign_signature`,
`tampered_payload` (Plätze auf 1000 geändert), `ticket_context`, `email_not_normalized`.
Gegenprobe: `cargo test --test vectors` und `php tools/php/verify_vectors.php testdata/licenses.json`.

Beispiel (`valid`):

```
payload  {"v":1,"kid":"test-2026-1","lid":"lic_8f3a2c","sub":"1042","email":"owner@example.org","plan":"team","seats":10,"iat":1793900000,"exp":1825502400}
license  eyJ2IjoxLCJraWQiOiJ0ZXN0LTIwMjYtMSIsImxpZCI6ImxpY184ZjNhMmMiLCJzdWIiOiIxMDQyIiwiZW1haWwiOiJvd25lckBleGFtcGxlLm9yZyIsInBsYW4iOiJ0ZWFtIiwic2VhdHMiOjEwLCJpYXQiOjE3OTM5MDAwMDAsImV4cCI6MTgyNTUwMjQwMH0.pnbaTN9YuVKd3tc4Gb1L09lkfVIN0irR6lUHpAjPQB99rCGQ8WipWrUvypQVnnRGrHnS4NKG0UPQGNqageCEBg
```

## Bekannte Grenze

Der Server vertraut den Schlüsseln seiner Konfiguration. Wer einen eigenen Server betreibt,
kann dort einen eigenen Schlüssel eintragen und sich selbst Lizenzen ausstellen. Technisch
lässt sich das bei Quelltext in fremder Hand nicht verhindern; die Elastic License 2.0 verbietet
es ("move, change, disable, or circumvent the license key functionality"). Wer das härter
will, bettet die öffentlichen Schlüssel der Webseite beim Bau ein und lässt die Konfiguration
nur zusätzliche Schlüssel für Tests zu (offener Punkt, siehe entwicklung.md).
