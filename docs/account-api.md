# Konto-API der App im Selbstbetrieb (`/api/v1`)

Im Selbstbetrieb (`IDENTITY=local`) bietet der Server unter **`<PUBLIC_URL>/api/v1`** dieselbe
Konto-API wie hangar.feoren.com. Hangar braucht so nur eine Server-Adresse: in den
Einstellungen `https://team.example.org/api/v1` eintragen. Den Live-Kanal nennt das Ticket
selbst (`relay_url`), der WebSocket `/v1/live` ist unverändert ([protocol.md](protocol.md)).

Im offiziellen Betrieb (`IDENTITY=official`) gibt es diese Routen nicht (404); dort spricht die
App mit der Webseite. Code: `src/identity/api.rs` (HTTP), Dienste in `src/identity/auth.rs` und
`src/identity/teams.rs`, Tests in `tests/account_api.rs`.

## Transport

- **TLS:** Hangar akzeptiert `http` und `ws` nur für `127.0.0.1`, `localhost` und `[::1]`. Im LAN
  oder im Netz braucht der Server TLS, etwa über Caddy (`Caddyfile`; im LAN `tls internal` mit
  der eigenen CA auf den Rechnern). `PUBLIC_URL` beginnt dann mit `https://`, `relay_url` mit
  `wss://`.
- **Eingaben:** `application/x-www-form-urlencoded` oder `application/json` (flaches Objekt),
  sonst 415. Werte gelten als Zeichenketten; ganze Zahlen werden Text, verschachtelte Werte
  zählen als fehlend; höchstens 32 Felder mit Namen bis 64 Zeichen. Körper über 16 KiB: 413.
- **Antworten:** JSON, `Cache-Control: no-store` und `Pragma: no-cache` (außer `/keys`:
  `public, max-age=3600`). Keine Cookies, kein CSRF, keine CORS-Freigabe.
- **IDs** sind opake Zeichenketten (hier `u_…`, `t_…`; auf der Webseite Dezimalzahlen als Text).
- **Fehler** als RFC 9457 `application/problem+json`:
  `{"type":"urn:hangar:api:problem:<code>","title","status","detail","code"}`. Die
  OAuth-Endpunkte tragen zusätzlich `error` und `error_description` (RFC 6749 5.2). Fehlt der
  Bearer oder ist er ungültig, abgelaufen oder widerrufen: 401 `invalid_token` mit
  `WWW-Authenticate: Bearer realm="hangar", error="invalid_token"`. Andere Methoden: 405 mit
  `Allow`; unbekannte Pfade unter `/api/v1`: 404 problem+json. Schreibende Anfragen mit einem
  fremden `Origin` (Browser einer anderen Seite): 403 problem+json `origin`; die App sendet
  keinen `Origin`.

## Endpunkte

| Methode, Pfad | Anmeldung | Eingabe | Antwort |
| --- | --- | --- | --- |
| `POST /oauth/device` | keine | `client_id`, optional `scope` (nur `team`), `device_name` (100 Zeichen), `platform` (`[A-Za-z0-9 ._-]`, 40) | `device_code`, `user_code` (`BCDF-GHJK`), `verification_uri` (`<PUBLIC_URL>/device`), `verification_uri_complete` (mit `?code=`), `expires_in` 600, `interval` 5 |
| `POST /oauth/token` | keine | `grant_type=urn:ietf:params:oauth:grant-type:device_code` mit `device_code`, oder `grant_type=refresh_token` mit `refresh_token`; jeweils `client_id` | `access_token`, `token_type` `Bearer`, `expires_in` 3600, `refresh_token`, `scope` `team` |
| `POST /oauth/revoke` | keine (das Token ist der Nachweis) | RFC 7009: `token`, optional `token_type_hint` (`refresh_token`, `access_token`), `client_id` | immer 200 ohne Körper |
| `GET /me` | Bearer | | `id`, `email`, `locale`, `seats_account_total`, `seats_account_used` (eigenes Konto; `name` gibt es im Selbstbetrieb nicht) |
| `GET /projects` | Bearer | | `{"projects":[{"id","name","role","owner_id","plan","seats_account_total","seats_account_used","pending_invitations"}]}`; Plätze des Eigentümerkontos; `pending_invitations` nur für owner und admin |
| `POST /relay-ticket` | Bearer | `project_id` | `ticket`, `expires_at` (Unix-Sekunden, 60 s), `relay_url` (`PUBLIC_URL` mit `http`→`ws`, `https`→`wss`, plus `/v1/live`); Nichtmitglied oder unbekannt: 404 |
| `GET /keys` | keine | | `{"keys":[{"kty":"OKP","crv":"Ed25519","x","kid","use":"sig","alg":"EdDSA"}]}`: der Ticketschlüssel dieses Servers |

`client_id`: `hangar-desktop` (sendet die App, wie bei der Webseite). `hangar` bleibt erlaubt,
damit bestehende Skripte und die alten Routen weiterlaufen; beide sind derselbe öffentliche
Client ohne Geheimnis.

OAuth-Fehler (400): `authorization_pending`, `slow_down` (zu schnell gefragt, Abstand +5 s),
`access_denied`, `expired_token`, `invalid_grant` (unbekannt, schon eingelöst, widerrufen),
`invalid_client`, `invalid_scope`, `invalid_request`, `unsupported_grant_type`. Abweichung von
der Webseite: `invalid_client` kommt hier mit 400 statt 401; Hangar wertet beides gleich.

**Nicht vorhanden:** `invite_url` in `/projects` fehlt, weil der Selbstbetrieb keine
Browserseite zum Einladen hat; Hangar zeigt den Einladen-Knopf dann nicht. Eingeladen wird über
`POST /v1/teams/{team}/invitations` ([http-api.md](http-api.md)). `/devices` (Geräteschlüssel) ist auch auf der
Webseite nur reserviert und fehlt hier.

## Tokens und Sitzungen

- Tokens sind opak (`hta_…`, `htr_…`) und liegen nur als SHA-256 in der Datenbank. Der Device
  Flow legt je Gerät eine Sitzung an (`auth_sessions`, `kind = 'app'`, mit Gerätename und
  Plattform).
- **Rotation:** jedes Einlösen eines Erneuerungstokens gibt ein neues Paar aus, das alte
  Zugriffstoken endet. Ein schon eingelöstes Erneuerungstoken heißt Diebstahl oder Fehler: die
  ganze Sitzung wird widerrufen (alle Tokens). Eine Gnadenfrist für verlorene Antworten wie auf
  der Webseite gibt es hier nicht; die App serialisiert Erneuerungen.
- **Widerruf (RFC 7009):** ein Erneuerungstoken beendet die ganze Gerätesitzung, ein
  Zugriffstoken nur sich selbst. `token_type_hint` ist nur ein Hinweis. Unbekannte, fremde oder
  schon widerrufene Tokens: ebenfalls 200 (keine Auskunft). Browsertokens sind ausgenommen.
- Laufende Live-Verbindungen eines widerrufenen Geräts enden spätestens beim nächsten
  `ticket.renew` (ohne gültiges Token gibt es kein neues Ticket).

## Ratenbegrenzung

Im Speicher je Prozess, Schlüssel gehasht (`src/http/ratelimit.rs`):

| Zweck | Grenze | Antwort |
| --- | --- | --- |
| Gerätestart (`/api/v1/oauth/device` und `/oauth/device_authorization` gemeinsam) | 30 je Adresse und Stunde | 429 `slow_down` mit `Retry-After: 60` |
| Token (`/api/v1/oauth/token` und `/oauth/token` gemeinsam) | 600 je Adresse und 15 min | 429 `slow_down` |
| Widerruf | 60 je Adresse und 15 min | 429 `slow_down` |
| Tickets (`/api/v1/relay-ticket` und `/v1/tickets` gemeinsam) | 600 je Konto und Stunde | 429 `rate_limited` |
| Bestätigen auf `/device` | 10 je Konto, 30 je Adresse und 15 min | Seite "zu viele Versuche" |

## Browserseite `/account/devices`

Hangar verlinkt `<Ursprung>/account/devices`. Ohne Browsersitzung fragt die Seite nach der
E-Mail-Adresse (Anmeldelink, Rücksprung auf die Liste). Angemeldet listet sie die Geräte des
Kontos (Name, Plattform, verbunden am, zuletzt benutzt, Zeiten in UTC) mit je einem Knopf
"Trennen" (POST mit CSRF-Token und Prüfung des Ursprungs). Trennen beendet die Gerätesitzung
sofort; danach führt ein Redirect zurück auf die Liste.
