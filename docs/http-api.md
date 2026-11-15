# HTTP-API (nur Selbstbetrieb)


Konto-API der App unter **`/api/v1`**, gleich der Webseite (Einzelheiten:
[docs/account-api.md](account-api.md)); Eingaben JSON oder Formular, Fehler als
`application/problem+json`:

| Methode und Pfad | Zweck |
| --- | --- |
| `POST /api/v1/oauth/device` | Device Flow starten (`client_id=hangar-desktop`, optional `scope=team`, `device_name`, `platform`) |
| `POST /api/v1/oauth/token` | `device_code` einlösen bzw. `refresh_token` rotieren |
| `POST /api/v1/oauth/revoke` | RFC 7009: Erneuerungstoken beendet die ganze Gerätesitzung; immer 200 |
| `GET /api/v1/me` | eigenes Konto mit Plätzen |
| `GET /api/v1/projects` | Teams mit Rolle, Plätzen des Eigentümers, offenen Einladungen |
| `POST /api/v1/relay-ticket` | Ticket für `hello` (`project_id`) mit `relay_url` |
| `GET /api/v1/keys` | öffentlicher Ticketschlüssel |
| `GET/POST /account/devices` | Browserseite: verbundene Geräte ansehen und trennen |

Weitere Routen (Verwaltung und Browser; die alten OAuth-Routen bleiben für bestehende Skripte,
`client_id` dort `hangar` oder `hangar-desktop`, nur Formular):

| Methode und Pfad | Zweck |
| --- | --- |
| `POST /oauth/device_authorization` | Device Flow starten (alte Form) |
| `POST /oauth/token` | `device_code` einlösen bzw. `refresh_token` rotieren (alte Form) |
| `GET/POST /device` | Browserseite: Code bestätigen |
| `POST /auth/email`, `GET/POST /auth/magic/{token}` | Anmeldelink anfordern und einlösen |
| `GET /v1/me` | eigenes Konto und Teams |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}`, `POST /v1/auth/logout` | Sitzungen |
| `POST /v1/teams`, `GET/DELETE /v1/teams/{team}` | Teams |
| `PATCH/DELETE /v1/teams/{team}/members/{user}` | Rolle ändern, entfernen, austreten |
| `POST /v1/teams/{team}/invitations` | einladen (`emails`, `role`, optional `lang`) |
| `POST .../invitations/{id}/resend`, `DELETE .../invitations/{id}` | erneut senden, widerrufen |
| `POST /v1/invitations/accept`, `GET/POST /invite/{token}` | annehmen (App bzw. Browser) |
| `GET/PUT/DELETE /v1/license` | Lizenzdokument |
| `POST /v1/tickets` | Ticket für `hello` (`team`, alte Form von `/api/v1/relay-ticket`) |

Fehler der Routen außerhalb von `/api/v1`: `{"error":"<code>"}` mit passendem Status (`unauthorized`, `forbidden`, `not_found`,
`invalid_request`, `rate_limited`, `seats_full`, `wrong_account`, `invalid_license`,
`license_expired`, `license_email_mismatch`, `license_in_use`).

