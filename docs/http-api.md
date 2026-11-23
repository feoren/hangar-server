# HTTP API (self-hosting only)


The app's account API under **`/api/v1`**, identical to the website (details:
[docs/account-api.md](account-api.md)); input as JSON or form data, errors as
`application/problem+json`:

| Method and path | Purpose |
| --- | --- |
| `POST /api/v1/oauth/device` | start the device flow (`client_id=hangar-desktop`, optional `scope=team`, `device_name`, `platform`) |
| `POST /api/v1/oauth/token` | redeem a `device_code` or rotate a `refresh_token` |
| `POST /api/v1/oauth/revoke` | RFC 7009: a refresh token ends the whole device session; always 200 |
| `GET /api/v1/me` | own account with seats |
| `GET /api/v1/projects` | teams with role, the owner's seats, open invitations |
| `GET /api/v1/projects/{id}/members` | the team's members as `{"members":[{"id","role"}]}`, owner first, the whole list in one answer; for members of the team only, 404 otherwise. Hangar follows removals with it (membership log, notes key) |
| `POST /api/v1/relay-ticket` | ticket for `hello` (`project_id`) with `relay_url` |
| `GET /api/v1/keys` | public ticket key |
| `GET/POST /account/devices` | browser page: view and disconnect connected devices |

Further routes (administration and browser; the old OAuth routes remain for existing scripts,
`client_id` there is `hangar` or `hangar-desktop`, form data only):

| Method and path | Purpose |
| --- | --- |
| `POST /oauth/device_authorization` | start the device flow (old form) |
| `POST /oauth/token` | redeem a `device_code` or rotate a `refresh_token` (old form) |
| `GET/POST /device` | browser page: confirm the code |
| `POST /auth/email`, `GET/POST /auth/magic/{token}` | request and redeem a magic link |
| `GET /v1/me` | own account and teams |
| `GET /v1/sessions`, `DELETE /v1/sessions/{id}`, `POST /v1/auth/logout` | sessions |
| `POST /v1/teams`, `GET/DELETE /v1/teams/{team}` | teams |
| `PATCH/DELETE /v1/teams/{team}/members/{user}` | change role, remove, leave |
| `POST /v1/teams/{team}/invitations` | invite (`emails`, `role`, optional `lang`); status per address `invited`, `renewed`, `member` or `license_required` (owner without an active license, nothing created) |
| `POST .../invitations/{id}/resend`, `DELETE .../invitations/{id}` | resend, revoke |
| `POST /v1/invitations/accept`, `GET/POST /invite/{token}` | accept (app or browser) |
| `GET/PUT/DELETE /v1/license` | license document |
| `POST /v1/tickets` | ticket for `hello` (`team`, old form of `/api/v1/relay-ticket`) |

Errors of the routes outside `/api/v1`: `{"error":"<code>"}` with a matching status (`unauthorized`, `forbidden`, `not_found`,
`invalid_request`, `rate_limited`, `seats_full`, `license_required`, `wrong_account`, `invalid_license`,
`license_expired`, `license_email_mismatch`, `license_in_use`).

