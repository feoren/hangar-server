# The app's account API in self-hosting (`/api/v1`)

In self-hosting (`IDENTITY=local`) the server offers the same account API as
hangar.feoren.com under **`<PUBLIC_URL>/api/v1`**. This way Hangar needs only one server address: enter
`https://team.example.org/api/v1` in the settings. The ticket itself names the live channel
(`relay_url`); the WebSocket `/v1/live` is unchanged ([protocol.md](protocol.md)).

In official mode (`IDENTITY=official`) these routes do not exist (404); there the
app talks to the website. Code: `src/identity/api.rs` (HTTP), services in `src/identity/auth.rs` and
`src/identity/teams.rs`, tests in `tests/account_api.rs`.

## Transport

- **TLS:** Hangar accepts `http` and `ws` only for `127.0.0.1`, `localhost` and `[::1]`. On a LAN
  or on the internet the server needs TLS, for example through Caddy (`Caddyfile`; on a LAN `tls internal` with
  its own CA installed on the machines). `PUBLIC_URL` then starts with `https://`, `relay_url` with
  `wss://`.
- **Input:** `application/x-www-form-urlencoded` or `application/json` (flat object),
  otherwise 415. Values are treated as strings; integers become text, nested values
  count as missing; at most 32 fields with names of up to 64 characters. Bodies over 16 KiB: 413.
- **Responses:** JSON, `Cache-Control: no-store` and `Pragma: no-cache` (except `/keys`:
  `public, max-age=3600`). No cookies, no CSRF, no CORS allowance.
- **IDs** are opaque strings (here `u_…`, `t_…`; on the website decimal numbers as text).
- **Errors** as RFC 9457 `application/problem+json`:
  `{"type":"urn:hangar:api:problem:<code>","title","status","detail","code"}`. The
  OAuth endpoints additionally carry `error` and `error_description` (RFC 6749 5.2). If the
  bearer token is missing, invalid, expired or revoked: 401 `invalid_token` with
  `WWW-Authenticate: Bearer realm="hangar", error="invalid_token"`. Other methods: 405 with
  `Allow`; unknown paths under `/api/v1`: 404 problem+json. Write requests with a
  foreign `Origin` (a browser on another site): 403 problem+json `origin`; the app sends
  no `Origin`.

## Endpoints

| Method, path | Authentication | Input | Response |
| --- | --- | --- | --- |
| `POST /oauth/device` | none | `client_id`, optional `scope` (only `team`), `device_name` (100 characters), `platform` (`[A-Za-z0-9 ._-]`, 40) | `device_code`, `user_code` (`BCDF-GHJK`), `verification_uri` (`<PUBLIC_URL>/device`), `verification_uri_complete` (with `?code=`), `expires_in` 600, `interval` 5 |
| `POST /oauth/token` | none | `grant_type=urn:ietf:params:oauth:grant-type:device_code` with `device_code`, or `grant_type=refresh_token` with `refresh_token`; `client_id` in both cases | `access_token`, `token_type` `Bearer`, `expires_in` 3600, `refresh_token`, `scope` `team` |
| `POST /oauth/revoke` | none (the token is the proof) | RFC 7009: `token`, optional `token_type_hint` (`refresh_token`, `access_token`), `client_id` | always 200 without a body |
| `GET /me` | Bearer | | `id`, `email`, `locale`, `seats_account_total`, `seats_account_used` (own account; there is no `name` in self-hosting) |
| `GET /projects` | Bearer | | `{"projects":[{"id","name","role","owner_id","plan","seats_account_total","seats_account_used","pending_invitations"}]}`; seats of the owner's account; `pending_invitations` only for owner and admin |
| `POST /relay-ticket` | Bearer | `project_id` | `ticket`, `expires_at` (Unix seconds, 60 s), `relay_url` (`PUBLIC_URL` with `http`→`ws`, `https`→`wss`, plus `/v1/live`); not a member or unknown: 404 |
| `GET /keys` | none | | `{"keys":[{"kty":"OKP","crv":"Ed25519","x","kid","use":"sig","alg":"EdDSA"}]}`: this server's ticket key |

`client_id`: `hangar-desktop` (sent by the app, as with the website). `hangar` remains allowed
so that existing scripts and the old routes keep working; both are the same public
client without a secret.

OAuth errors (400): `authorization_pending`, `slow_down` (polled too quickly, interval +5 s),
`access_denied`, `expired_token`, `invalid_grant` (unknown, already redeemed, revoked),
`invalid_client`, `invalid_scope`, `invalid_request`, `unsupported_grant_type`. Difference from
the website: `invalid_client` comes with 400 here instead of 401; Hangar treats both the same.

**Not available:** `invite_url` is missing from `/projects` because self-hosting has no
browser page for inviting; Hangar then does not show the invite button. Invitations are sent via
`POST /v1/teams/{team}/invitations` ([http-api.md](http-api.md)). `/devices` (device keys) is only reserved on the
website as well and is missing here.

## Tokens and sessions

- Tokens are opaque (`hta_…`, `htr_…`) and are stored in the database only as SHA-256. The device
  flow creates one session per device (`auth_sessions`, `kind = 'app'`, with device name and
  platform).
- **Rotation:** every redemption of a refresh token issues a new pair, and the old
  access token ends. A refresh token that was already redeemed means theft or an error: the
  whole session is revoked (all tokens). Unlike the website, there is no grace period for lost responses
  here; the app serializes refreshes.
- **Revocation (RFC 7009):** a refresh token ends the whole device session, an
  access token only itself. `token_type_hint` is only a hint. Unknown, foreign or
  already revoked tokens: also 200 (no information disclosed). Browser tokens are excluded.
- Live connections of a revoked device end at the latest on the next
  `ticket.renew` (without a valid token there is no new ticket).

## Rate limiting

In memory per process, keys hashed (`src/http/ratelimit.rs`):

| Purpose | Limit | Response |
| --- | --- | --- |
| Device start (`/api/v1/oauth/device` and `/oauth/device_authorization` combined) | 30 per address and hour | 429 `slow_down` with `Retry-After: 60` |
| Token (`/api/v1/oauth/token` and `/oauth/token` combined) | 600 per address and 15 min | 429 `slow_down` |
| Revocation | 60 per address and 15 min | 429 `slow_down` |
| Tickets (`/api/v1/relay-ticket` and `/v1/tickets` combined) | 600 per account and hour | 429 `rate_limited` |
| Confirming on `/device` | 10 per account, 30 per address and 15 min | page "too many attempts" |

## Browser page `/account/devices`

Hangar links to `<origin>/account/devices`. Without a browser session the page asks for the
email address (magic link, then back to the list). When signed in it lists the account's devices
(name, platform, connected at, last used, times in UTC), each with a
"Disconnect" button (POST with a CSRF token and an origin check). Disconnecting ends the device session
immediately; a redirect then leads back to the list.
