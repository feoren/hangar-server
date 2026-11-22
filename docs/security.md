# Security and threat model

> **Before real data:** The app's crypto design (hangar-team-crypto) is a custom protocol and
> needs an external cryptographic review before it handles real team data. The relay checks
> signatures, permissions and chains with the crate, but holds no keys.
>
> **Before any release:** The E2E scheme (device keys, membership log, epochs, HPKE wrapping,
> keyed hashes) is a custom protocol and needs an **external cryptographic review**. This
> server contains only the foundation (storage and distribution of opaque data); the
> cryptography lives in the app and is not reviewed here.

## What the server sees

| Data | Visible to the operator | Note |
| --- | --- | --- |
| Members | yes | account IDs (official) or email addresses (self-hosting), roles, join times |
| Devices | yes | device IDs per member, public signing and KEM keys, last connection |
| Epochs | yes | number, who rotated, when; number and size of the wrapped keys |
| Membership log | structure | index, hash, size, author, time; the content is opaque to the server |
| Reservations | hashes | who holds which hash, since when, release requests; not which task |
| Claims | hashes | how many files and folder levels per session, which hashes are equal (that is: two people are working on the same file); not which ones |
| Presence | yes | active/idle/away and timestamps; the status text is encrypted |
| Storage | metadata | kind (decision, task, transcript), size, epoch, author, time |
| Traffic | yes | who is connected with whom and when, request times, sizes, IP addresses (only in memory for rate limiting, hashed) |
| Team names | yes (self-hosting) | stored in plain text because they appear in invitation emails |
| Content | **no** | tasks, notes, file paths, lines, decisions, transcripts exist only in encrypted form |

Further consequences of the hashes: folder levels reveal the depth of paths; equal hashes over
time reveal how long someone works on the same file. Keyed hashes of an epoch cannot be
reversed without the key, but they can be compared within the epoch.

## Attackers and protection

| Attacker | Goal | Protection |
| --- | --- | --- |
| Stranger on the network | eavesdrop, take over a session | TLS via Caddy; tokens only in headers; HSTS; no cookies for the app |
| Stranger without an account | enter teams | Tickets: Ed25519, valid for 60 s, `jti` single use, team taken from the ticket; devices bound to one member |
| Member | release other people's reservations, bypass the seat limit | holder check per intent; the seat is decided by the website or by the acceptance transaction; rotation only by owner/admin |
| Stolen refresh token | stay signed in permanently | rotation; reuse revokes the entire session |
| Browser on a foreign site | CSRF, login CSRF, WebSocket hijacking | `Origin` check (WebSocket and writing requests), browser forms only with a matching `Origin`/`Sec-Fetch-Site`, synchronizer token, `SameSite=Lax`, `HttpOnly`, `__Host-` cookie under https |
| Link scanners in mail clients | consume magic links | GET only shows a confirmation; redemption happens via POST |
| Phishing with one's own device code | pull someone else's account onto one's own device (request a magic link with `return_to=/device?code=...` for someone else's address) | The code in the return URL only applies in the browser that requested the link (cookie, hash in `magic_links.browser_hash`); otherwise the person lands on `/device` without a code. The confirmation page names the device and shows no Allow button for unknown codes. Residual risk: someone who types in a foreign code themselves, or clicks a `verification_uri_complete` link and confirms it (RFC 8628, 5.4) |
| Connections without a ticket | occupy connection slots | 15 s deadline until the first valid `hello`; rejected `hello` messages count as broken frames |
| Mass requests | guessing codes, mail flood, memory | rate limiting per IP/address/account, device code 20^8, `slow_down` when polling, frame and list limits, storage quota, connection limits |
| Server operator | read content | E2E (app); the server knows neither team keys nor hash keys |
| Server operator | inject keys | protection lies in the signed membership log, which the clients verify; the server only checks the chain |
| Server operator | suppress or reorder events, analyse metadata | not prevented; clients detect gaps in `seq`, but not omissions at the end |
| Self-hoster | bypass the seat limit | possible with an own license key in the configuration; prohibited by the Elastic License 2.0 (see license-format.md) |

## Measures in place (excerpt, ASVS Level 2 as the benchmark)

- Prepared statements everywhere, SQL texts static; identifiers and hashes validated before use.
- Tokens: 32 random bytes from the operating system, stored as SHA-256; access 1 h,
  refresh 30 days, browser 12 h, magic link 15 min, device code 10 min, invitation 7 days.
- Sessions can be revoked individually (`DELETE /v1/sessions/{id}`, in the browser
  `/account/devices` with CSRF token and origin check); signing out revokes one's own session; the
  app signs out via `POST /api/v1/oauth/revoke` (RFC 7009), and a refresh token ends the entire
  device session. Reuse of a rotated refresh token revokes the session.
- Account API `/api/v1` ([account-api.md](account-api.md)): body at most 16 KiB, only form
  data or flat JSON, errors as problem+json without internal details, 401 with
  `WWW-Authenticate`; rate limiting for device start, token, revocation and tickets; only present
  in self-hosting.
- No disclosure of whether an address exists (same response; mail only to permitted addresses).
- Foreign teams respond with 404, not 403.
- Security headers: CSP without scripts (`default-src 'none'`), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer` (tokens in paths), COOP/CORP, `no-store`, HSTS
  under https.
- Logging: JSON, only route patterns instead of paths (no tokens in the log), no tickets, no
  email addresses in error messages to clients.
- Mail: no external images, no tracking, no content from tasks or files; subject lines without
  control characters; SMTP only with TLS (STARTTLS required, or SMTPS), certificates are
  verified.
- Container: distroless, without a shell, user `nonroot`, read-only file system except `/data`,
  all capabilities dropped.
- The ticket key for self-hosting is stored at `DATA_DIR/ticket-signing.key` (0600).

## Relay checks with hangar-team-crypto

- The relay only stores log entries that `LogVerifier` has accepted (signature of the sending
  device, permissions according to the lower of the log role and the ticket role, team, index,
  `prev`). This means no member can use the relay to inject entries that other clients would
  reject anyway, and the relay and the clients see the same log.
- New devices in the log must carry the keys that this holder registered over its own
  authenticated connection (`check_registered_keys`): an admin cannot enter keys of their own
  choosing for other holders.
- Rotations and device removals only arrive with their signed entry and are stored atomically;
  the relay's directory and the log never diverge.
- `key.wrap`: at most one package per sender and four per target and epoch, never replaced; a
  single device cannot occupy all slots.
- Residual risk: the relay sees the plain text of log entries (members, devices, roles, public
  keys); this is by design (the clients also read the log in plain text).
- A removed device reads the log only up to its removal (`relay_removed_devices.log_index`;
  for older blocks, the last entry up to the time of the block).

## Open points

- External crypto review (see above) and test vectors for step E in the app.
- Revoking permissions in official mode has two stages: the website's revocation list
  (`hangar-revoke-v1`, every 15 s, docs/revocation-format.md) and the app's `ticket.renew`
  (roughly every 5 min). If the website is unreachable, a revocation takes effect at the latest
  with the next ticket (`ticket.renew` or `CONNECTION_MAX_AGE_SECS`). In self-hosting, immediately.
- Defaults that limit residual risks until `ticket.renew` is in effect everywhere: maximum age of
  a connection per team 10 min (`CONNECTION_MAX_AGE_SECS=600`), at most 20 connections per
  client address (`MAX_CONNECTIONS_PER_IP=20`, IPv6 per /64).
- A lost device is removed by an owner, an admin or another device of the same member with
  `device.remove`: reservations released, key packages deleted, block list per team and holder.
  It still knows the current team key; only `key.rotate` locks it out.
- Grace period of the removed device (docs/protocol.md, `device.remove`): for at most 5 s per
  connection it may only send `memberlog.get`, even after a new `hello`, so that the app can
  verify the removal against the signed entry. It only receives entries up to the one that
  removed it, so nothing it was not already allowed to read before its removal: members,
  devices, roles, public keys, epoch commitments and the history link of a rotation
  (`HistoryLink`, encrypted with the secret of the new epoch, which the device no longer
  receives after its removal). In addition, stream, head and epoch number in the `welcome`. No
  reservations, claims, presence, notes, storage, key packages or `devices`; it writes nothing,
  does not count as a member and does not appear for anyone. A `hello` of this kind needs a
  fresh ticket (`jti` single use, rate-limited by the website) and occupies one connection slot
  per member and address; the per-connection rate limit still applies.
- `notify` never carries plain text: at most the encrypted note of a release request.
- The state for restarts (reservations, log position, notes) is kept in SQLite; it contains only
  hashes, holders and encrypted notes.
- Role changes take effect silently on the running connection; permissions are checked per
  message against the current role. A downgrade therefore cannot stop a single intent that is
  already in progress, but it does stop every subsequent one.
- `key.wrap` never replaces an existing package (`conflict`); only owner/admin or another device
  of the same member may wrap, never the target device itself (`e2e::check_wrap`).
- Outgoing requests: only fetching the revocation list, only to `REVOCATION_URL` (https, without
  redirects or proxy, 10 s, 1 MiB). The bearer token is kept only in the environment.
- Rate limiting and operation IDs live in the memory of a single process; multiple nodes would
  need Redis or the database.
- Passkeys and OIDC (GitHub, self-hosted forges) are planned for later.
- Account deletion and data export in self-hosting are still missing (GDPR Art. 17 and 20).
- Storage has a quota per team and a retention period only for transcripts
  (`TRANSCRIPT_RETENTION_DAYS`); decisions and tasks remain until the team is deleted.
- The notes key ring (protocol version 2) is one sealed record per team, readable only with the
  epoch key; the relay keeps the writing device's IDs and the time with it and deletes it with
  the team. Only a device of the verified log with owner or admin as its effective role may
  replace it, and only on top of the stored version (`conflict` otherwise), so a stolen ticket
  without a device in the log cannot overwrite it.
