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
- Rate limiting per address counts IPv6 per /64 and, four times as generous, per /48
  (`RateLimiter::hit_ip`). Someone with many /48 networks (a /32) can still fill a limiter table
  of 100000 keys; new addresses of that scope are then refused until windows end, known ones
  keep working.
- App sessions have no absolute lifetime: every refresh extends them by 30 days. A stolen
  refresh token that is used before the real device keeps its session alive until someone
  disconnects it under `/account/devices`; a second use by the real device revokes the session.
- An admin of one team learns from the invitation answer (`license_required` or not) whether an
  address already holds a seat in another team of the same owner, while that owner has no
  active license. A hit sends a real invitation; 50 invitations per hour.
- `install.sh` verifies downloads against the release's `SHA256SUMS` (integrity), not against
  the build provenance (`gh attestation verify` does that by hand, see development.md). The Caddy
  image in `docker-compose.yml` follows the tag `caddy:2-alpine` on purpose, so that security
  updates arrive without a new release of this server.
- A connection whose device the log does not list gets no snapshot at its `hello` (no holds,
  sealed notes or presence); the relay sends it once an entry admits the device, on the same
  connection. What it still receives is the logged event stream after its `hello` (see above).
- The snapshot has no size limit of its own: reservation notes of up to 16 KiB each, in a team
  that uses 32 holds per member to the full with about 16 members, can exceed the 16 MiB a
  connection's queue takes; connections that need a snapshot are then closed.
- `device.keys` of a device the log does not list yet keeps its first keys as well: other keys
  under the same device ID are `conflict`, the same keys again are fine (the app sends them at
  every `hello`). A second connection of the member's account can therefore not swap its own
  keys in under the ID of a device waiting for admission.
- Rows in `relay_device_keys` of devices never admitted and of removed members are kept and
  count against 16 devices per member and 512 per team.
- Rate limiting and operation IDs live in the memory of a single process; multiple nodes would
  need Redis or the database.
- Passkeys and OIDC (GitHub, self-hosted forges) are planned for later.
- Without mail (self-hosting, `MAIL_TRANSPORT=none`) the inviter receives the invitation link and
  could open it before the invited person. An account created that way counts as unproven: its
  first sign-in with a magic link or a `login-link` of the operator ends every session started
  before (browser and app) and denies approved device codes not yet fetched; relay tickets already
  issued stay valid until they expire (60 s), and open relay connections until
  `CONNECTION_MAX_AGE_SECS` (10 min). If an invited person reports their link as already used, the
  operator issues `login-link` for the address.
- Magic links: a link opened in a browser other than the one that requested it shows a warning
  (someone may have forwarded a link for their own account). Creating the link and the mail runs
  after the answer, so its timing does not tell whether an address is known. In closed sign-up
  (`SIGNUP=invite`) only addresses that may sign in count against the limit per address; with
  `SIGNUP=open` every address may, so anyone with many networks can fill that table (100000
  addresses per hour) and silence sign-in mails for new addresses for that time.
- Names and addresses from input lose invisible formatting characters (bidi overrides,
  zero-width characters); an address containing one is refused.
- Request headers must arrive within 10 s (`HEADER_READ_TIMEOUT`).
- Account deletion and data export in self-hosting are still missing (GDPR Art. 17 and 20).
- Storage has a quota per team (`BLOB_QUOTA_BYTES`), per member within a team of several (half
  of it, so that one member cannot lock the others out of storing) and per member over all teams
  (twice that),
  and a retention period only for transcripts (`TRANSCRIPT_RETENTION_DAYS`). On protocol version
  3 the author, an owner or an admin deletes a blob with `blob.delete`, which frees the quota;
  nothing of it stays.
- Decisions (protocol version 4) are blobs the app seals with the team's notes key; the relay
  never opens one. It keeps and shows to the team's counting devices of version 4 what it needs
  for the listing: how many decisions a team has, their padded sizes, who stored them (member
  and device) and when. At most 200 per team and 50 per member, each at most 24 KiB, so one
  member cannot take the whole team's room; owners and admins can delete anyone's. A connection
  that does not count as a device of the log gets neither the listing nor the hints
  `blob.stored` and `blob.deleted`, and a connection starts at most one listing per 5 s.
- Memory over all teams: claims at most 64 MiB in total and four times the per-team limit per
  member. Replay windows: once all of them together hold more than 32 MiB, every team that
  writes keeps only 128 KiB (older cursors get a snapshot), so beyond 32 MiB each loaded team
  adds at most that much. The limits per team alone would let one account with many teams fill
  the memory.
- The device ID in `hello` is chosen by the client. On protocol version 3 the connection proves
  that it holds the signing key the membership log lists for it (`device.prove` against the
  `welcome`'s random challenge); until then, and on every version for a device the log does not
  list, it may only register (`device.keys`, `device.prove`), read the log and the device
  directory, renew its ticket and ping (docs/protocol.md, "Proof of possession"). A blocked device
  (`device.remove`) that comes back with a new ID therefore acts as nothing and reads no
  claims, blobs, notes key ring or snapshot of reservations and presence. A second
  connection with a stolen ticket and a listed device ID acts as nothing on version 3, receives
  no targeted message (`claim.overlap`, `key.wrapped`, `notify`) and causes no presence or
  reservation change. What stays open:
  - every connection with a valid ticket receives the logged event stream (hashes, sealed small
    notes and statuses, readable only with an epoch key it may still have); `key.rotate` after a
    removal stays the cure, so after `device.remove` sign the device out on the website as well
    and rotate the key;
  - until `REQUIRE_DEVICE_PROOF=true`, a stolen, unused ticket with the ID of a listed device that
    never ran a version 3 app still acts as that device on versions 1 and 2. Once a holder has
    proved itself on version 3, the relay refuses its `hello` below version 3 and closes its open
    connections of older versions (`relay_device_proofs`).
- `device.keys` cannot change the keys of a device the verified log already lists (`conflict`).
- The notes key ring (protocol version 2) is one sealed record per team, readable only with the
  epoch key; the relay keeps the writing device's IDs and the time with it and deletes it with
  the team. Only a device of the verified log with owner or admin as its effective role may
  replace it, and only on top of the stored version (`conflict` otherwise). The relay checks the
  device ID from `hello`, not the possession of the device: a stolen, unused ticket of an owner
  or admin, used with the ID of one of that member's devices from the log, could overwrite the
  ring with garbage (the app does not accept a record whose signature does not verify, so notes
  become unreadable until an admin writes the ring again). On protocol version 3 such a ticket
  cannot act as the device (proof of possession, see above); the case stays open on versions 1
  and 2 for a device that never proved itself, until `REQUIRE_DEVICE_PROOF=true`.
