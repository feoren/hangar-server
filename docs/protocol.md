# Live protocol (versions 1 and 2)

The protocol belongs to the app: the crates `hangar-team-protocol` (step C) and `hangar-team-crypto`
(step E), kept here as unmodified copies under `vendor/` (origin in each `ORIGIN.md`). Messages,
limits, and the rules for reservations, claims, the log and the E2E checks come from the
crates; the reference is their READMEs plus `docs/wiki/pages/concepts/team-protocol.md` and
`team-crypto.md` in the app repository. This document
describes how the relay runs it. Open requests to the crate:
[protocol-wishes.md](protocol-wishes.md).

## Connection

- `GET /v1/live` with a WebSocket upgrade. The app sends no `Origin`; if one is present, it must
  be listed in `ALLOWED_ORIGINS` or equal `PUBLIC_URL`, otherwise 403.
- One text frame = one JSON object, at most 1 MiB (`limits::MAX_FRAME_BYTES`; larger frames are
  already rejected by the WebSocket reader). Binary frames: `err badRequest`.
- The server pings every 25 s; after 60 s without any sign of life it disconnects (close 1001).
- Limits: `MAX_CONNECTIONS` in total (200) and `MAX_CONNECTIONS_PER_IP` (20) per client address (IPv6 per /64)
  answer with 503 before the upgrade. Connections still waiting for their first valid `hello`
  have a quota of a quarter of `MAX_CONNECTIONS` (at least 1); when it is full, a new connection
  closes the oldest waiting one (1008) instead of being refused, so connections that never sign
  in cannot lock anybody out (the app sends `hello` right away). One address (IPv4, IPv6 per
  /48) may have a quarter of `MAX_CONNECTIONS_PER_IP` (at least 4) waiting, beyond that 503.
  After the first valid ticket the connection counts only in the total;
  `MAX_CONNECTIONS_PER_MEMBER` per member gives `err limit`; 30 frames/s per connection with a
  burst of 120 (`err rateLimited` with `retryAfterMs`); more than 20 malformed frames, binary
  frames, rejected `hello`s or other messages before `hello`: close 1008.
- Without a valid `hello` within `close::HELLO_TIMEOUT_SECS` (15 s) the server closes with
  `CLOSE_HELLO_TIMEOUT` (1008); pings alone do not hold a connection slot.
- Maximum age `CONNECTION_MAX_AGE_SECS` (default 10 min) per team, counted from the last verified
  ticket (`hello` or `ticket.renew`); after that, close 4401 and reconnect with a cursor. The
  short default limits residual risks (hoarded tickets, missed revocations) until the app's
  `ticket.renew` is in effect everywhere.
- Close codes: 1008 (`CLOSE_HELLO_TIMEOUT`), 1012 restart, 1013 reading too slowly
  (outgoing queue of 512 frames or 4 MiB full), 4401 (`CLOSE_ROLE_CHANGED`: new ticket required), 4403
  (`CLOSE_REMOVED`: removed, device removed, no seat, ticket invalid; for a removed
  device only after its grace period, see `device.remove`), 4404 (`CLOSE_TEAM_DELETED`: team
  deleted).

## Memory per connection

An idle connection needs a few dozen KiB (WebSocket buffers start at 16 KiB). Every connection
can hold a frame of up to 1 MiB in its read buffer, and its outgoing queue is limited to 512
frames and 4 MiB; a client that does not read fast enough is closed with 1013. The catch-up
after a `hello` (replay or snapshot, see below) goes into the queue as a single entry and does
not count against these limits but against its own budget of 16 MiB per connection (four teams
with a full replay window of 4 MiB): a client with a long replay is not closed before it could
read, and one that joins many teams without reading is closed with 1013. Plan about 2 MiB
per connection plus 64 MiB for the process: with the default of 200 connections that fits the
Compose limit of 512 MiB. If you raise `MAX_CONNECTIONS`, raise the memory limit in the same
proportion; at startup the server reads the cgroup memory limit and warns when
`MAX_CONNECTIONS` does not fit. Real frames are usually a few KiB; the large case is a `claim.set` with 1000
files and detail, or a `blob.put`.

## Frames

```
Client: {"v":1,"id":"<op>","team":"<team>","type":"task.reserve","body":{...}}
Server: {"v":1,"id":"<op answered>","seq":12,"team":"<team>","type":"task.reserved","body":{...}}
```

- `v` is the envelope version (`ENVELOPE_VERSION`, 1 for every protocol version so far) and is
  read first; a lower value gets `err outdatedClient`, a higher one `err badRequest`. Which message kinds a connection may
  use is the protocol version negotiated per team in `hello` (see below).
- `id`: operation ID. For intents with `ClientMessage::deduplicated` (all `task.*`, `blob.put`,
  `memberlog.append`, `key.rotate`, `key.wrap`, `notes.keys.set`) the relay remembers sender (member and
  device), team and `id` together with the digest of the content (`RecentOps`, 4096 per team): the same
  intent sent again gets the first answer, a different one under the same `id` gets `badRequest`.
- `team`: project ID of the website or team ID in self-hosting, opaque. Missing only for `ping`.
- Before every intent the relay checks the epoch (`ClientMessage::check_epoch`): hashes and
  encrypted content of any epoch other than the current one result in `err staleEpoch`.

## Signing in: `hello`

Ticket verification: [ticket-format.md](ticket-format.md). The member comes from `sub`, the device from
`hello.device`; device IDs are only unique per member (the same ID for two members means two
devices). One connection can sign in to several teams, but belongs to exactly one member.

- **Protocol version.** `hello.proto` offers a range; the relay speaks `ProtoRange::CURRENT`
  (`{1, 2}`) and answers with the highest version both speak in `welcome.proto` (an app of
  version 1 offers `{1, 1}` and gets 1). A range that ends below 1 gets `err outdatedClient`,
  one that starts above 2 `err badRequest`. The version holds per connection and team.
- **Replay** (cursor within the window): `welcome` with the `id` of the `hello`, then the events
  after the cursor in order, then live.
- **Snapshot**: `resync_required`, then `member.joined`, `task.reserved` per hold (plus
  `reservation.expiring` and `task.release_requested` where they apply), `presence.update`, and finally
  `welcome`.
- Replay and snapshot are queued in one piece under the team lock, whatever their length (up to
  the 2048 events of the window): no live event comes before or in between, and `welcome` is
  never dropped. Live events follow afterwards.
- A removed member only gets back in with a ticket issued after the removal
  (`iat` later than the revocation).

## `ticket.renew`

The app sends a fresh ticket for a signed-in team roughly every 5 minutes. Not
deduplicated. Before the team's `hello`: `err badRequest`.

- Valid (signature, kid, time, `aud`, unique `jti`, same member, `seat_ok`): silently adopt the role from
  the ticket, `ack`, restart the maximum age. An actual change is announced to everyone as
  `member.role_changed`.
- `prj` of a different team: `err forbidden`, then close 4403.
- Invalid, different member, `seat_ok: false`, already used: close 4403.

## Role changes during a connection

Decision of 2026-11-09: if the new role is known (from `ticket.renew`, from the
revocation list `role_changed` with `role`, in self-hosting from team management), it applies
immediately and silently on all of the member's connections; the team receives `member.role_changed`.
There is no disconnect: since permissions are checked per message against the connection's role,
owner and admin intents fail on their own after a downgrade (`err forbidden`, for example
on the next `key.rotate`). Only when a change is reported without a new role
(`role_changed` without `role`) does the relay close with 4401, and the app reconnects with a
new ticket.

## Event log

- Sequence numbers per team starting at 1 (`EventLog`), with a window of the last 2048 events in memory,
  and at most 4 MiB of them (`REPLAY_WINDOW_BYTES`, the encoded events): above that the oldest
  leave the window early, down to 3 MiB, and a cursor behind them gets a snapshot (`tooOld`).
  Usual events have a few hundred bytes; the limit only bites with many large notes or log
  entries.
- The log position (`EventLog::position`: stream and head) is stored together with the book in
  `relay_team_state`. On load, `EventLog::resume` continues the stream: a client exactly at the
  stored head carries on without a snapshot, an older cursor gets `tooOld` (the
  window exists only in memory). If the state is missing or unreadable, a new
  stream begins (`otherStream`, snapshot).
- **Durability rule:** no frame with a `seq` leaves the relay before a write whose
  head covers that `seq` is durable (SQLite `synchronous = FULL`). This applies to every
  logged event, including those that do not change the book (`member.joined`,
  `device.removed`). Otherwise a restart would assign the same `seq` to a new event, and a
  client would discard it as a duplicate. Test: `tests/persistence.rs`.
- After restoring a backup, the stored stream continues. Clients that had
  seen events after that point are ahead of the head (`ahead`) and fetch a snapshot.
- Logged: whatever `ServerMessage::loggable` lists. Not logged: `presence.update`,
  `claim.overlap`, `key.wrapped`, `notify`, `notes.keys.updated`, responses.
- Events go to all of the team's connections, including the one that triggered them; after that the response goes to
  the triggering connection. Targeted messages (`ServerMessage::recipient`) go only to their
  recipient. The one exception is `notes.keys.updated`, which announces the answer's own write
  and follows the `ack` of `notes.keys.set`.
- **Version filter.** A client kind newer than the connection's negotiated version
  (`ClientMessage::since`) gets `err badRequest`, as a relay of that version would answer; it is
  neither applied nor remembered for retries. A server kind newer than it
  (`ServerMessage::since`) is never sent to that connection: every frame carries its kind's
  version through the relay's single send path, which drops it for an older connection. Today
  only the notes key ring kinds are of version 2, and none of them is logged, so replay and
  snapshot are the same for both versions.

## Reservations

Rules: the crate's `ReservationBook` ("first wins" in order of arrival per team, 30 min timeout
only while offline with a warning 5 min before, release requests with a 10 min timeout and cooldown, `withdraw`,
`force_release` for owner/admin, rekey with `prev` and a grace period after a rotation). Time-driven
events (`Applied::timing`) are sent even when the intent is rejected. Presence is counted per connection.

After every operation the relay stores `ReservationBook::export()` (BookSnapshot v1) together with
the log position and the encrypted notes (`note`) that it keeps next to the book. On
load, `ReservationBook::restore(snapshot, policy, now)` restores everything: holds with
`since`, activity, warning, open release requests, cooldowns, epoch and rekey grace period. After that
all holders count as disconnected: the timeout of each hold runs from the restart (at least the
warning time), and the restart's events (`Restored::events`) go into the log. If a crash
left `key.rotate` already committed in the database but not in the book, the relay moves the book
to the database's epoch on load.

## notify

The crate's `Notify::attention`: for `task.release_requested` and `reservation.expiring` when
no device of the holding member is connected to the team. Targeted (only to the member), never
logged. Per member and team only the newest undelivered one is kept (`relay_pending_notify`,
survives restarts); it is sent right after the next `welcome` to all of the
member's connections and then deleted. In self-hosting a notification email without content is also sent.

## device.remove

`{holder, log}`, deduplicated, only with the signed `RemoveDevice` entry in `log`.
`LogVerifier::admit_device_remove` checks it against the log's rule (anyone may remove another
device of their own, the owner any other device, an admin a member's device; exactly `holder`). Without a valid
entry, or for a device the log does not know: `badRequest`. Then, in one transaction:
store the entry, put the device on the block list per team and holder (`relay_removed_devices`), delete its
key packages and `device.keys` in the team. Then `ReservationBook::remove_device`,
`ClaimBoard::clear_device`, `memberlog.appended` and `device.removed` (both logged). An
owner or admin should rotate the team key.

**Grace period of the removed device.** The app only believes its removal once it has verified the signed
entry in the log (the relay's events are not signed). That is why the
relay does not close immediately:

- From the entry onward its connections are no longer recipients (no presence, no claims, no
  reservations, they do not count as a member). They only receive `memberlog.appended` up to the
  removing entry and their own `device.removed`, both without `seq` (the crate allows
  logged events without `seq`): it does not get the events in between, such as the release of its
  reservations, and with a `seq` the app would see a gap
  (`SessionEnd::Gap`) and abort before verifying the log.
- After that a grace period runs (`Config::removed_grace_ms`, 5 s, not configurable through the
  environment). During it the relay only answers `memberlog.get` for this team, with entries after `after` up to
  and including the removing entry (`relay_removed_devices.log_index`); the device never gets later entries
  (new members, devices, epochs). Everything else for this team is answered with
  `err forbidden` and nothing is written.
- The grace period applies per team: other teams the same connection has joined keep working
  as usual. Only while every joined team is in its grace period are frames without a team
  (`ping`) and `hello` for further teams also answered with `err forbidden`.
- After the last page (`more: false`) or when the grace period ends, the connection leaves the
  team; close 4403 only when no other team is left on it.
- If the connection was already gone: a later `hello` from this device with a valid ticket gets
  only `welcome` (stream, head, epoch; no snapshot, no replay, no join events,
  no `see_member`) and then the same grace period. This applies only to a connection without another team and
  only with a ticket that `ticket.renew` would also accept (`ticket_age`: not issued up to a
  removal of the member or a role change); otherwise `err forbidden` as
  before.

The app verifies the log, discards its team identity and signs in with a new device ID.

## Claims

The crate's `ClaimBoard`: hashes `{area, file}` per file, `sameFile` for an identical file hash
(with the other side's encrypted `detail`), `sameArea` for an identical area; only for the same
`repo` and the same epoch, never two sessions of the same holder. Claims exist only in memory
(2000 sessions per team, 64 per device, 256 per member over all its devices, and a byte budget:
file hashes plus encrypted `detail` of all sessions of a member at most 4 MiB, of the whole team
at most 32 MiB; the largest `claim.set` takes about 240 KB, so a member fits 17 of them. Since
one account can be in many teams, there are limits over all loaded teams as well: a member at
most four times its limit per team, all claims of the relay together at most 64 MiB. Beyond a
limit `err limit`, and a replaced session counts with its new size), remain for 24 h after a
disconnect and then expire; on
leaving, `clear_member`, on removing a device, `clear_device`. Deliberately not persisted:
after a restart the board is empty, and every client resends `claim.set` for its sessions after
every `welcome`.

## E2E foundation

The relay keeps one `memberlog::LogVerifier` (hangar-team-crypto) per team. After a restart
it rebuilds it with `apply_all` from the stored entries. Every check runs on a
copy of the verifier; only once the database has written the entry does the copy replace the
original. A rejected entry therefore changes nothing and does not block the log: the next
valid entry at the same index goes through.

The **effective role** is the lower of the log role and the role in the connection's ticket: a
downgrade on the website takes effect immediately, even if the log does not know about it yet.

- `device.keys` `{sign, kem, proof}`: keys and proof of possession per team and holder
  (`relay_device_keys`). At most `limits::MAX_DEVICES_PER_MEMBER` (16) devices per member and
  `MAX_WRAPPED_KEYS` (512) per team, otherwise `limit`. `devices.get` lists them including the proof.
- `memberlog.append`: first `relay::check_registered_keys` (every device the entry
  adds carries exactly the keys this holder sent over its own connection;
  otherwise `forbidden`), then `LogVerifier::admit(append, sender, ticket_role)` (signature of the
  sending device, permissions per kind, team, index, `prev`, device limits). Entry 1 only with an
  owner ticket. Rotation and device removal through this path: `badRequest`. If the entry removes
  devices (member removed, `Admitted::removed`), they are blocked in the same transaction
  and their packages deleted, then `device.removed` and the grace period of the removed devices
  (see `device.remove`). Rejections answer with `LogError::code()`. `memberlog.get`
  answers with `MemberLogEntries::page`.
- `key.rotate` `{epoch, log, wrapped}`: `e2e::check_rotate`, then
  `LogVerifier::admit_rotation` (entry valid, its epoch equal to `epoch` and the log's next one,
  each package addressed to a different device of the log). Entry, epoch and all packages in one
  transaction or nothing; then `memberlog.appended` and `key.rotated` (logged, each device with
  only its own package from the rotation).
- `key.wrap`: `check_epoch`, then `relay::check_wrap(state, ticket_role, sender, wrap,
  stored_from)`: sender and target are devices of the log, owner/admin for any other device, a
  member only for another device of their own (`forbidden`), unknown target `notFound`, one package per sender,
  target and epoch (`conflict`), at most `limits::MAX_KEY_PACKAGES` (4) per target and
  epoch, including the one from the rotation (`limit`), never replaced. The target device receives
  `key.wrapped` (not logged). Packages are stored per (target, epoch, sender) along with their order.
- `key.get`: all stored packages of the requesting device for the epoch in `ack.keys`, in
  order of arrival; none: `notFound`. The device tries each one against the epoch's
  commitment.

## Notes key ring (version 2)

The team's key ring for shared project notes (ADR 0006, phase 2, in the app repository): one
opaque record per team, sealed by an owner's or admin's device under the current epoch. The
relay cannot read it; it checks role, epoch and version and keeps only the newest record
(`relay_notes_keys`).

- `notes.keys.get` (no body): any member's device. Answer `notes.keys {record}` with the op id,
  only to the asking connection; `record` is `{version, by, content}` or `null` when nothing is
  stored. A connection in its grace period after a device removal gets `err forbidden`.
- `notes.keys.set {base, content}`, deduplicated by op id. In this order:
  1. `content.epoch` the current epoch (`check_epoch`), otherwise `staleEpoch`;
  2. the sender is a device of the verified log and its effective role (the lower of log role and
     ticket role) is owner or admin, otherwise `forbidden` (also when the team has no log yet);
  3. `base` equals the stored version (0: none stored), otherwise `conflict`;
  4. stored in one write transaction as version `base + 1` together with the sending device,
     the epoch and the time, durable before the answer;
  5. `ack` to the sender, then `notes.keys.updated {version, by}` to every connection of the team
     that negotiated version 2 (not logged, no `seq`, no replay; the app fetches with
     `notes.keys.get` after every `welcome` and on every hint).
  The size (`MAX_INLINE_CIPHERTEXT_LEN`) is checked while decoding.
- The record goes with the team (team deleted). Removing a member or a device leaves it; the next
  rotation re-seals it in the app.
- A connection of version 1 gets `err badRequest` for both client kinds and never sees either
  server kind.

## Revocation list (official mode)

[revocation-format.md](revocation-format.md): every 15 s the relay fetches signed revocations from the
website and applies them to live connections.

## Error codes

`conflict`, `limit`, `forbidden`, `rateLimited`, `outdatedClient`, `staleEpoch`, `badRequest`,
`notFound`. Error texts never contain frame content.

## HTTP alongside the live channel

- `GET /health`: `{"status":"ok","version":...}` or 503.
- Self-hosting only: the app's account API under `/api/v1` (device flow, revocation, account,
  projects, `relay-ticket`), identical to the website: [account-api.md](account-api.md). This way the app
  only needs the base `<PUBLIC_URL>/api/v1`; the address of this live channel is in the
  ticket (`relay_url`, `ws`/`wss` derived from `PUBLIC_URL`). Administration (teams, invitations, license)
  under `/v1/...`, see [http-api.md](http-api.md).
