# Requests to the app's protocol crate

For the app session that maintains `hangar-team-protocol` and `hangar-team-crypto`. The
server uses both as unmodified copies (`vendor/`, origin in each `ORIGIN.md`, see
[development.md](development.md));
`src/wire.rs` only re-exports names. The earlier requests (E2E messages, `member.role_changed`,
`offline`, `ticket.renew`, close codes, permission helpers, `key.wrapped`, holder in `WrappedKey`) have
been implemented by the crate. Questions left open after b30b9d5, decided together with the app session on
2026-11-09:

- **Rotation with incomplete packages:** remains allowed. Requiring completeness
  would let a defective or malicious device key block every rotation. Devices without a
  package get one later via `key.wrap` from owner/admin or a device of the same member;
  the app reports `Rotation::failed` to the person who rotated.
- **Blocked devices after `RemoveMember`:** the block is permanent. On readmission the
  app always creates a new device identity (new ID, new keys); lifting the block
  would let old, possibly lost devices back in. On 4403 the app discards the
  team identity for that project.

From the interop run with the app (2026-11-09):

- **Handover (`task.release_answer` with `accept`) and note:** done. The new reservation
  carries `note: None`, sent as stored, so also in the snapshot. The request's note
  is a `ReleaseRequestNote` from the requester; as `task.reserved.note` the app opened it as a
  `ReservationNote` with the holder as sender, and the signature context did not match. The new
  holder then sends their own note via `task.reserve` (the relay announces it with
  `task.reserved`). This also settles the request "handover with the new holder's note".
- **`task.release_requested.requester` as a full holder:** open. Currently only `MemberId`;
  the app will provide the protocol fields in the crate later.

Earlier requests (history, implemented):

As of 525a8c7: requests 1 to 5 below are implemented (export/restore, `EventLog::position`,
`notify` with recipient, `CLOSE_TEAM_DELETED`, `device.remove`, description of
`CLOSE_ROLE_CHANGED`) and wired up in the relay. The text remains as history.

## 1. Reservations across a restart

`ReservationBook` has no way to restore stored holds (no `serde`,
no `restore`). For each held task the server stores only holder, epoch and note and
reserves it again on load (`Intent::Reserve` at the current epoch). Consequences: `since` and the
timeout start over; open release requests, cooldowns and holds from an older epoch
(rekey grace period) are lost. So that clients do not trust stale state, every
load begins a new `stream` (snapshot instead of replay).

Request: `ReservationBook::export()` and `ReservationBook::restore(...)` (or `Serialize`/
`Deserialize` for `Reservation`), so that a restart loses nothing; then the server can also
use `EventLog::resume` with a stored `head`.

## 2. `notify`

`Notify` has no recipient. A logged event goes to all devices of the team, but it is meant
only for the holder. The server therefore does not generate `notify` yet (in self-hosting a
notification email without content is sent). Request: a `member` field (recipient) or a targeted,
non-logged variant like `key.wrapped`.

## 3. Close code for a deleted team

The server closes with 4404 when a team is deleted (`project_deleted` in the revocation list, self-hosting).
The crate does not know this code. Request: `CLOSE_TEAM_DELETED = 4404` in the `close` module.

## 4. Removing a device

`ReservationBook::remove_device` and `ClaimBoard::clear_device` are wired up
(`Relay::remove_device`), but no message removes a device. Request: define where the
relay learns about it (a dedicated `device.remove` intent for owner/admin, or the website's revocation
list with a kind such as `device_removed`).

## 5. Role change without disconnecting

Decision by the coordinator (2026-11-09): role changes apply silently on the live connection,
from `ticket.renew` and from the revocation list (`role_changed` with `role`);
`member.role_changed` announces them. 4401 (`CLOSE_ROLE_CHANGED`) only when the new role is unknown.
Please align the description of `CLOSE_ROLE_CHANGED` in the crate with this.
