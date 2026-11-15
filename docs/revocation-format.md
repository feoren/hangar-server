# Revocation list (version 1, official mode)

So that revoked permissions do not take effect only with the next ticket, the relay in official
mode regularly fetches a signed revocation list from the website. Together with the app's
`ticket.renew` (roughly every 5 minutes), revoking permissions has two stages.

## Fetching

```
GET <REVOCATION_URL>?after=<cursor>
Authorization: Bearer <RELAY_REVOCATION_TOKEN>
```

Official: `REVOCATION_URL=https://hangar.feoren.com/api/v1/team/revocations`.

- Every `REVOCATION_INTERVAL_SECS` (default 15 s); with `more: true` the next page immediately
  (at most 50 in one round).
- `after`: the last stored cursor (`last` of the previous response), initially `0`.
- Outgoing only to exactly this address: `https://` (or `http://` to `localhost`/`127.0.0.1`),
  no redirects, no proxy, 10 s timeout, response at most 1 MiB.
- Response `200` with the compact document as text (`text/plain`), otherwise an error.
- Errors and unreachability stop nothing: the relay retries with increasing intervals
  (doubling, at most 5 min) and writes a warning to the log.

## Document

Like tickets ([ticket-format.md](ticket-format.md)), context `hangar-revoke-v1`:

```
document  = base64url(payload) "." base64url(Ed25519(sk, "hangar-revoke-v1." + base64url(payload)))
payload   = {"v":1,"kid":"…","aud":"hangar-relay","iat":…,"exp":iat+120,
             "after":<cursor of the request>,"last":<new cursor>,"more":false,
             "items":[{"rid":…,"prj":…,"sub":…|null,"kind":"…","role":"…","at":…}]}
```

Verified with the ticket keys (`TICKET_PUBLIC_KEYS`, same kid rotation):

1. Signature, context, kid.
2. `v == 1`, `aud` equal to `TICKET_AUDIENCE` (official: `hangar-relay`).
3. `exp > iat`, `exp - iat <= 300`, `iat <= now + 30 s`, `now < exp + 30 s`.
4. `after` equal to the requested cursor (an old response cannot be replayed).
5. At most 1000 entries.

An invalid document changes nothing (not even the cursor).

`after`, `last`, `rid`, `prj`, `sub` may be numbers or text; the relay compares text.
`at`: Unix seconds of the change on the website.

## Entries

| `kind` | Fields | Effect |
| --- | --- | --- |
| `member_removed` | `prj`, `sub`, `at` | member removed: reservations released, claims gone, `member.removed`, connections Close 4403 |
| `seat_lost` | `prj`, `sub`, `at` | like `member_removed`, until a new ticket with `seat_ok` arrives |
| `role_changed` | `prj`, `sub`, `role`, `at` | new role applied silently on the running connections, `member.role_changed`; without `role` Close 4401 (new ticket) |
| `project_deleted` | `prj`, `sub: null`, `at` | close the team (Close 4404), delete relay data |

- Idempotent per `rid`: an entry that has already been processed is skipped
  (`relay_revocations_seen`, 30 days). Unknown kinds are logged, remembered and skipped.
- Readmission: a ticket with `iat` after `at` reopens the team (the website has readmitted the
  person). An older ticket stays rejected, even after readmission.
- The cursor (`last`) is stored in `relay_revocation_cursor` and survives restarts. The website
  advances `last` only past entries older than 60 s (a smaller id can be committed after a
  larger one); younger entries therefore arrive several times and are skipped via `rid`. If
  `last` stops advancing, `more` is false.
- Floor for tickets (`relay_ticket_floors`, migration 0006): `member_removed`, `seat_lost` and
  `role_changed` set it to `at`. A ticket with `iat` up to that point does not open the team
  (`hello`: `err forbidden`) and does not renew a connection (`ticket.renew`: Close 4401 on a
  role change, 4403 on removal). Otherwise a downgraded member could use a previously hoarded,
  still valid ticket to get the old role back, for up to `CONNECTION_MAX_AGE_SECS`. The floor
  also stays in place after readmission.

## Configuration

| Variable | Meaning |
| --- | --- |
| `REVOCATION_URL` | address of the list on the website; if it is missing, revoked permissions only take effect with the next ticket (warning at startup) |
| `RELAY_REVOCATION_TOKEN` | secret bearer token of the relay at the website, at least 32 characters |
| `REVOCATION_INTERVAL_SECS` | interval between fetches, default 15 |

## Test data

`src/relay/revocation.rs` (unit tests) and `tests/revocation.rs` (a replica of the website) use
their own test keys. The website's test vector (`tests/php/fixtures/revocations-vector.json` in
the website repository) is available as `testdata/revocations-website.json` and is checked in
`tests/vectors.rs` (`website_revocation_list`) against `revocation::verify`: `valid` and
`empty` are accepted, `expired`, `ticket_context`, `other_key` and `tampered` are rejected. If
the website changes the vector, copy the file from there again.
