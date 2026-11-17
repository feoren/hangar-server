# Ticket format (version 1)

A ticket is the short-lived proof with which the app opens a live connection to a team. In
official mode it is issued by the website hangar.feoren.com (account, project, role and seat are
decided there), in self-hosting by the server's own identity. The app passes it on
unchanged in `hello.ticket`; only the relay verifies it.

## Structure

```
ticket   = base64url(payload) "." base64url(signature)
payload  = UTF-8 JSON object (fields below)
signature = Ed25519(secret_key, "hangar-ticket-v1." + base64url(payload))
```

- base64url according to RFC 4648 section 5, **without** `=` padding; other encodings are
  rejected.
- What is signed are the ASCII bytes of `hangar-ticket-v1.` followed by the base64url text of
  the payload, not the JSON itself. That is why neither side needs canonical JSON: exactly the
  bytes that were sent are verified. The context `hangar-ticket-v1` separates tickets from
  licenses (`hangar-license-v1`), so that neither document can pass as the other.
- Maximum length 2048 characters.

## Fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `v` | number | yes | format version, `1` |
| `kid` | text `[A-Za-z0-9_-]{1,64}` | yes | key ID; the relay uses it to select the public key |
| `sub` | text, 1 to 128 characters, no control characters | yes | account ID on the website (opaque) |
| `prj` | text, 1 to 128 characters, no control characters | yes | project ID on the website = team; must match the frame's `team` |
| `role` | `owner`, `admin`, `member` | yes | role in the project; `key.rotate` only for owner/admin |
| `seat_ok` | bool | yes | the website confirms the seat. `false`: the relay responds `err limit` |
| `iat` | Unix seconds | yes | issue time |
| `exp` | Unix seconds | yes | expiry; the website issues `iat + 60` |
| `jti` | text `[A-Za-z0-9_-]{16,64}` | yes | unique identifier; a second `hello` with the same `jti` is rejected |
| `aud` | text | yes | audience. The website issues `hangar-relay` (`TEAM_TICKET_AUDIENCE`), self-hosting its `PUBLIC_URL`. The relay requires exactly its `TICKET_AUDIENCE` (default: `hangar-relay` with `IDENTITY=official`, `PUBLIC_URL` with `local`); if `aud` is missing, the ticket is rejected |

Unknown fields are ignored (extension without a new version). An incompatible change increments
`v`; the relay rejects other versions.

## Relay verification rules

1. Form and length, strict base64url.
2. Read `kid` from the payload (only this field before verification), select the key from
   `TICKET_PUBLIC_KEYS`, reject unknown `kid`.
3. Signature with `verify_strict` (Ed25519 according to RFC 8032, without weak keys).
4. `v == 1`, `kid` in the payload equal to the selected one, fields well-formed.
5. `exp > iat` and `exp - iat <= 300`.
6. `iat <= now + 30 s` and `now < exp + 30 s` (clock skew 30 s).
7. `aud` equal to `TICKET_AUDIENCE` (required).
8. `prj` equal to the team of the `hello` frame; `seat_ok` true.
9. `jti` never used before (stored in SQLite until expiry, survives restarts).
10. The device (`hello.device`) belongs to this `sub` or is assigned to it now.

Every rejection is `err forbidden` for the client (or `limit` for `seat_ok: false`); only the
server log records the reason, and it never records the ticket itself.

## Key rotation

- `TICKET_PUBLIC_KEYS=web-2026-1:<b64>,web-2026-2:<b64>` holds several keys.
- Procedure: add the new key to the relay and restart, then sign with it on the website, and
  after 5 minutes (longest validity plus skew) remove the old one.
- The secret key exists only on the website (`.env`, never in the repository).

## How the website signs (PHP, libsodium)

```php
function hangar_b64url(string $bytes): string {
    return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

function hangar_ticket(array $claims, string $kid, string $seed32): string {
    // Fixed order only for readability; the bytes that are sent are what gets verified.
    $payload = [
        'v' => 1, 'kid' => $kid, 'sub' => (string) $claims['sub'], 'prj' => (string) $claims['prj'],
        'role' => $claims['role'], 'seat_ok' => (bool) $claims['seat_ok'],
        'iat' => time(), 'exp' => time() + 60,
        'jti' => hangar_b64url(random_bytes(16)),
        'aud' => 'hangar-relay',
    ];
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed32));
    $p = hangar_b64url($json);
    return $p . '.' . hangar_b64url(sodium_crypto_sign_detached('hangar-ticket-v1.' . $p, $secret));
}
```

Send `sub` and `prj` as text (even if they are numbers); the relay compares text.
Public key for the relay: `hangar_b64url(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed32)))`.

## Test vectors

`testdata/tickets.json` contains the test key (RFC 8032, section 7.1, test 1; publicly known,
for tests only), a fixed verification time `now` and, for each case, the exact payload, the
document and the expected result (`ok`, `expired`, `not_yet_valid`, `lifetime`,
`bad_signature`, `unknown_key`, `payload`). Cross-check:

```sh
cargo test --test vectors                                   # Rust side
php tools/php/verify_vectors.php testdata/tickets.json      # PHP builds byte-identical documents
```

Example (`valid`, verification time 1794225600):

```
payload  {"v":1,"kid":"test-2026-1","sub":"1042","prj":"317","role":"member","seat_ok":true,"iat":1794225590,"exp":1794225650,"jti":"Zx8qW2u0Tt6m1d9KcPq3vA"}
ticket   eyJ2IjoxLCJraWQiOiJ0ZXN0LTIwMjYtMSIsInN1YiI6IjEwNDIiLCJwcmoiOiIzMTciLCJyb2xlIjoibWVtYmVyIiwic2VhdF9vayI6dHJ1ZSwiaWF0IjoxNzk0MjI1NTkwLCJleHAiOjE3OTQyMjU2NTAsImp0aSI6Ilp4OHFXMnUwVHQ2bTFkOUtjUHEzdkEifQ.DaX2WEcL6DFRgNLKnEsY945sqKDLug1OOgDhPt60qdIh7Tm5VydoPEbtJkdA_Cn5VPwQf2Dwd_Txn4RZnaLzDQ
```
