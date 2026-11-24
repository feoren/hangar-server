# License format (version 1)

License documents apply to **self-hosting** (`IDENTITY=local`). The website hangar.feoren.com
sells seats and issues a signed document after purchase; the owner uploads it to their team
server (`PUT /v1/license`). The server verifies it only with public keys from its configuration
(`LICENSE_PUBLIC_KEYS`), offline.

In official mode there is no license check in the server: there, the website decides
about the seat and reports it in the ticket (`seat_ok`).

## Model: seats per account

- The owner buys `seats` seats. They apply to **all teams the owner has on this server**.
- What counts is the number of **distinct people** across all of the owner's teams, the owner
  included. Someone who is already in one of the owner's teams does not need a new seat for
  another one.
- Without a valid license, **Free: 1 person** applies, the owner alone. A server without a
  license is for private use by one person; teams need a license (Team plan). A license never
  results in fewer than 1 seat.
- The check happens **when an invitation is accepted**, in the same write transaction as the
  join. Open invitations do not occupy a seat. Refusals: `license_required` when the owner has
  no active license, `seats_full` when the license has no seat left.
- Without an active license, the server also refuses **new invitations** for people who do not
  hold a seat yet (API: status `license_required` per address, command `invite`: an error),
  since they could never be accepted. With a license, invitations beyond the seats are still
  created, so the owner can buy more seats before they are accepted.
- **Expiry or no license:** nothing is deleted, nobody is removed. People who already joined
  keep their seat and keep working, even beyond the limit; only joins of new people beyond the
  limit that then applies (1) are rejected. Renewing the license lifts that again.

## Structure

Same scheme as tickets ([ticket-format.md](ticket-format.md)), different context:

```
license   = base64url(payload) "." base64url(signature)
signature = Ed25519(secret_key, "hangar-license-v1." + base64url(payload))
```

Maximum length 4096 characters. Leading and trailing whitespace is removed on upload.

## Fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `v` | number | yes | `1` |
| `kid` | text `[A-Za-z0-9_-]{1,64}` | yes | key ID of the website |
| `lid` | text `[A-Za-z0-9_-]{1,64}` | yes | license ID; on a given server only one account can upload it; revocation via `LICENSE_REVOKED` |
| `sub` | text, up to 128 characters | yes | account ID on the website (for reference only, the server does not compare it) |
| `email` | text, lower case, no surrounding whitespace | yes | address of the account; must match the address of the uploading account on the server |
| `plan` | text `[a-z0-9-]{1,32}` | yes | plan, e.g. `team`; tiers later |
| `seats` | number 1 to 100000 | yes | seats |
| `features` | list of `[A-Za-z0-9_-]{1,64}`, at most 32 | no | additional features; version 1 knows none and ignores them |
| `iat` | Unix seconds | yes | issued at |
| `exp` | Unix seconds | yes | expiry, `exp > iat` |

Unknown fields are ignored. This leaves room for `plan` tiers or a later combination with
projects, without a new version.

## Verification rules

1. Signature, `kid` and form as for the ticket (context `hangar-license-v1`).
2. `v == 1`; fields as above; `email` must already be normalized (`Owner@…` is rejected).
3. `lid` not in `LICENSE_REVOKED`.
4. On upload: `email` equals the account address, `iat <= now + 300 s`, `now < exp`, and `iat`
   not older than the newest document of the same `lid` stored on this server before
   (`license_outdated`): after a downgrade the website issues a newer document with fewer seats,
   and the older one must not come back while it is still valid. The website therefore keeps the
   `lid` of a subscription and issues every change with a fresh `iat`.
5. On every seat check the stored document is verified again (rotated or revoked keys take
   effect immediately); expired means Free.

## How the website signs (PHP)

```php
function hangar_license(string $kid, string $seed32, string $licenseId, string $accountId,
                        string $email, string $plan, int $seats, int $validUntil, array $features = []): string {
    $payload = [
        'v' => 1, 'kid' => $kid, 'lid' => $licenseId, 'sub' => $accountId,
        'email' => mb_strtolower(trim($email)), 'plan' => $plan, 'seats' => $seats,
    ];
    if ($features !== []) { $payload['features'] = array_values($features); }
    $payload['iat'] = time();
    $payload['exp'] = $validUntil;
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed32));
    $p = sodium_bin2base64($json, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $s = sodium_crypto_sign_detached('hangar-license-v1.' . $p, $secret);
    return $p . '.' . sodium_bin2base64($s, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}
```

Recommendation: tie the validity to the subscription (e.g. end of the paid period plus 14 days)
and, on renewal, issue a new document that the owner downloads from their account.
`lid` = ID of the website's license record.

## Test vectors

`testdata/licenses.json` (test key from RFC 8032, for tests only): `valid` (10 seats),
`valid_with_features`, `expired` (signature valid, effectively 1 seat), `foreign_signature`,
`tampered_payload` (seats changed to 1000), `ticket_context`, `email_not_normalized`.
Cross-check: `cargo test --test vectors` and `php tools/php/verify_vectors.php testdata/licenses.json`.

Example (`valid`):

```
payload  {"v":1,"kid":"test-2026-1","lid":"lic_8f3a2c","sub":"1042","email":"owner@example.org","plan":"team","seats":10,"iat":1793900000,"exp":1825502400}
license  eyJ2IjoxLCJraWQiOiJ0ZXN0LTIwMjYtMSIsImxpZCI6ImxpY184ZjNhMmMiLCJzdWIiOiIxMDQyIiwiZW1haWwiOiJvd25lckBleGFtcGxlLm9yZyIsInBsYW4iOiJ0ZWFtIiwic2VhdHMiOjEwLCJpYXQiOjE3OTM5MDAwMDAsImV4cCI6MTgyNTUwMjQwMH0.pnbaTN9YuVKd3tc4Gb1L09lkfVIN0irR6lUHpAjPQB99rCGQ8WipWrUvypQVnnRGrHnS4NKG0UPQGNqageCEBg
```

## Known limitation

The server trusts the keys in its configuration. Anyone who runs their own server can add their
own key there and issue licenses to themselves. Technically this cannot be prevented when the
source code is in someone else's hands; the Elastic License 2.0 prohibits it ("move, change,
disable, or circumvent the license key functionality"). If you want this to be stricter, embed
the website's public keys at build time and let the configuration accept only additional keys
for tests (open point, see [development.md](development.md)).
