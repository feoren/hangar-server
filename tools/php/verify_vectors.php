<?php

declare(strict_types=1);

/**
 * Cross-checks the test vectors with PHP and libsodium, signing the way the website does.
 *
 * Usage: php tools/php/verify_vectors.php testdata/tickets.json testdata/licenses.json
 *
 * For each vector the document is re-signed from `payload_json` and compared with `document`
 * (Ed25519 is deterministic). Untampered vectors with the correct context must also verify
 * against the public key.
 */

function b64url(string $bytes): string
{
    return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

/** Signs like the website: base64url(payload) "." base64url(sig over "<context>.<payload_b64>"). */
function hangar_sign(string $payloadJson, string $context, string $seed): string
{
    $secret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    $payload = b64url($payloadJson);
    $signature = sodium_crypto_sign_detached($context . '.' . $payload, $secret);
    return $payload . '.' . b64url($signature);
}

function hangar_verify(string $document, string $context, string $publicKey): bool
{
    [$payload, $signature] = explode('.', $document, 2) + [1 => ''];
    $sig = sodium_base642bin($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    return sodium_crypto_sign_verify_detached($sig, $context . '.' . $payload, $publicKey);
}

$failures = 0;
foreach (array_slice($argv, 1) as $file) {
    $data = json_decode((string) file_get_contents($file), true, 16, JSON_THROW_ON_ERROR);
    $seed = sodium_hex2bin($data['key']['seed_hex']);
    $other = sodium_hex2bin($data['other_key_seed_hex']);
    $public = sodium_base642bin($data['key']['public_key_base64url'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    if (sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)) !== $public) {
        echo "$file: public key does not match\n";
        $failures++;
    }
    foreach ($data['vectors'] as $v) {
        if ($v['tampered']) {
            continue;
        }
        $built = hangar_sign($v['payload_json'], $v['signing_context'], $v['signed_with'] === 'key' ? $seed : $other);
        $same = hash_equals($v['document'], $built);
        $verifies = hangar_verify($v['document'], $data['context'], $public);
        $shouldVerify = $v['signed_with'] === 'key' && $v['signing_context'] === $data['context'];
        $ok = $same && ($verifies === $shouldVerify);
        printf("%-5s %s %s\n", $ok ? 'ok' : 'FAIL', basename($file), $v['name']);
        $failures += $ok ? 0 : 1;
    }
}
exit($failures === 0 ? 0 : 1);
