<?php

declare(strict_types=1);

/**
 * Gegenprobe der Testvektoren mit PHP und libsodium, so wie die Webseite signiert.
 *
 * Aufruf: php tools/php/verify_vectors.php testdata/tickets.json testdata/licenses.json
 *
 * Für jeden Vektor wird das Dokument aus `payload_json` neu signiert und mit `document`
 * verglichen (Ed25519 ist deterministisch). Unveränderte Vektoren mit dem richtigen Kontext
 * müssen sich außerdem mit dem öffentlichen Schlüssel prüfen lassen.
 */

function b64url(string $bytes): string
{
    return sodium_bin2base64($bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

/** Signiert wie die Webseite: base64url(payload) "." base64url(sig über "<kontext>.<payload_b64>"). */
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
        echo "$file: öffentlicher Schlüssel passt nicht\n";
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
        printf("%-5s %s %s\n", $ok ? 'ok' : 'FEHL', basename($file), $v['name']);
        $failures += $ok ? 0 : 1;
    }
}
exit($failures === 0 ? 0 : 1);
