<?php

declare(strict_types=1);

/**
 * Run by run.sh from inside the scratch consumer project. Exits non-zero, with
 * a message, on the first thing that does not hold.
 */

require __DIR__ . '/vendor/autoload.php';

use Activeledger\CanonicalJson;
use Activeledger\Client;
use Activeledger\KeyPair;
use Activeledger\Secp256k1KeyPair;
use Activeledger\Transaction;

function check(bool $condition, string $what): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL: $what\n");
        exit(1);
    }
    echo "ok   $what\n";
}

// The package must have come from the path repository, not this checkout.
$installed = realpath(dirname((new ReflectionClass(Client::class))->getFileName()));
check(
    str_starts_with($installed, realpath(__DIR__ . '/vendor/activeledger/sdk')),
    'Activeledger classes load from the installed package'
);

$server = proc_open(
    [PHP_BINARY, __DIR__ . '/loopback-server.php'],
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
if ($server === false || ($address = fgets($pipes[1])) === false) {
    fwrite(STDERR, "FAIL: could not start the loopback server\n");
    exit(1);
}
$url = 'http://' . trim($address);

try {
    $keys = [
        'ml-dsa-65' => KeyPair::generate(),
        'secp256k1' => Secp256k1KeyPair::generate(),
    ];

    foreach ($keys as $type => $key) {
        check($key->keyType()->value === $type, "$type: key reports its wire type");

        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('smoke')
            ->input('stream-in', $key, ['value' => 1])
            ->output('stream-out', ['value' => 2])
            ->build();

        $signature = base64_decode($tx->sigs()['stream-in'], true);
        check($signature !== false, "$type: signature is base64");
        check($key->verify($tx->signedBytes(), $signature), "$type: signature verifies over the body");
        check(
            !$key->verify($tx->signedBytes() . ' ', $signature),
            "$type: signature fails over altered bytes"
        );
        check(
            $tx->signedBytes() === CanonicalJson::bytes($tx->body()),
            "$type: signed bytes are the canonical body"
        );

        $committed = (new Client($url . '/committed'))->submit($tx);
        check($committed->committed() && $committed->newStreams() === ['stream-1'], "$type: committed reply");

        $rejected = (new Client($url . '/rejected'))->submit($tx);
        check(
            !$rejected->committed() && $rejected->errors() === ['1220 : Signature Incorrect'],
            "$type: rejected reply (HTTP 200) is not committed"
        );

        $identity = (new Client($url . '/committed'))->onboard($key);
        check($identity->streamId === 'stream-1', "$type: onboard returns the created stream");
    }

    check(
        $keys['ml-dsa-65']->publicKey() !== $keys['secp256k1']->publicKey(),
        'the two key types produce distinct public keys'
    );

    echo "smoke test passed\n";
} finally {
    fclose($pipes[0]);
    proc_terminate($server);
    proc_close($server);
}
