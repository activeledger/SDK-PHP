<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\Client;
use Activeledger\KeyPair;
use Activeledger\LedgerEvent;
use Activeledger\Transaction;
use PHPUnit\Framework\TestCase;

/**
 * Runs against a real 4-node Activeledger network.
 *
 * Every other test here checks this SDK against a published file. This one
 * checks it against a running ledger, which is the only thing that actually
 * decides whether a signature is acceptable -- the type string, the `$sigs`
 * keying and the exact signed bytes are all invisible to a unit test, and all
 * three fail as the same unhelpful 1220.
 *
 * Start the network from an activeledger checkout:
 *
 *     npm run test:network:serve
 *
 * then run with the URLs it prints:
 *
 *     AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 \
 *         vendor/bin/phpunit --testsuite live
 */
final class LiveNetworkTest extends TestCase
{
    /** @return list<string> */
    private static function nodes(): array
    {
        return self::split('AL_NODES');
    }

    /** @return list<string> */
    private static function storage(): array
    {
        return self::split('AL_STORAGE');
    }

    /** @return list<string> */
    private static function split(string $var): array
    {
        $raw = getenv($var);
        if ($raw === false || $raw === '') {
            return [];
        }

        return array_values(array_filter(explode(',', $raw)));
    }

    protected function setUp(): void
    {
        if (self::nodes() === []) {
            self::markTestSkipped("AL_NODES not set - start 'npm run test:network:serve'");
        }
    }

    private function client(int $index = 0): Client
    {
        return new Client(self::nodes()[$index]);
    }

    /**
     * Namespaces are claimed permanently, so a fixed name passes once and
     * fails every re-run against the same network -- which reads exactly like
     * a regression and is not one.
     */
    private function unique(string $prefix): string
    {
        return $prefix . (hrtime(true) % 100000000);
    }

    /**
     * Reads a document straight from a node's storage service.
     *
     * Deliberately in the test and NOT in the SDK: storage listens only on the
     * node's own host, so a real client cannot reach it and reads state
     * through a transaction's `$r` instead. This harness runs locally, where
     * storage is reachable by definition, and it is used here to assert what
     * the ledger RECORDED rather than what a contract chose to report.
     */
    private function storageRead(int $index, string $id): ?array
    {
        $storage = self::storage();
        if (!isset($storage[$index])) {
            self::markTestSkipped('AL_STORAGE not set - cannot verify what the ledger recorded');
        }

        $url = rtrim($storage[$index], '/') . '/activeledger/' . rawurlencode($id);
        $body = @file_get_contents($url);
        if ($body === false) {
            return null;
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Waits for a stream's metadata to appear on a given node.
     *
     * Consensus is a majority, so the origin's reply means MOST nodes have
     * committed and the rest may still be writing. Reading immediately is a
     * race that fails a few percent of the time and looks like flakiness in
     * the SDK rather than in the test.
     */
    private function awaitAuthorities(int $node, string $streamId): array
    {
        for ($attempt = 0; $attempt < 40; $attempt++) {
            $meta = $this->storageRead($node, $streamId . ':stream');

            if (is_array($meta['authorities'] ?? null) && $meta['authorities'] !== []) {
                return $meta['authorities'];
            }

            usleep(500_000);
        }

        self::fail("stream meta for $streamId never appeared on node $node");
    }

    public function testAnIdentityOnboardsAndIsRecordedCorrectly(): void
    {
        $key = KeyPair::generate();
        $identity = $this->client()->onboard($key);

        self::assertNotSame('', $identity->streamId);

        $authority = $this->awaitAuthorities(0, $identity->streamId)[0];

        // The type the LEDGER stored. If this is "rsa", the SDK omitted it and
        // every later signature would fail verification.
        self::assertSame('ml-dsa-65', $authority['type']);
        self::assertSame($key->publicKeyBase64(), $authority['public']);
        self::assertSame(KeyPair::PUBLIC_KEY_SIZE, strlen(base64_decode($authority['public'])));
    }

    public function testATransactionSignedByThisSdkIsAccepted(): void
    {
        $client = $this->client();
        $key = KeyPair::generate();
        $identity = $client->onboard($key);

        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('namespace')
            ->input($identity->streamId, $key, ['namespace' => $this->unique('php')])
            ->build();

        $response = $client->submit($tx);

        self::assertTrue($response->committed(), 'rejected: ' . $response->raw());
    }

    /**
     * Without this the suite would pass against a ledger that accepted
     * everything, which would make every test above meaningless.
     */
    public function testATamperedPayloadIsRejected(): void
    {
        $client = $this->client();
        $key = KeyPair::generate();
        $identity = $client->onboard($key);

        $honest = Transaction::builder()
            ->namespace('default')
            ->contract('namespace')
            ->input($identity->streamId, $key, ['namespace' => $this->unique('phptamper')])
            ->build();

        // Same signature, different body. Submitted raw because the builder
        // would re-sign it into a valid transaction.
        $tampered = str_replace('phptamper', 'phpstolen', $honest->toJson());

        $response = $client->submitRaw($tampered);

        self::assertFalse($response->committed(), 'a tampered payload was accepted: ' . $response->raw());
    }

    public function testAnIdentityOnboardedHereIsVisibleFromEveryNode(): void
    {
        $identity = $this->client()->onboard(KeyPair::generate());

        foreach (array_keys(self::storage()) as $node) {
            $authorities = $this->awaitAuthorities($node, $identity->streamId);
            self::assertSame('ml-dsa-65', $authorities[0]['type']);
        }
    }

    /**
     * An identity restored from a stored seed is the same identity to the
     * ledger. This is the one that matters for PHP specifically: the seed is
     * all a caller has, so if it did not round-trip, an identity could never
     * be reused across requests.
     */
    public function testAnIdentityRestoredFromItsSeedStillControlsItsStream(): void
    {
        $client = $this->client();
        $original = KeyPair::generate();
        $identity = $client->onboard($original);

        // Everything a caller would actually persist, and nothing else.
        $restored = KeyPair::fromSeedBase64($original->seedBase64());

        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('namespace')
            ->input($identity->streamId, $restored, ['namespace' => $this->unique('phpseed')])
            ->build();

        $response = $client->submit($tx);

        self::assertTrue($response->committed(), 'rejected: ' . $response->raw());
    }

    /**
     * SSE against a real Activeledger event stream.
     *
     * Aimed at the storage engine's /activeledgerevents/events, because that
     * is what this harness runs: Activecore, which serves the remote-facing
     * /api/activity and /api/events feeds, is a separate service and is not
     * started here. Storage listens only on the node's own host, so this is
     * NOT how a real client subscribes -- but it is a genuine ledger SSE
     * endpoint, and it proves the request headers are acceptable to a real
     * server and the response is not rejected.
     */
    public function testSubscribingToARealNodeIsAccepted(): void
    {
        $storage = self::storage();
        if ($storage === []) {
            self::markTestSkipped('AL_STORAGE not set');
        }

        $endpoint = rtrim($storage[0], '/') . '/activeledgerevents/events';

        $seen = 0;
        $started = hrtime(true);

        // Stops on the first event, or on the timeout if the ledger is quiet.
        $this->client()->subscribe(
            $endpoint,
            function (LedgerEvent $event) use (&$seen): bool {
                $seen++;
                return false;
            },
            3
        );

        $elapsedMs = (hrtime(true) - $started) / 1_000_000;

        // A refused stream returns immediately and throws; reaching here means
        // it was accepted and held open for the timeout, or delivered an event.
        self::assertTrue($seen > 0 || $elapsedMs >= 2000, "returned after {$elapsedMs}ms with no event");
    }

    /**
     * Pointing a subscription at the node rather than Activecore is the easy
     * mistake, and the node's answer (403) must surface as an error rather
     * than as a stream that never produces anything.
     */
    public function testSubscribingToTheNodePortIsReportedAsAnError(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->client()->subscribe('/api/events', static fn(LedgerEvent $e): bool => false, 5);
    }
}
