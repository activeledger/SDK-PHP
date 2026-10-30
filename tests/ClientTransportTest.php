<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\Client;
use Activeledger\KeyPair;
use Activeledger\LedgerEvent;
use Activeledger\Transaction;
use PHPUnit\Framework\TestCase;

/**
 * Client against a scripted server on 127.0.0.1, started per test class and
 * stopped when it ends. Nothing leaves the machine.
 *
 * The routes are described in tests/fixtures/loopback-server.php.
 */
final class ClientTransportTest extends TestCase
{
    private static LoopbackServer $server;

    public static function setUpBeforeClass(): void
    {
        self::$server = LoopbackServer::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$server->stop();
    }

    private function client(string $route, int $timeout = 30): Client
    {
        return new Client(self::$server->url . $route, null, $timeout);
    }

    /** A URL on this machine that nothing is listening on. */
    private static function closedPortUrl(): string
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($socket);
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return 'http://' . $name;
    }

    // -- submitRaw --------------------------------------------------------

    public function testACommittedReplyIsReturnedVerbatimAndReadsAsCommitted(): void
    {
        $response = $this->client('/committed')->submitRaw('{}');

        self::assertTrue($response->committed());
        self::assertSame(['stream-1'], $response->newStreams());
        self::assertSame(
            '{"$streams":{"new":[{"id":"stream-1"}],"updated":[]},"$summary":{"total":1,"vote":1,"commit":true}}',
            $response->raw()
        );
    }

    public function testARejectionAnsweredWithHttp200IsNotCommitted(): void
    {
        $response = $this->client('/rejected')->submitRaw('{}');

        self::assertFalse($response->committed());
        self::assertSame(['1220 : Signature Incorrect'], $response->errors());
    }

    public function testTheBodyIsPostedUnalteredAsJson(): void
    {
        $body = '{"$tx":{"note":"café ☃"},"$sigs":{}}';

        $this->client('/committed')->submitRaw($body);
        $request = self::$server->lastRequest();

        self::assertSame('POST', $request['method']);
        self::assertSame('/committed/', $request['path']);
        self::assertSame('application/json', $request['contentType']);
        self::assertSame($body, $request['body']);
    }

    public function testSubmitSendsTheTransactionsOwnEnvelope(): void
    {
        $tx = Transaction::onboard(KeyPair::generate());

        $this->client('/committed')->submit($tx);

        self::assertSame($tx->toJson(), self::$server->lastRequest()['body']);
    }

    public function testALargeBodyArrivesWhole(): void
    {
        // Big enough to span several reads on the server's side.
        $body = json_encode(['blob' => str_repeat('0123456789abcdef', 20000)], JSON_THROW_ON_ERROR);

        $this->client('/committed')->submitRaw($body);

        self::assertSame($body, self::$server->lastRequest()['body']);
    }

    public function testAnErrorStatusWithALedgerErrorBodyStillSurfacesTheErrors(): void
    {
        $response = $this->client('/status/503')->submitRaw('{}');

        self::assertFalse($response->committed());
        self::assertSame(['node said 503'], $response->errors());
    }

    public function testConnectionRefusedIsARuntimeExceptionNamingTheNode(): void
    {
        $url = self::closedPortUrl();

        try {
            (new Client($url))->submitRaw('{}');
            self::fail('a refused connection did not throw');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString("Request to $url failed", $e->getMessage());
            self::assertMatchesRegularExpression('/connect/i', $e->getMessage());
        }
    }

    public function testAConnectionClosedWithoutAReplyIsARuntimeException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^Request to .*\/close failed: /');
        $this->client('/close')->submitRaw('{}');
    }

    public function testASlowNodeTimesOutAtTheConfiguredLimit(): void
    {
        $started = microtime(true);

        try {
            $this->client('/hang', 1)->submitRaw('{}');
            self::fail('a node that never replies did not time out');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('failed', $e->getMessage());
            self::assertMatchesRegularExpression('/timed out/i', $e->getMessage());
        }

        // It waited for the limit rather than failing for another reason, and
        // did not wait for the 30 second default.
        $elapsed = microtime(true) - $started;
        self::assertGreaterThanOrEqual(0.9, $elapsed);
        self::assertLessThan(10, $elapsed);
    }

    // -- onboard ----------------------------------------------------------

    public function testOnboardReturnsTheIdentityTheLedgerCreated(): void
    {
        $signer = KeyPair::generate();

        $identity = $this->client('/committed')->onboard($signer);

        self::assertSame('stream-1', $identity->streamId);
        self::assertSame($signer, $identity->signer);
        self::assertSame($signer->publicKey(), $identity->publicKey());
    }

    public function testOnboardSubmitsASelfSignedTransactionTheKeyVerifies(): void
    {
        $signer = KeyPair::generate();

        $this->client('/committed')->onboard($signer);
        $body = self::$server->lastRequest()['body'];
        $sent = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        self::assertTrue($sent['$selfsign']);
        self::assertSame($signer->publicKey(), $sent['$tx']['$i']['identity']['publicKey']);

        // The signed bytes are the $tx text exactly as sent. Decoding and
        // re-encoding would turn the empty $o object into a list.
        $prefix = '{"$tx":';
        $suffix = ',"$selfsign":true,"$sigs":';
        $end = strpos($body, $suffix);
        self::assertStringStartsWith($prefix, $body);
        self::assertNotFalse($end);
        self::assertTrue($signer->verify(
            substr($body, strlen($prefix), $end - strlen($prefix)),
            base64_decode($sent['$sigs']['identity'], true)
        ));
    }

    public function testOnboardThrowsWithTheLedgersReplyWhenItWasRejected(): void
    {
        try {
            $this->client('/rejected')->onboard(KeyPair::generate());
            self::fail('a rejected onboard returned an identity');
        } catch (\RuntimeException $e) {
            self::assertStringStartsWith('Onboard failed: ', $e->getMessage());
            self::assertStringContainsString('1220 : Signature Incorrect', $e->getMessage());
        }
    }

    public function testOnboardThrowsOnAnErrorStatus(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Onboard failed: ');
        $this->client('/status/500')->onboard(KeyPair::generate());
    }

    public function testOnboardThrowsWhenTheReplyCreatedNoStream(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Onboard failed: not json');
        $this->client('/plain/200')->onboard(KeyPair::generate());
    }

    public function testOnboardPropagatesATransportFailure(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^Request to .* failed/');
        (new Client(self::closedPortUrl()))->onboard(KeyPair::generate());
    }

    // -- subscribe --------------------------------------------------------

    /** @return list<LedgerEvent> */
    private function collect(string $route, ?int $timeout = null): array
    {
        $events = [];
        $this->client('')->subscribe(
            self::$server->url . $route,
            static function (LedgerEvent $event) use (&$events): void {
                $events[] = $event;
            },
            $timeout
        );

        return $events;
    }

    public function testASubscriptionDeliversEveryEventUntilTheServerCloses(): void
    {
        $events = $this->collect('/sse');

        self::assertCount(2, $events);
        self::assertSame('first', $events[0]->name);
        self::assertSame(['n' => 1], $events[0]->json());
        self::assertNull($events[1]->name);
        self::assertSame(['n' => 2], $events[1]->json());
    }

    public function testARelativePathIsResolvedAgainstTheNodeUrl(): void
    {
        $events = [];
        $this->client('')->subscribe('/sse', static function (LedgerEvent $e) use (&$events): void {
            $events[] = $e;
        });

        self::assertCount(2, $events);
    }

    public function testReturningFalseFromTheCallbackStopsTheSubscription(): void
    {
        $seen = 0;
        $this->client('')->subscribe(self::$server->url . '/sse', static function () use (&$seen): bool {
            $seen++;
            return false;
        });

        self::assertSame(1, $seen);
    }

    public function testReturningFalseEndsAStreamThatWouldOtherwiseStaySilent(): void
    {
        // The server holds this connection open after its one event, so the
        // call can only return because the callback aborted the transfer.
        $seen = 0;
        $this->client('')->subscribe(self::$server->url . '/sse-hold', static function () use (&$seen): bool {
            $seen++;
            return false;
        });

        self::assertSame(1, $seen);
    }

    public function testTheRequestedTimeoutEndsASubscriptionWithoutAnError(): void
    {
        // One event arrives, then silence; the timeout is how it ends, and
        // the events received before it are not lost.
        $events = $this->collect('/sse-hold', 1);

        self::assertCount(1, $events);
        self::assertSame(['n' => 1], $events[0]->json());
    }

    public function testASubscriptionRefusedWithAnErrorStatusThrows(): void
    {
        foreach ([403, 500] as $status) {
            try {
                $this->collect("/status/$status");
                self::fail("a subscription answered with HTTP $status did not throw");
            } catch (\RuntimeException $e) {
                self::assertStringContainsString("rejected with HTTP $status", $e->getMessage());
                self::assertStringContainsString("/status/$status", $e->getMessage());
            }
        }
    }

    public function testASubscriptionConnectionClosedWithoutAReplyThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^Subscription to .*\/close failed: /');
        $this->collect('/close');
    }

    public function testASubscriptionToAClosedPortThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/^Subscription to http:\/\/127\.0\.0\.1:\d+\/ failed: /');
        (new Client('http://unused'))->subscribe(self::closedPortUrl() . '/', static fn() => null);
    }

    public function testATimeoutOnASilentServerEndsASubscriptionQuietly(): void
    {
        self::assertSame([], $this->collect('/hang', 1));
    }

    public function testActivitySubscriptionsAskActivecoreForTheRightPaths(): void
    {
        $client = new Client('http://unused', self::$server->url);

        foreach ([[null, '/api/activity/subscribe'], ['a b/c', '/api/activity/subscribe/a%20b%2Fc']] as [$stream, $path]) {
            try {
                $client->subscribeToActivity(static fn() => null, $stream);
            } catch (\RuntimeException) {
                // The scripted server answers 404 for these; the path it saw
                // is what is being checked.
            }

            self::assertSame($path, self::$server->lastRequest()['path']);
        }
    }

    public function testContractEventSubscriptionsAskActivecoreForTheRightPaths(): void
    {
        $client = new Client('http://unused', self::$server->url);

        $cases = [
            [null, null, '/api/events'],
            ['my contract', null, '/api/events/my%20contract'],
            ['my contract', 'on/ready', '/api/events/my%20contract/on%2Fready'],
        ];

        foreach ($cases as [$contract, $event, $path]) {
            try {
                $client->subscribeToContractEvents(static fn() => null, $contract, $event);
            } catch (\RuntimeException) {
                // 404 from the scripted server; see above.
            }

            self::assertSame($path, self::$server->lastRequest()['path']);
        }
    }

    public function testSubscribeAsksForAnEventStreamWithAGet(): void
    {
        $this->collect('/sse');
        $request = self::$server->lastRequest();

        self::assertSame('GET', $request['method']);
        self::assertSame('text/event-stream', $request['accept']);
    }
}
