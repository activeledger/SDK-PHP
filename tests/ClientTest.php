<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\Client;
use PHPUnit\Framework\TestCase;

/**
 * Client construction and the argument checks that happen before any
 * connection is attempted, so nothing here touches a network.
 */
final class ClientTest extends TestCase
{
    public function testTrailingSlashesAreStrippedFromBothUrls(): void
    {
        $client = new Client('http://node:5260//', 'http://core:5261/');

        self::assertSame('http://node:5260', $client->baseUrl());
        self::assertSame('http://core:5261', $client->coreUrl());
    }

    public function testCoreUrlDefaultsToNullAndIsNotTakenFromTheNode(): void
    {
        self::assertNull((new Client('http://node:5260'))->coreUrl());
    }

    public function testSubscribingToActivityWithoutACoreUrlIsRefused(): void
    {
        $client = new Client('http://node:5260');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('No Activecore URL');
        $client->subscribeToActivity(static fn() => null);
    }

    public function testSubscribingToContractEventsWithoutACoreUrlIsRefused(): void
    {
        $client = new Client('http://node:5260');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('No Activecore URL');
        $client->subscribeToContractEvents(static fn() => null, 'contract');
    }

    public function testAnEventNameWithoutAContractIsRefused(): void
    {
        $client = new Client('http://node:5260', 'http://core:5261');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('needs the contract');
        $client->subscribeToContractEvents(static fn() => null, null, 'event');
    }
}
