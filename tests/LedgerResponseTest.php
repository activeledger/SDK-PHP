<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\LedgerResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Response parsing. The ledger answers HTTP 200 for a rejected transaction,
 * so committed() is the only honest success signal and must not be fooled by
 * odd bodies.
 */
final class LedgerResponseTest extends TestCase
{
    public function testACleanSummaryIsCommitted(): void
    {
        $r = new LedgerResponse('{"$summary":{"total":1,"commit":1,"errors":[]}}');

        self::assertSame([], $r->errors());
        self::assertTrue($r->committed());
    }

    public function testReportedErrorsMeanNotCommitted(): void
    {
        $r = new LedgerResponse('{"$summary":{"errors":["1220: Signature Incorrect","other"]}}');

        self::assertSame(['1220: Signature Incorrect', 'other'], $r->errors());
        self::assertFalse($r->committed());
    }

    public function testNonStringErrorsAreEncodedAsJson(): void
    {
        $r = new LedgerResponse('{"$summary":{"errors":[{"code":1220},42]}}');

        self::assertSame(['{"code":1220}', '42'], $r->errors());
        self::assertFalse($r->committed());
    }

    public function testErrorsAreReindexedFromZero(): void
    {
        $r = new LedgerResponse('{"$summary":{"errors":{"a":"x","b":"y"}}}');

        self::assertSame(['x', 'y'], $r->errors());
    }

    public function testNewStreamsListsIdsAndSkipsMalformedEntries(): void
    {
        $r = new LedgerResponse(
            '{"$streams":{"new":[{"id":"abc"},{"id":7},{"name":"x"},"str",{"id":"def"}]}}'
        );

        self::assertSame(['abc', 'def'], $r->newStreams());
    }

    public function testNewStreamsIsEmptyWhenAbsentOrNotAList(): void
    {
        self::assertSame([], (new LedgerResponse('{"$streams":{}}'))->newStreams());
        self::assertSame([], (new LedgerResponse('{"$streams":{"new":"abc"}}'))->newStreams());
    }

    public function testResponsesAreReturnedAsAList(): void
    {
        $r = new LedgerResponse('{"$responses":{"k":{"balance":5},"j":"v"}}');

        self::assertSame([['balance' => 5], 'v'], $r->responses());
    }

    public function testResponsesAreEmptyWhenAbsentOrNotAnArray(): void
    {
        self::assertSame([], (new LedgerResponse('{}'))->responses());
        self::assertSame([], (new LedgerResponse('{"$responses":"x"}'))->responses());
    }

    public function testRawIsKeptExactlyAsReceived(): void
    {
        $body = '{ "$summary" : {"errors":[]} }' . "\n";

        self::assertSame($body, (new LedgerResponse($body))->raw());
    }

    public function testDecodedReturnsTheBody(): void
    {
        self::assertSame(['a' => [1, 2]], (new LedgerResponse('{"a":[1,2]}'))->decoded());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonObjectBodies(): array
    {
        return [
            'empty' => [''],
            'html' => ['<html>502 Bad Gateway</html>'],
            'scalar' => ['"ok"'],
            'number' => ['12'],
            'null' => ['null'],
        ];
    }

    /**
     * A body that is not a JSON object gives no errors, so committed() is
     * true. Pinned so a change to that behaviour is a deliberate one.
     *
     */
    #[DataProvider('nonObjectBodies')]
    public function testBodiesThatAreNotJsonObjectsParseToNothing(string $body): void
    {
        $r = new LedgerResponse($body);

        self::assertNull($r->decoded());
        self::assertSame($body, $r->raw());
        self::assertSame([], $r->errors());
        self::assertSame([], $r->newStreams());
        self::assertSame([], $r->responses());
    }
}
