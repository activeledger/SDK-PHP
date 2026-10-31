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
            'list' => ['[1,2]'],
            'empty list' => ['[]'],
        ];
    }

    /**
     * A body that is not a JSON object is an error, not a commit: an empty
     * reply or a proxy's HTML page says nothing about the transaction.
     */
    #[DataProvider('nonObjectBodies')]
    public function testBodiesThatAreNotJsonObjectsParseToNothing(string $body): void
    {
        $r = new LedgerResponse($body);

        self::assertNull($r->decoded());
        self::assertSame($body, $r->raw());
        self::assertSame(['Response body is not a JSON object'], $r->errors());
        self::assertFalse($r->committed());
        self::assertSame([], $r->newStreams());
        self::assertSame([], $r->responses());
    }

    public function testAnEmptySummaryObjectIsCommitted(): void
    {
        self::assertTrue((new LedgerResponse('{"$summary":{}}', 200))->committed());
    }

    /**
     * @return array<string, array{int}>
     */
    public static function failureStatuses(): array
    {
        return ['redirect' => [302], 'bad request' => [400], 'server error' => [500], 'unavailable' => [503], 'informational' => [100]];
    }

    #[DataProvider('failureStatuses')]
    public function testANon2xxStatusIsNotCommittedEvenWithAnEmptyObject(int $status): void
    {
        $r = new LedgerResponse('{"$summary":{}}', $status);

        self::assertFalse($r->committed());
        self::assertSame(["HTTP status $status"], $r->errors());
    }

    public function testNon2xxWithLedgerErrorsReportsTheLedgersErrors(): void
    {
        $r = new LedgerResponse('{"$summary":{"errors":["boom"]}}', 500);

        self::assertSame(['boom'], $r->errors());
    }

    public function test2xxStatusesAreAccepted(): void
    {
        self::assertTrue((new LedgerResponse('{"$summary":{}}', 200))->committed());
        self::assertTrue((new LedgerResponse('{"$summary":{}}', 204))->committed());
    }

    public static function summarylessBodies(): array
    {
        return [
            'empty object' => ['{}'],
            'other keys only' => ['{"$streams":{"new":[{"id":"a"}]}}'],
            'summary is a list' => ['{"$summary":[]}'],
            'summary is a string' => ['{"$summary":"ok"}'],
            'summary is null' => ['{"$summary":null}'],
        ];
    }

    #[DataProvider('summarylessBodies')]
    public function testABodyWithoutASummaryObjectIsNotCommitted(string $body): void
    {
        $r = new LedgerResponse($body, 200);

        self::assertFalse($r->committed());
        self::assertSame(['Response has no $summary object'], $r->errors());
    }
}
