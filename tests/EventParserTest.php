<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\EventParser;
use Activeledger\LedgerEvent;
use PHPUnit\Framework\TestCase;

/**
 * The event-stream framing rules, driven through the parser directly so each
 * rule is checked on its own -- including the ones that only show up when the
 * network splits a line across two chunks.
 */
final class EventParserTest extends TestCase
{
    /** @return list<LedgerEvent> */
    private function parse(string $body): array
    {
        $parser = new EventParser();
        $events = $parser->push($body);

        $final = $parser->finish();
        if ($final !== null) {
            $events[] = $final;
        }

        return $events;
    }

    public function testParsesASimpleEvent(): void
    {
        $events = $this->parse("data: hello\n\n");

        self::assertCount(1, $events);
        self::assertSame('hello', $events[0]->data);
        self::assertNull($events[0]->name);
        self::assertNull($events[0]->id);
    }

    public function testParsesNamedEventsAndIds(): void
    {
        $events = $this->parse("event: tx\nid: 1\ndata: {\"a\":1}\n\nevent: tx\nid: 2\ndata: {\"a\":2}\n\n");

        self::assertCount(2, $events);
        self::assertSame('tx', $events[0]->name);
        self::assertSame('1', $events[0]->id);
        self::assertSame('{"a":1}', $events[0]->data);
        self::assertSame('2', $events[1]->id);
    }

    public function testMultipleDataLinesJoinWithNewlines(): void
    {
        $events = $this->parse("data: one\ndata: two\n\n");

        self::assertCount(1, $events);
        self::assertSame("one\ntwo", $events[0]->data);
    }

    /**
     * Heartbeats keep the connection alive and are not events. Delivering them
     * would hand the caller a stream of empty payloads to filter.
     */
    public function testCommentHeartbeatsAreNotDelivered(): void
    {
        $events = $this->parse(": keep-alive\n\n: another\n\ndata: real\n\n");

        self::assertCount(1, $events);
        self::assertSame('real', $events[0]->data);
    }

    /**
     * event:/id: are per-event fields. Leaking them into the next event
     * mislabels it, and the mislabel looks like a server bug.
     */
    public function testFieldsDoNotLeakIntoTheFollowingEvent(): void
    {
        $events = $this->parse("event: named\nid: 7\ndata: first\n\ndata: second\n\n");

        self::assertCount(2, $events);
        self::assertSame('named', $events[0]->name);
        self::assertNull($events[1]->name);
        self::assertNull($events[1]->id);
    }

    public function testFieldOnlyBlocksProduceNoEventAndDoNotCarryOver(): void
    {
        $events = $this->parse("event: empty\n\nid: 9\n\ndata: real\n\n");

        self::assertCount(1, $events);
        self::assertSame('real', $events[0]->data);
        self::assertNull($events[0]->name);
        self::assertNull($events[0]->id);
    }

    public function testCarriageReturnsAreStripped(): void
    {
        $events = $this->parse("event: tx\r\ndata: payload\r\n\r\n");

        self::assertCount(1, $events);
        self::assertSame('tx', $events[0]->name);
        self::assertSame('payload', $events[0]->data);
    }

    /**
     * Exactly one space after the colon is framing; every other byte is
     * payload. Trimming would quietly corrupt a data field.
     */
    public function testOnlyOneSpaceAfterTheColonIsFraming(): void
    {
        $events = $this->parse("data:  leading\n\ndata:tight\n\ndata: trailing \n\n");

        self::assertCount(3, $events);
        self::assertSame(' leading', $events[0]->data);
        self::assertSame('tight', $events[1]->data);
        self::assertSame('trailing ', $events[2]->data);
    }

    public function testAnEventWithoutItsTrailingBlankLineIsStillDelivered(): void
    {
        $events = $this->parse("data: truncated\n");

        self::assertCount(1, $events);
        self::assertSame('truncated', $events[0]->data);
    }

    public function testAFinalLineWithNoNewlineAtAllIsStillDelivered(): void
    {
        $events = $this->parse('data: no newline');

        self::assertCount(1, $events);
        self::assertSame('no newline', $events[0]->data);
    }

    public function testAnEmptyStreamProducesNothing(): void
    {
        self::assertSame([], $this->parse(''));
        self::assertSame([], $this->parse("\n\n"));
        self::assertSame([], $this->parse(": just a heartbeat\n\n"));
    }

    /**
     * Chunk boundaries fall wherever the network puts them, including the
     * middle of a field name. Anything that assumes a chunk is a whole line
     * works locally and fails against a real server.
     */
    public function testAnEventSplitAcrossChunksIsReassembled(): void
    {
        $parser = new EventParser();
        $events = [];

        foreach (['eve', 'nt: t', "x\nda", 'ta: hel', "lo\n", "\n"] as $chunk) {
            $events = array_merge($events, $parser->push($chunk));
        }

        self::assertCount(1, $events);
        self::assertSame('tx', $events[0]->name);
        self::assertSame('hello', $events[0]->data);
    }

    public function testSeveralEventsInOneChunkAllArrive(): void
    {
        $events = $this->parse("data: a\n\ndata: b\n\ndata: c\n\n");

        self::assertSame(['a', 'b', 'c'], array_map(static fn($e) => $e->data, $events));
    }

    /**
     * Data payloads are JSON, and a colon inside one must not be mistaken for
     * field framing.
     */
    public function testColonsInsideAPayloadAreLeftAlone(): void
    {
        $events = $this->parse("data: {\"time\":\"12:30:00\",\"url\":\"http://x\"}\n\n");

        self::assertCount(1, $events);
        self::assertSame('{"time":"12:30:00","url":"http://x"}', $events[0]->data);
    }

    public function testUnknownFieldsAreIgnored(): void
    {
        $events = $this->parse("retry: 5000\nfoo: bar\ndata: real\n\n");

        self::assertCount(1, $events);
        self::assertSame('real', $events[0]->data);
    }

    public function testAnEmptyDataFieldStillMakesAnEvent(): void
    {
        $events = $this->parse("data:\n\n");

        self::assertCount(1, $events);
        self::assertSame('', $events[0]->data);
    }

    public function testJsonHelperDecodesThePayload(): void
    {
        $events = $this->parse("data: {\"stream\":\"abc\"}\n\n");

        self::assertSame(['stream' => 'abc'], $events[0]->json());
    }

    /** A non-JSON payload is not an error; it is simply not JSON. */
    public function testJsonHelperReturnsNullForNonJson(): void
    {
        $events = $this->parse("data: not json at all\n\n");

        self::assertNull($events[0]->json());
    }
}
