<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * Incremental parser for the event-stream format.
 *
 * Kept separate from the transport so the framing rules can be tested
 * directly. They matter more than they look: a `:` comment line is a
 * heartbeat and must not surface as an empty event, `event:` and `id:` belong
 * to one event and must not leak into the next, and exactly one space after
 * the colon is framing while every other byte is payload.
 */
final class EventParser
{
    private string $buffer = '';
    private ?string $name = null;
    private ?string $id = null;

    /** @var list<string> */
    private array $data = [];

    /**
     * Feeds a chunk of the stream, returning any events it completed.
     *
     * Chunk boundaries fall wherever the network puts them, so a line can
     * arrive in pieces. Anything incomplete stays buffered.
     *
     * @return list<LedgerEvent>
     */
    public function push(string $chunk): array
    {
        $this->buffer .= $chunk;
        $events = [];

        while (($index = strpos($this->buffer, "\n")) !== false) {
            $line = substr($this->buffer, 0, $index);
            $this->buffer = substr($this->buffer, $index + 1);

            $event = $this->line(rtrim($line, "\r"));
            if ($event !== null) {
                $events[] = $event;
            }
        }

        return $events;
    }

    /**
     * Ends the stream, returning a final event if one was pending.
     *
     * A stream that stops without a trailing blank line still has a complete
     * event in hand.
     */
    public function finish(): ?LedgerEvent
    {
        $leftover = $this->buffer;
        $this->buffer = '';

        $event = null;
        if ($leftover !== '') {
            $event = $this->line(rtrim($leftover, "\r"));
        }

        return $event ?? $this->take();
    }

    private function line(string $line): ?LedgerEvent
    {
        if ($line === '') {
            return $this->take();
        }

        if (str_starts_with($line, ':')) {
            // Comment or heartbeat. Ignored deliberately.
            return null;
        }

        if (str_starts_with($line, 'event:')) {
            $this->name = self::stripOneSpace(substr($line, 6));
        } elseif (str_starts_with($line, 'id:')) {
            $this->id = self::stripOneSpace(substr($line, 3));
        } elseif (str_starts_with($line, 'data:')) {
            $this->data[] = self::stripOneSpace(substr($line, 5));
        }

        return null;
    }

    private function take(): ?LedgerEvent
    {
        if ($this->data === []) {
            // Fields with no data do not make an event, but they also do not
            // carry over: the next event would otherwise be mislabelled.
            $this->name = null;
            $this->id = null;
            return null;
        }

        $event = new LedgerEvent($this->name, implode("\n", $this->data), $this->id);

        $this->name = null;
        $this->id = null;
        $this->data = [];

        return $event;
    }

    /**
     * Removes the single optional space after a field's colon.
     *
     * One space, not a trim. The event-stream format defines exactly one
     * optional space as framing; every other byte is payload. Trimming would
     * quietly alter a data field with meaningful leading or trailing
     * whitespace, and the damage would only show up in whatever consumed it.
     */
    private static function stripOneSpace(string $value): string
    {
        return str_starts_with($value, ' ') ? substr($value, 1) : $value;
    }
}
