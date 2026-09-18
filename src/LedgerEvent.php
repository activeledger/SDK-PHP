<?php

declare(strict_types=1);

namespace Activeledger;

/** One server-sent event. */
final class LedgerEvent
{
    public function __construct(
        /** The `event:` field, or null when unnamed. */
        public readonly ?string $name,
        /** The `data:` payload. Multiple data lines join with newlines. */
        public readonly string $data,
        /** The `id:` field, or null when absent. */
        public readonly ?string $id,
    ) {
    }

    /** The payload decoded as JSON, or null when it is not JSON. */
    public function json(): mixed
    {
        try {
            return json_decode($this->data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }
}
