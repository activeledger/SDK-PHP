<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * An array that always serialises as a JSON object.
 *
 * `[]` is ambiguous in PHP -- it is both an empty array and an empty object --
 * and `$o` in a transaction is an object that must serialise as `{}`. Getting
 * that wrong changes the signed bytes and produces a 1220 that points nowhere
 * near the cause.
 */
final class JsonObject
{
    /**
     * @param array<array-key, mixed> $entries
     */
    public function __construct(private array $entries = [])
    {
    }

    /**
     * Adds or replaces a key. A replaced key keeps its original position,
     * because the ledger signs the order the caller wrote.
     */
    public function set(string $key, mixed $value): self
    {
        $this->entries[$key] = $value;
        return $this;
    }

    public function get(string $key): mixed
    {
        return $this->entries[$key] ?? null;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->entries);
    }

    public function count(): int
    {
        return count($this->entries);
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /**
     * @return array<array-key, mixed>
     */
    public function entries(): array
    {
        return $this->entries;
    }
}
