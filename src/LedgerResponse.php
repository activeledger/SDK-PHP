<?php

declare(strict_types=1);

namespace Activeledger;

/** The ledger's reply to a submitted transaction. */
final class LedgerResponse
{
    private readonly ?array $parsed;

    public function __construct(private readonly string $raw)
    {
        $decoded = json_decode($raw, true);
        $this->parsed = is_array($decoded) ? $decoded : null;
    }

    /** The response body exactly as the node sent it. */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * Errors the network reported.
     *
     * Non-empty means the transaction did NOT commit, even though the HTTP
     * status was 200. The ledger answers 200 for a rejected transaction, so
     * treating HTTP success as ledger success is wrong -- and wrong in a way
     * that looks fine until something important silently did not happen.
     *
     * @return list<string>
     */
    public function errors(): array
    {
        $errors = $this->parsed['$summary']['errors'] ?? null;
        if (!is_array($errors)) {
            return [];
        }

        return array_values(array_map(
            static fn($e) => is_string($e) ? $e : (json_encode($e) ?: ''),
            $errors
        ));
    }

    /** True when errors() is empty. This, not the HTTP status. */
    public function committed(): bool
    {
        return $this->errors() === [];
    }

    /**
     * Stream ids this transaction created.
     *
     * @return list<string>
     */
    public function newStreams(): array
    {
        $streams = $this->parsed['$streams']['new'] ?? null;
        if (!is_array($streams)) {
            return [];
        }

        $ids = [];
        foreach ($streams as $stream) {
            if (is_array($stream) && isset($stream['id']) && is_string($stream['id'])) {
                $ids[] = $stream['id'];
            }
        }

        return $ids;
    }

    /**
     * Values contracts handed back with `returnToRemote`.
     *
     * @return list<mixed>
     */
    public function responses(): array
    {
        $responses = $this->parsed['$responses'] ?? null;

        return is_array($responses) ? array_values($responses) : [];
    }

    /** The whole decoded body, or null when it was not JSON. */
    public function decoded(): ?array
    {
        return $this->parsed;
    }
}
