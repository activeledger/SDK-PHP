<?php

declare(strict_types=1);

namespace Activeledger;

/** The ledger's reply to a submitted transaction. */
final class LedgerResponse
{
    private readonly ?array $parsed;

    /**
     * @param int|null $httpStatus The HTTP status the body arrived with, when
     *        known. A status outside 2xx is never a commit.
     */
    public function __construct(private readonly string $raw, private readonly ?int $httpStatus = null)
    {
        // Only a JSON object is a ledger reply; a list or scalar is not.
        $this->parsed = json_decode($raw) instanceof \stdClass ? json_decode($raw, true) : null;
    }

    /** The response body exactly as the node sent it. */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * Errors the network reported, or that this SDK found in the reply: a body
     * that is not a JSON object, or an HTTP status outside 2xx.
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
        $errors = is_array($errors) ? array_values(array_map(
            static fn($e) => is_string($e) ? $e : (json_encode($e) ?: ''),
            $errors
        )) : [];

        if ($errors === []) {
            if ($this->parsed === null) {
                $errors[] = 'Response body is not a JSON object';
            }
            if ($this->httpStatus !== null && ($this->httpStatus < 200 || $this->httpStatus > 299)) {
                $errors[] = "HTTP status {$this->httpStatus}";
            }
        }

        return $errors;
    }

    /**
     * True when errors() is empty: a JSON object reply, a 2xx status and no
     * reported errors. The ledger's own verdict, not the HTTP status alone.
     */
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
