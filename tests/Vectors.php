<?php

declare(strict_types=1);

namespace Activeledger\Tests;

/** Shared access to the vectors published by the ledger repository. */
final class Vectors
{
    /** @var list<array<string, string>>|null */
    private static ?array $cache = null;

    /** @return list<array<string, string>> */
    public static function all(): array
    {
        if (self::$cache === null) {
            $raw = file_get_contents(__DIR__ . '/data/pq-vectors.json');
            if ($raw === false) {
                throw new \RuntimeException('vector file missing');
            }
            self::$cache = json_decode($raw, true, 512, JSON_THROW_ON_ERROR)['vectors'];
        }

        return self::$cache;
    }

    /**
     * Only the ML-DSA-65 vectors. Falcon is not supported in PHP.
     *
     * @return list<array<string, string>>
     */
    public static function mlDsa(): array
    {
        return array_values(array_filter(
            self::all(),
            static fn(array $v): bool => $v['type'] === 'ml-dsa-65'
        ));
    }

    /** The canonical JSON the reference produced for a named message. */
    public static function reference(string $name): string
    {
        foreach (self::all() as $vector) {
            if ($vector['messageName'] === $name) {
                return $vector['message'];
            }
        }

        throw new \RuntimeException("no vector named $name");
    }
}
