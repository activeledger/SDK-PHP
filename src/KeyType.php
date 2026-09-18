<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * Key algorithms, with the exact strings the ledger uses.
 *
 * These strings are the whole contract: the ledger validates nothing else
 * about them. A typo, or key material of the wrong length, surfaces as 1220
 * "Signature Incorrect" and never as "unknown algorithm". The ledger also
 * DEFAULTS a missing type to `rsa` and then attempts RSA verification against
 * whatever it was given, so this SDK always sends the type explicitly.
 */
enum KeyType: string
{
    case Rsa = 'rsa';
    case Secp256k1 = 'secp256k1';
    case MlDsa65 = 'ml-dsa-65';
    case Falcon512 = 'falcon-512';

    /**
     * Parses a wire string. Deliberately strict and case-sensitive: the ledger
     * compares these exactly, so accepting `ML-DSA-65` here would only move
     * the failure somewhere less informative.
     */
    public static function fromWire(string $wire): self
    {
        // The ledger routes these to identical secp256k1 verification, so an
        // existing identity may already carry either. Accepted here and NEVER
        // emitted: the enum's value is always "secp256k1".
        if ($wire === 'bitcoin' || $wire === 'ethereum') {
            return self::Secp256k1;
        }

        return self::tryFrom($wire) ?? throw new \InvalidArgumentException(
            "Unknown key type '$wire' - expected rsa, secp256k1, ml-dsa-65 or falcon-512"
        );
    }

    public function isPostQuantum(): bool
    {
        return $this === self::MlDsa65 || $this === self::Falcon512;
    }
}
