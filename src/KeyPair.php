<?php

declare(strict_types=1);

namespace Activeledger;

use ParagonIE\PQCrypto\MLDSA65;
use ParagonIE\PQCrypto\MLDSA65\Signature;
use ParagonIE\PQCrypto\MLDSA65\SigningKey;
use ParagonIE\PQCrypto\MLDSA65\VerificationKey;

/**
 * An ML-DSA-65 key pair.
 *
 * ## The one thing to know before using this class
 *
 * A private key here is a **32-byte seed**, not the 4032-byte encoding that
 * the JavaScript, JVM, C#, Go and Rust SDKs export. That is a limitation of
 * the underlying library (`paragonie/pqcrypto_compat`), which implements
 * FIPS 204 key generation from a seed but not `skEncode`/`skDecode`.
 *
 * The consequence: **an identity created by another Activeledger SDK cannot
 * be used here.** Identities created here work everywhere, because the public
 * key and the signatures are in the standard encodings -- it is only the
 * private key at rest that differs.
 *
 * This class refuses a 4032-byte private key explicitly. It has to, because
 * the underlying library does not: it accepts any string as seed material,
 * hashes it, derives a completely different key, and signs happily. The
 * signatures then fail against the real identity, and the ledger reports 1220
 * "Signature Incorrect" -- a message that points nowhere near the cause. That
 * silent wrong answer is far more expensive than an exception here.
 */
final class KeyPair implements Signer
{
    /** FIPS 204 fixed sizes. */
    public const PUBLIC_KEY_SIZE = 1952;
    public const SIGNATURE_SIZE = 3309;

    /** The seed this library uses in place of an encoded private key. */
    public const SEED_SIZE = 32;

    /**
     * The private key size every other Activeledger SDK uses. Present only so
     * that a key in that format can be recognised and refused by name.
     */
    public const FOREIGN_PRIVATE_KEY_SIZE = 4032;

    private function __construct(
        private readonly ?SigningKey $signingKey,
        private readonly VerificationKey $verificationKey,
        private readonly ?string $seed,
    ) {
    }

    /** Generates a fresh key pair from the platform's secure random source. */
    public static function generate(): self
    {
        return self::fromSeed(random_bytes(self::SEED_SIZE));
    }

    /**
     * Restores a signing key pair from a stored 32-byte seed.
     *
     * @throws \InvalidArgumentException if the seed is not exactly 32 bytes
     */
    public static function fromSeed(string $seed): self
    {
        self::guardSeed($seed);

        $pair = (new MLDSA65())->keyFromSeed($seed);

        return new self($pair['signingKey'], $pair['verificationKey'], $seed);
    }

    /**
     * Restores a signing key pair from a base64 seed.
     *
     * @throws \InvalidArgumentException
     */
    public static function fromSeedBase64(string $seedBase64): self
    {
        return self::fromSeed(self::decode($seedBase64, 'seed'));
    }

    /**
     * A verify-only key pair from a stored public key.
     *
     * @throws \InvalidArgumentException
     */
    public static function fromPublicKeyBase64(string $publicKey): self
    {
        $bytes = self::decode($publicKey, 'public');

        if (strlen($bytes) !== self::PUBLIC_KEY_SIZE) {
            throw new \InvalidArgumentException(sprintf(
                'public key is %d bytes, expected %d',
                strlen($bytes),
                self::PUBLIC_KEY_SIZE
            ));
        }

        return new self(null, VerificationKey::fromBytes($bytes), null);
    }

    public function keyType(): KeyType
    {
        return KeyType::MlDsa65;
    }

    /** The public key, base64, exactly as the ledger stores it. */
    public function publicKey(): string
    {
        return base64_encode($this->verificationKey->bytes());
    }

    /**
     * The 32-byte seed, base64. This is what to store to reuse the identity.
     *
     * Not interchangeable with the private key the other SDKs export. See the
     * class docblock.
     *
     * @throws \LogicException if this pair can only verify
     */
    public function seedBase64(): string
    {
        if ($this->seed === null) {
            throw new \LogicException(
                'This key pair has no private key - it was created for verification only'
            );
        }

        return base64_encode($this->seed);
    }

    public function canSign(): bool
    {
        return $this->signingKey !== null;
    }

    /**
     * Signs a message, returning the raw signature.
     *
     * Signing is HEDGED: fresh entropy goes into every call, so signing one
     * message twice gives different bytes. That matches the reference
     * implementation, and it means a signature can never be compared for
     * equality -- only verified.
     *
     * The context string is empty, which is what the ledger signs with.
     *
     * @throws \LogicException if this pair can only verify
     */
    public function sign(string $message): string
    {
        if ($this->signingKey === null) {
            throw new \LogicException(
                'This key pair has no private key - it was created for verification only'
            );
        }

        return $this->signingKey->sign($message, '')->bytes();
    }

    /**
     * Verifies a signature over a message.
     *
     * Returns false for malformed input rather than throwing: a caller
     * checking a signature wants a yes or a no, and a signature of the wrong
     * length is simply a no.
     */
    public function verify(string $message, string $signature): bool
    {
        if (strlen($signature) !== self::SIGNATURE_SIZE) {
            return false;
        }

        try {
            return $this->verificationKey->verify(
                Signature::fromBytes($signature),
                $message,
                ''
            );
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function guardSeed(string $seed): void
    {
        if (strlen($seed) === self::SEED_SIZE) {
            return;
        }

        // The specific, expensive mistake gets its own message. Without it the
        // underlying library would accept these 4032 bytes as seed material,
        // derive an unrelated key and sign with it -- and every signature
        // would be rejected by the ledger as 1220 "Signature Incorrect".
        if (strlen($seed) === self::FOREIGN_PRIVATE_KEY_SIZE) {
            throw new \InvalidArgumentException(
                'This looks like the 4032-byte ML-DSA-65 private key exported by the '
                . 'JavaScript, JVM, C#, Go or Rust SDKs. The PHP SDK cannot use it: the '
                . 'underlying library implements key generation from a seed but not '
                . 'private key decoding, so an identity created elsewhere cannot be '
                . 'loaded here. Generate a new identity with KeyPair::generate() and '
                . 'store its seedBase64(). Identities created here work with every other '
                . 'SDK, because the public key and signatures are standard.'
            );
        }

        throw new \InvalidArgumentException(sprintf(
            'seed is %d bytes, expected %d',
            strlen($seed),
            self::SEED_SIZE
        ));
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function decode(string $value, string $role): string
    {
        $bytes = base64_decode($value, true);

        if ($bytes === false) {
            throw new \InvalidArgumentException("$role is not valid base64");
        }

        return $bytes;
    }
}
