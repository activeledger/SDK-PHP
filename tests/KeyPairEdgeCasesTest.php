<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\KeyPair;
use PHPUnit\Framework\TestCase;

/**
 * The seed and public-key entry points of KeyPair at the edges of their input:
 * every wrong length, the lengths one off the one that gets special treatment,
 * and the verify-only pair that comes back from a stored public key.
 */
final class KeyPairEdgeCasesTest extends TestCase
{
    /**
     * @return array<string, array{int}>
     */
    public static function wrongSeedLengths(): array
    {
        return [
            'empty' => [0],
            'one byte' => [1],
            'one short' => [31],
            'one long' => [33],
            'a BIP-39 seed' => [64],
            'one short of a foreign private key' => [4031],
            'one over a foreign private key' => [4033],
        ];
    }

    /**
     * @dataProvider wrongSeedLengths
     */
    public function testAnyOtherSeedLengthGetsThePlainLengthMessage(int $length): void
    {
        try {
            KeyPair::fromSeed(str_repeat("\x07", $length));
            self::fail("accepted a $length-byte seed");
        } catch (\InvalidArgumentException $e) {
            self::assertSame("seed is $length bytes, expected 32", $e->getMessage());
        }
    }

    public function testOnlyTheExactForeignLengthGetsTheExplanation(): void
    {
        try {
            KeyPair::fromSeed(str_repeat("\x07", KeyPair::FOREIGN_PRIVATE_KEY_SIZE));
            self::fail('accepted a 4032-byte seed');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('4032-byte', $e->getMessage());
            self::assertStringContainsString('KeyPair::generate()', $e->getMessage());
        }
    }

    public function testAForeignPrivateKeyIsRefusedThroughTheBase64EntryPointToo(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/4032-byte/');
        KeyPair::fromSeedBase64(base64_encode(str_repeat("\x07", KeyPair::FOREIGN_PRIVATE_KEY_SIZE)));
    }

    public function testASeedWithMalformedBase64IsRefusedBeforeItsLengthIsChecked(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('seed is not valid base64');
        KeyPair::fromSeedBase64('not base64!');
    }

    public function testAnEmptyBase64SeedIsALengthErrorNotABase64One(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('seed is 0 bytes, expected 32');
        KeyPair::fromSeedBase64('');
    }

    public function testAnAllZeroSeedIsAValidSeed(): void
    {
        // Length is the only check; a seed is key material, not a secret that
        // must look random, and refusing it would make vectors unusable.
        $key = KeyPair::fromSeed(str_repeat("\0", KeyPair::SEED_SIZE));

        self::assertSame(KeyPair::PUBLIC_KEY_SIZE, strlen(base64_decode($key->publicKey())));
        self::assertTrue($key->canSign());
    }

    public function testDifferentSeedsGiveDifferentPublicKeys(): void
    {
        self::assertNotSame(
            KeyPair::fromSeed(str_repeat("\x01", 32))->publicKey(),
            KeyPair::fromSeed(str_repeat("\x02", 32))->publicKey()
        );
    }

    // -- fromPublicKeyBase64 ----------------------------------------------

    public function testAPublicKeyRoundTripsAndVerifiesTheOriginalsSignatures(): void
    {
        $signer = KeyPair::generate();
        $verifier = KeyPair::fromPublicKeyBase64($signer->publicKey());

        self::assertSame($signer->publicKey(), $verifier->publicKey());

        $signature = $signer->sign('a message');
        self::assertTrue($verifier->verify('a message', $signature));
        self::assertFalse($verifier->verify('another message', $signature));
    }

    public function testAPublicKeyOnlyVerifiesItsOwnIdentity(): void
    {
        $signature = KeyPair::generate()->sign('a message');
        $stranger = KeyPair::fromPublicKeyBase64(KeyPair::generate()->publicKey());

        self::assertFalse($stranger->verify('a message', $signature));
    }

    public function testAVerifyOnlyPairReportsItsTypeAndCannotSign(): void
    {
        $verifier = KeyPair::fromPublicKeyBase64(KeyPair::generate()->publicKey());

        self::assertFalse($verifier->canSign());
        self::assertSame('ml-dsa-65', $verifier->keyType()->value);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function wrongPublicKeyLengths(): array
    {
        return [
            'empty' => [0],
            'one short' => [KeyPair::PUBLIC_KEY_SIZE - 1],
            'one long' => [KeyPair::PUBLIC_KEY_SIZE + 1],
            'a seed' => [KeyPair::SEED_SIZE],
        ];
    }

    /**
     * @dataProvider wrongPublicKeyLengths
     */
    public function testAPublicKeyOfTheWrongLengthNamesBothLengths(int $length): void
    {
        try {
            KeyPair::fromPublicKeyBase64(base64_encode(str_repeat("\x05", $length)));
            self::fail("accepted a $length-byte public key");
        } catch (\InvalidArgumentException $e) {
            self::assertSame("public key is $length bytes, expected 1952", $e->getMessage());
        }
    }

    public function testTheUrlSafeBase64AlphabetIsNotAccepted(): void
    {
        $valid = KeyPair::generate()->publicKey();
        $urlSafe = strtr($valid, '+/', '-_');

        // The key is 2604 base64 characters, so it all but certainly contains
        // a character the two alphabets disagree on; if it does not, there is
        // nothing to test and the assertion below says so.
        self::assertNotSame($valid, $urlSafe, 'generated key has no + or /');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('public is not valid base64');
        KeyPair::fromPublicKeyBase64($urlSafe);
    }
}
